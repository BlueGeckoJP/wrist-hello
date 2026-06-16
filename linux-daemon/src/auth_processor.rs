use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::{
    sync::{Notify, mpsc},
    time::timeout,
};
use tracing::{error, info};

use crate::{
    AUTH_TIMEOUT_SECONDS, auth_session::AuthSession, bindings::AuthIdentity,
    current_challenge::CurrentChallenge,
};

/// Represents the result of an authentication attempt
/// This enum does not include `Failure`; failures are represented simply as errors
/// `Denied` represents an explicit user denial or approval timeout
#[derive(Clone, Copy)]
pub enum AuthResult {
    Success { challenge: [u8; 32] },
    Denied { challenge: [u8; 32] },
}

pub struct AuthRequest {
    pub identity: AuthIdentity,
    pub result_tx: mpsc::Sender<bool>,
}

pub struct AuthProcessor {
    add_queue_rx: mpsc::Receiver<AuthRequest>,
    wrist_start_notify: Arc<Notify>,
    wrist_result_rx: mpsc::Receiver<AuthResult>,

    in_progress: Option<AuthRequest>,
    current_challenge: CurrentChallenge,

    queue: VecDeque<AuthRequest>,

    auth_session: AuthSession,
    notify_ready: Arc<AtomicBool>,
}

impl AuthProcessor {
    pub fn new(
        add_queue_rx: mpsc::Receiver<AuthRequest>,
        wrist_start_notify: Arc<Notify>,
        wrist_result_rx: mpsc::Receiver<AuthResult>,
        auth_session: AuthSession,
        current_challenge: CurrentChallenge,
        notify_ready: Arc<AtomicBool>,
    ) -> Self {
        Self {
            add_queue_rx,
            wrist_start_notify,
            wrist_result_rx,
            in_progress: None,
            current_challenge,
            queue: VecDeque::new(),
            auth_session,
            notify_ready,
        }
    }

    pub fn spawn(mut self) {
        tokio::spawn(async move {
            loop {
                if let Ok(req) = self.add_queue_rx.try_recv() {
                    if (self.queue.iter().find(|r| r.identity == req.identity)).is_some() {
                        info!(
                            "Received duplicate AuthRequest for uid={}, ignoring",
                            req.identity.uid
                        );
                        req.result_tx.send(false).await.ok();
                        continue;
                    }
                    self.queue.push_back(req);

                    info!(
                        "Queued AuthRequest for uid={}, queue length={}",
                        self.queue.back().unwrap().identity.uid,
                        self.queue.len()
                    );
                }

                if self.queue.is_empty() {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }

                let request = match self.queue.pop_front() {
                    Some(req) => req,
                    None => continue,
                };

                self.in_progress = Some(request);

                let verified = self.handle_verification().await;

                if let Some(req) = self.in_progress.take() {
                    let _ = req.result_tx.send(verified).await;
                }
            }
        });
    }

    async fn handle_verification(&mut self) -> bool {
        if let Ok(true) = self.auth_session.is_verified() {
            info!("Session already verified, skipping verification");
            return true;
        }

        if !self.notify_ready.load(Ordering::SeqCst) {
            error!("Notify not ready, cannot process verification request");
            return false;
        }

        if let Err(e) = self.current_challenge.refresh() {
            error!("Failed to refresh challenge: {}, skipping this request", e);
            return false;
        }

        info!("Triggering challenge for verification request");
        self.wrist_start_notify.notify_one();

        match timeout(
            Duration::from_secs(AUTH_TIMEOUT_SECONDS),
            self.wrist_result_rx.recv(),
        )
        .await
        {
            Ok(Some(AuthResult::Success { challenge })) => {
                info!("Received successful verification notification");

                match self.current_challenge.take_if_matches(&challenge) {
                    Ok(true) => {
                        info!(
                            "Challenge in verification notification matches current challenge, treating as successful verification"
                        );

                        if let Err(e) = self.auth_session.mark_verified() {
                            error!("Failed to mark session as verified: {}", e);
                            return false;
                        }

                        true
                    }
                    Ok(false) => {
                        error!(
                            "Received challenge in verification notification does not match current challenge, treating as failed verification"
                        );
                        false
                    }
                    Err(e) => {
                        error!(
                            "Failed to take current challenge: {}, treating as failed verification",
                            e
                        );
                        false
                    }
                }
            }
            Ok(Some(AuthResult::Denied { challenge })) => {
                info!("Received denied verification notification");

                match self.current_challenge.take_if_matches(&challenge) {
                    Ok(true) => {
                        info!(
                            "Challenge in denied verification notification matches current challenge, treating as explicit denial"
                        );
                    }
                    Ok(false) => {
                        error!(
                            "Received challenge in denied verification notification does not match current challenge, treating as failed verification"
                        );
                    }
                    Err(e) => {
                        error!(
                            "Failed to take current challenge: {}, treating as failed verification",
                            e
                        );
                    }
                }

                false
            }
            Ok(None) => {
                error!("Failed to receive verification notification");
                false
            }
            Err(e) => {
                error!("Failed to wait for verification notification: {}", e);
                false
            }
        }
    }
}
