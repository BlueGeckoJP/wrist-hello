use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::{
    sync::{
        Notify, mpsc,
        oneshot::{self, error::TryRecvError},
    },
    time::{error::Elapsed, timeout},
};
use tracing::{error, info};

use crate::{
    AUTH_TIMEOUT_SECONDS, auth_session::AuthSession, bindings::AuthIdentity,
    current_challenge::CurrentChallenge,
};

/// Represents the result of an authentication attempt
/// This enum does not include `Failure`; failures are represented simply as errors
/// `Denied` represents an explicit user denial from the wrist client
#[derive(Clone, Copy)]
pub enum AuthResult {
    Success { challenge: [u8; 32] },
    Denied { challenge: [u8; 32] },
}

pub struct AuthRequest {
    pub identity: AuthIdentity,
    pub result_tx: mpsc::Sender<bool>,
    pub cancel_rx: oneshot::Receiver<()>,
}

pub struct AuthProcessorContext {
    pub add_queue_rx: mpsc::Receiver<AuthRequest>,
    pub wrist_result_rx: mpsc::Receiver<AuthResult>,
    pub cancel_notify_tx: mpsc::Sender<[u8; 32]>,

    pub wrist_start_notify: Arc<Notify>,

    pub notify_ready: Arc<AtomicBool>,
    pub cancel_notify_ready: Arc<AtomicBool>,

    pub queue: VecDeque<AuthRequest>,

    pub auth_session: AuthSession,
    pub current_challenge: CurrentChallenge,
}

pub struct AuthProcessor {
    ctx: AuthProcessorContext,
}

impl AuthProcessor {
    pub fn new(ctx: AuthProcessorContext) -> Self {
        Self { ctx }
    }

    pub fn spawn(mut self) {
        tokio::spawn(async move {
            loop {
                let incoming_request = if self.ctx.queue.is_empty() {
                    match self.ctx.add_queue_rx.recv().await {
                        Some(req) => Some(req),
                        None => break,
                    }
                } else {
                    self.ctx.add_queue_rx.try_recv().ok()
                };

                if let Some(req) = incoming_request {
                    if (self.ctx.queue.iter().find(|r| r.identity == req.identity)).is_some() {
                        info!(
                            "Received duplicate AuthRequest for uid={}, ignoring",
                            req.identity.uid
                        );
                        req.result_tx.send(false).await.ok();
                        continue;
                    }
                    self.ctx.queue.push_back(req);

                    info!(
                        "Queued AuthRequest for uid={}, queue length={}",
                        self.ctx.queue.back().unwrap().identity.uid,
                        self.ctx.queue.len()
                    );
                }

                let mut request = match self.ctx.queue.pop_front() {
                    Some(req) => req,
                    None => continue,
                };

                match request.cancel_rx.try_recv() {
                    Ok(()) | Err(TryRecvError::Closed) => {
                        info!(
                            "AuthRequest cancelled before processing for uid={}, skipping",
                            request.identity.uid
                        );
                        continue;
                    }
                    Err(TryRecvError::Empty) => {}
                }

                let verified = self.handle_verification(&mut request.cancel_rx).await;

                if let Some(verified) = verified
                    && let Err(e) = request.result_tx.send(verified).await
                {
                    error!(
                        "Failed to send AuthRequest result to handler for uid={}: {}",
                        request.identity.uid, e
                    );
                }
            }
        });
    }

    async fn handle_verification(&mut self, cancel_rx: &mut oneshot::Receiver<()>) -> Option<bool> {
        if let Ok(true) = self.ctx.auth_session.is_verified() {
            info!("Session already verified, skipping verification");
            return Some(true);
        }

        if !self.ctx.notify_ready.load(Ordering::SeqCst)
            || !self.ctx.cancel_notify_ready.load(Ordering::SeqCst)
        {
            error!("Notify not ready, cannot process verification request");
            return Some(false);
        }

        self.drain_stale_wrist_results();

        if let Err(e) = self.ctx.current_challenge.refresh() {
            error!("Failed to refresh challenge: {}, skipping this request", e);
            return Some(false);
        }

        info!("Triggering challenge for verification request");
        self.ctx.wrist_start_notify.notify_one();

        tokio::select! {
            biased;

            _ = cancel_rx => {
                info!("AuthRequest cancelled while in progress");

                let challenge = match self.ctx.current_challenge.peek() {
                    Ok(challenge) => challenge,
                    Err(e) => {
                        error!("Failed to peek current challenge: {}, cannot send cancel notification to wrist", e);
                        return None;
                    }
                };

                if let Err(e) = self.ctx.cancel_notify_tx.send(challenge).await {
                    error!("Failed to send cancel notification to wrist: {}", e);
                }

                None
            }

            result = timeout(
                Duration::from_secs(AUTH_TIMEOUT_SECONDS),
                self.ctx.wrist_result_rx.recv(),
            ) => {
                Some(self.handle_wrist_result(result).await)
            }
        }
    }

    fn drain_stale_wrist_results(&mut self) {
        let mut drained = 0;

        while self.ctx.wrist_result_rx.try_recv().is_ok() {
            drained += 1;
        }

        if drained > 0 {
            info!("Drained {} stale wrist results from channel", drained);
        }
    }

    async fn handle_wrist_result(&self, result: Result<Option<AuthResult>, Elapsed>) -> bool {
        match result {
            Ok(Some(AuthResult::Success { challenge })) => {
                info!("Received successful verification notification");

                match self.ctx.current_challenge.take_if_matches(&challenge) {
                    Ok(true) => {
                        info!(
                            "Challenge in verification notification matches current challenge, treating as successful verification"
                        );

                        if let Err(e) = self.ctx.auth_session.mark_verified() {
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

                match self.ctx.current_challenge.take_if_matches(&challenge) {
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
