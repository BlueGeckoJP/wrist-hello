use std::sync::{Arc, atomic::AtomicBool};

use bluer::gatt::local::{
    Characteristic, CharacteristicNotifier, CharacteristicNotify, CharacteristicNotifyMethod,
    CharacteristicRead, ReqError,
};
use tokio::sync::Notify;
use tracing::{error, info};

use crate::{
    CHALLENGE_CHAR_UUID, current_challenge::CurrentChallenge, notify_ready_guard::NotifyReadyGuard,
};

/// Generates the GATT characteristic for the authentication challenge
pub fn generate_challenge_char(
    current_challenge: CurrentChallenge,
    notify_ready: Arc<AtomicBool>,
    wrist_start_notify: Arc<Notify>,
) -> Characteristic {
    let challenge_for_read = current_challenge.clone();
    let challenge_for_notify = current_challenge.clone();

    Characteristic {
        uuid: CHALLENGE_CHAR_UUID,
        read: Some(CharacteristicRead {
            read: true,
            encrypt_authenticated_read: true,
            fun: Box::new(move |req| {
                info!("CHALLENGE_CHAR:READ: Connected from {}", req.device_address);
                Box::pin(handle_challenge_read(challenge_for_read.clone()))
            }),
            ..Default::default()
        }),
        notify: Some(CharacteristicNotify {
            notify: true,
            method: CharacteristicNotifyMethod::Fun(Box::new(move |notifier| {
                let challenge_for_notify = challenge_for_notify.clone();
                let wrist_start_notify = wrist_start_notify.clone();
                Box::pin(handle_challenge_notify(
                    notifier,
                    challenge_for_notify,
                    wrist_start_notify,
                    notify_ready.clone(),
                ))
            })),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Handles read requests for the challenge characteristic by generating a new challenge
async fn handle_challenge_read(current_challenge: CurrentChallenge) -> Result<Vec<u8>, ReqError> {
    let new_challenge = current_challenge.refresh().map_err(|e| {
        error!("READ: Failed to refresh challenge: {}", e);
        ReqError::Failed
    })?;

    info!("READ: Generated new challenge: {:?}", new_challenge);
    Ok(new_challenge.to_vec())
}

/// Handles notifications for the challenge characteristic by sending
/// the challenge updated by the AuthProcessor to the wearos-app client.
/// Notifications to the wearos-app client are triggered via
/// `wrist_start_notify: Arc<Notify>`
async fn handle_challenge_notify(
    mut notifier: CharacteristicNotifier,
    current_challenge: CurrentChallenge,
    wrist_start_notify: Arc<Notify>,
    notify_ready: Arc<AtomicBool>,
) {
    let _ready_guard = NotifyReadyGuard::new(notify_ready);

    loop {
        wrist_start_notify.notified().await;
        let challenge = match current_challenge.peek() {
            Ok(ch) => ch.to_vec(),
            Err(e) => {
                error!("NOTIFY: Failed to peek challenge: {}", e);
                return;
            }
        };

        info!("NOTIFY: Re-triggered challenge: {:?}", challenge);
        if notifier.notify(challenge).await.is_err() {
            error!("NOTIFY: Failed to send notification");
            break;
        }
    }
}
