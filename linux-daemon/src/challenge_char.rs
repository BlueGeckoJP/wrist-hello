use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use bluer::gatt::local::{
    Characteristic, CharacteristicNotifier, CharacteristicNotify, CharacteristicNotifyMethod,
    CharacteristicRead, ReqError,
};
use tokio::sync::Notify;
use tracing::{error, info};

use crate::{CHALLENGE_CHAR_UUID, current_challenge::CurrentChallenge};

/// Generates the GATT characteristic for the authentication challenge
pub fn generate_challenge_char(
    current_challenge: CurrentChallenge,
    challenge_trigger: Arc<Notify>,
    is_first_notify: Arc<AtomicBool>,
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
                let challenge_trigger = challenge_trigger.clone();
                let is_first_notify = is_first_notify.clone();
                Box::pin(handle_challenge_notify(
                    notifier,
                    challenge_for_notify,
                    challenge_trigger,
                    is_first_notify,
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

/// Handles notifications for the challenge characteristic by generating a new challenge and sending it to the wearos-app client
/// Notifications to the wearos-app client are triggered via `challenge_trigger: Arc<Notify>`
async fn handle_challenge_notify(
    mut notifier: CharacteristicNotifier,
    current_challenge: CurrentChallenge,
    challenge_trigger: Arc<Notify>,
    is_first_notify: Arc<AtomicBool>,
) {
    let new_challenge = match current_challenge.refresh() {
        Ok(ch) => ch.to_vec(),
        Err(e) => {
            error!("NOTIFY: Failed to refresh challenge: {}", e);
            return;
        }
    };

    info!("NOTIFY: Generated new challenge: {:?}", new_challenge);
    if notifier.notify(new_challenge).await.is_err() {
        error!("NOTIFY: Failed to send notification");
        return;
    }
    is_first_notify.store(false, Ordering::SeqCst);

    loop {
        challenge_trigger.notified().await;
        let new_challenge = match current_challenge.refresh() {
            Ok(ch) => ch.to_vec(),
            Err(e) => {
                error!("NOTIFY: Failed to refresh challenge: {}", e);
                return;
            }
        };

        info!("NOTIFY: Re-triggered challenge: {:?}", new_challenge);
        if notifier.notify(new_challenge).await.is_err() {
            error!("NOTIFY: Failed to send notification");
            break;
        }
    }
}
