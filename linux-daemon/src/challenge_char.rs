use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, Ordering},
};

use bluer::gatt::local::{
    Characteristic, CharacteristicNotifier, CharacteristicNotify, CharacteristicNotifyMethod,
    CharacteristicRead, ReqError,
};
use rand::RngExt;
use tokio::sync::Notify;
use tracing::{error, info};

use crate::CHALLENGE_CHAR_UUID;

pub fn generate_challenge_char(
    current_challenge: Arc<RwLock<Vec<u8>>>,
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
                let state = challenge_for_read.clone();
                Box::pin(handle_challenge_read(state))
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

async fn handle_challenge_read(challenge_read: Arc<RwLock<Vec<u8>>>) -> Result<Vec<u8>, ReqError> {
    let new_challenge = {
        let mut rng = rand::rngs::ThreadRng::default();
        let mut ch = vec![0u8; 32];
        rng.fill(ch.as_mut_slice());
        ch
    };

    if let Ok(mut locked) = challenge_read.write() {
        *locked = new_challenge.clone();
    }

    info!("READ: Generated new challenge: {:?}", new_challenge);
    Ok(new_challenge)
}

async fn handle_challenge_notify(
    mut notifier: CharacteristicNotifier,
    challenge_notify: Arc<RwLock<Vec<u8>>>,
    challenge_trigger: Arc<Notify>,
    is_first_notify: Arc<AtomicBool>,
) {
    let new_challenge = {
        let mut rng = rand::rngs::ThreadRng::default();
        let mut ch = vec![0u8; 32];
        rng.fill(ch.as_mut_slice());
        ch
    };
    if let Ok(mut locked) = challenge_notify.write() {
        *locked = new_challenge.clone();
    }
    info!("NOTIFY: Generated new challenge: {:?}", new_challenge);
    if notifier.notify(new_challenge).await.is_err() {
        error!("NOTIFY: Failed to send notification");
        return;
    }
    is_first_notify.store(false, Ordering::SeqCst);

    loop {
        challenge_trigger.notified().await;
        let new_challenge = {
            let mut rng = rand::rngs::ThreadRng::default();
            let mut ch = vec![0u8; 32];
            rng.fill(ch.as_mut_slice());
            ch
        };
        if let Ok(mut locked) = challenge_notify.write() {
            *locked = new_challenge.clone();
        }
        info!("NOTIFY: Re-triggered challenge: {:?}", new_challenge);
        if notifier.notify(new_challenge).await.is_err() {
            error!("NOTIFY: Failed to send notification");
            break;
        }
    }
}
