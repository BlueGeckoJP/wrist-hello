use std::sync::{Arc, atomic::AtomicBool};

use bluer::gatt::local::{
    Characteristic, CharacteristicNotifier, CharacteristicNotify, CharacteristicNotifyMethod,
};
use tokio::sync::{Mutex, mpsc};
use tracing::{error, info};

use crate::{CANCEL_CHAR_UUID, notify_ready_guard::NotifyReadyGuard};

/// Generates the GATT characteristic for authentication cancellation
pub fn generate_cancel_char(
    cancel_notify_rx: mpsc::Receiver<[u8; 32]>,
    cancel_notify_ready: Arc<AtomicBool>,
) -> Characteristic {
    let cancel_notify_rx = Arc::new(Mutex::new(cancel_notify_rx));

    Characteristic {
        uuid: CANCEL_CHAR_UUID,
        notify: Some(CharacteristicNotify {
            notify: true,
            method: CharacteristicNotifyMethod::Fun(Box::new(move |notifier| {
                let cancel_notify_rx = cancel_notify_rx.clone();
                Box::pin(handle_cancel_notify(
                    notifier,
                    cancel_notify_rx,
                    cancel_notify_ready.clone(),
                ))
            })),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Handles notifications for the cancel characteristic by sending cancellation data to the wearos-app client
async fn handle_cancel_notify(
    mut notifier: CharacteristicNotifier,
    cancel_notify_rx: Arc<Mutex<mpsc::Receiver<[u8; 32]>>>,
    cancel_notify_ready: Arc<AtomicBool>,
) {
    let _ready_guard = NotifyReadyGuard::new(cancel_notify_ready);

    loop {
        let cancel_data = {
            let mut cancel_notify_rx = cancel_notify_rx.lock().await;
            match cancel_notify_rx.recv().await {
                Some(data) => data.to_vec(),
                None => {
                    error!("NOTIFY: Cancel notification channel closed");
                    return;
                }
            }
        };

        info!("NOTIFY: Re-triggered cancel: {:?}", cancel_data);
        if notifier.notify(cancel_data).await.is_err() {
            error!("NOTIFY: Failed to send notification");
            break;
        }
    }
}
