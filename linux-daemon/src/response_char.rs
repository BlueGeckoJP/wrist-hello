use std::{
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::SystemTime,
};

use bluer::gatt::local::{
    Characteristic, CharacteristicWrite, CharacteristicWriteMethod, ReqError,
};
use ecdsa::signature::Verifier;
use p256::{
    ecdsa::{Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
};
use tracing::{error, info};

use crate::RESPONSE_CHAR_UUID;

pub fn generate_response_char(
    challenge_verify: Arc<RwLock<Vec<u8>>>,
    last_verified_at: Arc<AtomicU64>,
    public_key_der_bytes: Vec<u8>,
) -> Characteristic {
    Characteristic {
        uuid: RESPONSE_CHAR_UUID,
        write: Some(CharacteristicWrite {
            write: true,
            write_without_response: true,
            encrypt_authenticated_write: true,
            method: CharacteristicWriteMethod::Fun(Box::new(move |new_value, req| {
                info!("RESPONSE_CHAR:WRITE: Connected from {}", req.device_address);
                Box::pin(handle_response_write(
                    new_value.clone(),
                    challenge_verify.clone(),
                    last_verified_at.clone(),
                    public_key_der_bytes.clone(),
                ))
            })),
            ..Default::default()
        }),
        ..Default::default()
    }
}

async fn handle_response_write(
    new_value: Vec<u8>,
    challenge_verify: Arc<RwLock<Vec<u8>>>,
    last_verified_at: Arc<AtomicU64>,
    public_key_der_bytes: Vec<u8>,
) -> Result<(), ReqError> {
    let challenge = {
        let locked = challenge_verify.read().unwrap();
        locked.clone()
    };

    let verifying_key = match VerifyingKey::from_public_key_der(&public_key_der_bytes) {
        Ok(key) => key,
        Err(_) => {
            error!("Error: Invalid public key");
            return Err(ReqError::Failed);
        }
    };

    let signature = match Signature::from_der(&new_value) {
        Ok(sig) => sig,
        Err(_) => {
            error!("Error: Invalid signature");
            return Err(ReqError::Failed);
        }
    };

    match verifying_key.verify(&challenge, &signature) {
        Ok(_) => {
            info!("Success");
            let now = SystemTime::now();
            let timestamp = now
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            last_verified_at.store(timestamp, Ordering::SeqCst);

            Ok(())
        }
        Err(e) => {
            error!("Error: Invalid signature: {}", e);
            Err(ReqError::Failed)
        }
    }
}
