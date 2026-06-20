use bluer::gatt::local::{
    Characteristic, CharacteristicWrite, CharacteristicWriteMethod, ReqError,
};
use ecdsa::signature::Verifier;
use p256::{
    ecdsa::{Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
};
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::{RESPONSE_CHAR_UUID, auth_processor::AuthResult, current_challenge::CurrentChallenge};

const DENY_RESPONSE_MARKER: u8 = 0x00;

/// Generates the GATT characteristic for the authentication challenge response
pub fn generate_response_char(
    current_challenge: CurrentChallenge,
    public_key_der_bytes: Vec<u8>,
    wrist_result_tx: mpsc::Sender<AuthResult>,
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
                    current_challenge.clone(),
                    public_key_der_bytes.clone(),
                    wrist_result_tx.clone(),
                ))
            })),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Handles writes to the response characteristic
///
/// A value starting with `0x00` followed by the current 32-byte
/// challenge is treated as an explicit deny response from the
/// wearos-app client. Otherwise, the value is treated as a DER-encoded ECDSA
/// signature and verified against the current challenge
///
/// This handler only classifies/verifies the write and forwards an `AuthResult`.
/// `AuthProcessor` owns the final request decision and consumes the matching challenge.
async fn handle_response_write(
    new_value: Vec<u8>,
    current_challenge: CurrentChallenge,
    public_key_der_bytes: Vec<u8>,
    wrist_result_tx: mpsc::Sender<AuthResult>,
) -> Result<(), ReqError> {
    if new_value.first() == Some(&DENY_RESPONSE_MARKER) {
        if new_value.len() != 1 + 32 {
            error!("Error: Invalid deny response length");
            return Err(ReqError::Failed);
        }

        if let Err(e) = wrist_result_tx
            .send(AuthResult::Denied {
                challenge: new_value[1..].try_into().unwrap(),
            })
            .await
        {
            error!("Error: Failed to send deny result: {}", e);
        }

        return Ok(());
    }

    let challenge = match current_challenge.peek() {
        Ok(ch) => ch,
        Err(e) => {
            error!("Error: Failed to get current challenge: {}", e);
            return Err(ReqError::Failed);
        }
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

            if let Err(e) = wrist_result_tx
                .send(AuthResult::Success { challenge })
                .await
            {
                error!("Error: Failed to send success result: {}", e);
            }

            Ok(())
        }
        Err(e) => {
            error!("Error: Invalid signature: {}", e);
            Err(ReqError::Failed)
        }
    }
}
