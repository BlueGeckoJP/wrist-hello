use bluer::gatt::local::{
    Characteristic, CharacteristicWrite, CharacteristicWriteMethod, ReqError,
};
use ecdsa::signature::Verifier;
use p256::{
    ecdsa::{Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
};
use tracing::{error, info};

use crate::{
    RESPONSE_CHAR_UUID, auth_session::AuthSession, current_challenge::CurrentChallenge,
    pending_notifications::PendingNotifications,
};

const DENY_RESPONSE_MARKER: u8 = 0x00;

/// Generates the GATT characteristic for the authentication challenge response
pub fn generate_response_char(
    current_challenge: CurrentChallenge,
    pending_notifications: PendingNotifications,
    auth_session: AuthSession,
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
                    current_challenge.clone(),
                    public_key_der_bytes.clone(),
                    pending_notifications.clone(),
                    auth_session.clone(),
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
async fn handle_response_write(
    new_value: Vec<u8>,
    current_challenge: CurrentChallenge,
    public_key_der_bytes: Vec<u8>,
    pending_notifications: PendingNotifications,
    auth_session: AuthSession,
) -> Result<(), ReqError> {
    if new_value.first() == Some(&DENY_RESPONSE_MARKER) {
        if new_value.len() != 1 + 32 {
            error!("Error: Invalid deny response length");
            return Err(ReqError::Failed);
        }

        match current_challenge.take_if_matches(&new_value[1..]) {
            Ok(true) => {}
            Ok(false) => {
                error!("Error: Deny response challenge does not match current challenge");
                return Err(ReqError::Failed);
            }
            Err(e) => {
                error!(
                    "Error: Failed to get current challenge for deny response: {}",
                    e
                );
                return Err(ReqError::Failed);
            }
        }

        pending_notifications.fail_all().map_err(|e| {
            error!("Error: Failed to fail pending notifications: {}", e);
            ReqError::Failed
        })?;

        info!("Authentication denied by client");
        return Ok(());
    }

    let challenge = match current_challenge.take() {
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

            match auth_session.mark_verified() {
                Ok(_) => info!("Marked session as verified"),
                Err(e) => {
                    error!("Error: Failed to mark session as verified: {}", e);
                    return Err(ReqError::Failed);
                }
            }

            match pending_notifications.notify_all() {
                Ok(count) => info!("Notified {} pending notifications", count),
                Err(e) => {
                    error!("Error: Failed to notify pending notifications: {}", e);
                    return Err(ReqError::Failed);
                }
            }

            Ok(())
        }
        Err(e) => {
            error!("Error: Invalid signature: {}", e);
            Err(ReqError::Failed)
        }
    }
}
