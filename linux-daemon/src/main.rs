use std::sync::{Arc, RwLock};

use bluer::{
    Uuid,
    gatt::local::{
        Application, Characteristic, CharacteristicNotifier, CharacteristicNotify,
        CharacteristicNotifyMethod, CharacteristicRead, CharacteristicWrite,
        CharacteristicWriteMethod, ReqError, Service,
    },
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::RngExt;

const SERVICE_UUID: Uuid = Uuid::from_u128(0xddc6ea97_db6e_4ecd_a3ff_0143368ef829);
const CHALLENGE_CHAR_UUID: Uuid = Uuid::from_u128(0x5794ca86_3a5e_45ca_85f9_42a74cd460a7);
const RESPONSE_CHAR_UUID: Uuid = Uuid::from_u128(0xf68c58c2_a1f2_456f_a118_f1c6ce566a0a);

#[tokio::main]
async fn main() -> bluer::Result<()> {
    let session = bluer::Session::new().await?;
    let adapter = session.default_adapter().await?;
    println!("Using adapter {}", adapter.name());

    adapter.set_powered(true).await?;
    println!("Adapter powered on");

    let current_challenge = Arc::new(RwLock::new(vec![0u8; 32]));
    let challenge_read = current_challenge.clone();
    let challenge_notify = current_challenge.clone();
    let challenge_verify = current_challenge.clone();

    let challenge_char = Characteristic {
        uuid: CHALLENGE_CHAR_UUID,
        read: Some(CharacteristicRead {
            read: true,
            fun: Box::new(move |_req| {
                let state = challenge_read.clone();
                Box::pin(async move {
                    let new_challenge = {
                        let mut rng = rand::rngs::ThreadRng::default();
                        let mut ch = vec![0u8; 32];
                        rng.fill(ch.as_mut_slice());
                        ch
                    };

                    if let Ok(mut locked) = state.write() {
                        *locked = new_challenge.clone();
                    }

                    println!("READ: Generated new challenge: {:?}", new_challenge);
                    Ok(new_challenge)
                })
            }),
            ..Default::default()
        }),
        notify: Some(CharacteristicNotify {
            notify: true,
            method: CharacteristicNotifyMethod::Fun(Box::new(move |mut notifier| {
                let state = challenge_notify.clone();
                Box::pin(async move {
                    let new_challenge = {
                        let mut rng = rand::rngs::ThreadRng::default();
                        let mut ch = vec![0u8; 32];
                        rng.fill(ch.as_mut_slice());
                        ch
                    };

                    if let Ok(mut locked) = state.write() {
                        *locked = new_challenge.clone();
                    }

                    println!("NOTIFY: Generated new challenge: {:?}", new_challenge);
                    let _ = notifier.notify(new_challenge).await;
                })
            })),
            ..Default::default()
        }),
        ..Default::default()
    };

    let response_char = Characteristic {
        uuid: RESPONSE_CHAR_UUID,
        write: Some(CharacteristicWrite {
            write: true,
            write_without_response: true,
            method: CharacteristicWriteMethod::Fun(Box::new(move |new_value, _req| {
                let state = challenge_verify.clone();
                Box::pin(async move {
                    if new_value.len() != 64 {
                        println!("Error: The signature length is not 64");
                        return Err(ReqError::InvalidValueLength);
                    }

                    let challenge = {
                        let locked = state.read().unwrap();
                        locked.clone()
                    };

                    // TODO: Replace it with actual key
                    let public_key_bytes = [0u8; 32];

                    let verifying_key = match VerifyingKey::from_bytes(&public_key_bytes) {
                        Ok(key) => key,
                        Err(_) => {
                            println!("Error: Invalid public key");
                            return Err(ReqError::Failed);
                        }
                    };

                    let signature_bytes: [u8; 64] = match new_value.try_into() {
                        Ok(bytes) => bytes,
                        Err(_) => {
                            println!("Error: Invalid signature");
                            return Err(ReqError::InvalidValueLength);
                        }
                    };
                    let signature = Signature::from_bytes(&signature_bytes);

                    match verifying_key.verify(&challenge, &signature) {
                        Ok(_) => {
                            println!("Success");
                            Ok(())
                        }
                        Err(e) => {
                            println!("Error: Invalid signature: {}", e);
                            Err(ReqError::Failed)
                        }
                    }
                })
            })),
            ..Default::default()
        }),
        ..Default::default()
    };

    let app = Application {
        services: vec![Service {
            uuid: SERVICE_UUID,
            primary: true,
            characteristics: vec![challenge_char, response_char],
            ..Default::default()
        }],
        ..Default::default()
    };

    let _app_handle = adapter.serve_gatt_application(app).await?;
    println!("GATT application registered");

    let le_advertisement = bluer::adv::Advertisement {
        advertisement_type: bluer::adv::Type::Peripheral,
        service_uuids: vec![SERVICE_UUID].into_iter().collect(),
        discoverable: Some(true),
        local_name: Some("wrist-hello-server".to_string()),
        ..Default::default()
    };
    let _adv_handle = adapter.advertise(le_advertisement).await?;
    println!("Advertising started");

    println!("Server running. Press Ctrl-C to quit.");
    tokio::signal::ctrl_c().await?;

    println!("Stopping");
    Ok(())
}
