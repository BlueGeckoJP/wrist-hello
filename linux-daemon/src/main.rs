mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use std::{
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::SystemTime,
};

use bluer::{
    Uuid,
    gatt::local::{
        Application, Characteristic, CharacteristicNotify, CharacteristicNotifyMethod,
        CharacteristicRead, CharacteristicWrite, CharacteristicWriteMethod, ReqError, Service,
    },
};
use ecdsa::signature::Verifier;
use p256::{
    ecdsa::{Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
};
use rand::RngExt;
use tokio::{io::AsyncWriteExt, net::UnixListener};

const SERVICE_UUID: Uuid = Uuid::from_u128(0xddc6ea97_db6e_4ecd_a3ff_0143368ef829);
const CHALLENGE_CHAR_UUID: Uuid = Uuid::from_u128(0x5794ca86_3a5e_45ca_85f9_42a74cd460a7);
const RESPONSE_CHAR_UUID: Uuid = Uuid::from_u128(0xf68c58c2_a1f2_456f_a118_f1c6ce566a0a);

const SOCKET_PATH: &str = "/run/wrist-hello/auth.sock";

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

    let last_verified_at = Arc::new(AtomicU64::new(0));
    let last_verified_at_verify = last_verified_at.clone();

    let challenge_char = Characteristic {
        uuid: CHALLENGE_CHAR_UUID,
        read: Some(CharacteristicRead {
            read: true,
            fun: Box::new(move |req| {
                println!("CHALLENGE_CHAR:READ: Connected from {}", req.device_address);
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
            method: CharacteristicWriteMethod::Fun(Box::new(move |new_value, req| {
                println!("RESPONSE_CHAR:WRITE: Connected from {}", req.device_address);
                let state = challenge_verify.clone();
                let last_verified_at_verify = last_verified_at_verify.clone();
                Box::pin(async move {
                    let challenge = {
                        let locked = state.read().unwrap();
                        locked.clone()
                    };

                    // TODO: Replace it with actual key
                    // Public key bytes
                    let verifying_key_der = hex::decode("<ACTUAL_PUB_KEY_DER>").unwrap();

                    let verifying_key = match VerifyingKey::from_public_key_der(&verifying_key_der)
                    {
                        Ok(key) => key,
                        Err(_) => {
                            println!("Error: Invalid public key");
                            return Err(ReqError::Failed);
                        }
                    };

                    let signature = match Signature::from_der(&new_value) {
                        Ok(sig) => sig,
                        Err(_) => {
                            println!("Error: Invalid signature");
                            return Err(ReqError::Failed);
                        }
                    };

                    match verifying_key.verify(&challenge, &signature) {
                        Ok(_) => {
                            println!("Success");
                            let now = SystemTime::now();
                            let timestamp = now
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                            last_verified_at_verify.store(timestamp, Ordering::SeqCst);

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

    tokio::spawn(async move {
        if let Err(e) = start_socket_server(last_verified_at).await {
            println!("Error in socket server: {}", e);
        }
    });
    println!("Socket server started");

    println!("Server running. Press Ctrl-C to quit.");
    tokio::signal::ctrl_c().await?;

    println!("Stopping");
    Ok(())
}

async fn start_socket_server(last_verified_at: Arc<AtomicU64>) -> eyre::Result<()> {
    // The bind() function will fail if the socket file already exists
    let _ = std::fs::remove_file(SOCKET_PATH);

    let listener = UnixListener::bind(SOCKET_PATH)?;
    println!("Listening on {}", SOCKET_PATH);

    loop {
        match listener.accept().await {
            Ok((mut stream, _addr)) => {
                println!("Connection accepted");
                let last_verified_at = last_verified_at.clone();
                tokio::spawn(async move {
                    let response = {
                        let last_verified_at = last_verified_at.load(Ordering::SeqCst);
                        let elapsed_res = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH);

                        match elapsed_res {
                            Ok(duration) => {
                                let elapsed = duration.as_secs().saturating_sub(last_verified_at);
                                match elapsed {
                                    0 => bindings::SocketPayload {
                                        status: bindings::STATUS_UNVERIFIED,
                                        has_elapsed: 0,
                                        elapsed: 0,
                                    },
                                    elapsed if elapsed <= 30 => bindings::SocketPayload {
                                        status: bindings::STATUS_VERIFIED,
                                        has_elapsed: 1,
                                        elapsed,
                                    },
                                    elapsed => bindings::SocketPayload {
                                        status: bindings::STATUS_EXPIRED,
                                        has_elapsed: 1,
                                        elapsed,
                                    },
                                }
                            }
                            Err(_) => bindings::SocketPayload {
                                status: bindings::STATUS_ERROR,
                                has_elapsed: 0,
                                elapsed: 0,
                            },
                        }
                    };
                    let mut raw_buffer = vec![0u8; 10];
                    unsafe {
                        bindings::socket_payload_serialize(
                            &response,
                            raw_buffer.as_mut_ptr(),
                            raw_buffer.len(),
                        );
                    }
                    if let Err(e) = stream.write_all(&raw_buffer).await {
                        println!("Error writing to socket: {}", e);
                    }
                    if let Err(e) = stream.flush().await {
                        println!("Error flushing socket: {}", e);
                    }
                    println!("Connection closed");
                });
            }
            Err(e) => {
                println!("Error: {}", e);
                break;
            }
        }
    }

    Ok(())
}
