mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use std::{
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
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
use serde::Deserialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
    sync::Notify,
};
use xdg::BaseDirectories;

const SERVICE_UUID: Uuid = Uuid::from_u128(0xddc6ea97_db6e_4ecd_a3ff_0143368ef829);
const CHALLENGE_CHAR_UUID: Uuid = Uuid::from_u128(0x5794ca86_3a5e_45ca_85f9_42a74cd460a7);
const RESPONSE_CHAR_UUID: Uuid = Uuid::from_u128(0xf68c58c2_a1f2_456f_a118_f1c6ce566a0a);

const SOCKET_PATH: &str = "/run/wrist-hello/auth.sock";

#[derive(Deserialize)]
struct AppConfig {
    public_key_der: String,
    #[serde(skip)]
    public_key_der_hex: Vec<u8>,
}

impl AppConfig {
    fn load() -> eyre::Result<Self> {
        let xdg_dirs = BaseDirectories::new();
        let config_home = match xdg_dirs.get_config_home() {
            Some(home) => home,
            None => eyre::bail!("Failed to get config home directory"),
        };
        let path = config_home.join("wrist-hello-config.toml");

        let contents = std::fs::read_to_string(path)?;
        let mut config: AppConfig = toml::from_str(&contents)?;

        config.public_key_der_hex = hex::decode(&config.public_key_der)?;

        Ok(config)
    }
}

#[tokio::main]
async fn main() -> bluer::Result<()> {
    let app_config = match AppConfig::load() {
        Ok(config) => Arc::new(config),
        Err(e) => {
            println!("Error loading config: {}", e);
            return Ok(());
        }
    };

    let session = bluer::Session::new().await?;
    let adapter = session.default_adapter().await?;
    println!("Using adapter {}", adapter.name());

    adapter.set_powered(true).await?;
    println!("Adapter powered on");

    let current_challenge = Arc::new(RwLock::new(vec![0u8; 32]));
    let challenge_read = current_challenge.clone();
    let challenge_notify = current_challenge.clone();
    let challenge_verify = current_challenge.clone();

    let challenge_trigger = Arc::new(Notify::new());
    let challenge_trigger_notify = challenge_trigger.clone();
    let challenge_trigger_socket = challenge_trigger.clone();

    let last_verified_at = Arc::new(AtomicU64::new(0));
    let last_verified_at_verify = last_verified_at.clone();

    let is_first_notify = Arc::new(AtomicBool::new(true));
    let is_first_notify_notify = is_first_notify.clone();
    let is_first_notify_cmd = is_first_notify.clone();

    let challenge_char = Characteristic {
        uuid: CHALLENGE_CHAR_UUID,
        read: Some(CharacteristicRead {
            read: true,
            encrypt_authenticated_read: true,
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
                let trigger = challenge_trigger_notify.clone();
                let is_first_notify_notify = is_first_notify_notify.clone();
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
                    println!("NOTIFY: Initial challenge: {:?}", new_challenge);
                    if notifier.notify(new_challenge).await.is_err() {
                        return;
                    }
                    is_first_notify_notify.store(false, Ordering::SeqCst);

                    loop {
                        trigger.notified().await;
                        let new_challenge = {
                            let mut rng = rand::rngs::ThreadRng::default();
                            let mut ch = vec![0u8; 32];
                            rng.fill(ch.as_mut_slice());
                            ch
                        };
                        if let Ok(mut locked) = state.write() {
                            *locked = new_challenge.clone();
                        }
                        println!("NOTIFY: Re-triggered challenge: {:?}", new_challenge);
                        if notifier.notify(new_challenge).await.is_err() {
                            break;
                        }
                    }
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
            encrypt_authenticated_write: true,
            method: CharacteristicWriteMethod::Fun(Box::new(move |new_value, req| {
                println!("RESPONSE_CHAR:WRITE: Connected from {}", req.device_address);
                let state = challenge_verify.clone();
                let last_verified_at_verify = last_verified_at_verify.clone();
                let app_config = app_config.clone();
                Box::pin(async move {
                    let challenge = {
                        let locked = state.read().unwrap();
                        locked.clone()
                    };

                    let verifying_key =
                        match VerifyingKey::from_public_key_der(&app_config.public_key_der_hex) {
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
        if let Err(e) = start_socket_server(
            last_verified_at,
            challenge_trigger_socket,
            is_first_notify_cmd,
        )
        .await
        {
            println!("Error in socket server: {}", e);
        }
    });
    println!("Socket server started");

    println!("Server running. Press Ctrl-C to quit.");
    tokio::signal::ctrl_c().await?;

    println!("Stopping");
    Ok(())
}

async fn start_socket_server(
    last_verified_at: Arc<AtomicU64>,
    challenge_trigger: Arc<Notify>,
    is_first_notify: Arc<AtomicBool>,
) -> eyre::Result<()> {
    // The bind() function will fail if the socket file already exists
    let _ = std::fs::remove_file(SOCKET_PATH);

    let listener = UnixListener::bind(SOCKET_PATH)?;
    println!("Listening on {}", SOCKET_PATH);

    loop {
        let (mut stream, addr) = match listener.accept().await {
            Ok((stream, addr)) => (stream, addr),
            Err(e) => {
                println!("Error accepting connection: {}", e);
                continue;
            }
        };

        let last_verified_at = last_verified_at.clone();
        let challenge_trigger = challenge_trigger.clone();
        let is_first_notify = is_first_notify.clone();

        tokio::spawn(async move {
            println!("Connection accepted from {:?}", addr);

            let mut buf = vec![0u8; 1024];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => {
                        println!("Connection closed by client");
                        return;
                    }
                    Ok(n) => {
                        let received_data = &buf[..n];
                        let mut cmd: bindings::SocketCommand = 0;
                        match unsafe {
                            bindings::socket_command_deserialize(
                                received_data.as_ptr(),
                                received_data.len(),
                                &mut cmd,
                            )
                        } {
                            true => println!("Received command: {}", cmd),
                            false => {
                                println!("Failed to deserialize command");
                                return;
                            }
                        }

                        match cmd {
                            bindings::CMD_CHECK_STATUS => {
                                println!("CMD_CHECK_STATUS received");

                                let last_verified_at = last_verified_at.load(Ordering::SeqCst);
                                let unix_now = SystemTime::now()
                                    .duration_since(SystemTime::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs();
                                let elapsed = unix_now.saturating_sub(last_verified_at);
                                let result = if last_verified_at == 0 {
                                    bindings::SocketPayload {
                                        status: bindings::STATUS_UNVERIFIED,
                                        has_elapsed: 0,
                                        elapsed: 0,
                                    }
                                } else if elapsed <= 30 {
                                    bindings::SocketPayload {
                                        status: bindings::STATUS_VERIFIED,
                                        has_elapsed: 1,
                                        elapsed,
                                    }
                                } else {
                                    bindings::SocketPayload {
                                        status: bindings::STATUS_EXPIRED,
                                        has_elapsed: 1,
                                        elapsed,
                                    }
                                };

                                let mut raw_buffer = vec![0u8; 10];
                                unsafe {
                                    bindings::socket_payload_serialize(
                                        &result,
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
                                println!("Replied and connection closed");
                            }
                            bindings::CMD_TRIGGER_CHALLENGE => {
                                if is_first_notify.load(Ordering::SeqCst) {
                                    println!(
                                        "CMD_TRIGGER_CHALLENGE received, but notification skipped because the is_first_notify flag is true"
                                    );
                                } else {
                                    println!("CMD_TRIGGER_CHALLENGE received");
                                    challenge_trigger.notify_one();
                                }
                            }
                            _ => {
                                println!("Unknown command received: {}", cmd);
                            }
                        }
                    }
                    Err(e) => {
                        println!("Error reading from socket: {}", e);
                        return;
                    }
                }
            }
        });
    }
}
