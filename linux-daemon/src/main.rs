mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
mod advertisement_handle;
mod auth_processor;
mod auth_session;
mod characteristics;
mod current_challenge;
mod notify_ready_guard;
mod socket_server;
mod verification_handler;

use std::sync::{Arc, atomic::AtomicBool};

use bluer::{
    Uuid,
    gatt::local::{Application, Service},
};
use serde::Deserialize;
use tokio::sync::{Notify, mpsc};
use tracing::{error, info};
use xdg::BaseDirectories;

use crate::{
    advertisement_handle::advertise_service, auth_session::AuthSession,
    current_challenge::CurrentChallenge, socket_server::SocketServer,
};

const SERVICE_UUID: Uuid = Uuid::from_u128(0xddc6ea97_db6e_4ecd_a3ff_0143368ef829);
const CHALLENGE_CHAR_UUID: Uuid = Uuid::from_u128(0x5794ca86_3a5e_45ca_85f9_42a74cd460a7);
const RESPONSE_CHAR_UUID: Uuid = Uuid::from_u128(0xf68c58c2_a1f2_456f_a118_f1c6ce566a0a);
const CANCEL_CHAR_UUID: Uuid = Uuid::from_u128(0x2679d328_1fb9_4cd5_9efe_382a723bcad7);

const AUTH_IDENTITY_SIZE: usize = std::mem::size_of::<bindings::AuthIdentity>();
pub const AUTH_TIMEOUT_SECONDS: u64 = 30;

fn default_auth_cache_ttl_seconds() -> Option<u64> {
    Some(0)
}

#[derive(Deserialize)]
struct AppConfig {
    public_key_der: String,
    #[serde(skip)]
    public_key_der_hex: Vec<u8>,
    #[serde(default = "default_auth_cache_ttl_seconds")]
    auth_cache_ttl_seconds: Option<u64>,
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
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();

    let app_config = match AppConfig::load() {
        Ok(config) => Arc::new(config),
        Err(e) => {
            error!("Error loading config: {}", e);
            eyre::bail!("Failed to load config: {}", e);
        }
    };

    let session = bluer::Session::new().await?;
    let adapter = session.default_adapter().await?;
    info!("Using adapter {}", adapter.name());

    adapter.set_powered(true).await?;
    info!("Adapter powered on");

    let auth_session = AuthSession::new(
        app_config
            .auth_cache_ttl_seconds
            .expect("auth_cache_ttl_seconds must be set in config"),
    );
    let current_challenge = CurrentChallenge::default();

    let notify_ready = Arc::new(AtomicBool::new(false));
    let cancel_notify_ready = Arc::new(AtomicBool::new(false));

    let wrist_start_notify = Arc::new(Notify::new());

    let (add_queue_tx, add_queue_rx) = mpsc::channel(100);
    let (wrist_result_tx, wrist_result_rx) = mpsc::channel(1);
    let (cancel_notify_tx, cancel_notify_rx) = mpsc::channel(1);

    let auth_processor = auth_processor::AuthProcessor::new(
        add_queue_rx,
        wrist_start_notify.clone(),
        wrist_result_rx,
        auth_session.clone(),
        current_challenge.clone(),
        notify_ready.clone(),
        cancel_notify_tx,
    );
    auth_processor.spawn();

    let app = Application {
        services: vec![Service {
            uuid: SERVICE_UUID,
            primary: true,
            characteristics: vec![
                characteristics::challenge_char::generate_challenge_char(
                    current_challenge.clone(),
                    notify_ready.clone(),
                    wrist_start_notify.clone(),
                ),
                characteristics::response_char::generate_response_char(
                    current_challenge.clone(),
                    app_config.public_key_der_hex.clone(),
                    wrist_result_tx.clone(),
                ),
                characteristics::cancel_characteristic::generate_cancel_char(
                    cancel_notify_rx,
                    cancel_notify_ready,
                ),
            ],

            ..Default::default()
        }],
        ..Default::default()
    };

    let app_handle = adapter.serve_gatt_application(app).await?;
    info!("GATT application registered");

    let advertisement_handle = advertise_service(&adapter).await?;
    info!("Advertising started");

    let socket_server = Arc::new(SocketServer::new(add_queue_tx.clone()));

    tokio::spawn(async move {
        if let Err(e) = socket_server.spawn().await {
            error!("Error in socket server: {}", e);
        }
    });
    info!("Socket server started");

    info!("Server running. Press Ctrl-C to quit.");
    tokio::signal::ctrl_c().await?;

    info!("Stopping");

    drop(app_handle);
    advertisement_handle.unregister();

    Ok(())
}
