mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
mod advertisement_handle;
mod auth_session;
mod challenge_char;
mod current_challenge;
mod notify_ready_guard;
mod pending_notifications;
mod response_char;
mod socket_server;

use std::sync::{Arc, atomic::AtomicBool};

use bluer::{
    Uuid,
    gatt::local::{Application, Service},
};
use serde::Deserialize;
use tokio::sync::Notify;
use tracing::{error, info};
use xdg::BaseDirectories;

use crate::{
    advertisement_handle::advertise_service, auth_session::AuthSession,
    current_challenge::CurrentChallenge, pending_notifications::PendingNotifications,
    socket_server::SocketServer,
};

const SERVICE_UUID: Uuid = Uuid::from_u128(0xddc6ea97_db6e_4ecd_a3ff_0143368ef829);
const CHALLENGE_CHAR_UUID: Uuid = Uuid::from_u128(0x5794ca86_3a5e_45ca_85f9_42a74cd460a7);
const RESPONSE_CHAR_UUID: Uuid = Uuid::from_u128(0xf68c58c2_a1f2_456f_a118_f1c6ce566a0a);

fn default_auth_cache_ttl_seconds() -> Option<u64> {
    Some(60)
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

    let current_challenge = CurrentChallenge::default();
    let challenge_trigger = Arc::new(Notify::new());
    let pending_notifications = PendingNotifications::default();
    let auth_session = AuthSession::new(
        app_config
            .auth_cache_ttl_seconds
            .expect("auth_cache_ttl_seconds must be set in config"),
    );
    let notify_ready = Arc::new(AtomicBool::new(false));

    let app = Application {
        services: vec![Service {
            uuid: SERVICE_UUID,
            primary: true,
            characteristics: vec![
                challenge_char::generate_challenge_char(
                    current_challenge.clone(),
                    challenge_trigger.clone(),
                    notify_ready.clone(),
                ),
                response_char::generate_response_char(
                    current_challenge.clone(),
                    pending_notifications.clone(),
                    auth_session.clone(),
                    app_config.public_key_der_hex.clone(),
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

    let socket_server = Arc::new(SocketServer::new(
        challenge_trigger.clone(),
        pending_notifications,
        auth_session,
        notify_ready.clone(),
    ));

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
