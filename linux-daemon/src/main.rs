mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
mod auth_caches;
mod challenge_char;
mod pending_notifications;
mod response_char;
mod socket_server;

use std::sync::{Arc, RwLock, atomic::AtomicBool};

use bluer::{
    Uuid,
    gatt::local::{Application, Service},
};
use serde::Deserialize;
use tokio::sync::Notify;
use tracing::{error, info};
use xdg::BaseDirectories;

use crate::{
    auth_caches::AuthCaches, pending_notifications::PendingNotifications,
    socket_server::SocketServer,
};

const SERVICE_UUID: Uuid = Uuid::from_u128(0xddc6ea97_db6e_4ecd_a3ff_0143368ef829);
const CHALLENGE_CHAR_UUID: Uuid = Uuid::from_u128(0x5794ca86_3a5e_45ca_85f9_42a74cd460a7);
const RESPONSE_CHAR_UUID: Uuid = Uuid::from_u128(0xf68c58c2_a1f2_456f_a118_f1c6ce566a0a);

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
    tracing_subscriber::fmt::init();

    let app_config = match AppConfig::load() {
        Ok(config) => Arc::new(config),
        Err(e) => {
            error!("Error loading config: {}", e);
            return Ok(());
        }
    };

    let session = bluer::Session::new().await?;
    let adapter = session.default_adapter().await?;
    info!("Using adapter {}", adapter.name());

    adapter.set_powered(true).await?;
    info!("Adapter powered on");

    let current_challenge = Arc::new(RwLock::new(vec![0u8; 32]));
    let challenge_read = current_challenge.clone();
    let challenge_verify = current_challenge.clone();

    let challenge_trigger = Arc::new(Notify::new());
    let challenge_trigger_notify = challenge_trigger.clone();
    let challenge_trigger_socket = challenge_trigger.clone();

    let is_first_notify = Arc::new(AtomicBool::new(true));
    let is_first_notify_notify = is_first_notify.clone();
    let is_first_notify_cmd = is_first_notify.clone();

    let pending_notifications = PendingNotifications::default();

    let app = Application {
        services: vec![Service {
            uuid: SERVICE_UUID,
            primary: true,
            characteristics: vec![
                challenge_char::generate_challenge_char(
                    challenge_read,
                    challenge_trigger_notify,
                    is_first_notify_notify,
                ),
                response_char::generate_response_char(
                    challenge_verify,
                    pending_notifications.clone(),
                    app_config.public_key_der_hex.clone(),
                ),
            ],

            ..Default::default()
        }],
        ..Default::default()
    };

    let _app_handle = adapter.serve_gatt_application(app).await?;
    info!("GATT application registered");

    let le_advertisement = bluer::adv::Advertisement {
        advertisement_type: bluer::adv::Type::Peripheral,
        service_uuids: vec![SERVICE_UUID].into_iter().collect(),
        discoverable: Some(true),
        local_name: Some("wrist-hello-server".to_string()),
        ..Default::default()
    };
    let _adv_handle = adapter.advertise(le_advertisement).await?;
    info!("Advertising started");

    let auth_caches = AuthCaches::default();

    let socket_server = Arc::new(SocketServer::new(
        challenge_trigger_socket,
        is_first_notify_cmd,
        auth_caches,
        pending_notifications,
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
    Ok(())
}
