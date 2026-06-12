//! On some environments, BlueZ D-Bus advertisement registration
//! (LEAdvertisingManager1.RegisterAdvertisement) fails with
//! org.bluez.Error.Failed / Invalid Parameters (0x0d).
//! Hoewver, the controller/kernel path can still register advertisements
//! via btmgmt add-adv, so this falls back to btmgmt when the D-Bus path fails.
//! btmgmt may hang when started without a TTY, so stdin/stdout/stderr must be
//! inherited by the child process.

use std::process::{Command, Stdio};

use tracing::{error, info};

use crate::SERVICE_UUID;

pub enum AdvertisementHandle {
    Bluer(bluer::adv::AdvertisementHandle),
    Btmgmt(BtmgmtAdvertisementHandle),
}

impl AdvertisementHandle {
    pub fn unregister(self) {
        match self {
            AdvertisementHandle::Bluer(handle) => drop(handle),
            AdvertisementHandle::Btmgmt(handle) => handle.unregister(),
        }
    }
}

pub struct BtmgmtAdvertisementHandle {
    adapter_name: String,
    instance_id: u8,
}

impl BtmgmtAdvertisementHandle {
    fn unregister(self) {
        let _ = run_bluetooth_mgmt(&[
            "-i",
            &self.adapter_name,
            "rm-adv",
            &self.instance_id.to_string(),
        ]);
    }
}

pub async fn advertise_service(adapter: &bluer::Adapter) -> eyre::Result<AdvertisementHandle> {
    let le_advertisement = bluer::adv::Advertisement {
        advertisement_type: bluer::adv::Type::Peripheral,
        service_uuids: vec![SERVICE_UUID].into_iter().collect(),
        discoverable: Some(true),
        local_name: Some("wrist-hello-server".to_string()),
        ..Default::default()
    };

    if let Ok(handle) = adapter.advertise(le_advertisement).await {
        info!("Advertising started with bluer");
        return Ok(AdvertisementHandle::Bluer(handle));
    }

    error!("Failed to advertise with bluer, falling back to btmgmt");

    match register_btmgmt_advertisement(adapter.name()) {
        Ok(handle) => {
            info!("Registered advertisement: btmgmt fallback");
            return Ok(AdvertisementHandle::Btmgmt(handle));
        }
        Err(e) => {
            error!("Failed to register advertisement with btmgmt: {}", e);
            eyre::bail!("btmgmt fallback failed: {e}");
        }
    }
}

fn register_btmgmt_advertisement(adapter_name: &str) -> eyre::Result<BtmgmtAdvertisementHandle> {
    if !is_running_as_root()? {
        eyre::bail!(
            "btmgmt advertisement requires root privileges or CAP_NET_ADMIN capability. Run `sudo cargo run` or grant CAP_NET_ADMIN to the binary"
        );
    }

    let instance_id = 1;
    let service_uuid = SERVICE_UUID.to_string();

    let _ = run_bluetooth_mgmt(&["-i", adapter_name, "rm-adv", &instance_id.to_string()]);

    run_bluetooth_mgmt(&[
        "-i",
        adapter_name,
        "add-adv",
        "-c",
        "-g",
        "-u",
        &service_uuid,
        &instance_id.to_string(),
    ])?;

    Ok(BtmgmtAdvertisementHandle {
        adapter_name: adapter_name.to_string(),
        instance_id,
    })
}

fn run_bluetooth_mgmt(args: &[&str]) -> eyre::Result<()> {
    let status = Command::new("timeout")
        .arg("5")
        .arg("btmgmt")
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;

    if status.success() {
        return Ok(());
    }

    eyre::bail!(
        "btmgmt {:?} failed with status {}. Try running from an interactive terminal with sudo or CAP_NET_ADMIN",
        args,
        status
    )
}

fn is_running_as_root() -> eyre::Result<bool> {
    let output = Command::new("id").arg("-u").output()?;
    if !output.status.success() {
        eyre::bail!("failed to check current uid with `id -u`");
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim() == "0")
}
