//! On some environments, BlueZ D-Bus advertisement registration
//! (LEAdvertisingManager1.RegisterAdvertisement) fails with
//! org.bluez.Error.Failed / Invalid Parameters (0x0d).
//! Hoewver, the controller/kernel path can still register advertisements
//! via btmgmt add-adv, so this falls back to btmgmt when the D-Bus path fails.
//! btmgmt may hang when started without a TTY, so stdin/stdout/stderr must be
//! inherited by the child process.

use std::process::{Command, Output, Stdio};

use tracing::{error, info};

use crate::SERVICE_UUID;

const BTMGMT_TIMEOUT_SECONDS: &str = "5";

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

    match adapter.advertise(le_advertisement.clone()).await {
        Ok(handle) => {
            info!("Advertising started with bluer");
            return Ok(AdvertisementHandle::Bluer(handle));
        }
        Err(e) => {
            error!("Failed to advertise with bluer: {e}, falling back to btmgmt",);
        }
    }

    match register_btmgmt_advertisement(adapter.name()) {
        Ok(handle) => {
            info!("Registered advertisement: btmgmt fallback");
            Ok(AdvertisementHandle::Btmgmt(handle))
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

    // Bluetooth must be both enabled and visible; otherwise it will not show up
    // on the Pixel Watch and cannot be connected. In KDE, turn on:
    // Configure Bluetooth... -> Configure... -> Visible
    let add_adv_result = run_bluetooth_mgmt(&[
        "-i",
        adapter_name,
        "add-adv",
        "-c",
        "-g",
        "-u",
        &service_uuid,
        &instance_id.to_string(),
    ]);

    // On some systems, btmgmt add-adv updates the controller state but the
    // btmgmt/script child does not exit when spawned by this daemon. In that
    // case, trust advinfo over the timed-out child exit status.
    if add_adv_result.is_err() && !btmgmt_advertisement_exists(adapter_name)? {
        add_adv_result?;
    }

    Ok(BtmgmtAdvertisementHandle {
        adapter_name: adapter_name.to_string(),
        instance_id,
    })
}

fn btmgmt_advertisement_exists(adapter_name: &str) -> eyre::Result<bool> {
    let output = run_bluetooth_mgmt_output(&["-i", adapter_name, "advinfo"])?;
    if !output.status.success() {
        eyre::bail!(
            "btmgmt advinfo failed with status {}. Try running from an interactive terminal with sudo or CAP_NET_ADMIN",
            output.status
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let output = format!("{stdout}{stderr}");

    Ok(output.contains("Instances list with ") && !output.contains("Instances list with 0 items"))
}

fn run_bluetooth_mgmt_output(args: &[&str]) -> eyre::Result<Output> {
    let btmgmt_cmd = shell_words::join(std::iter::once("btmgmt").chain(args.iter().copied()));

    Command::new("timeout")
        .arg(BTMGMT_TIMEOUT_SECONDS)
        .arg("script")
        .arg("-q")
        .arg("-e")
        .arg("-c")
        .arg(btmgmt_cmd)
        .arg("/dev/null")
        .output()
        .map_err(Into::into)
}

fn run_bluetooth_mgmt(args: &[&str]) -> eyre::Result<()> {
    let btmgmt_cmd = shell_words::join(std::iter::once("btmgmt").chain(args.iter().copied()));

    // Simply inheriting stdio does not necessarily create a TTY, so `btmgmt` may hang in some environments
    // To avoid this, we need to run it through the `script` command, which creates a pseudo-TTY

    // Without using `Stdio:nulL()`, the process may wait for the full timeout duration even after the command has finished
    let status = Command::new("timeout")
        .arg(BTMGMT_TIMEOUT_SECONDS)
        .arg("script")
        .arg("-q")
        .arg("-e")
        .arg("-c")
        .arg(btmgmt_cmd)
        .arg("/dev/null")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
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
