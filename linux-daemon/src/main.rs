use bluer::{
    Uuid,
    gatt::local::{Application, Service},
};

const SERVICE_UUID: Uuid = Uuid::from_u128(0xddc6ea97_db6e_4ecd_a3ff_0143368ef829);

#[tokio::main]
async fn main() -> bluer::Result<()> {
    let session = bluer::Session::new().await?;
    let adapter = session.default_adapter().await?;
    println!("Using adapter {}", adapter.name());

    adapter.set_powered(true).await?;
    println!("Adapter powered on");

    let app = Application {
        services: vec![Service {
            uuid: SERVICE_UUID,
            primary: true,
            characteristics: Vec::new(),
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
