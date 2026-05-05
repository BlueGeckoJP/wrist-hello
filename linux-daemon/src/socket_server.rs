use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::SystemTime,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream, unix::SocketAddr},
    sync::Notify,
};
use tracing::{error, info, warn};

use crate::bindings;

const SOCKET_PATH: &str = "/run/wrist-hello/auth.sock";

pub async fn spawn(
    last_verified_at: Arc<AtomicU64>,
    challenge_trigger: Arc<Notify>,
    is_first_notify: Arc<AtomicBool>,
) -> eyre::Result<()> {
    // The bind() function will fail if the socket file already exists
    let _ = std::fs::remove_file(SOCKET_PATH);

    let listener = UnixListener::bind(SOCKET_PATH)?;
    info!("Listening on {}", SOCKET_PATH);

    loop {
        let (stream, addr) = match listener.accept().await {
            Ok((stream, addr)) => (stream, addr),
            Err(e) => {
                error!("Failed to accept connection: {}", e);
                continue;
            }
        };

        let last_verified_at = last_verified_at.clone();
        let challenge_trigger = challenge_trigger.clone();
        let is_first_notify = is_first_notify.clone();

        tokio::spawn(handle_client(
            stream,
            addr,
            last_verified_at,
            challenge_trigger,
            is_first_notify,
        ));
    }
}

async fn handle_client(
    mut stream: UnixStream,
    addr: SocketAddr,
    last_verified_at: Arc<AtomicU64>,
    challenge_trigger: Arc<Notify>,
    is_first_notify: Arc<AtomicBool>,
) -> eyre::Result<()> {
    info!("Accepted connection from {:?}", addr);

    let mut buf = [0u8; 1024];
    loop {
        let n = match stream.read(&mut buf).await {
            Ok(0) => {
                info!("Client {:?} disconnected", addr);
                break;
            }
            Ok(n) => n,
            Err(e) => {
                error!("Failed to read from client {:?}: {}", addr, e);
                break;
            }
        };

        handle_socket_command(
            &mut stream,
            &buf[..n],
            last_verified_at.clone(),
            challenge_trigger.clone(),
            is_first_notify.clone(),
        )
        .await?;
    }

    Ok(())
}

async fn handle_socket_command(
    stream: &mut UnixStream,
    data: &[u8],
    last_verified_at: Arc<AtomicU64>,
    challenge_trigger: Arc<Notify>,
    is_first_notify: Arc<AtomicBool>,
) -> eyre::Result<()> {
    let mut cmd: bindings::SocketCommand = 0;
    match unsafe { bindings::socket_command_deserialize(data.as_ptr(), data.len(), &mut cmd) } {
        true => info!("Received command: {:?}", cmd),
        false => {
            error!("Failed to deserialize command from socket data");
            return Err(eyre::eyre!("Failed to deserialize command"));
        }
    }

    match cmd {
        bindings::CMD_CHECK_STATUS => handle_check_status(stream, last_verified_at).await,
        bindings::CMD_TRIGGER_CHALLENGE => {
            handle_trigger_challenge(is_first_notify, challenge_trigger).await
        }
        _ => {
            error!("Received unknown command: {:?}", cmd);
        }
    }

    Ok(())
}

async fn handle_check_status(stream: &mut UnixStream, last_verified_at: Arc<AtomicU64>) {
    info!("Handling check status command");

    let last_verified_at = last_verified_at.load(Ordering::SeqCst);
    let unix_now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let elapsed = unix_now.saturating_sub(last_verified_at);
    let result_payload = if last_verified_at == 0 {
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

    let mut buf = [0u8; 10];
    unsafe {
        bindings::socket_payload_serialize(&result_payload, buf.as_mut_ptr(), buf.len());
    }

    if let Err(e) = stream.write_all(&buf).await {
        error!("Failed to send response to client: {}", e);
    }
    if let Err(e) = stream.flush().await {
        error!("Failed to flush response to client: {}", e);
    }
    info!("Sent status response to client: {:?}", result_payload);
}

async fn handle_trigger_challenge(
    is_first_notify: Arc<AtomicBool>,
    challenge_trigger: Arc<Notify>,
) {
    info!("Handling trigger challenge command");

    if is_first_notify.load(Ordering::SeqCst) {
        warn!("First notify, skipping challenge trigger");
    } else {
        info!("Triggering challenge");
        challenge_trigger.notify_one();
    }
}
