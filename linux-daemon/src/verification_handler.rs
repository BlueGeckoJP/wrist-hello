use std::{mem::MaybeUninit, sync::atomic::Ordering, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::oneshot,
    time::timeout,
};
use tracing::{error, info, warn};

use crate::{
    AUTH_IDENTITY_SIZE, bindings, pending_notifications::AuthResult, socket_server::SocketServer,
};

const AUTH_TIMEOUT_SECONDS: u64 = 30;

pub async fn handle_verification_request(server: &SocketServer, stream: &mut UnixStream) {
    let auth_identity = match receive_auth_identity(stream).await {
        Ok(identity) => identity,
        Err(e) => {
            eprintln!("Failed to receive AuthIdentity: {}", e);
            return;
        }
    };

    if let Ok(true) = server.auth_session.is_verified() {
        info!("Session already verified, skipping verification");
        if let Err(e) = reply_to_stream(stream, &[0u8]).await {
            error!("Failed to send already verified response to client: {}", e);
        }
        return;
    }

    let (notify_tx, notify_rx) = oneshot::channel();
    let notify_id = match server.pending_notifications.add_one(notify_tx) {
        Ok(id) => id,
        Err(e) => {
            error!("Failed to add notify to pending notifications: {}", e);
            return;
        }
    };

    let verified = if !server.notify_ready.load(Ordering::SeqCst) {
        error!("Notify not ready, cannot process verification request");
        false
    } else {
        info!("Triggering challenge for verification request");
        server.challenge_trigger.notify_one();

        match timeout(Duration::from_secs(AUTH_TIMEOUT_SECONDS), notify_rx).await {
            Ok(Ok(AuthResult::Success)) => {
                info!("Received successful verification notification");
                true
            }
            Ok(Ok(AuthResult::Denied)) => {
                warn!("Received denied verification notification");
                false
            }
            Ok(Err(e)) => {
                error!("Failed to receive verification notification: {}", e);
                false
            }
            Err(e) => {
                error!("Failed to wait for verification notification: {}", e);
                false
            }
        }
    };

    if let Err(e) = server.pending_notifications.remove_one(&notify_id) {
        error!("Failed to remove notify from pending notifications: {}", e);
    }

    if !verified {
        if let Err(e) = reply_to_stream(stream, &[1u8]).await {
            error!("Failed to send failure response to client: {}", e);
        }
        return;
    }

    if let Err(e) = reply_to_stream(stream, &[0u8]).await {
        error!("Failed to send success response to client: {}", e);
    }

    info!(
        "Verified client: uid={}, tty={}, service={}",
        auth_identity.uid,
        c_bytes_to_string(&auth_identity.tty),
        c_bytes_to_string(&auth_identity.service)
    );
}

async fn receive_auth_identity(stream: &mut UnixStream) -> eyre::Result<bindings::AuthIdentity> {
    let mut buf = [0u8; AUTH_IDENTITY_SIZE];
    let n = match stream.read_exact(&mut buf).await {
        Ok(0) => {
            eyre::bail!("Client disconnected");
        }
        Ok(n) => n,
        Err(e) => {
            eyre::bail!("Failed to read from client: {}", e);
        }
    };
    let raw = &buf[..n];

    let mut auth_identity_uninit = MaybeUninit::<bindings::AuthIdentity>::uninit();

    unsafe {
        if !bindings::auth_identity_deserialize(
            raw.as_ptr(),
            raw.len(),
            auth_identity_uninit.as_mut_ptr(),
        ) {
            eyre::bail!("Failed to deserialize AuthIdentity");
        }

        Ok(auth_identity_uninit.assume_init())
    }
}

async fn reply_to_stream(stream: &mut UnixStream, response: &[u8]) -> eyre::Result<()> {
    stream.write_all(response).await?;
    stream.flush().await?;
    Ok(())
}

fn c_bytes_to_string(cbytes: &[i8]) -> String {
    let cstr = unsafe { std::ffi::CStr::from_ptr(cbytes.as_ptr()) };
    cstr.to_string_lossy().into_owned()
}
