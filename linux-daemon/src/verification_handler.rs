use std::mem::MaybeUninit;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::{mpsc, oneshot},
};
use tracing::{error, info, warn};

use crate::{AUTH_IDENTITY_SIZE, bindings, socket_server::ServerContext};

pub async fn handle_verification_request(server: &ServerContext, stream: &mut UnixStream) {
    let auth_identity = match receive_auth_identity(stream).await {
        Ok(identity) => identity,
        Err(e) => {
            error!("Failed to receive AuthIdentity: {}", e);
            return;
        }
    };

    let (result_tx, mut result_rx) = mpsc::channel(1);
    let (cancel_tx, cancel_rx) = oneshot::channel();
    if let Err(e) = server
        .add_queue_tx
        .send(crate::auth_processor::AuthRequest {
            identity: auth_identity,
            result_tx,
            cancel_rx,
        })
        .await
    {
        error!("Failed to send AuthRequest to AuthProcessor: {}", e);
        return;
    }

    tokio::select! {
        biased;

        cancel = read_cancel_from_stream(stream) => {
            let cancel = cancel.unwrap_or_else(|e| {
                warn!("Failed to read cancel signal from client: {}", e);
                0
            });

            if cancel as u32 != bindings::AUTH_MSG_PAM_CANCELLED {
                warn!("Received unexpected cancel signal from client: {}", cancel);
                return;
            }

            let _ = cancel_tx.send(());
            info!("Received cancel signal from client, cancelling authentication request");
        }

        result = result_rx.recv() => {
            let verified = result.unwrap_or_else(|| {
                warn!("AuthProcessor dropped the result channel without sending a response");
                false
            });

            let response = if verified { [0u8] } else { [1u8] };

            if let Err(e) = reply_to_stream(stream, &response).await {
                error!(
                    "Failed to send response to client: response={:?}, error={}",
                    response, e
                );
            }

            if verified {
                info!(
                    "Verified client: uid={}, tty={}, service={}",
                    auth_identity.uid,
                    c_bytes_to_string(&auth_identity.tty),
                    c_bytes_to_string(&auth_identity.service)
                );
            }
        }
    }
}

async fn read_cancel_from_stream(stream: &mut UnixStream) -> eyre::Result<u8> {
    let mut buf = [0u8; 1];
    match stream.read_exact(&mut buf).await {
        Ok(0) => {
            eyre::bail!("Client disconnected");
        }
        Ok(_) => Ok(buf[0]),
        Err(e) => {
            eyre::bail!("Failed to read cancel signal from client: {}", e);
        }
    }
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
