use std::{
    mem::{self, MaybeUninit},
    os::fd::AsRawFd,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::Notify,
    time::timeout,
};
use tracing::{error, info, warn};

use crate::{auth_session::AuthSession, bindings, pending_notifications::PendingNotifications};

const SOCKET_PATH: &str = "/run/wrist-hello/auth.sock";

pub struct SocketServer {
    challenge_trigger: Arc<Notify>,
    pending_notifications: PendingNotifications,
    auth_session: AuthSession,
    notify_ready: Arc<AtomicBool>,
}

impl SocketServer {
    pub fn new(
        challenge_trigger: Arc<Notify>,
        pending_notifications: PendingNotifications,
        auth_session: AuthSession,
        notify_ready: Arc<AtomicBool>,
    ) -> Self {
        Self {
            challenge_trigger,
            pending_notifications,
            auth_session,
            notify_ready,
        }
    }

    pub async fn spawn(self: Arc<Self>) -> eyre::Result<()> {
        // The bind() function will fail if the socket file already exists
        let _ = std::fs::remove_file(SOCKET_PATH);

        let listener = UnixListener::bind(SOCKET_PATH)?;
        info!("Listening on {}", SOCKET_PATH);

        loop {
            let (mut stream, addr) = match listener.accept().await {
                Ok((stream, addr)) => (stream, addr),
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                    continue;
                }
            };

            match Self::is_peer_root(&stream) {
                Ok(true) => {}
                Ok(false) => {
                    warn!("Rejected connection from non-root peer: {:?}", addr);
                    continue;
                }
                Err(e) => {
                    error!("Failed to get peer credentials: {}", e);
                    continue;
                }
            }

            let server = self.clone();
            tokio::spawn(async move {
                info!("Accepted connection from {:?}", addr);
                server.handle_verify(&mut stream).await
            });
        }
    }

    async fn handle_verify(&self, stream: &mut UnixStream) {
        let mut buf = [0u8; mem::size_of::<bindings::AuthIdentity>()];
        let n = match stream.read_exact(&mut buf).await {
            Ok(0) => {
                info!("Client disconnected");
                return;
            }
            Ok(n) => n,
            Err(e) => {
                error!("Failed to read from client: {}", e);
                return;
            }
        };
        let auth_identity = match Self::raw_to_auth_identity(&buf[..n]) {
            Ok(identity) => identity,
            Err(e) => {
                error!("{}", e);
                return;
            }
        };

        if let Ok(true) = self.auth_session.is_verified() {
            info!("Session already verified, skipping verification");
            if let Err(e) = Self::reply_to_stream(stream, &[0u8]).await {
                error!("Failed to send already verified response to client: {}", e);
            }
            return;
        }

        let notify = Arc::new(Notify::new());
        if let Err(e) = self.pending_notifications.add_one(notify.clone()) {
            error!("Failed to add notify to pending notifications: {}", e);
            return;
        }

        if !self.notify_ready.load(Ordering::SeqCst) {
            error!("Notify not ready, cannot trigger challenge");
            if let Err(e) = self.pending_notifications.remove_one(notify) {
                error!("Failed to remove notify from pending notifications: {}", e);
            }
            return;
        }

        info!("Triggering challenge");
        self.challenge_trigger.notify_one();

        match timeout(Duration::from_secs(5), notify.notified()).await {
            Ok(_) => info!("Received verification notification"),
            Err(e) => {
                error!("Failed to wait for verification notification: {}", e);
                if let Err(e) = self.pending_notifications.remove_one(notify) {
                    error!("Failed to remove notify from pending notifications: {}", e);
                }
                return;
            }
        }

        if let Err(e) = Self::reply_to_stream(stream, &[0u8]).await {
            error!("Failed to send verification response to client: {}", e);
        }

        info!(
            "Verified client: uid={}, tty={}, service={}",
            auth_identity.uid,
            Self::c_bytes_to_string(&auth_identity.tty),
            Self::c_bytes_to_string(&auth_identity.service)
        );

        if let Err(e) = self.pending_notifications.remove_one(notify) {
            error!("Failed to remove notify from pending notifications: {}", e);
        }
    }

    async fn reply_to_stream(stream: &mut UnixStream, response: &[u8]) -> eyre::Result<()> {
        stream.write_all(response).await?;
        stream.flush().await?;
        Ok(())
    }

    fn is_peer_root(stream: &UnixStream) -> eyre::Result<bool> {
        let fd = stream.as_raw_fd();

        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;

        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };

        if ret != 0 {
            eyre::bail!("getsockopt failed: {}", std::io::Error::last_os_error());
        }

        Ok(cred.uid == 0)
    }

    fn c_bytes_to_string(cbytes: &[i8]) -> String {
        let cstr = unsafe { std::ffi::CStr::from_ptr(cbytes.as_ptr()) };
        cstr.to_string_lossy().into_owned()
    }

    fn raw_to_auth_identity(raw: &[u8]) -> eyre::Result<bindings::AuthIdentity> {
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
}
