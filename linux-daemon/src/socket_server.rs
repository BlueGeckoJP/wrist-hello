use std::{
    mem,
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

use crate::{auth_caches::AuthCaches, bindings, pending_notifications::PendingNotifications};

const SOCKET_PATH: &str = "/run/wrist-hello/auth.sock";

pub struct SocketServer {
    challenge_trigger: Arc<Notify>,
    is_first_notify: Arc<AtomicBool>,
    auth_caches: AuthCaches,
    pending_notifications: PendingNotifications,
}

impl SocketServer {
    pub fn new(
        challenge_trigger: Arc<Notify>,
        is_first_notify: Arc<AtomicBool>,
        auth_caches: AuthCaches,
        pending_notifications: PendingNotifications,
    ) -> Self {
        Self {
            challenge_trigger,
            is_first_notify,
            auth_caches,
            pending_notifications,
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
        let mut buf = [0u8; mem::size_of::<bindings::AuthCache>()];
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

        if let Ok(auth_cache) = self.auth_caches.verify_auth_cache(&buf[..n]) {
            info!(
                "Auth cache verified: uid={}, tty={}, service={}, expires_at={}",
                auth_cache.uid,
                Self::c_bytes_to_string(&auth_cache.tty),
                Self::c_bytes_to_string(&auth_cache.service),
                auth_cache.expires_at
            );
        } else {
            let notify = Arc::new(Notify::new());
            if let Err(e) = self.pending_notifications.add_one(notify.clone()) {
                error!("Failed to add notify to pending notifications: {}", e);
                return;
            }

            if self.is_first_notify.load(Ordering::SeqCst) {
                warn!("First notify, skipping challenge trigger");
            } else {
                info!("Triggering challenge");
                self.challenge_trigger.notify_one();
            }

            match timeout(Duration::from_secs(5), notify.notified()).await {
                Ok(_) => info!("Received verification notification"),
                Err(e) => {
                    error!("Failed to wait for verification notification: {}", e);
                    return;
                }
            }
        }

        if let Err(e) = stream.write_all(&[0u8]).await {
            error!(
                "Failed to send verification failure response to client: {}",
                e
            );
        }

        if let Err(e) = stream.flush().await {
            error!("Failed to flush response to client: {}", e);
        }

        self.auth_caches.put(&buf[..n]).unwrap_or_else(|e| {
            error!("Failed to update auth cache timestamp: {}", e);
        });

        if let Ok(length) = self.auth_caches.inner_length()
            && length > 100
            && let Err(e) = self.auth_caches.remove_expired_caches()
        {
            error!("Failed to remove expired auth caches: {}", e);
        }
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
        let cstr = unsafe { std::ffi::CStr::from_ptr(cbytes.as_ptr() as *const i8) };
        cstr.to_string_lossy().into_owned()
    }
}
