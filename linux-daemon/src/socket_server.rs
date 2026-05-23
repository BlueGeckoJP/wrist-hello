use std::{
    mem,
    os::fd::AsRawFd,
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

use crate::{auth_caches::AuthCaches, bindings};

const SOCKET_PATH: &str = "/run/wrist-hello/auth.sock";

pub struct SocketServer {
    last_verified_at: Arc<AtomicU64>,
    challenge_trigger: Arc<Notify>,
    is_first_notify: Arc<AtomicBool>,
    auth_caches: AuthCaches,
}

impl SocketServer {
    pub fn new(
        last_verified_at: Arc<AtomicU64>,
        challenge_trigger: Arc<Notify>,
        is_first_notify: Arc<AtomicBool>,
        auth_caches: AuthCaches,
    ) -> Self {
        Self {
            last_verified_at,
            challenge_trigger,
            is_first_notify,
            auth_caches,
        }
    }

    pub async fn spawn(self: Arc<Self>) -> eyre::Result<()> {
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
            tokio::spawn(async move { server.handle_client(stream, addr).await });
        }
    }

    async fn handle_client(&self, mut stream: UnixStream, addr: SocketAddr) -> eyre::Result<()> {
        info!("Accepted connection from {:?}", addr);

        let mut buf = [0u8; mem::size_of::<bindings::SocketCommand>()];
        loop {
            let n = match stream.read_exact(&mut buf).await {
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

            self.handle_socket_command(&mut stream, &buf[..n]).await?;
        }

        Ok(())
    }

    async fn handle_socket_command(
        &self,
        stream: &mut UnixStream,
        data: &[u8],
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
            bindings::CMD_CHECK_STATUS => self.handle_check_status(stream).await,
            bindings::CMD_TRIGGER_CHALLENGE => self.handle_trigger_challenge().await,
            bindings::CMD_HAS_VALID_CACHE => self.handle_has_valid_cache(stream).await,
            bindings::CMD_ADD_AUTH_CACHE => self.handle_add_auth_cache(stream).await,
            _ => {
                error!("Received unknown command: {:?}", cmd);
            }
        }

        Ok(())
    }

    async fn handle_check_status(&self, stream: &mut UnixStream) {
        info!("Handling check status command");

        let last_verified_at = self.last_verified_at.load(Ordering::SeqCst);
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

    async fn handle_trigger_challenge(&self) {
        info!("Handling trigger challenge command");

        if self.is_first_notify.load(Ordering::SeqCst) {
            warn!("First notify, skipping challenge trigger");
        } else {
            info!("Triggering challenge");
            self.challenge_trigger.notify_one();
        }
    }

    async fn handle_has_valid_cache(&self, stream: &mut UnixStream) {
        info!("Handling has valid cache command");

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

        let valid_auth_cache = self.auth_caches.verify_auth_cache(&buf[..n]).is_ok();

        if let Err(e) = stream.write_all(&[valid_auth_cache as u8]).await {
            error!("Failed to send response to client: {}", e);
        }

        if let Err(e) = stream.flush().await {
            error!("Failed to flush response to client: {}", e);
        }

        info!("Sent has valid cache response to client");
    }

    async fn handle_add_auth_cache(&self, stream: &mut UnixStream) {
        info!("Handling add auth cache command");

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

        if let Err(e) = self.auth_caches.put(&buf[..n]) {
            error!("Failed to add auth cache: {}", e);
        }

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
}
