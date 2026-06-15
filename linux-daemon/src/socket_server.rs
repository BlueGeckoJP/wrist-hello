use std::{
    mem::{self},
    os::fd::AsRawFd,
    sync::{Arc, atomic::AtomicBool},
};

use tokio::{
    net::{UnixListener, UnixStream},
    sync::Notify,
};
use tracing::{error, info, warn};

use crate::{
    auth_session::AuthSession, pending_notifications::PendingNotifications,
    verification_handler::handle_verification_request,
};

const SOCKET_PATH: &str = "/run/wrist-hello/auth.sock";

#[derive(Clone)]
pub struct ServerContext {
    pub challenge_trigger: Arc<Notify>,
    pub pending_notifications: PendingNotifications,
    pub auth_session: AuthSession,
    pub notify_ready: Arc<AtomicBool>,
}

pub struct SocketServer {
    ctx: ServerContext,
}

impl SocketServer {
    pub fn new(
        challenge_trigger: Arc<Notify>,
        pending_notifications: PendingNotifications,
        auth_session: AuthSession,
        notify_ready: Arc<AtomicBool>,
    ) -> Self {
        let ctx = ServerContext {
            challenge_trigger,
            pending_notifications,
            auth_session,
            notify_ready,
        };
        Self { ctx }
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

            let ctx = self.ctx.clone();
            tokio::spawn(async move {
                info!("Accepted connection from {:?}", addr);
                handle_verification_request(&ctx, &mut stream).await
            });
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
