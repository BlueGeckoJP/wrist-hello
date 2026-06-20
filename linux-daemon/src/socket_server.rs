use std::{
    mem::{self},
    os::fd::AsRawFd,
    sync::Arc,
};

use tokio::{
    net::{UnixListener, UnixStream},
    sync::mpsc,
};
use tracing::{error, info, warn};

use crate::{auth_processor::AuthRequest, verification_handler::handle_verification_request};

const SOCKET_PATH: &str = "/run/wrist-hello/auth.sock";

#[derive(Clone)]
pub struct ServerContext {
    pub add_queue_tx: mpsc::Sender<AuthRequest>,
}

pub struct SocketServer {
    ctx: ServerContext,
}

impl SocketServer {
    pub fn new(add_queue_tx: mpsc::Sender<AuthRequest>) -> Self {
        let ctx = ServerContext { add_queue_tx };
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
