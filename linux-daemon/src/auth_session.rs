use std::{
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

const TTL_SECS: u64 = 60;

#[derive(Default)]
struct SessionData {
    verified_at: u64,
    expires_at: u64,
}

#[derive(Clone, Default)]
pub struct AuthSession {
    inner: Arc<Mutex<SessionData>>,
}

impl AuthSession {
    pub fn mark_verified(&self) -> eyre::Result<()> {
        let mut session_data = self
            .inner
            .lock()
            .map_err(|_| eyre::eyre!("Failed to acquire lock on session data"))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| eyre::eyre!("Failed to get current time"))?
            .as_secs();

        session_data.verified_at = now;
        session_data.expires_at = now + TTL_SECS;

        Ok(())
    }

    pub fn is_verified(&self) -> eyre::Result<bool> {
        let session_data = self
            .inner
            .lock()
            .map_err(|_| eyre::eyre!("Failed to acquire lock on session data"))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| eyre::eyre!("Failed to get current time"))?
            .as_secs();

        Ok(session_data.verified_at > 0 && session_data.expires_at > now)
    }
}
