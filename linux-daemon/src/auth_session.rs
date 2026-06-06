use std::{
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Default)]
struct SessionData {
    verified_at: u64,
    expires_at: u64,
}

/// Represents an authentication session for a user (authentication cache)
/// It tracks when the session was verified and when it expires
#[derive(Clone)]
pub struct AuthSession {
    inner: Arc<Mutex<SessionData>>,
    ttl_seconds: u64,
}

impl AuthSession {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SessionData::default())),
            ttl_seconds,
        }
    }

    /// Marks the session as verified, updating the verification and expiration times
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
        session_data.expires_at = now + self.ttl_seconds;

        Ok(())
    }

    /// Checks if the session is currently verified
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
