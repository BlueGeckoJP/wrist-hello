use std::{
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

/// Time-to-live for a verified session, in seconds
const TTL_SECS: u64 = 60;

#[derive(Default)]
struct SessionData {
    verified_at: u64,
    expires_at: u64,
}

/// Represents an authentication session for a user (authentication cache)
/// It tracks when the session was verified and when it expires
#[derive(Clone, Default)]
pub struct AuthSession {
    inner: Arc<Mutex<SessionData>>,
}

impl AuthSession {
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
        session_data.expires_at = now + TTL_SECS;

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
