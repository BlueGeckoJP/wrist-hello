use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

/// Represents pending notifications used to notify the UNIX socket worker when the wearos-app client challenge response is successfully verified
#[derive(Clone, Default)]
pub struct PendingNotifications {
    inner: Arc<Mutex<Vec<Arc<Notify>>>>,
}

impl PendingNotifications {
    /// Adds a new pending notification to the list
    pub fn add_one(&self, notify: Arc<Notify>) -> eyre::Result<()> {
        match self.inner.lock() {
            Ok(mut inner) => inner.push(notify),
            Err(e) => eyre::bail!("Failed to lock pending notifications: {}", e),
        }

        Ok(())
    }

    /// Notifies all pending notifications and clears the list
    pub fn notify_all(&self) -> eyre::Result<usize> {
        let mut inner = match self.inner.lock() {
            Ok(inner) => inner,
            Err(e) => eyre::bail!("Failed to lock pending notifications: {}", e),
        };

        inner.iter().for_each(|notify| notify.notify_one());
        let count = inner.len();
        inner.clear();

        Ok(count)
    }
}
