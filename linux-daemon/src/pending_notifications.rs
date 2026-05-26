use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

#[derive(Clone, Default)]
pub struct PendingNotifications {
    inner: Arc<Mutex<Vec<Arc<Notify>>>>,
}

impl PendingNotifications {
    pub fn add_one(&self, notify: Arc<Notify>) -> eyre::Result<()> {
        match self.inner.lock() {
            Ok(mut inner) => inner.push(notify),
            Err(e) => eyre::bail!("Failed to lock pending notifications: {}", e),
        }

        Ok(())
    }

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
