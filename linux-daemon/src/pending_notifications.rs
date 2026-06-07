use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;

/// Represents the result of an authentication attempt
/// This enum does not include `Failure`; failures are represented simply as errors
/// `Denied` represents an explicit user denial or approval timeout
#[derive(Clone, Copy)]
pub enum AuthResult {
    Success,
    Denied,
}

struct PendingNotification {
    uuid: String,
    sender: oneshot::Sender<AuthResult>,
}

/// Represents pending notifications used to notify the UNIX socket workers waiting for an authentication result
#[derive(Clone, Default)]
pub struct PendingNotifications {
    inner: Arc<Mutex<Vec<PendingNotification>>>,
}

impl PendingNotifications {
    fn send_all(&self, result: AuthResult) -> eyre::Result<usize> {
        let mut inner = match self.inner.lock() {
            Ok(inner) => inner,
            Err(e) => eyre::bail!("Failed to lock pending notifications: {}", e),
        };

        let notifications: Vec<_> = inner.drain(..).collect();
        let num_notifications = notifications.len();

        for notification in notifications {
            let _ = notification.sender.send(result);
        }

        Ok(num_notifications)
    }

    /// Adds a new pending notification to the list and returns its UUID
    pub fn add_one(&self, sender: oneshot::Sender<AuthResult>) -> eyre::Result<String> {
        let id = uuid::Uuid::new_v4().to_string();

        let pending = PendingNotification {
            uuid: id.clone(),
            sender,
        };

        match self.inner.lock() {
            Ok(mut inner) => inner.push(pending),
            Err(e) => eyre::bail!("Failed to lock pending notifications: {}", e),
        }

        Ok(id)
    }

    /// Sends a successful authentication result and consumes all pending notifications
    pub fn notify_all(&self) -> eyre::Result<usize> {
        Ok(self.send_all(AuthResult::Success)?)
    }

    /// Sends a failed/denied authentication result and consumes all pending notifications
    pub fn fail_all(&self) -> eyre::Result<usize> {
        Ok(self.send_all(AuthResult::Denied)?)
    }

    /// Removes a pending notification by its UUID
    pub fn remove_one(&self, uuid: &str) -> eyre::Result<()> {
        let mut inner = match self.inner.lock() {
            Ok(inner) => inner,
            Err(e) => eyre::bail!("Failed to lock pending notifications: {}", e),
        };

        inner.retain(|n| n.uuid != uuid);

        Ok(())
    }
}
