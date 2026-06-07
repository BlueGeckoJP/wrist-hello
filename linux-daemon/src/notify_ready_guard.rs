use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub struct NotifyReadyGuard {
    ready: Arc<AtomicBool>,
}

impl NotifyReadyGuard {
    pub fn new(ready: Arc<AtomicBool>) -> Self {
        ready.store(true, Ordering::SeqCst);
        Self { ready }
    }
}

impl Drop for NotifyReadyGuard {
    fn drop(&mut self) {
        self.ready.store(false, Ordering::SeqCst);
    }
}
