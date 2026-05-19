use std::{
    mem::MaybeUninit,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use eyre::OptionExt;

use crate::bindings;

#[derive(Clone, Default)]
pub struct AuthCaches {
    inner: Arc<Mutex<Vec<bindings::AuthCache>>>,
}

impl AuthCaches {
    pub fn put(&self, raw_item: &[u8]) -> eyre::Result<()> {
        let mut auth_cache_uninit = MaybeUninit::<bindings::AuthCache>::uninit();

        let auth_cache = unsafe {
            if !bindings::auth_cache_deserialize(
                raw_item.as_ptr(),
                raw_item.len(),
                auth_cache_uninit.as_mut_ptr(),
            ) {
                eyre::bail!("Failed to deserialize auth cache");
            }

            auth_cache_uninit.assume_init()
        };

        match self.inner.lock() {
            Ok(mut auth_caches) => auth_caches.push(auth_cache),
            Err(e) => eyre::bail!("Failed to acquire lock on auth caches: {e}"),
        }

        Ok(())
    }

    pub fn contains_valid_cache(&self) -> eyre::Result<bindings::AuthCache> {
        let Ok(unix_now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            eyre::bail!("Failed to get current time");
        };

        self.inner
            .lock()
            .map_err(|_| eyre::eyre!("Failed to acquire lock on auth caches"))?
            .iter()
            .find(|item| item.expires_at > unix_now.as_secs() as i64)
            .copied()
            .ok_or_eyre("Failed to find valid auth cache")
    }
}
