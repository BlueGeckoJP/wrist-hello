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
    fn raw_to_auth_cache(raw_item: &[u8]) -> eyre::Result<bindings::AuthCache> {
        let mut auth_cache_uninit = MaybeUninit::<bindings::AuthCache>::uninit();

        unsafe {
            if !bindings::auth_cache_deserialize(
                raw_item.as_ptr(),
                raw_item.len(),
                auth_cache_uninit.as_mut_ptr(),
            ) {
                eyre::bail!("Failed to deserialize auth cache");
            }

            Ok(auth_cache_uninit.assume_init())
        }
    }

    pub fn put(&self, raw_item: &[u8]) -> eyre::Result<()> {
        let auth_cache = Self::raw_to_auth_cache(raw_item)?;

        match self.inner.lock() {
            Ok(mut auth_caches) => auth_caches.push(auth_cache),
            Err(e) => eyre::bail!("Failed to acquire lock on auth caches: {e}"),
        }

        Ok(())
    }

    pub fn verify_auth_cache(&self, raw_item: &[u8]) -> eyre::Result<bindings::AuthCache> {
        let auth_cache = Self::raw_to_auth_cache(raw_item)?;

        let Ok(unix_now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            eyre::bail!("Failed to get current time");
        };

        self.inner
            .lock()
            .map_err(|_| eyre::eyre!("Failed to acquire lock on auth caches"))?
            .iter()
            .find(|item| {
                item.expires_at > unix_now.as_secs() as i64
                    && auth_cache.uid == item.uid
                    && auth_cache.tty == item.tty
                    && auth_cache.service == item.service
            })
            .copied()
            .ok_or_eyre("Failed to find valid auth cache")
    }

    pub fn inner_length(&self) -> eyre::Result<usize> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| eyre::eyre!("Failed to acquire lock on auth caches"))?;
        Ok(inner.len())
    }

    pub fn remove_expired_caches(&self) -> eyre::Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?;

        self.inner
            .lock()
            .map_err(|_| eyre::eyre!("Failed to acquire lock on auth caches"))?
            .retain(|item| item.expires_at > now.as_secs() as i64);

        Ok(())
    }
}
