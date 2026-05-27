use std::sync::{Arc, Mutex};

use rand::RngExt;

/// Represents the current authentication challenge that can be read by the wearos-app client and is updated on each read/notify request
/// The contents of the challenge are simply a random sequence of 32 `u8` values
/// This struct only provides a consume-and-read function to prevent the same challenge from being signed twice
#[derive(Clone, Default)]
pub struct CurrentChallenge {
    challenge: Arc<Mutex<Option<[u8; 32]>>>,
}

impl CurrentChallenge {
    /// Refreshes the current challenge by generating a new random sequence of 32 `u8` values
    pub fn refresh(&self) -> eyre::Result<[u8; 32]> {
        let mut rng = rand::rngs::ThreadRng::default();
        let mut ch = [0u8; 32];
        rng.fill(&mut ch);

        let mut challenge = self
            .challenge
            .lock()
            .map_err(|_| eyre::eyre!("Failed to acquire lock on current challenge"))?;

        challenge.replace(ch);

        Ok(ch)
    }

    /// Takes the current challenge, consuming it and returning the value
    pub fn take(&self) -> eyre::Result<[u8; 32]> {
        let challenge = self
            .challenge
            .lock()
            .map_err(|_| eyre::eyre!("Failed to acquire lock on current challenge"))?
            .take();

        match challenge {
            Some(ch) => Ok(ch),
            None => eyre::bail!("Current challenge is not set"),
        }
    }
}
