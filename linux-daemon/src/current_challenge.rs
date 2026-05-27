use std::sync::{Arc, Mutex};

use rand::RngExt;

#[derive(Clone, Default)]
pub struct CurrentChallenge {
    challenge: Arc<Mutex<Option<[u8; 32]>>>,
}

impl CurrentChallenge {
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
