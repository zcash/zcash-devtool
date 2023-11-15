use gumdrop::Options;

use zcash_primitives::consensus::Parameters;

use crate::{
    data::{erase_wallet_state, get_wallet_seed_and_birthday},
    remote::connect_to_lightwalletd,
};

// Options accepted for the `reset` command
#[derive(Debug, Options)]
pub(crate) struct Command {}

impl Command {
    pub(crate) async fn run(
        self,
        params: impl Parameters + 'static,
        wallet_dir: Option<String>,
    ) -> Result<(), anyhow::Error> {
        // Connect to the client (for re-initializing the wallet).
        let client = connect_to_lightwalletd().await?;

        // Load the wallet seed and birthday from disk.
        let (seed, birthday) = get_wallet_seed_and_birthday(wallet_dir.as_ref())?;

        // Erase the wallet state (excluding key material).
        erase_wallet_state(wallet_dir.as_ref()).await;

        // Re-initialize the wallet state.
        super::init::Command::init_dbs(client, params, wallet_dir, seed, birthday.into()).await
    }
}
