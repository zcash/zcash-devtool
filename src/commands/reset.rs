use gumdrop::Options;

use zcash_primitives::consensus::Parameters;

use crate::{
    data::{erase_wallet_state, read_keys},
    remote::{connect_to_lightwalletd, Lightwalletd},
};

// Options accepted for the `reset` command
#[derive(Debug, Options)]
pub(crate) struct Command {}

impl Command {
    pub(crate) async fn run(
        self,
        params: impl Parameters + Lightwalletd + 'static,
        wallet_dir: Option<String>,
    ) -> Result<(), anyhow::Error> {
        // Connect to the client (for re-initializing the wallet).
        let client = connect_to_lightwalletd(&params).await?;

        // Load the wallet seed and birthday from disk.
        let keys = read_keys(wallet_dir.as_ref())?;

        // Erase the wallet state (excluding key material).
        erase_wallet_state(wallet_dir.as_ref()).await;

        // Re-initialize the wallet state.
        super::init::Command::init_dbs(
            client,
            params,
            wallet_dir,
            keys.seed(),
            keys.birthday().into(),
        )
        .await
    }
}