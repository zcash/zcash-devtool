use anyhow::anyhow;
use gumdrop::Options;
use rusqlite::Connection;
use zcash_client_sqlite::WalletDb;
use zcash_protocol::consensus::Parameters;

use crate::{
    data::{erase_wallet_state, read_config},
    remote::{tor_client, Servers},
};

// Options accepted for the `reset` command
#[derive(Debug, Options)]
pub(crate) struct Command {
    #[options(help = "the number of accounts to re-initialise the wallet with (default is 1)")]
    accounts: Option<usize>,

    #[options(
        help = "the server to re-initialize with (default is \"ecc\")",
        default = "ecc",
        parse(try_from_str = "Servers::parse")
    )]
    server: Servers,
}

impl Command {
    pub(crate) async fn run<P: Parameters + 'static>(
        self,
        wallet_dir: Option<String>,
        db_data: &mut WalletDb<Connection, P>,
    ) -> Result<(), anyhow::Error> {
        // Load the wallet network, seed, and birthday from disk.
        let keys = read_config(wallet_dir.as_ref())?;
        let params = keys.network();

        // Connect to the client (for re-initializing the wallet).
        let client = self
            .server
            .pick(params)?
            .connect(|| tor_client(wallet_dir.as_ref()))
            .await?;

        // Erase the wallet state (excluding key material).
        erase_wallet_state(wallet_dir.as_ref()).await;

        // Re-initialize the wallet state.
        super::init::Command::init_dbs(
            client,
            wallet_dir,
            db_data,
            keys.seed()
                .ok_or(anyhow!("Seed is required for database reset"))?,
            keys.birthday().into(),
            self.accounts.unwrap_or(1),
        )
        .await
    }
}
