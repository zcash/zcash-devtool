use anyhow::anyhow;
use gumdrop::Options;

use zcash_client_backend::proto::service;

use crate::{
    config::WalletConfig,
    data::erase_wallet_state,
    remote::{tor_client, Servers},
};

// Options accepted for the `reset` command
#[derive(Debug, Options)]
pub(crate) struct Command {
    #[options(help = "age identity file to decrypt the mnemonic phrase with")]
    identity: String,

    #[options(help = "the number of accounts to re-initialise the wallet with (default is 1)")]
    accounts: Option<usize>,

    #[options(
        help = "the server to re-initialize with (default is \"ecc\")",
        default = "ecc",
        parse(try_from_str = "Servers::parse")
    )]
    server: Servers,

    #[options(help = "disable connections via TOR")]
    disable_tor: bool,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        // Load the wallet network, seed, and birthday from disk.
        let mut config = WalletConfig::read(wallet_dir.as_ref())?;
        let params = config.network();

        // Connect to the client (for re-initializing the wallet).
        let server = self.server.pick(params)?;
        let mut client = if self.disable_tor {
            server.connect_direct().await?
        } else {
            server.connect(|| tor_client(wallet_dir.as_ref())).await?
        };

        // Get the current chain height (for the wallet's recover-until height).
        let chain_tip = client
            .get_latest_block(service::ChainSpec::default())
            .await?
            .into_inner()
            .height
            .try_into()
            .expect("block heights must fit into u32");

        let birthday =
            super::init::Command::get_wallet_birthday(client, config.birthday(), Some(chain_tip))
                .await?;

        // Erase the wallet state (excluding key material).
        erase_wallet_state(wallet_dir.as_ref()).await;

        // Decrypt the mnemonic to access the seed.
        let identities = age::IdentityFile::from_file(self.identity)?.into_identities()?;
        config.decrypt(identities.iter().map(|i| i.as_ref() as _))?;

        // Re-initialize the wallet state.
        super::init::Command::init_dbs(
            params,
            wallet_dir.as_ref(),
            config
                .seed()
                .ok_or(anyhow!("Seed is required for database reset"))?,
            birthday,
            self.accounts.unwrap_or(1),
        )
    }
}
