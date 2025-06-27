use bip0039::{Count, English, Mnemonic};
use clap::Args;
use rand::rngs::OsRng;
use secrecy::{SecretVec, Zeroize};
use zcash_client_backend::{data_api::WalletWrite, proto::service};
use zcash_client_sqlite::{util::SystemClock, WalletDb};

use crate::{commands::wallet, config::get_wallet_network, data::get_db_paths, remote::Servers};

// Options accepted for the `list-addresses` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// A name for the account
    #[arg(long)]
    account_name: String,

    #[arg(short, long)]
    #[arg(default_value = "ecc", value_parser = Servers::parse)]
    server: Servers,

    /// A flag indicating whether a QR code should be displayed for the address.
    #[cfg(feature = "qr")]
    #[arg(long, default_value = "true")]
    display_qr: bool,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let params = get_wallet_network(wallet_dir.as_ref())?;
        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let mut db_data = WalletDb::for_path(db_data, params, SystemClock, OsRng)?;

        let mnemonic = Mnemonic::<English>::generate(Count::Words24);

        let seed = {
            let mut seed = mnemonic.to_seed("");
            let secret = seed.to_vec();
            seed.zeroize();
            SecretVec::new(secret)
        };

        let server = self.server.pick(params)?;
        let mut client = server.connect_direct().await?;

        // Get the current chain height (for the wallet's birthday and/or recover-until height).
        let chain_tip: u32 = client
            .get_latest_block(service::ChainSpec::default())
            .await?
            .into_inner()
            .height
            .try_into()
            .expect("block heights must fit into u32");

        let birthday = wallet::init::Command::get_wallet_birthday(
            client,
            chain_tip.saturating_sub(100).into(),
            None,
        )
        .await?;

        db_data.create_account(&self.account_name, &seed, &birthday, None)?;

        Ok(())
    }
}
