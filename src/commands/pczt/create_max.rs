use std::{path::PathBuf, str::FromStr};

use clap::Args;
use rand::rngs::OsRng;
use tokio::{
    fs::File,
    io::{stdout, AsyncWriteExt},
};
use uuid::Uuid;

use zcash_address::ZcashAddress;
use zcash_client_backend::{
    data_api::{
        wallet::{create_pczt_from_proposal, propose_send_max_transfer, ConfirmationsPolicy},
        Account as _, MaxSpendMode,
    },
    fees::StandardFeeRule,
    wallet::OvkPolicy,
};
use zcash_client_sqlite::{util::SystemClock, WalletDb};
use zcash_protocol::{
    memo::{Memo, MemoBytes},
    ShieldedProtocol,
};

use crate::{commands::select_account, config::WalletConfig, data::get_db_paths, error};

// Options accepted for the `pczt create-max` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// The UUID of the account to send funds from
    account_id: Option<Uuid>,

    /// The recipient's Unified, Sapling or transparent address
    #[arg(long)]
    address: String,

    /// A memo to send to the recipient
    #[arg(long)]
    memo: Option<String>,

    /// Spend all _currently_ spendable funds where it could be the case that the wallet
    /// has received other funds that are not confirmed and therefore not spendable yet
    /// and the caller evaluates that as an acceptable scenario.
    ///
    /// Default is to spend **all funds**, failing if there are unspendable funds in the
    /// wallet or if the wallet is not yet synced.
    #[arg(long)]
    only_spendable: bool,

    /// Path to a file to which to write the PCZT. If not provided, writes to stdout.
    #[arg(long)]
    output: Option<PathBuf>,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let config = WalletConfig::read(wallet_dir.as_ref())?;
        let params = config.network();

        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let mut db_data = WalletDb::for_path(db_data, params, SystemClock, OsRng)?;
        let account = select_account(&db_data, self.account_id)?;

        let recipient =
            ZcashAddress::from_str(&self.address).map_err(|_| error::Error::InvalidRecipient)?;
        let memo = self
            .memo
            .map(|memo| Memo::from_str(&memo))
            .transpose()?
            .map(MemoBytes::from);
        let mode = if self.only_spendable {
            MaxSpendMode::MaxSpendable
        } else {
            MaxSpendMode::Everything
        };

        // Create the PCZT.
        let proposal = propose_send_max_transfer(
            &mut db_data,
            &params,
            account.id(),
            &[ShieldedProtocol::Sapling, ShieldedProtocol::Orchard],
            &StandardFeeRule::Zip317,
            recipient,
            memo,
            mode,
            ConfirmationsPolicy::default(),
        )
        .map_err(error::Error::SendMax)?;

        let pczt = create_pczt_from_proposal(
            &mut db_data,
            &params,
            account.id(),
            OvkPolicy::Sender,
            &proposal,
        )
        .map_err(error::Error::from)?;

        if let Some(output_path) = &self.output {
            File::create(output_path)
                .await?
                .write_all(&pczt.serialize())
                .await?;
        } else {
            let mut stdout = stdout();
            stdout.write_all(&pczt.serialize()).await?;
            stdout.flush().await?;
        }

        Ok(())
    }
}
