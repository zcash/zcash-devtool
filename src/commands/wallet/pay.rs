#![allow(deprecated)]

use age::Identity;
use clap::Args;
use uuid::Uuid;

use zip321::TransactionRequest;

use zcash_primitives::transaction::TxVersion;

use crate::{
    commands::wallet::send::{pay, PaymentContext},
    remote::ConnectionArgs,
};

// Options accepted for the `pay` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// The UUID of the account to send funds from
    account_id: Option<Uuid>,

    /// age identity file to decrypt the mnemonic phrase with
    #[arg(short, long)]
    identity: String,

    /// The [`ZIP 321`] payment request describing the payment(s) to be constructed.
    ///
    /// [`ZIP 321`]: https://zips.z.cash/zip-0321
    #[arg(long)]
    payment_uri: String,

    #[command(flatten)]
    connection: ConnectionArgs,

    /// Note management: the number of notes to maintain in the wallet
    #[arg(long)]
    #[arg(default_value_t = 4)]
    target_note_count: usize,

    /// Note management: the minimum allowed value for split change amounts
    #[arg(long)]
    #[arg(default_value_t = 10000000)]
    min_split_output_value: u64,

    /// Do not require confirmation after inspection of the generated proposal
    #[arg(long)]
    disable_confirmation: bool,
}

impl PaymentContext for Command {
    fn spending_account(&self) -> Option<Uuid> {
        self.account_id
    }

    fn age_identities(&self) -> anyhow::Result<Vec<Box<dyn Identity>>> {
        let identities = age::IdentityFile::from_file(self.identity.clone())?.into_identities()?;
        Ok(identities)
    }

    fn connection_args(&self) -> &ConnectionArgs {
        &self.connection
    }

    fn target_note_count(&self) -> usize {
        self.target_note_count
    }

    fn min_split_output_value(&self) -> u64 {
        self.min_split_output_value
    }

    fn require_confirmation(&self) -> bool {
        !self.disable_confirmation
    }

    fn tx_version(&self) -> Option<TxVersion> {
        None
    }
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let request = TransactionRequest::from_uri(&self.payment_uri)?;

        pay(wallet_dir, self, request).await
    }
}
