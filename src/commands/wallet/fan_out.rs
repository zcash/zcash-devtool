use std::str::FromStr;

use age::Identity;
use anyhow::anyhow;
use clap::Args;
use rand::rngs::OsRng;
use uuid::Uuid;

use zcash_address::ZcashAddress;
use zcash_client_backend::data_api::Account as _;
use zcash_client_sqlite::{WalletDb, util::SystemClock};
use zcash_keys::keys::UnifiedAddressRequest;
use zcash_primitives::transaction::TxVersion;

use crate::{commands::select_account, config::get_wallet_network, data::get_db_paths, remote::ConnectionArgs};

use super::send::{PaymentContext, pay};

/// Options accepted for the `wallet fan-out` command.
///
/// Repeatedly self-sends a small payment with a high `--target-note-count`,
/// so the leftover change is split into many notes instead of one. Used to
/// build a synthetic "very active wallet" (many small Orchard notes) for
/// testing note-management and migration flows without waiting for real
/// usage history. On regtest, a block must be mined (and the wallet synced)
/// between rounds so each round's change notes are confirmed and spendable
/// as inputs to the next round; this command performs one round per
/// invocation; drive the mine/sync loop from the shell.
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// The UUID of the account to fan out notes within
    account_id: Option<Uuid>,

    /// age identity file to decrypt the mnemonic phrase with
    #[arg(short, long)]
    identity: String,

    /// The amount in zatoshis of the (otherwise irrelevant) explicit payment;
    /// the rest of the selected input value becomes split change.
    #[arg(long)]
    #[arg(default_value_t = 1000)]
    value: u64,

    /// Note management: the number of notes to split change into
    #[arg(long)]
    #[arg(default_value_t = 80)]
    target_note_count: usize,

    /// Note management: the minimum allowed value for split change amounts
    #[arg(long)]
    #[arg(default_value_t = 10000000)]
    min_split_output_value: u64,

    #[command(flatten)]
    connection: ConnectionArgs,
}

struct FanOutRound {
    account_id: Option<Uuid>,
    identity: String,
    connection: ConnectionArgs,
    target_note_count: usize,
    min_split_output_value: u64,
}

impl PaymentContext for FanOutRound {
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
        false
    }

    fn tx_version(&self) -> Option<TxVersion> {
        None
    }
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        // The fan-out target is the account's own default address: change
        // outputs are always paid to the account regardless, so an explicit
        // self-payment here just avoids needing a real second party.
        let params = get_wallet_network(wallet_dir.as_ref())?;
        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let db_data = WalletDb::for_path(db_data, params, SystemClock, OsRng)?;
        let account = select_account(&db_data, self.account_id)?;
        let (ua, _) = account
            .uivk()
            .default_address(UnifiedAddressRequest::AllAvailableKeys)?;
        let address = ZcashAddress::from_str(&ua.encode(&params))
            .map_err(|_| anyhow!("Failed to re-parse the account's own default address"))?;

        let payment = zip321::Payment::without_memo(
            address,
            zcash_protocol::value::Zatoshis::from_u64(self.value)?,
        );
        let request = zip321::TransactionRequest::new(vec![payment])
            .map_err(|e| anyhow!("Failed to build self-payment request: {:?}", e))?;

        let context = FanOutRound {
            account_id: self.account_id,
            identity: self.identity,
            connection: self.connection,
            target_note_count: self.target_note_count,
            min_split_output_value: self.min_split_output_value,
        };

        pay(wallet_dir, context, request).await
    }
}
