use anyhow::anyhow;
use clap::Args;
use rand::rngs::OsRng;
use uuid::Uuid;

use zcash_client_backend::data_api::{Account as _, WalletRead};
use zcash_client_sqlite::{WalletDb, util::SystemClock};
use zcash_pool_migration_backend::engine::{MigrationTxKind, MigrationTxState};
use zcash_pool_migration_backend::state::{AdvanceStep, Blocker};

use crate::{commands::select_account, config::get_wallet_network, data::get_db_paths};

use super::store::{load_migration, open_connection};

/// Options accepted for the `migration status` command.
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// The UUID of the account whose migration to report on
    account_id: Option<Uuid>,
}

impl Command {
    pub(crate) fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let params = get_wallet_network(wallet_dir.as_ref())?;
        let (_, db_path) = get_db_paths(wallet_dir.as_ref());
        let mut conn = open_connection(&db_path)?;

        // `PoolMigrations` is account-scoped now, so the account must be resolved before loading
        // -- in its own scope, since `WalletDb::from_connection` and a direct `&conn` borrow for
        // `load_migration` can't both be alive at once.
        let account_id = {
            let wallet_db = WalletDb::from_connection(&mut conn, params, SystemClock, OsRng);
            select_account(&wallet_db, self.account_id)?.id()
        };

        let Some(state) = load_migration(&conn, account_id)? else {
            println!("No migration in progress.");
            return Ok(());
        };

        println!("Status: {}", state.status().as_ref());
        // Must be the LIVE chain tip, not a synthetic stand-in: next_step()/transaction_statuses()
        // treat anything with scheduled_height <= target_height as due, so a synthetic height
        // derived from the migration's OWN schedule (e.g. its max) would make transactions look
        // ready regardless of the real chain -- the opposite of "safe". Matches migration advance.
        let wallet_db = WalletDb::from_connection(&mut conn, params, SystemClock, OsRng);
        let tip = wallet_db
            .chain_height()
            .map_err(|e| anyhow!("wallet read failed: {e:?}"))?
            .ok_or_else(|| anyhow!("wallet is not synced"))?;
        let target_height = tip + 1;

        let statuses = state.transaction_statuses(target_height);
        println!("Transactions ({}):", statuses.len());
        for tx in &statuses {
            let kind = match tx.kind() {
                MigrationTxKind::Preparation { layer, index } => {
                    format!("preparation layer={layer} index={index}")
                }
                MigrationTxKind::Transfer { crossing } => format!("transfer crossing={crossing}"),
            };
            let state_str = match tx.state() {
                MigrationTxState::AwaitingSignature => "awaiting_signature".to_string(),
                MigrationTxState::Signed => "signed".to_string(),
                MigrationTxState::Proved => "proved".to_string(),
                MigrationTxState::Broadcast { txid } => {
                    format!("broadcast (txid {})", hex::encode(*txid.as_ref()))
                }
                MigrationTxState::Mined { height } => format!("mined at {height}"),
            };
            let blocker = match tx.blocked_on() {
                Some(Blocker::Dependencies) => " [blocked: dependencies]",
                Some(Blocker::Schedule) => " [blocked: schedule]",
                Some(Blocker::AnchorBoundary) => " [blocked: anchor boundary not yet settled]",
                Some(Blocker::Signature) => " [blocked: awaiting external signature]",
                Some(Blocker::Expired) => " [blocked: expired, needs rebuild]",
                None => "",
            };
            println!(
                "  [{}] {kind}: {state_str}, scheduled >= {}{blocker}",
                u32::from(tx.id()),
                tx.scheduled_height(),
            );
        }

        match state.next_step(target_height) {
            AdvanceStep::Prove { id } => {
                println!(
                    "Next: prove transaction {} (`migration advance`)",
                    u32::from(id)
                )
            }
            AdvanceStep::Broadcast { id } => {
                println!(
                    "Next: broadcast transaction {} (`migration advance`)",
                    u32::from(id)
                )
            }
            AdvanceStep::Rebuild { id } => {
                println!(
                    "Next: rebuild expired transfer {} (`migration advance`)",
                    u32::from(id)
                )
            }
            AdvanceStep::Waiting => println!("Next: waiting on dependencies or a scheduled height"),
            AdvanceStep::Complete => println!("Migration complete."),
        }

        Ok(())
    }
}
