use anyhow::anyhow;
use clap::Args;
use rand::rngs::OsRng;
use uuid::Uuid;

use zcash_client_backend::data_api::{Account as _, WalletRead};
use zcash_client_sqlite::{WalletDb, util::SystemClock};
use zcash_pool_migration::engine::{MigrationTxKind, prove_preparation, prove_transfer};
use zcash_pool_migration::state::AdvanceStep;
use zcash_pool_migration::wallet::WalletMigrationProver;

use crate::{commands::select_account, config::get_wallet_network, data::get_db_paths};

use super::store::{load_migration, open_connection, persist_migration};

/// Options accepted for the `migration advance` command.
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// The UUID of the account whose migration to advance
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

        let Some(mut state) = load_migration(&conn, account_id)? else {
            println!("No migration in progress.");
            return Ok(());
        };

        // Every transaction is already built and signed at commit time now (one signing phase),
        // so there is nothing left for `advance` to build. It proves transactions whose deferred
        // anchor is ready (installing it and the spend witnesses through the PCZT `Updater` role,
        // ZIP 374) and orders broadcasts against the LIVE chain tip, same as `migration status`
        // -- anything derived from the migration's own schedule would make transactions look
        // ready regardless of the real chain.
        let mut wallet_db = WalletDb::from_connection(&mut conn, params, SystemClock, OsRng);
        let account = select_account(&wallet_db, self.account_id)?;
        let fvk = account
            .ufvk()
            .and_then(|ufvk| ufvk.orchard())
            .cloned()
            .ok_or_else(|| anyhow!("account has no Orchard viewing key"))?;
        let account_id_for_prover = account.id();

        let tip = wallet_db
            .chain_height()
            .map_err(|e| anyhow!("wallet read failed: {e:?}"))?
            .ok_or_else(|| anyhow!("wallet is not synced"))?;
        let target_height = tip + 1;

        match state.next_step(target_height) {
            AdvanceStep::Prove { id } => {
                let kind = state
                    .transaction_statuses(target_height)
                    .into_iter()
                    .find(|tx| tx.id() == id)
                    .map(|tx| tx.kind())
                    .ok_or_else(|| anyhow!("transaction {} not found", u32::from(id)))?;

                let mut prover =
                    WalletMigrationProver::new(&mut wallet_db, account_id_for_prover, fvk);
                match kind {
                    MigrationTxKind::Transfer { .. } => {
                        prove_transfer(&mut prover, &mut state, id).map_err(|e| {
                            anyhow!("proving transfer {} failed: {e}", u32::from(id))
                        })?;
                    }
                    // A preparation carries no drawn anchor boundary of its own (it anchors to its
                    // already-mined dependencies), so the caller picks the checkpoint; the current
                    // tip is always valid since the dependencies are already confirmed mined by
                    // the time `next_step` returns `Prove` for it.
                    MigrationTxKind::Preparation { .. } => {
                        prove_preparation(&mut prover, &mut state, id, tip).map_err(|e| {
                            anyhow!("proving preparation {} failed: {e}", u32::from(id))
                        })?;
                    }
                }
                persist_migration(&mut conn, account_id, &state)?;
                println!("Proved transaction {}.", u32::from(id));
            }
            AdvanceStep::Broadcast { id } => {
                println!(
                    "Transaction {} is proved and ready to broadcast, but broadcasting isn't \
                     wired up in this command yet: it needs a lightwalletd client and extracting \
                     the finalized transaction from the proven PCZT, neither of which any \
                     `migration` command builds yet. Re-run `migration advance` once that lands, \
                     or `migration status` to check state anytime.",
                    u32::from(id)
                );
            }
            AdvanceStep::Rebuild { id } => {
                println!(
                    "Transfer {} expired before mining and needs to be rebuilt with a fresh \
                     anchor and signed anew -- not implemented in this command yet (rebuilding \
                     needs the account's spend authority, the same as `migration commit`).",
                    u32::from(id)
                );
            }
            AdvanceStep::Waiting => {
                println!("Waiting on dependencies or a scheduled height. Nothing to do now.");
            }
            AdvanceStep::Complete => {
                println!("Migration complete.");
            }
        }

        Ok(())
    }
}
