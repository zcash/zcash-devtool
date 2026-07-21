use anyhow::anyhow;
use clap::Args;
use rand::rngs::OsRng;

use zcash_client_backend::data_api::WalletRead;
use zcash_client_sqlite::{WalletDb, util::SystemClock};
use zcash_pool_migration_backend::state::AdvanceStep;

use crate::{config::get_wallet_network, data::get_db_paths};

use super::store::{load_migration, open_connection};

/// Options accepted for the `migration advance` command.
#[derive(Debug, Args)]
pub(crate) struct Command {}

impl Command {
    pub(crate) fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let params = get_wallet_network(wallet_dir.as_ref())?;
        let (_, db_path) = get_db_paths(wallet_dir.as_ref());
        let mut conn = open_connection(&db_path)?;

        let Some(state) = load_migration(&mut conn)? else {
            println!("No migration in progress.");
            return Ok(());
        };

        // Every transaction is already built and signed at commit time now (one signing phase),
        // so there is nothing left for `advance` to build -- it only orders broadcasts against
        // the LIVE chain tip (`migration status` uses a synthetic height instead, since it
        // doesn't need a synced wallet just to display state).
        let wallet_db = WalletDb::from_connection(&mut conn, params, SystemClock, OsRng);
        let tip = wallet_db
            .chain_height()
            .map_err(|e| anyhow!("wallet read failed: {e:?}"))?
            .ok_or_else(|| anyhow!("wallet is not synced"))?;
        let target_height = tip + 1;

        match state.next_step(target_height) {
            AdvanceStep::Broadcast { id } => {
                println!(
                    "Transaction {} is pre-signed and ready to prove and broadcast, but that \
                     step is not implemented yet: proving needs the anchor drawn at scheduling \
                     time installed through the PCZT Updater role (orchard PR #535's \
                     `Updater::set_anchor` / `ActionUpdater::set_spend_witness`), which no \
                     command here calls yet. Stopping; re-run `migration advance` once that \
                     lands, or `migration status` to check the current state anytime.",
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
