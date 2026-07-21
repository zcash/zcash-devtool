use clap::Args;

use zcash_pool_migration_backend::engine::{MigrationTxKind, MigrationTxState};
use zcash_pool_migration_backend::state::AdvanceStep;

use crate::data::get_db_paths;

use super::store::{load_migration, open_connection};

/// Options accepted for the `migration status` command.
#[derive(Debug, Args)]
pub(crate) struct Command {}

impl Command {
    pub(crate) fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let (_, db_path) = get_db_paths(wallet_dir.as_ref());
        let mut conn = open_connection(&db_path)?;

        let Some(state) = load_migration(&mut conn)? else {
            println!("No migration in progress.");
            return Ok(());
        };

        println!("Status: {}", state.status.as_ref());
        println!("Transactions ({}):", state.transactions.len());
        for tx in &state.transactions {
            let kind = match tx.kind {
                MigrationTxKind::Preparation { layer, index } => {
                    format!("preparation layer={layer} index={index}")
                }
                MigrationTxKind::Transfer { crossing } => format!("transfer crossing={crossing}"),
            };
            let state_str = match tx.state {
                MigrationTxState::Planned => "planned".to_string(),
                MigrationTxState::AwaitingSignature => "awaiting_signature".to_string(),
                MigrationTxState::Signed => "signed".to_string(),
                MigrationTxState::Proved => "proved".to_string(),
                MigrationTxState::Broadcast { txid } => format!("broadcast (txid {})", hex::encode(txid)),
                MigrationTxState::Mined { height } => format!("mined at {height}"),
                MigrationTxState::Expired => "expired".to_string(),
            };
            println!(
                "  [{}] {kind}: {state_str}, scheduled >= {}, expiry {}",
                tx.id.0, tx.scheduled_height, tx.expiry_height
            );
        }

        // `target_height` mirrors what the commit commands use: chain tip + 1. `next_step` only
        // needs it to decide whether a due transaction's scheduled height has arrived, so a
        // status display that doesn't have a live chain tip on hand uses the highest scheduled
        // height actually present, which is always safe (never claims something is due before
        // its own schedule says so).
        let target_height = state
            .transactions
            .iter()
            .map(|t| t.scheduled_height)
            .max()
            .unwrap_or(0);
        match state.next_step(target_height) {
            AdvanceStep::BuildPreparationLayer { layer } => {
                println!("Next: build and sign preparation layer {layer} (`migration advance`)")
            }
            AdvanceStep::BuildTransfers => {
                println!("Next: build and sign the transfers (`migration advance`)")
            }
            AdvanceStep::Broadcast { id } => {
                println!("Next: prove and broadcast transaction {} (`migration advance`)", id.0)
            }
            AdvanceStep::Waiting => println!("Next: waiting on dependencies or a scheduled height"),
            AdvanceStep::Complete => println!("Migration complete."),
        }

        Ok(())
    }
}
