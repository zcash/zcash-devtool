use anyhow::anyhow;
use clap::Args;
use rand::rngs::OsRng;
use uuid::Uuid;

use zcash_client_backend::data_api::{Account as _, WalletRead};
use zcash_client_sqlite::{WalletDb, util::SystemClock};
use zcash_pool_migration::engine::{MigrationTxKind, MigrationTxState};
use zcash_pool_migration::satisfiability::DuenessTargets;
use zcash_pool_migration::state::{Blocker, NextAction};

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

        // `PoolMigrations` is account-scoped, so the account must be resolved before loading --
        // in its own scope, since `WalletDb::from_connection` and the store's borrow of the same
        // connection can't both be alive at once.
        //
        // The two heights must come from the wallet, not from anything derived from the
        // migration's own schedule: dueness is judged against them, so a synthetic stand-in (the
        // schedule's own maximum, say) would make transactions look ready regardless of the real
        // chain. Matches `migration advance`.
        let (account_id, scanned, tip) = {
            let wallet_db = WalletDb::from_connection(&mut conn, params, SystemClock, OsRng);
            let account = select_account(&wallet_db, self.account_id)?;
            let scanned = wallet_db
                .block_fully_scanned()
                .map_err(|e| anyhow!("wallet read failed: {e:?}"))?
                .ok_or_else(|| anyhow!("wallet has not scanned any blocks yet"))?
                .block_height();
            let tip = wallet_db
                .chain_height()
                .map_err(|e| anyhow!("wallet read failed: {e:?}"))?
                .ok_or_else(|| anyhow!("wallet is not synced"))?;
            (account.id(), scanned, tip)
        };
        let targets = DuenessTargets::new(scanned + 1, tip + 1);

        let Some(state) = load_migration(params, &conn, account_id)? else {
            println!("No migration in progress.");
            return Ok(());
        };

        println!("Status: {}", state.status().as_ref());
        println!(
            "Judged at scanned target {}, estimated target {}",
            targets.scanned(),
            targets.effective()
        );

        let statuses = state.transaction_statuses(targets);
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
                MigrationTxState::Mined { txid, height } => {
                    format!("mined at {height} (txid {})", hex::encode(*txid.as_ref()))
                }
            };
            let blocker = match tx.blocked_on() {
                Some(Blocker::Dependencies) => " [blocked: dependencies]".to_string(),
                Some(Blocker::Schedule) => " [blocked: schedule]".to_string(),
                Some(Blocker::AnchorBoundary) => {
                    " [blocked: anchor boundary not yet settled]".to_string()
                }
                Some(Blocker::Signature) => " [blocked: awaiting external signature]".to_string(),
                Some(Blocker::ExpiryImminent) => {
                    " [blocked: expiry probably passed, withheld pending scan]".to_string()
                }
                Some(Blocker::Expired) => " [blocked: expired, needs rebuild]".to_string(),
                Some(Blocker::AwaitingReevaluation) => {
                    " [blocked: a node rejected its broadcast; sync and re-drive]".to_string()
                }
                Some(Blocker::Unsatisfiable) => {
                    // `UnsatisfiableKind` is `#[non_exhaustive]`; its stable wire name is what
                    // there is to render, and a future release may add one this build cannot
                    // name.
                    let kind = tx
                        .unsatisfiable_kind()
                        .map(|k| k.as_ref().to_owned())
                        .unwrap_or_else(|| "unknown".to_owned());
                    format!(" [blocked: can never mine ({kind})]")
                }
                None => match tx.action() {
                    Some(NextAction::Prove) if tx.ready() => " [ready: prove]".to_string(),
                    Some(NextAction::Broadcast) if tx.ready() => " [ready: broadcast]".to_string(),
                    _ => String::new(),
                },
            };
            println!(
                "  [{}] {kind}: {state_str}, scheduled >= {}, expires after {}{blocker}",
                u32::from(tx.id()),
                tx.scheduled_height(),
                tx.expiry_height(),
            );
        }

        // A read-only summary. The authoritative decision of what to do next is made by
        // `advance_migration` (which `migration advance` drives): it puts each candidate to the
        // wallet's satisfiability oracle and records what it finds, so it writes and this does
        // not. What is reported here is the state machine's own view, unverified.
        if state.is_terminal() {
            println!("Next: nothing -- the migration has reached a terminal status.");
        } else if state.replan_required() {
            println!(
                "Next: re-plan -- too much of the planned value can never mine (`migration \
                 advance` will say so)."
            );
        } else if let Some(tx) = statuses.iter().find(|tx| tx.ready()) {
            let action = match tx.action() {
                Some(NextAction::Prove) => "prove",
                Some(NextAction::Broadcast) => "broadcast",
                None => "act on",
            };
            println!(
                "Next: {action} transaction {} (`migration advance`)",
                u32::from(tx.id())
            );
        } else {
            println!("Next: waiting on dependencies, an anchor boundary, or a scheduled height");
        }

        let expired = state.expired_transactions(targets);
        if !expired.is_empty() {
            println!(
                "Expired without mining ({}): {}",
                expired.len(),
                expired
                    .iter()
                    .map(|id| u32::from(*id).to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }

        Ok(())
    }
}
