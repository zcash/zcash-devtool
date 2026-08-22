use anyhow::anyhow;
use clap::Args;
use rand::rngs::OsRng;
use uuid::Uuid;

use zcash_client_backend::data_api::{Account as _, WalletRead};
use zcash_client_sqlite::{WalletDb, util::SystemClock};
use zcash_pool_migration::engine::{
    MigrationTxKind, PoolMigrationRead, PoolMigrationWrite, ProveOutcome, prove_preparation,
    prove_transfer,
};
use zcash_pool_migration::satisfiability::{
    AdvanceConfig, DuenessTargets, ReorgSettleDepth, advance_migration,
};
use zcash_pool_migration::state::{AdvanceStep, StepKind};
use zcash_pool_migration::wallet::WalletMigrationProver;

use crate::{commands::select_account, config::get_wallet_network, data::get_db_paths};

use super::store::{migration_store, open_connection};

/// How far the chain must advance past a divergence before this command treats a displacement as
/// permanent. Caller policy that `zcash_pool_migration` deliberately ships no default for: the
/// right value tracks the chain's block spacing, and ten blocks is the same settle margin the
/// crate's own anchor-depth gate (`PROVABLE_ANCHOR_DEPTH`) uses at the 75-second block target.
const REORG_SETTLE_DEPTH: ReorgSettleDepth = ReorgSettleDepth::new(10);

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

        // The account's identity, its Orchard viewing key, and the two heights the migration's
        // dueness is judged against, read through a `WalletDb` view that is dropped before the
        // migration store borrows the same connection.
        let (account_id, fvk, scanned, tip) = {
            let wallet_db = WalletDb::from_connection(&mut conn, params, SystemClock, OsRng);
            let account = select_account(&wallet_db, self.account_id)?;
            let fvk = account
                .ufvk()
                .and_then(|ufvk| ufvk.orchard())
                .cloned()
                .ok_or_else(|| anyhow!("account has no Orchard viewing key"))?;
            // The SCANNED frontier is what every persisted verdict and every anchor lookup rests
            // on: a checkpoint only exists where the wallet has scanned. The chain tip is merely
            // this wallet's best estimate of where the chain has reached, and only re-orders (or
            // protectively withholds) work the scanned frontier already justifies.
            let scanned = wallet_db
                .block_fully_scanned()
                .map_err(|e| anyhow!("wallet read failed: {e:?}"))?
                .ok_or_else(|| anyhow!("wallet has not scanned any blocks yet"))?
                .block_height();
            let tip = wallet_db
                .chain_height()
                .map_err(|e| anyhow!("wallet read failed: {e:?}"))?
                .ok_or_else(|| anyhow!("wallet is not synced"))?;
            (account.id(), fvk, scanned, tip)
        };
        // Both heights carry the engine's TARGET convention: the height of the next block a
        // transaction could be mined in.
        let targets = DuenessTargets::new(scanned + 1, tip + 1);

        let mut rng = OsRng;
        let config = AdvanceConfig::new(REORG_SETTLE_DEPTH);

        // `advance_migration` plans the next step, verifies it against the store's satisfiability
        // oracle, and persists every determination it makes along the way -- so the step it
        // returns is one this wallet can actually act on.
        let (advance, mut state) = {
            let mut store = migration_store(params, &mut conn, account_id)?;
            let Some(mut state) = store.get_migration()? else {
                println!("No migration in progress.");
                return Ok(());
            };
            let advance = advance_migration(&mut store, &mut state, targets, &config, &mut rng)?;
            (advance, state)
        };

        match advance.step() {
            AdvanceStep::Prove { transactions } => {
                // The step names the WHOLE currently provable set: proving emits nothing a
                // network observer can see, so there is no reason to space it out. Each proof is
                // taken with the wallet borrowed mutably (witness resolution caches into the
                // commitment tree) and then persisted through the store, which needs the same
                // connection -- hence the alternating scopes.
                for target in transactions {
                    let id = target.id();
                    let outcome = {
                        let mut wallet_db =
                            WalletDb::from_connection(&mut conn, params, SystemClock, OsRng);
                        let mut prover =
                            WalletMigrationProver::new(&mut wallet_db, account_id, fvk.clone());
                        match target.kind() {
                            MigrationTxKind::Transfer { .. } => prove_transfer(
                                &params,
                                &mut prover,
                                &mut state,
                                id,
                                scanned,
                                &mut rng,
                            ),
                            // A preparation carries no drawn anchor boundary of its own (it
                            // anchors to its already-mined dependencies), so the caller picks the
                            // checkpoint; the scanned frontier is always valid, since the
                            // dependencies are confirmed mined at or below it by the time this
                            // step is offered.
                            MigrationTxKind::Preparation { .. } => {
                                prove_preparation(&mut prover, &mut state, id, scanned)
                            }
                        }
                        .map_err(|e| anyhow!("proving transaction {} failed: {e}", u32::from(id)))?
                    };

                    let mut store = migration_store(params, &mut conn, account_id)?;
                    match outcome {
                        ProveOutcome::Proved(proven) => {
                            store.store_proved_transaction(&mut state, proven)?;
                            println!("Proved transaction {}.", u32::from(id));
                        }
                        ProveOutcome::NotYetProvable => {
                            // Nothing was concluded, but a proving-time anchor re-draw may have
                            // been recorded on the way; persisting it costs one write and saves
                            // re-deriving it.
                            store.replace_migration(&state)?;
                            println!(
                                "Transaction {} is not provable yet: an input it spends is not \
                                 among the account's unspent notes, and the wallet has not \
                                 scanned past every dependency's mined height. Sync further and \
                                 re-run.",
                                u32::from(id)
                            );
                        }
                        ProveOutcome::MarkedUnsatisfiable { replan_required } => {
                            store.replace_migration(&state)?;
                            println!(
                                "Transaction {} can never mine: an input it spends was seen spent \
                                 elsewhere. It is marked unsatisfiable, along with everything \
                                 stranded behind it.",
                                u32::from(id)
                            );
                            if replan_required {
                                println!(
                                    "Enough planned value is now unsatisfiable that the migration \
                                     must be re-planned; the next `migration advance` will say so."
                                );
                            }
                        }
                    }
                }
            }
            AdvanceStep::Broadcast { id } => {
                println!(
                    "Transaction {} is proved and due to broadcast, but broadcasting isn't wired \
                     up in this command yet: it needs a lightwalletd client alongside \
                     `PoolMigrations::take_transaction_for_broadcast`, which extracts the \
                     finalized transaction and records it wallet-side. Re-run `migration advance` \
                     once that lands, or `migration status` to check state anytime.",
                    u32::from(*id)
                );
            }
            AdvanceStep::Rebuild { id } => {
                println!(
                    "Transfer {} expired before mining and needs to be rebuilt with a fresh \
                     anchor and signed anew -- not implemented in this command yet (rebuilding \
                     needs the account's spend authority, the same as `migration commit`).",
                    u32::from(*id)
                );
            }
            AdvanceStep::Replan => {
                println!(
                    "Too much of this migration's planned value can never mine, so it must be \
                     re-planned: mark it superseded and plan a new migration over the remaining \
                     balance. Superseding isn't wired up in this command yet."
                );
            }
            AdvanceStep::Reevaluate => {
                println!(
                    "A node rejected a broadcast of one of this migration's transactions, and \
                     this wallet hasn't scanned far enough to say why. Sync to at least the tip \
                     that node reported, then re-run `migration advance`."
                );
            }
            AdvanceStep::Waiting => {
                println!("Waiting on dependencies or a scheduled height. Nothing to do now.");
            }
            AdvanceStep::Complete => {
                println!("Migration complete.");
            }
        }

        // The outlook: what the migration holds once the step above is executed. Advisory -- the
        // height is a floor, and the `migration advance` run that reaches it decides (and may
        // displace) the step for itself.
        if let Some((height, kind)) = advance.next() {
            let what = match kind {
                StepKind::Prove => "proving",
                StepKind::Broadcast => "a broadcast",
                StepKind::Rebuild => "an expired transfer's rebuild",
                StepKind::Replan => "a re-plan",
                StepKind::Reevaluate => "a re-evaluation after syncing",
                StepKind::Waiting => "more waiting",
                StepKind::Complete => "nothing further",
            };
            println!("Outlook: {what}, from target height {height}.");
        }

        Ok(())
    }
}
