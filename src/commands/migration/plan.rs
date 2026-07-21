use anyhow::anyhow;
use clap::Args;
use rand::rngs::OsRng;
use uuid::Uuid;

use zcash_client_backend::data_api::{Account as _, InputSource, WalletRead, wallet::TargetHeight};
use zcash_client_sqlite::{WalletDb, util::SystemClock};
use zcash_pool_migration_backend::engine::{MigrationBackend, plan_migration};
use zcash_protocol::ShieldedPool;

use crate::{commands::select_account, config::get_wallet_network, data::get_db_paths};

use super::store::{open_connection, prep_fee_zatoshi};

/// Options accepted for the `migration plan` command.
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// The UUID of the account to preview a migration for
    account_id: Option<Uuid>,
}

/// A read-only [`MigrationBackend`] over a wallet, with no spending capability. `plan_migration`
/// is pure orchestration ("no cryptography, and nothing is built, signed, or persisted" per its
/// doc comment), so previewing a migration needs no spending key -- unlike `WalletMigration`,
/// which bundles one from construction for the commit path.
struct PlanBackend<'a, W: WalletRead + InputSource> {
    wallet: &'a W,
    account: <W as InputSource>::AccountId,
}

impl<'a, W> MigrationBackend for PlanBackend<'a, W>
where
    W: WalletRead + InputSource,
{
    type Error = anyhow::Error;

    fn spendable_orchard_note_values(&self) -> Result<Vec<u64>, Self::Error> {
        let tip = self
            .wallet
            .chain_height()
            .map_err(|_| anyhow!("wallet read failed"))?
            .ok_or_else(|| anyhow!("wallet is not synced"))?;
        let target = TargetHeight::from(u32::from(tip) + 1);
        let received = self
            .wallet
            .select_unspent_notes(self.account, &[ShieldedPool::Orchard], target, &[])
            .map_err(|_| anyhow!("note selection failed"))?;
        Ok(received
            .orchard()
            .iter()
            .map(|rn| rn.note().value().inner())
            .collect())
    }

    fn chain_tip_height(&self) -> Result<u32, Self::Error> {
        let tip = self
            .wallet
            .chain_height()
            .map_err(|_| anyhow!("wallet read failed"))?
            .ok_or_else(|| anyhow!("wallet is not synced"))?;
        Ok(u32::from(tip))
    }
}

impl Command {
    pub(crate) fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let params = get_wallet_network(wallet_dir.as_ref())?;
        let (_, db_path) = get_db_paths(wallet_dir.as_ref());
        let mut conn = open_connection(&db_path)?;
        let wallet_db = WalletDb::from_connection(&mut conn, params, SystemClock, OsRng);
        let account = select_account(&wallet_db, self.account_id)?;
        let backend = PlanBackend {
            wallet: &wallet_db,
            account: account.id(),
        };

        let mut rng = OsRng;
        let plan = plan_migration(&backend, prep_fee_zatoshi(), &mut rng)
            .map_err(|e| anyhow!("{e}"))?;

        println!("Note split:");
        println!("  Crossing values: {:?}", plan.note_split().crossing_values());
        println!(
            "  Note fee buffer: {} zatoshi/note",
            plan.note_split().note_fee_buffer_zatoshi()
        );
        if let Some(change) = plan.note_split().change() {
            println!("  Change (left in Orchard): {change} zatoshi");
        }
        println!("Funding notes ({}):", plan.funding_notes().len());
        for (i, value) in plan.funding_notes().iter().enumerate() {
            println!("  [{i}] {value} zatoshi");
        }
        println!(
            "Preparation: {} layer(s), {} transaction(s)",
            plan.preparation().layer_count(),
            plan.preparation().transaction_count()
        );
        println!("Transfer schedule ({} entries):", plan.schedule().len());
        for (i, s) in plan.schedule().iter().enumerate() {
            println!(
                "  [{i}] broadcast at {}, expiry {}",
                s.broadcast_height(),
                s.expiry_height()
            );
        }

        Ok(())
    }
}
