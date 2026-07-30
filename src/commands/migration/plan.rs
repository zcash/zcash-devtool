use anyhow::anyhow;
use clap::Args;
use rand::rngs::OsRng;
use uuid::Uuid;

use zcash_client_backend::data_api::{
    Account as _, InputSource, WalletRead, wallet::TargetHeight,
    wallet::input_selection::LockFilter,
};
use zcash_client_sqlite::{WalletDb, util::SystemClock};
use zcash_pool_migration::{
    engine::{MigrationBackend, plan_migration},
    scheduling::SchedulingParams,
};
use zcash_protocol::ShieldedPool;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;

use crate::{commands::select_account, config::get_wallet_network, data::get_db_paths};

use super::store::open_connection;

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

    fn spendable_orchard_note_values(&self) -> Result<Vec<Zatoshis>, Self::Error> {
        let tip = self
            .wallet
            .chain_height()
            .map_err(|_| anyhow!("wallet read failed"))?
            .ok_or_else(|| anyhow!("wallet is not synced"))?;
        let target = TargetHeight::from(u32::from(tip) + 1);
        let received = self
            .wallet
            .select_unspent_notes(
                self.account,
                &[ShieldedPool::Orchard],
                target,
                &[],
                LockFilter::Unfiltered,
            )
            .map_err(|_| anyhow!("note selection failed"))?;
        received
            .orchard()
            .iter()
            .map(|rn| {
                Zatoshis::from_u64(rn.note().value().inner())
                    .map_err(|e| anyhow!("note value out of range: {e}"))
            })
            .collect()
    }

    fn chain_tip_height(&self) -> Result<BlockHeight, Self::Error> {
        self.wallet
            .chain_height()
            .map_err(|_| anyhow!("wallet read failed"))?
            .ok_or_else(|| anyhow!("wallet is not synced"))
    }

    fn scheduling_params(&self) -> SchedulingParams {
        SchedulingParams::new_with_default_distributions(self.wallet.anchor_retention_interval())
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
        let plan = plan_migration(&params, &backend, &mut rng).map_err(|e| anyhow!("{e}"))?;

        println!("Note split:");
        println!("  Crossing values: {:?}", plan.crossing_values());
        println!("Funding notes ({}):", plan.funding_notes().len());
        for (i, value) in plan.funding_notes().iter().enumerate() {
            println!("  [{i}] {} zatoshi", value.into_u64());
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
