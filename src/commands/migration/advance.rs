use anyhow::anyhow;
use clap::Args;
use rand::rngs::OsRng;
use secrecy::ExposeSecret;
use uuid::Uuid;

use zcash_client_backend::data_api::{Account as _, WalletRead};
use zcash_client_sqlite::{WalletDb, util::SystemClock};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_pool_migration_backend::engine::{commit_pending_preparation, commit_transfers};
use zcash_pool_migration_backend::state::AdvanceStep;
use zcash_pool_migration_backend::wallet::WalletMigration;

use crate::{commands::select_account, config::WalletConfig, data::get_db_paths};

use super::store::{InMemoryStore, load_migration, open_connection, persist_migration};

/// Options accepted for the `migration advance` command.
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// The UUID of the account the migration belongs to
    account_id: Option<Uuid>,

    /// age identity file to decrypt the mnemonic phrase with
    #[arg(short, long)]
    identity: String,
}

impl Command {
    pub(crate) fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let mut config = WalletConfig::read(wallet_dir.as_ref())?;
        let params = config.network();
        let (_, db_path) = get_db_paths(wallet_dir.as_ref());
        let mut conn = open_connection(&db_path)?;

        let Some(mut state) = load_migration(&mut conn)? else {
            println!("No migration in progress.");
            return Ok(());
        };

        let identities = age::IdentityFile::from_file(self.identity)?.into_identities()?;
        let seed = config
            .decrypt_seed(identities.iter().map(|i| i.as_ref() as _))?
            .ok_or_else(|| anyhow!("Seed must be present to advance a migration"))?;

        // A short-lived WalletDb borrows `conn` to look up the account; dropped before the loop
        // so `conn` is free again for the loop's own WalletDb/PoolMigrations borrows.
        let (account_id, usk) = {
            let wallet_db = WalletDb::from_connection(&mut conn, params.clone(), SystemClock, OsRng);
            let account = select_account(&wallet_db, self.account_id)?;
            let derivation = account
                .source()
                .key_derivation()
                .ok_or_else(|| anyhow!("Cannot advance a migration for a view-only account"))?;
            let usk =
                UnifiedSpendingKey::from_seed(&params, seed.expose_secret(), derivation.account_index())
                    .map_err(|e| anyhow!("{e:?}"))?;
            (account.id(), usk)
        };

        let target_height = {
            let wallet_db = WalletDb::from_connection(&mut conn, params.clone(), SystemClock, OsRng);
            let tip = wallet_db
                .chain_height()
                .map_err(|e| anyhow!("wallet read failed: {e:?}"))?
                .ok_or_else(|| anyhow!("wallet is not synced"))?;
            u32::from(tip) + 1
        };

        let mut rng = OsRng;
        loop {
            match state.next_step(target_height) {
                AdvanceStep::BuildPreparationLayer { layer } => {
                    println!("Building and signing preparation layer {layer}...");
                    let mut wallet_db =
                        WalletDb::from_connection(&mut conn, params.clone(), SystemClock, OsRng);
                    let mut migration = WalletMigration::new(
                        &mut wallet_db,
                        account_id,
                        usk.clone(),
                        InMemoryStore::from(state.clone()),
                    );
                    state = commit_pending_preparation(&params, target_height, &mut migration, &mut rng)
                        .map_err(|e| anyhow!("{e}"))?;
                    drop(wallet_db);
                    persist_migration(&mut conn, &state)?;
                }
                AdvanceStep::BuildTransfers => {
                    println!("Building and signing the transfers...");
                    let mut wallet_db =
                        WalletDb::from_connection(&mut conn, params.clone(), SystemClock, OsRng);
                    let mut migration = WalletMigration::new(
                        &mut wallet_db,
                        account_id,
                        usk.clone(),
                        InMemoryStore::from(state.clone()),
                    );
                    state = commit_transfers(&params, target_height, &mut migration, &mut rng)
                        .map_err(|e| anyhow!("{e}"))?;
                    drop(wallet_db);
                    persist_migration(&mut conn, &state)?;
                }
                AdvanceStep::Broadcast { id } => {
                    println!(
                        "Transaction {} is pre-signed and ready to prove and broadcast, but that \
                         step is not implemented yet: the crate deliberately re-anchors a \
                         transaction to a freshly drawn boundary at proving time (see \
                         `WalletMigration`'s `ANCHOR_CONFIRMATIONS` doc comment), and no \
                         crate-exposed helper for that anchor refresh exists yet -- not here, and \
                         not in zallet's own integration either. Stopping; re-run `migration \
                         advance` once that lands, or `migration status` to check the current \
                         state anytime.",
                        id.0
                    );
                    break;
                }
                AdvanceStep::Waiting => {
                    println!("Waiting on dependencies or a scheduled height. Nothing to build now.");
                    break;
                }
                AdvanceStep::Complete => {
                    println!("Migration complete.");
                    break;
                }
            }
        }

        Ok(())
    }
}
