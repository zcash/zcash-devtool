use std::fs;

use anyhow::anyhow;
use clap::Args;
use rand::rngs::OsRng;
use secrecy::ExposeSecret;
use uuid::Uuid;

use zcash_client_backend::data_api::{Account as _, WalletRead};
use zcash_client_sqlite::{WalletDb, util::SystemClock};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_pool_migration_backend::engine::{build_preparation_unsigned, commit_preparation, plan_migration};
use zcash_pool_migration_backend::wallet::WalletMigration;

use crate::{commands::select_account, config::WalletConfig, data::get_db_paths};

use super::store::{InMemoryStore, load_migration, open_connection, persist_migration, prep_fee_zatoshi};

/// Options accepted for the `migration commit` command.
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// The UUID of the account to commit a migration for
    account_id: Option<Uuid>,

    /// age identity file to decrypt the mnemonic phrase with
    #[arg(short, long)]
    identity: String,

    /// Build the preparation for an EXTERNAL signer (e.g. Keystone) instead of signing
    /// in-process: leaves the transactions unsigned in the persisted state, and additionally
    /// writes each one to `<wallet-dir>/unsigned-pczts/<id>.pczt` for `pczt to-qr-batch`.
    #[arg(long)]
    external: bool,
}

impl Command {
    pub(crate) fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let mut config = WalletConfig::read(wallet_dir.as_ref())?;
        let params = config.network();
        let (_, db_path) = get_db_paths(wallet_dir.as_ref());
        let mut conn = open_connection(&db_path)?;

        if let Some(existing) = load_migration(&mut conn)? {
            if !existing.is_terminal() {
                return Err(anyhow!(
                    "a migration is already in progress (status: {}); use `migration status` \
                     or `migration advance`, not `commit`",
                    existing.status.as_ref()
                ));
            }
        }

        let identities = age::IdentityFile::from_file(self.identity)?.into_identities()?;
        let seed = config
            .decrypt_seed(identities.iter().map(|i| i.as_ref() as _))?
            .ok_or_else(|| anyhow!("Seed must be present to commit a migration"))?;

        let mut wallet_db = WalletDb::from_connection(&mut conn, params.clone(), SystemClock, OsRng);
        let account = select_account(&wallet_db, self.account_id)?;
        let derivation = account
            .source()
            .key_derivation()
            .ok_or_else(|| anyhow!("Cannot commit a migration for a view-only account"))?;
        let usk = UnifiedSpendingKey::from_seed(&params, seed.expose_secret(), derivation.account_index())
            .map_err(|e| anyhow!("{e:?}"))?;
        let account_id = account.id();

        let target_height = wallet_db
            .chain_height()
            .map_err(|e| anyhow!("wallet read failed: {e:?}"))?
            .ok_or_else(|| anyhow!("wallet is not synced"))?;
        let target_height = u32::from(target_height) + 1;

        let mut migration =
            WalletMigration::new(&mut wallet_db, account_id, usk, InMemoryStore::default());
        let mut rng = OsRng;
        let plan = plan_migration(&migration, prep_fee_zatoshi(), &mut rng)
            .map_err(|e| anyhow!("{e}"))?;

        println!(
            "Committing migration: {} funding note(s), {} preparation layer(s), {} preparation transaction(s)",
            plan.funding_notes().len(),
            plan.preparation().layer_count(),
            plan.preparation().transaction_count(),
        );

        let (state, unsigned) = if self.external {
            let (state, unsigned) =
                build_preparation_unsigned(&params, target_height, &mut migration, &plan, &mut rng)
                    .map_err(|e| anyhow!("{e}"))?;
            (state, unsigned)
        } else {
            let state = commit_preparation(&params, target_height, &mut migration, &plan, &mut rng)
                .map_err(|e| anyhow!("{e}"))?;
            (state, Vec::new())
        };

        drop(wallet_db);
        persist_migration(&mut conn, &state)?;

        println!(
            "Migration committed: status={}, {} transaction(s) recorded",
            state.status.as_ref(),
            state.transactions.len()
        );

        if self.external {
            let out_dir = db_path
                .parent()
                .ok_or_else(|| anyhow!("wallet database path has no parent directory"))?
                .join("unsigned-pczts");
            fs::create_dir_all(&out_dir)?;
            println!("{} unsigned PCZT(s) for external signing:", unsigned.len());
            for tx in &unsigned {
                let path = out_dir.join(format!("{}.pczt", tx.id.0));
                fs::write(&path, &tx.pczt)?;
                println!("  {}", path.display());
            }
            println!(
                "Batch-QR them with: pczt to-qr-batch --pczt {}/*.pczt",
                out_dir.display()
            );
        }

        Ok(())
    }
}
