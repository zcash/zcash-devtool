use std::fs;

use anyhow::anyhow;
use clap::Args;
use rand::rngs::OsRng;
use secrecy::ExposeSecret;
use uuid::Uuid;

use zcash_client_backend::data_api::{Account as _, WalletRead};
use zcash_client_sqlite::{WalletDb, util::SystemClock};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_pool_migration::engine::{
    CommitError, build_preparation_unsigned, commit_preparation, plan_migration,
};
use zcash_pool_migration::satisfiability::ReplanThreshold;
use zcash_pool_migration::wallet::WalletMigration;

use crate::{commands::select_account, config::WalletConfig, data::get_db_paths};

use super::store::{InMemoryStore, load_migration, open_connection, persist_migration};

/// Options accepted for the `migration commit` command.
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// The UUID of the account to commit a migration for
    account_id: Option<Uuid>,

    /// age identity file to decrypt the mnemonic phrase with
    #[arg(short, long)]
    identity: String,

    /// Build the migration for an EXTERNAL signer (e.g. Keystone) instead of signing
    /// in-process: leaves every transaction unsigned in the persisted state, and additionally
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

        // The account's identity, viewing key, and derivation path, read through a `WalletDb`
        // view that is dropped before the migration store borrows the same connection.
        // `PoolMigrations` is account-scoped, so the account must be resolved before loading.
        let (account_id, ufvk, account_index) = {
            let wallet_db = WalletDb::from_connection(&mut conn, params, SystemClock, OsRng);
            let account = select_account(&wallet_db, self.account_id)?;
            let account_index = account
                .source()
                .key_derivation()
                .ok_or_else(|| anyhow!("Cannot commit a migration for a view-only account"))?
                .account_index();
            // The key the account's notes were received with: the engine derives the Orchard
            // full viewing key it plans, builds and stores against from this, and checks the
            // spend authority passed to `commit_preparation` against it.
            let ufvk = account.ufvk().cloned().ok_or_else(|| {
                anyhow!("Cannot commit a migration for an account with no unified full viewing key")
            })?;
            (account.id(), ufvk, account_index)
        };
        let loaded = load_migration(params, &conn, account_id)?;

        let identities = age::IdentityFile::from_file(self.identity)?.into_identities()?;
        let seed = config
            .decrypt_seed(identities.iter().map(|i| i.as_ref() as _))?
            .ok_or_else(|| anyhow!("Seed must be present to commit a migration"))?;
        let usk = UnifiedSpendingKey::from_seed(&params, seed.expose_secret(), account_index)
            .map_err(|e| anyhow!("{e:?}"))?;

        let map_commit_err = |e: CommitError<_>| match e {
            CommitError::MigrationInProgress => anyhow!(
                "a migration is already in progress; use `migration status` or `migration \
                 advance`, not `commit`"
            ),
            other => anyhow!("{other}"),
        };

        // Fail fast on a leftover output dir BEFORE building anything: `fs::rename` below can't
        // replace a non-empty directory (so a re-run would die only after all the build work),
        // and a leftover-but-empty dir would let a previous run's stale `<id>.pczt` files mix
        // with this run's in the suggested `*.pczt` glob.
        let external_out_dir = if self.external {
            let out_dir = db_path
                .parent()
                .ok_or_else(|| anyhow!("wallet database path has no parent directory"))?
                .join("unsigned-pczts");
            if out_dir.exists() {
                return Err(anyhow!(
                    "{} already exists (from a previous `migration commit --external`?); move \
                     or delete it first so this run's PCZTs can't mix with stale ones",
                    out_dir.display()
                ));
            }
            Some(out_dir)
        } else {
            None
        };

        let mut rng = OsRng;
        let (state, unsigned) = {
            let wallet_db = WalletDb::from_connection(&mut conn, params, SystemClock, OsRng);

            let target_height = wallet_db
                .chain_height()
                .map_err(|e| anyhow!("wallet read failed: {e:?}"))?
                .ok_or_else(|| anyhow!("wallet is not synced"))?
                + 1;

            let mut migration =
                WalletMigration::new(&wallet_db, account_id, ufvk, InMemoryStore::from(loaded));
            let plan = plan_migration(&params, &migration, &mut rng).map_err(|e| anyhow!("{e}"))?;

            println!(
                "Committing migration: {} funding note(s), {} preparation layer(s), {} preparation transaction(s)",
                plan.funding_notes().len(),
                plan.preparation().layer_count(),
                plan.preparation().transaction_count(),
            );

            if self.external {
                build_preparation_unsigned(
                    &params,
                    target_height,
                    &mut migration,
                    &plan,
                    &mut rng,
                    ReplanThreshold::DEFAULT,
                )
                .map_err(map_commit_err)?
            } else {
                // The spend authority is the CALL's, not the adapter's: `WalletMigration` holds
                // only viewing authority, and the Orchard spending key is live just for this
                // call (checked against the account's viewing key before anything is built).
                let state = commit_preparation(
                    &params,
                    target_height,
                    &mut migration,
                    usk.orchard(),
                    &plan,
                    &mut rng,
                    ReplanThreshold::DEFAULT,
                )
                .map_err(map_commit_err)?;
                (state, Vec::new())
            }
        };

        if let Some(out_dir) = &external_out_dir {
            let staged_out_dir =
                out_dir.with_file_name(format!(".unsigned-pczts-{}.tmp", Uuid::new_v4()));
            fs::create_dir(&staged_out_dir)?;
            println!("{} unsigned PCZT(s) for external signing:", unsigned.len());
            let write_all = || -> anyhow::Result<()> {
                for tx in unsigned {
                    let (id, pczt) = tx.into_parts();
                    let path = staged_out_dir.join(format!("{}.pczt", u32::from(id)));
                    fs::write(&path, &pczt)?;
                }
                // Do not persist a migration that needs external signatures until every PCZT has
                // been written successfully. Otherwise a full disk or interrupted write can leave
                // the wallet permanently reporting an in-progress migration whose signing material
                // does not exist. The staged directory also ensures callers never see a partial set.
                fs::rename(&staged_out_dir, out_dir)?;
                Ok(())
            };
            if let Err(e) = write_all() {
                // Best-effort: don't strand the staged temp dir next to the wallet on failure.
                let _ = fs::remove_dir_all(&staged_out_dir);
                return Err(e);
            }
            for entry in fs::read_dir(out_dir)? {
                println!("  {}", entry?.path().display());
            }
            println!(
                "Batch-QR them with: pczt to-qr-batch --pczt {}/*.pczt",
                out_dir.display()
            );
        }

        persist_migration(params, &mut conn, account_id, &state)?;

        println!(
            "Migration committed: status={}, {} transaction(s) recorded",
            state.status().as_ref(),
            state.transactions().len()
        );

        if self.external {
            println!(
                "External signing material is ready; record the PCZT paths above before signing."
            );
        }

        Ok(())
    }
}
