use std::convert::Infallible;
use std::path::Path;

use rusqlite::Connection;

use zcash_pool_migration_backend::engine::{
    MigrationState, MigrationTxId, MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
};
use zcash_pool_migration_backend::note_splitting::{FeePolicy, Zip317FeePolicy};
use zcash_pool_migration_backend::preparation::PREP_TX_ACTIONS;
use zcash_pool_migration_sqlite::PoolMigrations;

/// A throwaway in-memory `PoolMigrationRead`/`Write`, used only for the duration of one engine
/// call. `WalletDb::from_connection` (for the engine's wallet access) and `PoolMigrations` (the
/// real SQLite store) both need to borrow the wallet's connection, so they are never constructed
/// at once: this decouples the engine's internal store parameter from persistence, which happens
/// as an explicit load-before/save-after wrapping each call. Mirrors zallet's `InMemoryStore`
/// (zcash/zallet#623, `zallet_core::migrate`).
#[derive(Default)]
pub(crate) struct InMemoryStore {
    state: Option<MigrationState>,
}

impl PoolMigrationRead for InMemoryStore {
    type Error = Infallible;

    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
        Ok(self.state.clone())
    }
}

impl PoolMigrationWrite for InMemoryStore {
    fn put_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
        self.state = Some(state.clone());
        Ok(())
    }

    fn update_transaction(
        &mut self,
        id: MigrationTxId,
        tx_state: MigrationTxState,
    ) -> Result<(), Self::Error> {
        if let Some(state) = &mut self.state
            && let Some(tx) = state.transactions.iter_mut().find(|t| t.id == id)
        {
            tx.state = tx_state;
        }
        Ok(())
    }
}

/// Opens the wallet's SQLite connection directly (not via `WalletDb::for_path`), so migration
/// commands can construct both a `WalletDb` view (for the engine) and a `PoolMigrations` view
/// (for persistence) over the same connection, sequentially -- never both at once, avoiding an
/// overlapping-borrow conflict. Ensures the migration tables exist; idempotent, and normally a
/// no-op since `zcash_client_sqlite`'s own schema migration already created them.
pub(crate) fn open_connection(db_path: &Path) -> anyhow::Result<Connection> {
    let conn = Connection::open(db_path)?;
    rusqlite::vtab::array::load_module(&conn)?;
    zcash_pool_migration_sqlite::init_migration_tables(&conn)?;
    Ok(conn)
}

/// The ZIP-317 fee reserved per note-preparation transaction (a padded 16-action transaction),
/// which the note split and the preparation planner both reserve. Matches zallet's
/// `prep_fee_zatoshi` (zcash/zallet#623).
pub(crate) fn prep_fee_zatoshi() -> u64 {
    PREP_TX_ACTIONS as u64 * Zip317FeePolicy.marginal_fee_zatoshi()
}

/// Loads the persisted migration from the real SQLite store over `conn`.
pub(crate) fn load_migration(conn: &mut Connection) -> anyhow::Result<Option<MigrationState>> {
    Ok(PoolMigrations::new(&mut *conn).get_migration()?)
}

/// Persists a migration to the real SQLite store over `conn`, replacing any existing one.
pub(crate) fn persist_migration(conn: &mut Connection, state: &MigrationState) -> anyhow::Result<()> {
    PoolMigrations::new(&mut *conn).put_migration(state)?;
    Ok(())
}
