use std::convert::Infallible;
use std::path::Path;

use rusqlite::Connection;

use zcash_pool_migration_backend::engine::{
    MigrationState, MigrationTxId, MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
};
use zcash_pool_migration_sqlite::orchard_ironwood::PoolMigrations;

/// A throwaway in-memory `PoolMigrationRead`/`Write`, used only for the duration of one engine
/// call. `WalletDb::from_connection` (for the engine's wallet access) and `PoolMigrations` (the
/// real SQLite store) both need to borrow the wallet's connection, so they are never constructed
/// at once: this decouples the engine's internal store parameter from persistence, which happens
/// as an explicit load-before/save-after wrapping each call. The engine's own
/// `MigrationInProgress` guard reads through this store too, so it must be SEEDED with whatever
/// is actually persisted, not left empty, or a genuinely in-progress migration would silently be
/// overwritten. Mirrors zallet's `InMemoryStore` (zcash/zallet#623, `zallet_core::migrate`).
#[derive(Default)]
pub(crate) struct InMemoryStore {
    state: Option<MigrationState>,
}

impl From<Option<MigrationState>> for InMemoryStore {
    fn from(state: Option<MigrationState>) -> Self {
        Self { state }
    }
}

impl PoolMigrationRead for InMemoryStore {
    type Error = Infallible;

    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
        Ok(self.state.clone())
    }
}

impl PoolMigrationWrite for InMemoryStore {
    fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
        self.state = Some(state.clone());
        Ok(())
    }

    fn update_transaction(
        &mut self,
        id: MigrationTxId,
        tx_state: MigrationTxState,
    ) -> Result<(), Self::Error> {
        if let Some(state) = &mut self.state {
            state.set_transaction_state(id, tx_state);
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
    zcash_pool_migration_sqlite::orchard_ironwood::init_migration_tables(&conn)?;
    Ok(conn)
}

/// Loads the persisted migration from the real SQLite store over `conn`.
pub(crate) fn load_migration(conn: &mut Connection) -> anyhow::Result<Option<MigrationState>> {
    Ok(PoolMigrations::new(&mut *conn).get_migration()?)
}

/// Persists a migration to the real SQLite store over `conn`, replacing any existing one.
pub(crate) fn persist_migration(
    conn: &mut Connection,
    state: &MigrationState,
) -> anyhow::Result<()> {
    PoolMigrations::new(&mut *conn).replace_migration(state)?;
    Ok(())
}
