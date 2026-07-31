use std::convert::Infallible;
use std::path::Path;

use rusqlite::Connection;

use zcash_client_sqlite::AccountUuid;
use zcash_client_sqlite::pool_migration::orchard_ironwood::PoolMigrations;
use zcash_pool_migration::engine::{
    MigrationState, MigrationTransferId, MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
};

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
        _id: MigrationTransferId,
        _tx_state: MigrationTxState,
    ) -> Result<(), Self::Error> {
        // The engine only ever drives this store through `replace_migration` with the whole
        // updated state (checked directly against zcash_pool_migration::engine -- every
        // internal call site persists via `replace_migration`, never `update_transaction`; the
        // latter exists on the trait only for a real store's finer-grained persistence, e.g.
        // zcash_client_sqlite's PoolMigrations). This store is a scratch mirror for the duration
        // of one engine call, so there is nothing to do here.
        Ok(())
    }
}

/// Opens the wallet's SQLite connection directly (not via `WalletDb::for_path`), so migration
/// commands can construct both a `WalletDb` view (for the engine) and a `PoolMigrations` view
/// (for persistence) over the same connection, sequentially -- never both at once, avoiding an
/// overlapping-borrow conflict. The migration tables are created by `zcash_client_sqlite`'s own
/// schema migrations now (`orchard_ironwood_migration_tables`), so nothing extra needs to run
/// here -- the caller is expected to have already opened/migrated the wallet DB through the
/// normal `WalletDb` path before reaching for this connection.
pub(crate) fn open_connection(db_path: &Path) -> anyhow::Result<Connection> {
    let conn = Connection::open(db_path)?;
    rusqlite::vtab::array::load_module(&conn)?;
    Ok(conn)
}

/// Loads the persisted migration from the real SQLite store over `conn`, scoped to `account`.
/// `PoolMigrations` is now account-scoped (it resolves `account` to its `accounts` row up front),
/// so the caller must know the account before it can load a migration -- unlike before this pin,
/// when the store had no notion of which account it belonged to.
pub(crate) fn load_migration(
    conn: &Connection,
    account: AccountUuid,
) -> anyhow::Result<Option<MigrationState>> {
    Ok(PoolMigrations::for_account(conn, account)?.get_migration()?)
}

/// Persists a migration to the real SQLite store over `conn`, scoped to `account`, replacing any
/// existing one.
pub(crate) fn persist_migration(
    conn: &mut Connection,
    account: AccountUuid,
    state: &MigrationState,
) -> anyhow::Result<()> {
    PoolMigrations::for_account(&mut *conn, account)?.replace_migration(state)?;
    Ok(())
}
