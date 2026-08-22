use std::fmt;
use std::path::Path;

use rusqlite::Connection;

use zcash_client_sqlite::AccountUuid;
use zcash_client_sqlite::pool_migration::orchard_ironwood::PoolMigrations;
use zcash_client_sqlite::util::SystemClock;
use zcash_pool_migration::engine::{
    MigrationState, MigrationTransaction, MigrationTransferId, MigrationTxState, PoolMigrationRead,
    PoolMigrationWrite, ProvedTransaction,
};
use zcash_pool_migration::satisfiability::{ReorgSettleDepth, StepSatisfiability};
use zcash_protocol::TxId;
use zcash_protocol::consensus::{BlockHeight, Parameters};

/// Why the commit-path scratch store could not answer.
#[derive(Debug)]
pub(crate) enum ScratchStoreError {
    /// A satisfiability question was put to the scratch store. The oracle
    /// [`PoolMigrationRead::check_step_satisfiability`] answers is the wallet's live view of
    /// whether a pre-signed transaction's inputs still exist unspent, which only the real SQLite
    /// store (with the wallet's notes and scan frontier) can supply; a scratch mirror holding
    /// nothing but a `MigrationState` has no evidence to answer from. Only the drive API
    /// (`advance_migration`, and the `migration advance` command that calls it) asks this, and it
    /// runs against the real store.
    NoChainView,
}

impl fmt::Display for ScratchStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScratchStoreError::NoChainView => f.write_str(
                "the commit-path scratch migration store holds no chain view, so it cannot judge \
                 whether a transaction's inputs are still spendable",
            ),
        }
    }
}

impl std::error::Error for ScratchStoreError {}

/// A throwaway in-memory `PoolMigrationRead`/`Write`, used only for the duration of one engine
/// call. `WalletDb::from_connection` (for the engine's wallet access) and `PoolMigrations` (the
/// real SQLite store) both need to borrow the wallet's connection, so they are never constructed
/// at once: this decouples the engine's internal store parameter from persistence, which happens
/// as an explicit load-before/save-after wrapping each call. The engine's own
/// `MigrationInProgress` guard reads through this store too, so it must be SEEDED with whatever
/// is actually persisted, not left empty, or a genuinely in-progress migration would silently be
/// overwritten. Mirrors zallet's `InMemoryStore` (zcash/zallet#623, `zallet_core::migrate`).
///
/// This is the COMMIT path's store only. Committing asks a store to report the migration in
/// progress and to persist the one it builds, and nothing else; the drive path, which does need a
/// chain view (to prove, to sweep in-flight transactions, and to put candidates to the
/// satisfiability oracle), uses [`migration_store`] instead.
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
    type Error = ScratchStoreError;

    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
        Ok(self.state.clone())
    }

    fn check_step_satisfiability(
        &self,
        _tx: &MigrationTransaction,
        _settle: ReorgSettleDepth,
    ) -> Result<StepSatisfiability, Self::Error> {
        Err(ScratchStoreError::NoChainView)
    }

    fn mined_height(&self, _txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
        // Inclusion is what a wallet's scan discovers, and this store has none. The
        // `WalletMigration` adapter answers this from the wallet rather than delegating to its
        // store, so nothing reaches here on the commit path; a caller that did ask gets the same
        // honest refusal as the satisfiability oracle rather than a fabricated "not mined".
        Err(ScratchStoreError::NoChainView)
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

    fn store_proved_transaction(
        &mut self,
        state: &mut MigrationState,
        proven: ProvedTransaction,
    ) -> Result<(), Self::Error> {
        // The contract's whole content for a store with no wallet tables of its own: record the
        // proof on the state, then persist that state.
        proven.apply(state);
        self.replace_migration(state)
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

/// The real SQLite pool-migration store over `conn`, scoped to `account`.
///
/// `PoolMigrations` is account-scoped (it resolves `account` to its `accounts` row up front), so
/// the caller must know the account before it can reach a migration. The network parameters and
/// clock are what the store's wallet-side records need, and are required for any WRITE through
/// it; the returned store borrows `conn` mutably, so a `WalletDb` over the same connection must
/// be dropped first and re-created afterwards.
pub(crate) fn migration_store<P: Parameters>(
    params: P,
    conn: &mut Connection,
    account: AccountUuid,
) -> anyhow::Result<PoolMigrations<&mut Connection, P, SystemClock>> {
    Ok(PoolMigrations::for_account(
        params,
        SystemClock,
        conn,
        account,
    )?)
}

/// Loads the persisted migration from the real SQLite store over `conn`, scoped to `account`.
///
/// A shared borrow: reading a migration writes nothing, so a caller that only reports on one
/// never has to hand the store write access.
pub(crate) fn load_migration<P: Parameters>(
    params: P,
    conn: &Connection,
    account: AccountUuid,
) -> anyhow::Result<Option<MigrationState>> {
    Ok(PoolMigrations::for_account(params, SystemClock, conn, account)?.get_migration()?)
}

/// Persists a migration to the real SQLite store over `conn`, scoped to `account`, replacing any
/// existing one.
pub(crate) fn persist_migration<P: Parameters>(
    params: P,
    conn: &mut Connection,
    account: AccountUuid,
    state: &MigrationState,
) -> anyhow::Result<()> {
    migration_store(params, conn, account)?.replace_migration(state)?;
    Ok(())
}
