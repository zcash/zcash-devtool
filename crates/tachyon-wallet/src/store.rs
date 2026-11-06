//! One SQLite writer lock covers selection and durable reservation of inputs.

use crate::{chain::Block, funding_balance::Snapshot, note::Receipt};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
use udon::field::Field;
use zcash_tachyon::{Anchor, EpochIndex, QrProfile, Tachygram, constants::EPOCH_SIZE, pasta::Fp};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub rpc_url: String,
    pub cookie_file: Option<PathBuf>,
    pub activation: u32,
    pub activation_hash: String,
    pub genesis: String,
    pub network_id: String,
    pub seed: [u8; 32],
    /// Missing on existing wallets, which retain their activation-based history.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub birthday_height: Option<u32>,
}

#[derive(Serialize, Deserialize)]
pub struct Pending {
    pub txid: String,
    pub raw: String,
    pub expiry: u32,
    pub source: String,
    pub receipt: Option<Receipt>,
}

pub struct StoredOperation {
    pub id: String,
    pub txid: String,
    pub request: serde_json::Value,
}

pub struct Store {
    conn: Connection,
}

/// Chain evidence access for proofs: tests may use an in-memory slice, while
/// production reads only the epochs it needs from SQLite and uses the proof
/// cache. Cached proofs are serialized with ragu's versioned wire format.
pub enum ChainData<'a> {
    Blocks(&'a [Block]),
    Store(&'a Store),
}

impl<'a> From<&'a [Block]> for ChainData<'a> {
    fn from(blocks: &'a [Block]) -> Self {
        Self::Blocks(blocks)
    }
}

impl<'a> From<&'a Vec<Block>> for ChainData<'a> {
    fn from(blocks: &'a Vec<Block>) -> Self {
        Self::Blocks(blocks)
    }
}

impl<'a> From<&'a Store> for ChainData<'a> {
    fn from(store: &'a Store) -> Self {
        Self::Store(store)
    }
}

impl<'a> From<&'a ChainData<'a>> for ChainData<'a> {
    fn from(chain: &'a ChainData<'a>) -> Self {
        match chain {
            Self::Blocks(blocks) => Self::Blocks(blocks),
            Self::Store(store) => Self::Store(store),
        }
    }
}

impl ChainData<'_> {
    pub fn tip(&self) -> Result<Block> {
        match self {
            Self::Blocks(blocks) => blocks.last().cloned().context("wallet has not synced"),
            Self::Store(store) => store.tip()?.context("wallet has not synced"),
        }
    }

    /// All blocks in `epoch`, plus the first block of the next epoch when the
    /// epoch has closed. Only this range is read, never the whole chain.
    pub fn epoch_blocks(&self, epoch: u32) -> Result<Vec<Block>> {
        match self {
            Self::Blocks(blocks) => Ok(blocks
                .iter()
                .filter(|block| block.epoch == epoch || block.epoch == epoch + 1)
                .cloned()
                .collect()),
            Self::Store(store) => {
                let activation = self.tip()?.activation_height;
                let start = activation
                    .checked_add(epoch.checked_mul(EPOCH_SIZE).context("epoch overflow")?)
                    .context("epoch height overflow")?;
                store.blocks_range(start, start.saturating_add(EPOCH_SIZE))
            }
        }
    }

    /// The stamp that created `cm`, its epoch and its preceding anchor.
    pub fn creation(&self, cm: Tachygram) -> Result<Option<(u32, Anchor, Vec<Tachygram>)>> {
        let id = hex::encode(Fp::from(cm).to_bytes());
        let blocks: Vec<Block> = match self {
            Self::Blocks(blocks) => blocks.to_vec(),
            Self::Store(store) => match store.tachygram_height(&id)? {
                Some(height) => store.block(height)?.into_iter().collect(),
                None => Vec::new(),
            },
        };
        for block in blocks {
            let mut cursor = block.entry()?;
            for stamp in &block.stamps {
                let members = stamp.members()?;
                if members.contains(&cm) {
                    return Ok(Some((block.epoch, cursor, members)));
                }
                cursor = cursor.next_stamp(EpochIndex::new(block.epoch), &stamp.commitment()?)?;
            }
        }
        Ok(None)
    }

    pub fn bucket_proof(
        &self,
        epoch: u32,
        profile: QrProfile,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        match self {
            Self::Blocks(_) => Ok(None),
            Self::Store(store) => store.bucket_proof(epoch, profile),
        }
    }

    pub fn put_bucket_proof(
        &self,
        epoch: u32,
        profile: QrProfile,
        pcd: &[u8],
        members: &[u8],
    ) -> Result<()> {
        match self {
            Self::Blocks(_) => Ok(()),
            Self::Store(store) => store.put_bucket_proof(epoch, profile, pcd, members),
        }
    }

    pub fn spendable_proof_bytes(&self, note_id: &str) -> Result<Option<Vec<u8>>> {
        match self {
            Self::Blocks(_) => Ok(None),
            Self::Store(store) => store.spendable_proof(note_id),
        }
    }

    pub fn put_spendable_proof_bytes(&self, note_id: &str, pcd: &[u8]) -> Result<()> {
        match self {
            Self::Blocks(_) => Ok(()),
            Self::Store(store) => store.put_spendable_proof(note_id, pcd),
        }
    }
}

/// Never overwrite receipt files, and create private data with restrictive permissions.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .context("cannot create private file (it may already exist)")?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

impl Store {
    pub fn open(dir: &Path, initialize: bool) -> Result<Self> {
        if initialize && !dir.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(dir)?;
            }
            #[cfg(not(unix))]
            fs::create_dir_all(dir)?;
        }
        let metadata = fs::symlink_metadata(dir).context("wallet does not exist; run init")?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "wallet must be a real directory"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                metadata.permissions().mode() & 0o077 == 0,
                "wallet directory must be private (chmod 700)"
            );
        }
        let path = dir.join("tachyon.sqlite");
        if initialize {
            write_private(&path, &[])?;
        }
        ensure!(
            fs::symlink_metadata(&path)?.is_file(),
            "wallet database must be a regular file"
        );
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        conn.busy_timeout(Duration::from_secs(1))?;
        conn.execute_batch("PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; BEGIN IMMEDIATE;")?;
        if initialize {
            conn.execute_batch(
                "CREATE TABLE config (id INTEGER PRIMARY KEY CHECK(id=1), data TEXT NOT NULL);
                CREATE TABLE blocks (height INTEGER PRIMARY KEY, data TEXT NOT NULL);
                CREATE TABLE notes (id TEXT PRIMARY KEY, data TEXT NOT NULL);
                CREATE TABLE pending (txid TEXT PRIMARY KEY, data TEXT NOT NULL);",
            )?;
        }
        Ok(Self { conn })
    }
    pub fn commit(&self) -> Result<()> {
        Ok(self.conn.execute_batch("COMMIT")?)
    }
    pub fn set_config(&self, config: &Config) -> Result<()> {
        self.conn.execute(
            "INSERT INTO config VALUES(1, ?)",
            [serde_json::to_string(config)?],
        )?;
        Ok(())
    }
    pub fn config(&self) -> Result<Config> {
        let json: String = self
            .conn
            .query_row("SELECT data FROM config WHERE id=1", [], |r| r.get(0))?;
        let config: Config = serde_json::from_str(&json)?;
        ensure!(config.version == 1, "unsupported wallet database version");
        Ok(config)
    }
    pub fn blocks(&self) -> Result<Vec<Block>> {
        let mut blocks: Vec<Block> = self.read_all("SELECT data FROM blocks ORDER BY height")?;
        // Backfills retain the already downloaded suffix. Until the gap closes,
        // only the contiguous prefix is usable by balance/proof construction.
        if let Some(gap) = blocks.windows(2).position(|pair| {
            pair[0].height.checked_add(1) != Some(pair[1].height)
                || pair[1].previous_block_hash != pair[0].hash
                || pair[1].anchor_before != pair[0].anchor_after
        }) {
            blocks.truncate(gap + 1);
        }
        Ok(blocks)
    }
    pub fn first_height(&self) -> Result<Option<u32>> {
        self.conn
            .query_row("SELECT MIN(height) FROM blocks", [], |row| row.get(0))
            .optional()
            .map(|value| value.flatten())
            .map_err(Into::into)
    }
    pub fn tip(&self) -> Result<Option<Block>> {
        // Backfills may leave a cached suffix above a gap. Only the contiguous
        // prefix is usable as wallet evidence; walking heights in SQL avoids
        // deserializing that suffix or the whole chain.
        self.conn
            .query_row(
                "WITH RECURSIVE contiguous(height) AS (
                    SELECT MIN(height) FROM blocks
                    UNION ALL
                    SELECT contiguous.height + 1 FROM contiguous
                    JOIN blocks ON blocks.height = contiguous.height + 1
                 )
                 SELECT data FROM blocks WHERE height = (SELECT MAX(height) FROM contiguous)",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|data| Ok(serde_json::from_str(&data)?))
            .transpose()
    }
    pub fn blocks_range(&self, start: u32, end: u32) -> Result<Vec<Block>> {
        self.conn
            .prepare("SELECT data FROM blocks WHERE height BETWEEN ? AND ? ORDER BY height")?
            .query_map(params![start, end], |row| row.get::<_, String>(0))?
            .map(|row| Ok(serde_json::from_str(&row?)?))
            .collect()
    }
    fn index_block(&self, block: &Block) -> Result<()> {
        for stamp in &block.stamps {
            for member in &stamp.tachygrams {
                self.conn.execute(
                    "INSERT INTO tachygrams VALUES(?, ?) ON CONFLICT DO NOTHING",
                    params![member, block.height],
                )?;
            }
        }
        for txid in &block.transactions {
            self.conn.execute(
                "INSERT INTO block_transactions VALUES(?, ?) ON CONFLICT DO NOTHING",
                params![txid, block.height],
            )?;
        }
        self.conn.execute(
            "UPDATE note_nullifiers SET spent_height=?
             WHERE spent_height IS NULL
             AND nullifier IN (SELECT id FROM tachygrams WHERE height=?)",
            params![block.height, block.height],
        )?;
        Ok(())
    }
    /// Additive, one-time index migration for existing wallets. Steady-state
    /// sync only indexes the blocks it appends.
    fn ensure_indexes(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS tachygrams (id TEXT NOT NULL, height INTEGER NOT NULL, PRIMARY KEY(id, height));
             CREATE INDEX IF NOT EXISTS tachygrams_by_height ON tachygrams(height);
             CREATE TABLE IF NOT EXISTS block_transactions (txid TEXT NOT NULL, height INTEGER NOT NULL, PRIMARY KEY(txid, height));
             CREATE INDEX IF NOT EXISTS transactions_by_height ON block_transactions(height);
             CREATE TABLE IF NOT EXISTS note_nullifiers (
                note_id TEXT NOT NULL, epoch INTEGER NOT NULL, nullifier TEXT NOT NULL UNIQUE,
                spent_height INTEGER, PRIMARY KEY(note_id, epoch));
             CREATE INDEX IF NOT EXISTS note_nullifiers_by_spend ON note_nullifiers(spent_height);",
        )?;
        let version: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM metadata WHERE key='chain_index_v1'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if version.is_none() {
            for block in self.blocks()? {
                self.index_block(&block)?;
            }
            self.conn
                .execute("INSERT INTO metadata VALUES('chain_index_v1', '1')", [])?;
        }
        Ok(())
    }
    pub fn tachygram_height(&self, id: &str) -> Result<Option<u32>> {
        self.ensure_indexes()?;
        Ok(self
            .conn
            .query_row(
                "SELECT MIN(height) FROM tachygrams WHERE id=?",
                [id],
                |row| row.get(0),
            )
            .optional()?
            .flatten())
    }
    pub fn has_tachygram(&self, id: &str) -> Result<bool> {
        Ok(self.tachygram_height(id)?.is_some())
    }
    pub fn has_transaction(&self, txid: &str) -> Result<bool> {
        self.ensure_indexes()?;
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM block_transactions WHERE txid=?)",
            [txid],
            |row| row.get(0),
        )?)
    }
    pub fn block_by_txid(&self, txid: &str) -> Result<Option<Block>> {
        self.ensure_indexes()?;
        let height: Option<u32> = self
            .conn
            .query_row(
                "SELECT MIN(height) FROM block_transactions WHERE txid=?",
                [txid],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        height
            .map(|height| self.block(height))
            .transpose()
            .map(Option::flatten)
    }
    pub fn block(&self, height: u32) -> Result<Option<Block>> {
        self.conn
            .query_row("SELECT data FROM blocks WHERE height=?", [height], |row| {
                row.get::<_, String>(0)
            })
            .optional()?
            .map(|data| Ok(serde_json::from_str(&data)?))
            .transpose()
    }
    pub fn clear_funding_snapshot(&self) -> Result<()> {
        if self.table_exists("funding_snapshot")? {
            self.conn.execute("DELETE FROM funding_snapshot", [])?;
        }
        Ok(())
    }
    fn ensure_proof_tables(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS epoch_proofs (
                epoch INTEGER NOT NULL, depth INTEGER NOT NULL, bits INTEGER NOT NULL,
                pcd BLOB NOT NULL, members BLOB NOT NULL,
                PRIMARY KEY(epoch, depth, bits));
             CREATE TABLE IF NOT EXISTS spendable_proofs (
                note_id TEXT PRIMARY KEY, pcd BLOB NOT NULL);",
        )?;
        Ok(())
    }
    pub fn bucket_proof(
        &self,
        epoch: u32,
        profile: QrProfile,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        self.ensure_proof_tables()?;
        self.conn
            .query_row(
                "SELECT pcd, members FROM epoch_proofs WHERE epoch=? AND depth=? AND bits=?",
                params![epoch, profile.depth, profile.bits],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(Into::into)
    }
    pub fn put_bucket_proof(
        &self,
        epoch: u32,
        profile: QrProfile,
        pcd: &[u8],
        members: &[u8],
    ) -> Result<()> {
        self.ensure_proof_tables()?;
        self.conn.execute(
            "INSERT INTO epoch_proofs VALUES(?, ?, ?, ?, ?)
             ON CONFLICT(epoch, depth, bits) DO UPDATE SET pcd=excluded.pcd, members=excluded.members",
            params![epoch, profile.depth, profile.bits, pcd, members],
        )?;
        Ok(())
    }
    pub fn spendable_proof(&self, note_id: &str) -> Result<Option<Vec<u8>>> {
        self.ensure_proof_tables()?;
        self.conn
            .query_row(
                "SELECT pcd FROM spendable_proofs WHERE note_id=?",
                [note_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(Into::into)
    }
    pub fn put_spendable_proof(&self, note_id: &str, pcd: &[u8]) -> Result<()> {
        self.ensure_proof_tables()?;
        self.conn.execute(
            "INSERT INTO spendable_proofs VALUES(?, ?)
             ON CONFLICT(note_id) DO UPDATE SET pcd=excluded.pcd",
            params![note_id, pcd],
        )?;
        Ok(())
    }
    pub fn clear_chain(&self) -> Result<()> {
        self.conn.execute("DELETE FROM blocks", [])?;
        if self.table_exists("tachygrams")? {
            self.conn.execute("DELETE FROM tachygrams", [])?;
            self.conn.execute("DELETE FROM block_transactions", [])?;
        }
        if self.table_exists("epoch_proofs")? {
            self.conn.execute("DELETE FROM epoch_proofs", [])?;
            self.conn.execute("DELETE FROM spendable_proofs", [])?;
        }
        if self.table_exists("note_nullifiers")? {
            self.conn
                .execute("UPDATE note_nullifiers SET spent_height=NULL", [])?;
        }
        self.clear_funding_snapshot()
    }
    pub fn notes(&self) -> Result<Vec<Receipt>> {
        self.read_all("SELECT data FROM notes ORDER BY id")
    }
    pub fn notes_without_nullifier(&self, epoch: u32) -> Result<Vec<Receipt>> {
        self.ensure_indexes()?;
        self.conn
            .prepare(
                "SELECT notes.data FROM notes
                 LEFT JOIN note_nullifiers nn ON nn.note_id=notes.id AND nn.epoch=?
                 WHERE nn.note_id IS NULL
                 AND NOT EXISTS (
                    SELECT 1 FROM note_nullifiers spent
                    WHERE spent.note_id=notes.id AND spent.spent_height IS NOT NULL
                 ) ORDER BY notes.id",
            )?
            .query_map([epoch], |row| row.get::<_, String>(0))?
            .map(|row| Ok(serde_json::from_str(&row?)?))
            .collect()
    }
    pub fn note_nullifier_epochs(&self, note_id: &str) -> Result<BTreeSet<u32>> {
        self.ensure_indexes()?;
        Ok(self
            .conn
            .prepare("SELECT epoch FROM note_nullifiers WHERE note_id=?")?
            .query_map([note_id], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }
    pub fn put_note_nullifier(
        &self,
        note_id: &str,
        epoch: u32,
        nullifier: &str,
        spent_height: Option<u32>,
    ) -> Result<()> {
        self.ensure_indexes()?;
        self.conn.execute(
            "INSERT INTO note_nullifiers VALUES(?, ?, ?, ?) ON CONFLICT DO NOTHING",
            params![note_id, epoch, nullifier, spent_height],
        )?;
        Ok(())
    }
    pub fn spent_note_ids(&self) -> Result<BTreeSet<String>> {
        self.ensure_indexes()?;
        Ok(self
            .conn
            .prepare("SELECT DISTINCT note_id FROM note_nullifiers WHERE spent_height IS NOT NULL")?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }
    pub fn mined_note_ids(&self) -> Result<BTreeSet<String>> {
        self.ensure_indexes()?;
        Ok(self
            .conn
            .prepare(
                "SELECT DISTINCT notes.id FROM notes JOIN tachygrams ON tachygrams.id=notes.id",
            )?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }
    pub fn pending(&self) -> Result<Vec<Pending>> {
        self.read_all("SELECT data FROM pending ORDER BY txid")
    }
    pub fn operation(&self, id: &str) -> Result<Option<StoredOperation>> {
        if !self.table_exists("operations")? {
            return Ok(None);
        }
        let row: Option<(String, String)> = self
            .conn
            .query_row(
                "SELECT txid, request FROM operations WHERE id=?",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        row.map(|(txid, request)| {
            Ok(StoredOperation {
                id: id.into(),
                txid,
                request: serde_json::from_str(&request)?,
            })
        })
        .transpose()
    }
    pub fn operation_ids(&self) -> Result<std::collections::BTreeMap<String, String>> {
        if !self.table_exists("operations")? {
            return Ok(Default::default());
        }
        Ok(self
            .conn
            .prepare("SELECT txid, id FROM operations")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?)
    }
    pub fn put_operation(&self, operation: &StoredOperation) -> Result<()> {
        // The ID, signed bytes, input reservation and receipts commit atomically before broadcast.
        // Create lazily so older v1 wallets need no reset or eager migration.
        self.conn.execute_batch("CREATE TABLE IF NOT EXISTS operations (
            id TEXT PRIMARY KEY, txid TEXT NOT NULL UNIQUE REFERENCES pending(txid), request TEXT NOT NULL
        );")?;
        self.conn.execute(
            "INSERT INTO operations VALUES(?, ?, ?)",
            params![
                operation.id,
                operation.txid,
                serde_json::to_string(&operation.request)?
            ],
        )?;
        Ok(())
    }
    fn table_exists(&self, table: &str) -> Result<bool> {
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?)",
            [table],
            |row| row.get(0),
        )?)
    }
    pub fn funding_snapshot(&self) -> Result<Option<Snapshot>> {
        if !self.table_exists("funding_snapshot")? {
            return Ok(None);
        }
        self.conn
            .query_row("SELECT data FROM funding_snapshot WHERE id=1", [], |row| {
                row.get::<_, String>(0)
            })
            .optional()?
            .map(|data| Ok(serde_json::from_str(&data)?))
            .transpose()
    }
    pub fn put_funding_snapshot(&self, snapshot: &Snapshot) -> Result<()> {
        // Additive, lazy migration: existing v1 wallets remain readable before their next sync.
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS funding_snapshot (id INTEGER PRIMARY KEY CHECK(id=1), data TEXT NOT NULL);"
        )?;
        self.conn.execute(
            "INSERT INTO funding_snapshot VALUES(1, ?) ON CONFLICT(id) DO UPDATE SET data=excluded.data",
            [serde_json::to_string(snapshot)?],
        )?;
        Ok(())
    }
    fn read_all<T: serde::de::DeserializeOwned>(&self, sql: &str) -> Result<Vec<T>> {
        self.conn
            .prepare(sql)?
            .query_map([], |row| row.get::<_, String>(0))?
            .map(|row| Ok(serde_json::from_str(&row?)?))
            .collect()
    }
    pub fn put_block(&self, block: &Block) -> Result<()> {
        self.ensure_indexes()?;
        self.conn.execute(
            "INSERT INTO blocks VALUES(?, ?) ON CONFLICT(height) DO UPDATE SET data=excluded.data",
            params![block.height, serde_json::to_string(block)?],
        )?;
        self.index_block(block)?;
        Ok(())
    }
    pub fn rewind(&self, height: u32) -> Result<()> {
        self.conn
            .execute("DELETE FROM blocks WHERE height > ?", [height])?;
        if self.table_exists("tachygrams")? {
            self.conn
                .execute("DELETE FROM tachygrams WHERE height > ?", [height])?;
            self.conn
                .execute("DELETE FROM block_transactions WHERE height > ?", [height])?;
        }
        if self
            .funding_snapshot()?
            .is_some_and(|snapshot| snapshot.height > height)
        {
            self.conn.execute("DELETE FROM funding_snapshot", [])?;
        }
        if self.table_exists("note_nullifiers")? {
            self.conn.execute(
                "UPDATE note_nullifiers SET spent_height=NULL WHERE spent_height > ?",
                [height],
            )?;
        }
        self.rewind_proofs(height)
    }
    fn rewind_proofs(&self, _height: u32) -> Result<()> {
        // Reorgs are rare; discard composed evidence rather than risk reusing
        // a bucket or lineage derived from a removed epoch transition.
        if self.table_exists("epoch_proofs")? {
            self.conn.execute("DELETE FROM epoch_proofs", [])?;
            self.conn.execute("DELETE FROM spendable_proofs", [])?;
        }
        Ok(())
    }
    pub fn put_note(&self, receipt: &Receipt) -> Result<()> {
        let existing: Option<String> = self
            .conn
            .query_row("SELECT data FROM notes WHERE id=?", [receipt.id()?], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(existing) = existing {
            let mut previous: Receipt = serde_json::from_str(&existing)?;
            let mut incoming = receipt.clone();
            let locator = incoming.locator.take().or(previous.locator.take());
            previous.locator = None;
            ensure!(
                previous == incoming,
                "conflicting receipt for this commitment"
            );
            incoming.locator = locator;
            self.conn.execute(
                "UPDATE notes SET data=? WHERE id=?",
                params![serde_json::to_string(&incoming)?, receipt.id()?],
            )?;
        } else {
            self.conn.execute(
                "INSERT INTO notes VALUES(?, ?)",
                params![receipt.id()?, serde_json::to_string(receipt)?],
            )?;
        }
        Ok(())
    }
    pub fn reserve(&self, pending: &Pending) -> Result<()> {
        self.conn.execute(
            "INSERT INTO pending VALUES(?, ?)",
            params![pending.txid, serde_json::to_string(pending)?],
        )?;
        Ok(())
    }
}
