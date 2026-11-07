//! One SQLite writer lock covers selection and durable reservation of inputs.

use crate::{chain::Block, funding_balance::Snapshot, note::Receipt};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashSet},
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
    /// The payment request, as `lookup` prints it; null for rows written before this field.
    #[serde(default)]
    pub request: serde_json::Value,
}

pub struct StoredOperation {
    pub id: String,
    pub txid: String,
    pub request: serde_json::Value,
}

pub struct Store {
    conn: Connection,
    evidence: Option<Connection>,
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

    /// The entry anchor of `epoch` (`sntl_epoch`).
    ///
    /// This is the boundary anchor that `SpendableLift` reaches after the
    /// preceding epoch closes. It is distinct from an ordinary anchor in the
    /// same epoch, and anchor spans must never cross it.
    pub fn epoch_sentinel(&self, epoch: u32) -> Result<Anchor> {
        let blocks = self.epoch_blocks(epoch)?;
        let first = blocks
            .iter()
            .find(|block| block.epoch == epoch)
            .context("missing epoch start block")?;
        first.entry()
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

    pub fn epoch_node(
        &self,
        epoch: u32,
        kind: u8,
        first: u32,
        last: u32,
        profile: QrProfile,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        match self {
            Self::Blocks(_) => Ok(None),
            Self::Store(store) => store.epoch_node(epoch, kind, first, last, profile),
        }
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "persistent cache identity and proof payload"
    )]
    pub fn put_epoch_node(
        &self,
        epoch: u32,
        kind: u8,
        first: u32,
        last: u32,
        profile: QrProfile,
        pcd: &[u8],
        members: &[u8],
    ) -> Result<()> {
        match self {
            Self::Blocks(_) => Ok(()),
            Self::Store(store) => {
                store.put_epoch_node(epoch, kind, first, last, profile, pcd, members)
            }
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
        Self::open_with_mode(dir, initialize, false)
    }
    pub fn open_readonly(dir: &Path) -> Result<Self> {
        Self::open_with_mode(dir, false, true)
    }
    fn open_with_mode(dir: &Path, initialize: bool, read_only: bool) -> Result<Self> {
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
        let flags = if read_only {
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
        } else {
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
        };
        let conn = Connection::open_with_flags(path, flags)?;
        conn.busy_timeout(Duration::from_secs(1))?;
        if read_only {
            conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        } else {
            conn.execute_batch(
                "PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; BEGIN IMMEDIATE;",
            )?;
        }
        if initialize {
            conn.execute_batch(
                "CREATE TABLE config (id INTEGER PRIMARY KEY CHECK(id=1), data TEXT NOT NULL);
                CREATE TABLE blocks (height INTEGER PRIMARY KEY, data TEXT NOT NULL);
                CREATE TABLE notes (id TEXT PRIMARY KEY, data TEXT NOT NULL);
                CREATE TABLE pending (txid TEXT PRIMARY KEY, data TEXT NOT NULL);",
            )?;
        }
        let evidence = if read_only {
            None
        } else if let Some(directory) = std::env::var_os("TACHYON_EVIDENCE_DIR") {
            let directory = PathBuf::from(directory);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(&directory)?;
            }
            #[cfg(not(unix))]
            fs::create_dir_all(&directory)?;
            let path = directory.join("evidence.sqlite");
            let evidence = Connection::open(path)?;
            evidence.busy_timeout(Duration::from_secs(300))?;
            evidence.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
            Some(evidence)
        } else {
            None
        };
        let store = Self { conn, evidence };
        if !read_only {
            store.ensure_pending_meta()?;
        }
        Ok(store)
    }
    /// Keep the transaction payloads in `pending` for recovery and rebroadcast,
    /// while maintaining a small metadata index for hot-path status and
    /// reservation checks. Existing wallets are migrated once.
    fn ensure_pending_meta(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS pending_meta (
                txid TEXT PRIMARY KEY,
                expiry INTEGER NOT NULL,
                source TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS pending_meta_by_expiry ON pending_meta(expiry, source);",
        )?;
        let migrated: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM metadata WHERE key='pending_meta_v1'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if migrated.is_some() {
            return Ok(());
        }
        let mut rows = self.conn.prepare("SELECT data FROM pending")?;
        let mut pending = rows.query([])?;
        let mut insert = self
            .conn
            .prepare("INSERT OR IGNORE INTO pending_meta(txid, expiry, source) VALUES(?, ?, ?)")?;
        while let Some(row) = pending.next()? {
            let data: String = row.get(0)?;
            let entry: Pending = serde_json::from_str(&data)?;
            insert.execute(params![entry.txid, entry.expiry, entry.source])?;
        }
        self.conn.execute(
            "INSERT INTO metadata(key, value) VALUES('pending_meta_v1', '1')
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [],
        )?;
        Ok(())
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
    pub fn check_evidence_identity(&self, config: &Config) -> Result<()> {
        if self.evidence.is_none() {
            return Ok(());
        }
        let conn = self.evidence_conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        )?;
        let cached: Option<String> = conn
            .query_row(
                "SELECT value FROM metadata WHERE key='network_id'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(cached) = cached {
            ensure!(
                cached == config.network_id,
                "shared evidence belongs to a different network; use a fresh evidence directory"
            );
        } else {
            conn.execute(
                "INSERT OR IGNORE INTO metadata VALUES('network_id', ?)",
                [&config.network_id],
            )?;
        }
        Ok(())
    }
    pub fn network_identity_valid(&self, config: &Config) -> Result<bool> {
        self.ensure_indexes()?;
        let expected = format!("{}:{}", config.genesis, config.activation_hash);
        let cached: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM metadata WHERE key='network_identity_v1'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        Ok(cached.as_deref() == Some(expected.as_str()))
    }
    pub fn mark_network_identity_valid(&self, config: &Config) -> Result<()> {
        self.ensure_indexes()?;
        self.conn.execute(
            "INSERT INTO metadata VALUES('network_identity_v1', ?)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [format!("{}:{}", config.genesis, config.activation_hash)],
        )?;
        Ok(())
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
    pub fn has_transaction(&self, txid: &str) -> Result<bool> {
        self.ensure_indexes()?;
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM block_transactions WHERE txid=?)",
            [txid],
            |row| row.get(0),
        )?)
    }
    pub fn transaction_height(&self, txid: &str) -> Result<Option<u32>> {
        self.ensure_indexes()?;
        Ok(self
            .conn
            .query_row(
                "SELECT MIN(height) FROM block_transactions WHERE txid=?",
                [txid],
                |row| row.get(0),
            )
            .optional()?
            .flatten())
    }
    pub fn block_by_txid(&self, txid: &str) -> Result<Option<Block>> {
        self.transaction_height(txid)?
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
             CREATE TABLE IF NOT EXISTS epoch_nodes (
                epoch INTEGER NOT NULL, kind INTEGER NOT NULL,
                first INTEGER NOT NULL, last INTEGER NOT NULL,
                depth INTEGER NOT NULL, bits INTEGER NOT NULL,
                pcd BLOB NOT NULL, members BLOB NOT NULL,
                PRIMARY KEY(epoch, kind, first, last, depth, bits));
             CREATE TABLE IF NOT EXISTS spendable_proofs (
                note_id TEXT PRIMARY KEY, pcd BLOB NOT NULL);",
        )?;
        Ok(())
    }
    fn evidence_conn(&self) -> &Connection {
        self.evidence.as_ref().unwrap_or(&self.conn)
    }
    fn ensure_evidence_tables(&self) -> Result<()> {
        let conn = self.evidence_conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS epoch_proofs (
                epoch INTEGER NOT NULL, depth INTEGER NOT NULL, bits INTEGER NOT NULL,
                pcd BLOB NOT NULL, members BLOB NOT NULL,
                PRIMARY KEY(epoch, depth, bits));
             CREATE TABLE IF NOT EXISTS epoch_nodes (
                epoch INTEGER NOT NULL, kind INTEGER NOT NULL,
                first INTEGER NOT NULL, last INTEGER NOT NULL,
                depth INTEGER NOT NULL, bits INTEGER NOT NULL,
                pcd BLOB NOT NULL, members BLOB NOT NULL,
                PRIMARY KEY(epoch, kind, first, last, depth, bits));",
        )?;
        Ok(())
    }
    fn clear_shared_epoch_proofs(&self) -> Result<()> {
        self.ensure_evidence_tables()?;
        let conn = self.evidence_conn();
        conn.execute("DELETE FROM epoch_proofs", [])?;
        conn.execute("DELETE FROM epoch_nodes", [])?;
        Ok(())
    }
    pub fn bucket_proof(
        &self,
        epoch: u32,
        profile: QrProfile,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        self.ensure_evidence_tables()?;
        self.evidence_conn()
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
        self.ensure_evidence_tables()?;
        self.evidence_conn().execute(
            "INSERT INTO epoch_proofs VALUES(?, ?, ?, ?, ?)
             ON CONFLICT(epoch, depth, bits) DO UPDATE SET pcd=excluded.pcd, members=excluded.members",
            params![epoch, profile.depth, profile.bits, pcd, members],
        )?;
        Ok(())
    }
    pub fn epoch_node(
        &self,
        epoch: u32,
        kind: u8,
        first: u32,
        last: u32,
        profile: QrProfile,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        self.ensure_evidence_tables()?;
        self.evidence_conn()
            .query_row(
                "SELECT pcd, members FROM epoch_nodes
                 WHERE epoch=? AND kind=? AND first=? AND last=? AND depth=? AND bits=?",
                params![epoch, kind, first, last, profile.depth, profile.bits],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(Into::into)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "persistent cache identity and proof payload"
    )]
    pub fn put_epoch_node(
        &self,
        epoch: u32,
        kind: u8,
        first: u32,
        last: u32,
        profile: QrProfile,
        pcd: &[u8],
        members: &[u8],
    ) -> Result<()> {
        self.ensure_evidence_tables()?;
        self.evidence_conn().execute(
            "INSERT INTO epoch_nodes VALUES(?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(epoch, kind, first, last, depth, bits)
             DO UPDATE SET pcd=excluded.pcd, members=excluded.members",
            params![
                epoch,
                kind,
                first,
                last,
                profile.depth,
                profile.bits,
                pcd,
                members
            ],
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
        self.ensure_proof_tables()?;
        self.conn.execute("DELETE FROM blocks", [])?;
        if self.table_exists("tachygrams")? {
            self.conn.execute("DELETE FROM tachygrams", [])?;
            self.conn.execute("DELETE FROM block_transactions", [])?;
        }
        if self.table_exists("epoch_proofs")? {
            self.conn.execute("DELETE FROM epoch_proofs", [])?;
            self.conn.execute("DELETE FROM epoch_nodes", [])?;
            self.conn.execute("DELETE FROM spendable_proofs", [])?;
        }
        if self.table_exists("note_nullifiers")? {
            self.conn
                .execute("UPDATE note_nullifiers SET spent_height=NULL", [])?;
        }
        self.clear_shared_epoch_proofs()?;
        self.clear_funding_snapshot()
    }
    pub fn notes(&self) -> Result<Vec<Receipt>> {
        self.read_all("SELECT data FROM notes ORDER BY id")
    }
    pub fn unresolved_notes(&self) -> Result<Vec<Receipt>> {
        self.ensure_indexes()?;
        self.conn
            .prepare(
                "SELECT data FROM notes
                 WHERE NOT EXISTS (SELECT 1 FROM tachygrams WHERE id=notes.id)
                 ORDER BY id",
            )?
            .query_map([], |row| row.get::<_, String>(0))?
            .map(|row| Ok(serde_json::from_str(&row?)?))
            .collect()
    }
    pub fn confirmed_unspent_note_rows(&self) -> Result<Vec<(String, String)>> {
        self.ensure_indexes()?;
        self.conn
            .prepare(
                "SELECT notes.id, notes.data FROM notes
                 WHERE EXISTS (SELECT 1 FROM tachygrams WHERE tachygrams.id=notes.id)
                 AND NOT EXISTS (
                    SELECT 1 FROM note_nullifiers
                    WHERE note_nullifiers.note_id=notes.id
                    AND note_nullifiers.spent_height IS NOT NULL
                 ) ORDER BY notes.id",
            )?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }
    pub fn note(&self, id: &str) -> Result<Option<Receipt>> {
        let data: Option<String> = self
            .conn
            .query_row("SELECT data FROM notes WHERE id=?", [id], |row| row.get(0))
            .optional()?;
        data.map(|data| serde_json::from_str(&data).map_err(Into::into))
            .transpose()
    }
    pub fn confirmed_notes_without_nullifier(&self, epoch: u32) -> Result<Vec<Receipt>> {
        self.ensure_indexes()?;
        self.conn
            .prepare(
                "SELECT notes.data FROM notes
                 LEFT JOIN note_nullifiers nn ON nn.note_id=notes.id AND nn.epoch=?
                 WHERE nn.note_id IS NULL
                 AND EXISTS (SELECT 1 FROM tachygrams WHERE id=notes.id)
                 AND NOT EXISTS (
                    SELECT 1 FROM note_nullifiers spent
                    WHERE spent.note_id=notes.id AND spent.spent_height IS NOT NULL
                 ) ORDER BY notes.id",
            )?
            .query_map([epoch], |row| row.get::<_, String>(0))?
            .map(|row| Ok(serde_json::from_str(&row?)?))
            .collect()
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
    /// Sources of pending operations that have not expired at `tip_height`.
    /// This reads the small metadata index, never the raw transaction blobs.
    pub fn reserved_sources(&self, tip_height: Option<u32>) -> Result<BTreeSet<String>> {
        let mut sources = BTreeSet::new();
        if !self.table_exists("pending_meta")? {
            for pending in self.pending()? {
                if tip_height.is_none_or(|height| height <= pending.expiry) {
                    sources.insert(pending.source);
                }
            }
            return Ok(sources);
        }
        if let Some(height) = tip_height {
            let mut statement = self
                .conn
                .prepare("SELECT source FROM pending_meta WHERE expiry >= ?")?;
            for source in statement.query_map([height], |row| row.get(0))? {
                sources.insert(source?);
            }
        } else {
            let mut statement = self.conn.prepare("SELECT source FROM pending_meta")?;
            for source in statement.query_map([], |row| row.get(0))? {
                sources.insert(source?);
            }
        }
        Ok(sources)
    }
    pub fn pending_summaries(&self) -> Result<Vec<(String, u32, String)>> {
        if !self.table_exists("pending_meta")? {
            return Ok(self
                .pending()?
                .into_iter()
                .map(|pending| (pending.txid, pending.expiry, pending.source))
                .collect());
        }
        Ok(self
            .conn
            .prepare("SELECT txid, expiry, source FROM pending_meta ORDER BY txid")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?)
    }
    /// The payment request saved with each pending transaction, keyed by txid.
    ///
    /// SQLite extracts the field, so the raw transaction payloads are never deserialized;
    /// rows written before the field existed are absent.
    pub fn pending_requests(
        &self,
    ) -> Result<std::collections::BTreeMap<String, serde_json::Value>> {
        let mut requests = std::collections::BTreeMap::new();
        let mut statement = self.conn.prepare(
            "SELECT txid, json_extract(data, '$.request') FROM pending
             WHERE json_type(data, '$.request') = 'object'",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let request: String = row.get(1)?;
            requests.insert(row.get(0)?, serde_json::from_str(&request)?);
        }
        Ok(requests)
    }
    pub fn pending_by_txid(&self, txid: &str) -> Result<Option<Pending>> {
        let data: Option<String> = self
            .conn
            .query_row("SELECT data FROM pending WHERE txid=?", [txid], |row| {
                row.get(0)
            })
            .optional()?;
        data.map(|data| serde_json::from_str(&data).map_err(Into::into))
            .transpose()
    }
    /// All mined transaction IDs in the wallet's canonical synced chain.
    ///
    /// Loading this set once avoids re-running `tip()` and a transaction lookup
    /// for every historical pending row during balance snapshots.
    pub fn mined_txids(&self) -> Result<HashSet<String>> {
        self.conn
            .prepare("SELECT txid FROM block_transactions")?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<HashSet<_>>>()
            .map_err(Into::into)
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
        if self.funding_snapshot()?.as_ref() == Some(snapshot) {
            return Ok(());
        }
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
        self.ensure_proof_tables()?;
        // Reorgs are rare; discard composed evidence rather than risk reusing
        // a bucket or lineage derived from a removed epoch transition.
        if self.table_exists("epoch_proofs")? {
            self.conn.execute("DELETE FROM epoch_proofs", [])?;
            self.conn.execute("DELETE FROM epoch_nodes", [])?;
            self.conn.execute("DELETE FROM spendable_proofs", [])?;
        }
        self.clear_shared_epoch_proofs()?;
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
        self.conn.execute(
            "INSERT OR REPLACE INTO pending_meta(txid, expiry, source) VALUES(?, ?, ?)",
            params![pending.txid, pending.expiry, pending.source],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_metadata_migrates_without_touching_payloads() -> Result<()> {
        let directory = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let store = Store::open(directory.path(), true)?;
        store.commit()?;
        let pending = Pending {
            txid: "legacy-tx".into(),
            raw: "large transaction payload".into(),
            expiry: 10,
            source: "notes:legacy-note".into(),
            receipt: None,
            request: serde_json::Value::Null,
        };
        store.conn.execute(
            "INSERT INTO pending VALUES(?, ?)",
            params![pending.txid, serde_json::to_string(&pending)?],
        )?;
        store.conn.execute("DROP TABLE pending_meta", [])?;
        store
            .conn
            .execute("DELETE FROM metadata WHERE key='pending_meta_v1'", [])?;
        drop(store);

        let store = Store::open(directory.path(), false)?;
        assert_eq!(
            store.reserved_sources(Some(10))?,
            BTreeSet::from(["notes:legacy-note".to_string()])
        );
        assert!(store.reserved_sources(Some(11))?.is_empty());
        Ok(())
    }
}
