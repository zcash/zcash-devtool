use anyhow::anyhow;
use gumdrop::Options;

use rusqlite::{named_params, Connection};
use zcash_primitives::{
    consensus::BlockHeight,
    transaction::{
        components::{amount::NonNegativeAmount, Amount},
        TxId,
    },
};

use crate::{data::get_db_paths, ui::format_zec};

// Options accepted for the `list` command
#[derive(Debug, Options)]
pub(crate) struct Command {}

impl Command {
    pub(crate) fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let (_, db_data) = get_db_paths(wallet_dir);

        let conn = Connection::open(db_data)?;
        rusqlite::vtab::array::load_module(&conn)?;

        let mut stmt_txs = conn.prepare(
            "SELECT mined_height,
                txid,
                expiry_height,
                account_balance_delta,
                fee_paid,
                sent_note_count,
                received_note_count,
                memo_count,
                block_time,
                expired_unmined,
                -- Fallback order for transaction history ordering:
                COALESCE(
                    -- Block height the transaction was mined at (if mined and known).
                    mined_height,
                    -- Expiry height for the transaction (if non-zero, which is always the
                    -- case for transactions we create).
                    CASE WHEN expiry_height == 0 THEN NULL ELSE expiry_height END
                    -- Mempool height (i.e. chain height + 1, so it appears most recently
                    -- in history). We represent this with NULL.
                ) AS sort_height
            FROM v_transactions
            WHERE account_id = :account_id
            ORDER BY
                -- By default, integer ordering places NULL before all values. Flip this
                -- around so that transactions in the mempool are shown as most recent.
                CASE WHEN sort_height IS NULL THEN 1 ELSE 0 END,
                sort_height",
        )?;

        println!("Transactions:");
        for row in stmt_txs.query_and_then(
            named_params! {":account_id": 0},
            |row| -> anyhow::Result<_> {
                WalletTx::from_parts(
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                )
            },
        )? {
            let tx = row?;
            println!("");
            tx.print();
        }

        Ok(())
    }
}

struct WalletTx {
    mined_height: Option<BlockHeight>,
    txid: TxId,
    expiry_height: Option<BlockHeight>,
    account_balance_delta: Amount,
    fee_paid: Option<NonNegativeAmount>,
    sent_note_count: usize,
    received_note_count: usize,
    memo_count: usize,
    block_time: Option<i64>,
    expired_unmined: bool,
}

impl WalletTx {
    fn from_parts(
        mined_height: Option<u32>,
        txid: Vec<u8>,
        expiry_height: Option<u32>,
        account_balance_delta: i64,
        fee_paid: Option<u64>,
        sent_note_count: usize,
        received_note_count: usize,
        memo_count: usize,
        block_time: Option<i64>,
        expired_unmined: bool,
    ) -> anyhow::Result<Self> {
        Ok(WalletTx {
            mined_height: mined_height.map(BlockHeight::from_u32),
            txid: TxId::from_bytes(txid.try_into().map_err(|_| anyhow!("Invalid TxId"))?),
            expiry_height: expiry_height.map(BlockHeight::from_u32),
            account_balance_delta: Amount::from_i64(account_balance_delta)
                .map_err(|()| anyhow!("Amount out of range"))?,
            fee_paid: fee_paid
                .map(|v| NonNegativeAmount::from_u64(v).map_err(|()| anyhow!("Fee out of range")))
                .transpose()?,
            sent_note_count,
            received_note_count,
            memo_count,
            block_time,
            expired_unmined,
        })
    }

    fn print(&self) {
        let height_to_str = |height: Option<BlockHeight>, def: &str| {
            height.map(|h| h.to_string()).unwrap_or(def.to_owned())
        };

        println!("{}", self.txid);
        if let Some((height, block_time)) = self.mined_height.zip(self.block_time) {
            println!(
                "     Mined: {} ({})",
                height,
                time::OffsetDateTime::from_unix_timestamp(block_time),
            );
        } else {
            println!(
                "  {} (expiry height: {})",
                if self.expired_unmined {
                    " Expired"
                } else {
                    " Unmined"
                },
                height_to_str(self.expiry_height, "Unknown"),
            );
        }
        println!("    Amount: {}", format_zec(self.account_balance_delta));
        println!(
            "  Fee paid: {}",
            self.fee_paid
                .map(format_zec)
                .as_ref()
                .map(|s| s.as_str())
                .unwrap_or("Unknown"),
        );
        println!(
            "  Sent {} notes, received {} notes, {} memos",
            self.sent_note_count, self.received_note_count, self.memo_count,
        );
    }
}
