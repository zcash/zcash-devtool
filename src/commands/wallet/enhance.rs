use std::collections::BTreeSet;

use anyhow::anyhow;
use rusqlite::OptionalExtension;
use clap::Args;
use futures_util::StreamExt;
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use tonic::{Code, transport::Channel};
use tracing::info;
use zcash_client_backend::{
    data_api::{
        TransactionDataRequest, TransactionStatus, WalletRead, WalletWrite,
        wallet::decrypt_and_store_transaction,
    },
    proto::service::{
        self, BlockRange, RawTransaction, compact_tx_streamer_client::CompactTxStreamerClient,
    },
};
use zcash_client_sqlite::{WalletDb, util::SystemClock};
use zcash_keys::encoding::AddressCodec;
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::{BlockHeight, BranchId, Parameters};

use crate::{config::get_wallet_network, data::get_db_paths, remote::ConnectionArgs};

// Options accepted for the `enhance` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    #[command(flatten)]
    connection: ConnectionArgs,

    /// Fetch received transactions from this Blindfetch server over PIR
    /// instead of asking lightwalletd for each txid.
    #[arg(long)]
    blindfetch: Option<String>,

    /// With --blindfetch, fetch transactions the Blindfetch database does not
    /// cover from lightwalletd by txid. This reveals those txids.
    #[arg(long, requires = "blindfetch")]
    allow_fallback: bool,

    /// With --blindfetch, keep running and fetch every this many seconds,
    /// whether or not anything arrived. Without it, enhance fetches exactly
    /// one fixed round and exits; run it after every sync, unconditionally.
    #[arg(long, requires = "blindfetch")]
    every: Option<u64>,

    /// With --blindfetch, check the server's index against a second
    /// Blindfetch server before sending any query.
    #[arg(long, requires = "blindfetch")]
    compare_with: Option<String>,

    /// Rounds per fetch. Every fetch sends exactly this many (four queries
    /// each); transactions that do not fit wait for the next fetch.
    #[arg(long, default_value_t = 1, requires = "blindfetch")]
    rounds: usize,
}

/// One fetch, always exactly `rounds` rounds, so the traffic never depends
/// on how many transactions the wallet wanted. What does not fit waits for
/// the next tick or the next run.
async fn blindfetch_once<P: Parameters>(
    bf: &bf_client::Blindfetch,
    params: &P,
    wants: &[bf_client::Want],
    rounds: usize,
) -> anyhow::Result<(Vec<(bf_client::Want, bf_client::Fetched)>, Vec<bf_client::RoundStats>)> {
    bf.fetch_tick(params, wants, rounds).await
}

/// Where the wallet saw a transaction mined, which is all a Blindfetch server
/// needs to be asked for it.
fn mined_position(
    db_path: &std::path::Path,
    txid: &TxId,
) -> Result<Option<bf_core::TxKey>, anyhow::Error> {
    let conn = rusqlite::Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let row = conn
        .query_row(
            "SELECT mined_height, tx_index FROM transactions WHERE txid = ?1",
            [txid.as_ref().as_slice()],
            |r| Ok((r.get::<_, Option<u32>>(0)?, r.get::<_, Option<u32>>(1)?)),
        )
        .optional()?;
    Ok(match row {
        Some((Some(height), Some(tx_index))) => Some(bf_core::TxKey { height, tx_index }),
        _ => None,
    })
}

fn parse_raw_transaction<P: Parameters>(
    params: &P,
    chain_tip: BlockHeight,
    tx: RawTransaction,
) -> Result<(Transaction, Option<BlockHeight>), anyhow::Error> {
    let mined_height = (tx.height > 0 && tx.height <= u64::from(u32::MAX))
        .then(|| BlockHeight::from_u32(u32::try_from(tx.height).unwrap()));

    let tx = Transaction::read(
        &tx.data[..],
        // We assume unmined transactions are created with the current consensus branch ID.
        BranchId::for_height(params, mined_height.unwrap_or(chain_tip)),
    )?;

    Ok((tx, mined_height))
}

async fn fetch_transaction<P: Parameters>(
    client: &mut CompactTxStreamerClient<Channel>,
    params: &P,
    chain_tip: BlockHeight,
    txid: TxId,
) -> Result<Option<(Transaction, Option<BlockHeight>)>, anyhow::Error> {
    let request = service::TxFilter {
        hash: txid.as_ref().to_vec(),
        ..Default::default()
    };
    // This is the request Blindfetch replaces: it names the transaction.
    println!("lightwalletd GetTransaction {txid}");

    let raw_tx = match client.get_transaction(request).await {
        Ok(response) => Ok(Some(response.into_inner())),
        Err(status) => {
            if status.code() == Code::NotFound {
                Ok(None)
            } else {
                Err(status)
            }
        }
    }?;

    raw_tx
        .map(|raw_tx| parse_raw_transaction(params, chain_tip, raw_tx))
        .transpose()
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let params = get_wallet_network(wallet_dir.as_ref())?;
        let (_, db_path) = get_db_paths(wallet_dir.as_ref());

        let mut db_data = WalletDb::for_path(&db_path, params, SystemClock, UnwrapErr(SysRng))?;
        let chain_tip = db_data.chain_height()?.ok_or_else(|| {
            anyhow!("Chain height must be available to perform transaction enhancement.")
        })?;

        // TODO:
        // - Create a shared Tor client.
        // - Create an isolated `lightwalletd` connection for each transaction.
        // - Spread transactions across all available servers.
        // - Fetch transactions in parallel, with timing noise.
        let mut client = self.connection.connect(params, wallet_dir.as_ref()).await?;

        let mut satisfied_requests = BTreeSet::new();

        let strict = self.blindfetch.is_some() && !self.allow_fallback;
        if let Some(url) = &self.blindfetch {
            // A server that once failed a check is never used again from this
            // wallet. Retrying would let it probe which queries were real.
            let lock = db_path.with_file_name("blindfetch-untrusted");
            if std::fs::read_to_string(&lock).is_ok_and(|s| s.lines().any(|l| l == url.as_str())) {
                anyhow::bail!("{url} failed a Blindfetch check earlier and is locked out (see {})", lock.display());
            }
            let mut bf = bf_client::Blindfetch::connect(url).await?;
            if let Some(other) = &self.compare_with {
                bf.compare_with(other).await?;
                println!("Index matches {other}.");
            }
            let info = bf.info().clone();
            // A database version ahead of the wallet's own view of the chain
            // can only be a per-client tag.
            anyhow::ensure!(
                BlockHeight::from_u32(info.last_height) <= chain_tip,
                "the server claims height {} but this wallet's chain tip is {chain_tip}; refusing",
                info.last_height
            );
            // A server far behind the chain would leave new payments pending
            // forever without saying so.
            anyhow::ensure!(
                BlockHeight::from_u32(info.last_height) + 300 >= chain_tip,
                "the server's database stops at height {}, far behind this wallet's tip {chain_tip}; refusing",
                info.last_height
            );
            println!(
                "Blindfetch: {} transactions, heights {}..={}, {} rows, {} queries per round",
                info.transactions, info.first_height, info.last_height, info.num_rows, info.batch
            );

            // Ticks fall on fixed deadlines, however long a tick's work takes.
            let scheduled = self.every.is_some();
            let mut ticks = self
                .every
                .map(|secs| tokio::time::interval(std::time::Duration::from_secs(secs.max(1))));
            // Set once the server fails a check. From then on every tick is
            // dummies only, so the server cannot see that anything changed.
            let mut caught = false;

            loop {
                if let Some(t) = ticks.as_mut() {
                    t.tick().await;
                }
                let mut wants = Vec::new();
                let mut unlocated = Vec::new();
                for request in if caught { vec![] } else { db_data.transaction_data_requests()? } {
                    if let TransactionDataRequest::Enhancement(txid) = &request {
                        if satisfied_requests.contains(&request) {
                            continue;
                        }
                        match mined_position(&db_path, txid)? {
                            Some(key) => wants.push(bf_client::Want { key, txid: *txid }),
                            None => unlocated.push(*txid),
                        }
                    }
                }

                // A rebuilt database is the one failure worth retrying, once.
                // Any other failure means the server misbehaved: lock it out.
                let outcome = match blindfetch_once(&bf, &params, &wants, self.rounds).await {
                    Err(e) if e.to_string().contains("rebuilt its database") => {
                        bf = bf_client::Blindfetch::connect(url).await?;
                        blindfetch_once(&bf, &params, &wants, self.rounds).await
                    }
                    other => other,
                };
                let (results, rounds) = match outcome {
                    Ok(r) => r,
                    Err(e) if e.to_string().contains(bf_client::UNTRUSTED) => {
                        use std::io::Write as _;
                        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&lock)?;
                        writeln!(f, "{url}")?;
                        eprintln!("ALERT: {e}. Locked out in {}.", lock.display());
                        if !scheduled {
                            return Err(e);
                        }
                        // Keep the same schedule with dummies only, so the
                        // server cannot tell which wallet it caught out.
                        caught = true;
                        continue;
                    }
                    Err(e) => return Err(e),
                };

                let mut not_covered = unlocated;
                let mut fetched = 0;
                let mut waiting = 0;
                for (want, result) in results {
                    match result {
                        bf_client::Fetched::Found(tx) => {
                            info!("Enhancing tx {:?} from Blindfetch", want.txid);
                            // A local storage error (say, the database is busy
                            // with a sync) must not change the schedule: log
                            // it and try this transaction again next tick.
                            match decrypt_and_store_transaction(
                                &params,
                                &mut db_data,
                                &tx,
                                Some(BlockHeight::from_u32(want.key.height)),
                            ) {
                                Ok(_) => {
                                    satisfied_requests.insert(TransactionDataRequest::Enhancement(want.txid));
                                    fetched += 1;
                                }
                                Err(e) => eprintln!("Could not store {}: {e}; will retry", want.txid),
                            }
                        }
                        bf_client::Fetched::NotCovered => not_covered.push(want.txid),
                        bf_client::Fetched::Missing => {
                            eprintln!(
                                "Warning: the server's index does not list {}, mined at height {} inside its range. \
                                 If this wallet received a shielded note in it, the server is withholding it.",
                                want.txid, want.key.height
                            );
                            not_covered.push(want.txid);
                        }
                        bf_client::Fetched::Deferred => waiting += 1,
                    }
                }

                let (up, down, ms): (usize, usize, u128) = rounds
                    .iter()
                    .fold((0, 0, 0), |a, r| (a.0 + r.bytes_up, a.1 + r.bytes_down, a.2 + r.millis));
                println!(
                    "Fetched {fetched} of {} transactions in {} round(s) of {} queries: {:.1} MiB up, {:.1} MiB down, {ms} ms",
                    wants.len(),
                    rounds.len(),
                    info.batch,
                    up as f64 / 1048576.0,
                    down as f64 / 1048576.0,
                );
                if waiting > 0 {
                    println!("{waiting} more did not fit in this fetch and wait for the next one.");
                }
                println!("lightwalletd was not asked for any of them.");

                for txid in &not_covered {
                    println!("Not in the Blindfetch database yet, left for later: {txid}");
                    // In one-shot mode, keep the lightwalletd loop below from
                    // asking for it. On a schedule, leave it pending so a later
                    // tick fetches it once the server has indexed it.
                    if !self.allow_fallback && !scheduled {
                        satisfied_requests.insert(TransactionDataRequest::Enhancement(*txid));
                    }
                }

                if !scheduled {
                    break;
                }
            }
        }

        loop {
            let mut new_request_encountered = false;
            for data_request in db_data.transaction_data_requests()? {
                if satisfied_requests.contains(&data_request) {
                    continue;
                } else {
                    new_request_encountered = true;
                }

                info!("Fetching data for request {:?}", data_request);
                match &data_request {
                    TransactionDataRequest::GetStatus(txid) => {
                        let status = fetch_transaction(&mut client, &params, chain_tip, *txid)
                            .await?
                            .map_or(TransactionStatus::TxidNotRecognized, |(_, mined_height)| {
                                mined_height.map_or(
                                    TransactionStatus::NotInMainChain,
                                    TransactionStatus::Mined,
                                )
                            });
                        info!("Got status {:?}", status);
                        db_data.set_transaction_status(*txid, status)?;
                    }
                    TransactionDataRequest::Enhancement(txid) if strict => {
                        // Asking lightwalletd would name the transaction.
                        println!("Deferred, not asking lightwalletd: {txid}");
                    }
                    TransactionDataRequest::Enhancement(txid) => {
                        match fetch_transaction(&mut client, &params, chain_tip, *txid).await? {
                            None => {
                                info!("Txid not recognized {:?}", txid);
                                db_data.set_transaction_status(
                                    *txid,
                                    TransactionStatus::TxidNotRecognized,
                                )?;
                            }
                            Some((tx, mined_height)) => {
                                info!(
                                    "Enhancing tx {:?} with mined height {:?}",
                                    txid, mined_height
                                );
                                decrypt_and_store_transaction(
                                    &params,
                                    &mut db_data,
                                    &tx,
                                    mined_height,
                                )?;
                            }
                        }
                    }
                    TransactionDataRequest::TransactionsInvolvingAddress(tia) => {
                        let address = tia.address().encode(&params);
                        let request = service::TransparentAddressBlockFilter {
                            address: address.clone(),
                            range: Some(BlockRange {
                                start: Some(service::BlockId {
                                    height: u64::from(tia.block_range_start()),
                                    ..Default::default()
                                }),
                                end: tia.block_range_end().map(|h| service::BlockId {
                                    height: u64::from(h - 1), // `BlockRange` end is inclusive.
                                    ..Default::default()
                                }),
                                pool_types: Default::default(),
                            }),
                        };

                        let mut stream = client.get_taddress_txids(request).await?.into_inner();
                        while let Some(raw_tx) = stream.next().await {
                            let (tx, mined_height) =
                                parse_raw_transaction(&params, chain_tip, raw_tx?)?;
                            info!(
                                "Found tx {:?} for address {} with mined height {:?}",
                                tx.txid(),
                                address,
                                mined_height
                            );
                            decrypt_and_store_transaction(&params, &mut db_data, &tx, mined_height)?
                        }
                    }
                }

                satisfied_requests.insert(data_request);
            }

            if !new_request_encountered {
                break;
            }
        }

        Ok(())
    }
}
