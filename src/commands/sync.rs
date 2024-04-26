use std::path::Path;

use anyhow::anyhow;
use futures_util::TryStreamExt;
use gumdrop::Options;
use orchard::tree::MerkleHashOrchard;
use prost::Message;
use tokio::{fs::File, io::AsyncWriteExt, task::JoinHandle};

use tonic::transport::Channel;
use tracing::{debug, error, info};
use zcash_client_backend::{
    data_api::{
        chain::{
            error::Error as ChainError, scan_cached_blocks, BlockSource, ChainState,
            CommitmentTreeRoot,
        },
        scanning::{ScanPriority, ScanRange},
        WalletCommitmentTrees, WalletRead, WalletWrite,
    },
    proto::service::{self, compact_tx_streamer_client::CompactTxStreamerClient, BlockId},
};
use zcash_client_sqlite::{chain::BlockMeta, FsBlockDb, FsBlockDbError, WalletDb};
use zcash_primitives::merkle_tree::HashSer;
use zcash_protocol::consensus::{BlockHeight, Parameters};

use crate::{
    data::{get_block_path, get_db_paths, get_wallet_network},
    error,
    remote::{connect_to_lightwalletd, Servers},
};

#[cfg(feature = "tui")]
use {crate::tui::Tui, zcash_protocol::consensus::NetworkUpgrade};

#[cfg(feature = "tui")]
mod defrag;

const BATCH_SIZE: u32 = 10_000;

// Options accepted for the `sync` command
#[derive(Debug, Options)]
pub(crate) struct Command {
    #[options(
        help = "the server to sync with (default is \"ecc\")",
        default = "ecc",
        parse(try_from_str = "Servers::parse")
    )]
    server: Servers,

    #[cfg(feature = "tui")]
    pub(crate) defrag: bool,
}

impl Command {
    pub(crate) async fn run(
        self,
        wallet_dir: Option<String>,
        #[cfg(feature = "tui")] tui: Tui,
    ) -> Result<(), anyhow::Error> {
        let params = get_wallet_network(wallet_dir.as_ref())?;

        let (fsblockdb_root, db_data) = get_db_paths(wallet_dir.as_ref());
        let fsblockdb_root = fsblockdb_root.as_path();
        let mut db_cache = FsBlockDb::for_path(fsblockdb_root).map_err(error::Error::from)?;
        let mut db_data = WalletDb::for_path(db_data, params)?;
        let mut client = connect_to_lightwalletd(self.server.pick(params)?).await?;

        #[cfg(feature = "tui")]
        let tui_handle = if self.defrag {
            let mut app = defrag::App::new(
                db_data
                    .get_wallet_birthday()?
                    .unwrap_or_else(|| params.activation_height(NetworkUpgrade::Sapling).unwrap()),
            );
            let handle = app.handle();
            tokio::spawn(async move {
                if let Err(e) = app.run(tui).await {
                    error!("Error while running TUI: {e}");
                }
            });
            Some(handle)
        } else {
            None
        };

        // 1) Download note commitment tree data from lightwalletd
        // 2) Pass the commitment tree data to the database.
        update_subtree_roots(&mut client, &mut db_data).await?;

        async fn running<P: Parameters + Send + 'static>(
            client: &mut CompactTxStreamerClient<Channel>,
            params: &P,
            fsblockdb_root: &Path,
            db_cache: &mut FsBlockDb,
            db_data: &mut WalletDb<rusqlite::Connection, P>,
            #[cfg(feature = "tui")] tui_handle: Option<&defrag::AppHandle>,
        ) -> Result<bool, anyhow::Error> {
            // 3) Download chain tip metadata from lightwalletd
            // 4) Notify the wallet of the updated chain tip.
            let _chain_tip = update_chain_tip(client, db_data).await?;

            // 5) Get the suggested scan ranges from the wallet database
            info!("Fetching scan ranges");
            let mut scan_ranges = db_data.suggest_scan_ranges()?;
            info!("Fetched {} scan ranges", scan_ranges.len());
            #[cfg(feature = "tui")]
            if let Some(handle) = tui_handle {
                if handle.set_scan_ranges(&scan_ranges, _chain_tip) {
                    // TUI exited.
                    return Ok(false);
                }
            }

            // Store the handles to cached block deletions (which we spawn into separate
            // tasks to allow us to continue downloading and scanning other ranges).
            let mut block_deletions = vec![];

            // 6) Run the following loop until the wallet's view of the chain tip as of
            //    the previous wallet session is valid.
            loop {
                // If there is a range of blocks that needs to be verified, it will always
                // be returned as the first element of the vector of suggested ranges.
                match scan_ranges.first() {
                    Some(scan_range) if scan_range.priority() == ScanPriority::Verify => {
                        // Download the blocks in `scan_range` into the block source,
                        // overwriting any existing blocks in this range.
                        let block_meta = download_blocks(
                            client,
                            fsblockdb_root,
                            db_cache,
                            scan_range,
                            #[cfg(feature = "tui")]
                            tui_handle,
                        )
                        .await?;

                        let chain_state =
                            download_chain_state(client, scan_range.block_range().start - 1)
                                .await?;

                        // Scan the downloaded blocks and check for scanning errors that
                        // indicate the wallet's chain tip is out of sync with blockchain
                        // history.
                        let scan_ranges_updated = scan_blocks(
                            params,
                            fsblockdb_root,
                            db_cache,
                            db_data,
                            &chain_state,
                            scan_range,
                            #[cfg(feature = "tui")]
                            tui_handle,
                            #[cfg(feature = "tui")]
                            _chain_tip,
                        )?;

                        // Delete the now-scanned blocks, because keeping the entire chain
                        // in CompactBlock files on disk is horrendous for the filesystem.
                        block_deletions.push(delete_cached_blocks(fsblockdb_root, block_meta));

                        if scan_ranges_updated {
                            // The suggested scan ranges have been updated, so we re-request.
                            scan_ranges = db_data.suggest_scan_ranges()?;
                            #[cfg(feature = "tui")]
                            if let Some(handle) = tui_handle {
                                if handle.set_scan_ranges(&scan_ranges, _chain_tip) {
                                    // TUI exited.
                                    return Ok(false);
                                }
                            }
                        } else {
                            // At this point, the cache and scanned data are locally
                            // consistent (though not necessarily consistent with the
                            // latest chain tip - this would be discovered the next time
                            // this codepath is executed after new blocks are received) so
                            // we can break out of the loop.
                            break;
                        }
                    }
                    _ => {
                        // Nothing to verify; break out of the loop
                        break;
                    }
                }
            }

            // 7) Loop over the remaining suggested scan ranges, retrieving the requested data
            //    and calling `scan_cached_blocks` on each range.
            let scan_ranges = db_data.suggest_scan_ranges()?;
            debug!("Suggested ranges: {:?}", scan_ranges);
            #[cfg(feature = "tui")]
            if let Some(handle) = tui_handle {
                if handle.set_scan_ranges(&scan_ranges, _chain_tip) {
                    // TUI exited.
                    return Ok(false);
                }
            }
            for scan_range in scan_ranges.into_iter().flat_map(|r| {
                // Limit the number of blocks we download and scan at any one time.
                (0..).scan(r, |acc, _| {
                    if acc.is_empty() {
                        None
                    } else if let Some((cur, next)) =
                        acc.split_at(acc.block_range().start + BATCH_SIZE)
                    {
                        *acc = next;
                        Some(cur)
                    } else {
                        let cur = acc.clone();
                        let end = acc.block_range().end;
                        *acc = ScanRange::from_parts(end..end, acc.priority());
                        Some(cur)
                    }
                })
            }) {
                // Download the blocks in `scan_range` into the block source.
                let block_meta = download_blocks(
                    client,
                    fsblockdb_root,
                    db_cache,
                    &scan_range,
                    #[cfg(feature = "tui")]
                    tui_handle,
                )
                .await?;

                let chain_state =
                    download_chain_state(client, scan_range.block_range().start - 1).await?;

                // Scan the downloaded blocks.
                let scan_ranges_updated = scan_blocks(
                    params,
                    fsblockdb_root,
                    db_cache,
                    db_data,
                    &chain_state,
                    &scan_range,
                    #[cfg(feature = "tui")]
                    tui_handle,
                    #[cfg(feature = "tui")]
                    _chain_tip,
                )?;

                // Delete the now-scanned blocks.
                block_deletions.push(delete_cached_blocks(fsblockdb_root, block_meta));

                if scan_ranges_updated {
                    // The suggested scan ranges have been updated (either due to a continuity
                    // error or because a higher priority range has been added).
                    info!("Waiting for cached blocks to be deleted...");
                    for deletion in block_deletions {
                        deletion.await?;
                    }
                    return Ok(true);
                }
            }

            info!("Waiting for cached blocks to be deleted...");
            for deletion in block_deletions {
                deletion.await?;
            }
            Ok(false)
        }

        while running(
            &mut client,
            &params,
            fsblockdb_root,
            &mut db_cache,
            &mut db_data,
            #[cfg(feature = "tui")]
            tui_handle.as_ref(),
        )
        .await?
        {}

        Ok(())
    }
}

async fn update_subtree_roots<P: Parameters>(
    client: &mut CompactTxStreamerClient<Channel>,
    db_data: &mut WalletDb<rusqlite::Connection, P>,
) -> Result<(), anyhow::Error> {
    let mut request = service::GetSubtreeRootsArg::default();
    request.set_shielded_protocol(service::ShieldedProtocol::Sapling);
    // Hack to work around a bug in the initial lightwalletd implementation.
    request.max_entries = 65536;
    let sapling_roots: Vec<CommitmentTreeRoot<sapling::Node>> = client
        .get_subtree_roots(request)
        .await?
        .into_inner()
        .and_then(|root| async move {
            let root_hash = sapling::Node::read(&root.root_hash[..])?;
            Ok(CommitmentTreeRoot::from_parts(
                BlockHeight::from_u32(root.completing_block_height as u32),
                root_hash,
            ))
        })
        .try_collect()
        .await?;

    info!("Sapling tree has {} subtrees", sapling_roots.len());
    db_data.put_sapling_subtree_roots(0, &sapling_roots)?;

    let mut request = service::GetSubtreeRootsArg::default();
    request.set_shielded_protocol(service::ShieldedProtocol::Orchard);
    // Hack to work around a bug in the initial lightwalletd implementation.
    request.max_entries = 65536;
    let orchard_roots: Vec<CommitmentTreeRoot<MerkleHashOrchard>> = client
        .get_subtree_roots(request)
        .await?
        .into_inner()
        .and_then(|root| async move {
            let root_hash = MerkleHashOrchard::read(&root.root_hash[..])?;
            Ok(CommitmentTreeRoot::from_parts(
                BlockHeight::from_u32(root.completing_block_height as u32),
                root_hash,
            ))
        })
        .try_collect()
        .await?;

    info!("Orchard tree has {} subtrees", orchard_roots.len());
    db_data.put_orchard_subtree_roots(0, &orchard_roots)?;

    Ok(())
}

async fn update_chain_tip<P: Parameters>(
    client: &mut CompactTxStreamerClient<Channel>,
    db_data: &mut WalletDb<rusqlite::Connection, P>,
) -> Result<BlockHeight, anyhow::Error> {
    let tip_height: BlockHeight = client
        .get_latest_block(service::ChainSpec::default())
        .await?
        .get_ref()
        .height
        .try_into()
        // TODO
        .map_err(|_| error::Error::InvalidAmount)?;

    info!("Latest block height is {}", tip_height);
    db_data.update_chain_tip(tip_height)?;

    Ok(tip_height)
}

async fn download_blocks(
    client: &mut CompactTxStreamerClient<Channel>,
    fsblockdb_root: &Path,
    db_cache: &FsBlockDb,
    scan_range: &ScanRange,
    #[cfg(feature = "tui")] tui_handle: Option<&defrag::AppHandle>,
) -> Result<Vec<BlockMeta>, anyhow::Error> {
    info!("Fetching {}", scan_range);
    #[cfg(feature = "tui")]
    if let Some(handle) = tui_handle {
        handle.set_fetching_range(Some(scan_range.block_range().clone()));
    }
    let mut start = service::BlockId::default();
    start.height = scan_range.block_range().start.into();
    let mut end = service::BlockId::default();
    end.height = (scan_range.block_range().end - 1).into();
    let range = service::BlockRange {
        start: Some(start),
        end: Some(end),
    };
    let block_meta = client
        .get_block_range(range)
        .await
        .map_err(anyhow::Error::from)?
        .into_inner()
        .and_then(|block| async move {
            let (sapling_outputs_count, orchard_actions_count) = block
                .vtx
                .iter()
                .map(|tx| (tx.outputs.len() as u32, tx.actions.len() as u32))
                .fold((0, 0), |(acc_sapling, acc_orchard), (sapling, orchard)| {
                    (acc_sapling + sapling, acc_orchard + orchard)
                });

            let meta = BlockMeta {
                height: block.height(),
                block_hash: block.hash(),
                block_time: block.time,
                sapling_outputs_count,
                orchard_actions_count,
            };

            let encoded = block.encode_to_vec();
            let mut block_file = File::create(get_block_path(fsblockdb_root, &meta)).await?;
            block_file.write_all(&encoded).await?;

            Ok(meta)
        })
        .try_collect::<Vec<_>>()
        .await?;

    db_cache
        .write_block_metadata(&block_meta)
        .map_err(error::Error::from)?;

    #[cfg(feature = "tui")]
    if let Some(handle) = tui_handle {
        handle.set_fetching_range(None);
    }
    Ok(block_meta)
}

async fn download_chain_state(
    client: &mut CompactTxStreamerClient<Channel>,
    block_height: BlockHeight,
) -> Result<ChainState, anyhow::Error> {
    let tree_state = client
        .get_tree_state(BlockId {
            height: block_height.into(),
            hash: vec![],
        })
        .await?;

    Ok(tree_state.into_inner().to_chain_state()?)
}

fn delete_cached_blocks(fsblockdb_root: &Path, block_meta: Vec<BlockMeta>) -> JoinHandle<()> {
    let fsblockdb_root = fsblockdb_root.to_owned();
    tokio::spawn(async move {
        for meta in block_meta {
            if let Err(e) = tokio::fs::remove_file(get_block_path(&fsblockdb_root, &meta)).await {
                error!("Failed to remove {:?}: {}", meta, e);
            }
        }
    })
}

/// Scans the given block range and checks for scanning errors that indicate the wallet's
/// chain tip is out of sync with blockchain history.
///
/// Returns `true` if scanning these blocks materially changed the suggested scan ranges.
#[allow(clippy::too_many_arguments)]
fn scan_blocks<P: Parameters + Send + 'static>(
    params: &P,
    fsblockdb_root: &Path,
    db_cache: &mut FsBlockDb,
    db_data: &mut WalletDb<rusqlite::Connection, P>,
    initial_chain_state: &ChainState,
    scan_range: &ScanRange,
    #[cfg(feature = "tui")] tui_handle: Option<&defrag::AppHandle>,
    #[cfg(feature = "tui")] chain_tip: BlockHeight,
) -> Result<bool, anyhow::Error> {
    info!("Scanning {}", scan_range);
    #[cfg(feature = "tui")]
    if let Some(handle) = tui_handle {
        handle.set_scanning_range(Some(scan_range.block_range().clone()));
    }
    let scan_result = scan_cached_blocks(
        params,
        db_cache,
        db_data,
        scan_range.block_range().start,
        initial_chain_state,
        scan_range.len(),
    );
    #[cfg(feature = "tui")]
    if let Some(handle) = tui_handle {
        handle.set_scanning_range(None);
    }

    match scan_result {
        Err(ChainError::Scan(err)) if err.is_continuity_error() => {
            // Pick a height to rewind to, which must be at least one block before the
            // height at which the error occurred, but may be an earlier height determined
            // based on heuristics such as the platform, available bandwidth, size of
            // recent CompactBlocks, etc.
            let rewind_height = err.at_height().saturating_sub(10);
            info!(
                "Chain reorg detected at {}, rewinding to {}",
                err.at_height(),
                rewind_height,
            );

            // Rewind to the chosen height.
            db_data.truncate_to_height(rewind_height)?;

            // Delete cached blocks from rewind_height onwards.
            //
            // This does imply that assumed-valid blocks will be re-downloaded, but it is
            // also possible that in the intervening time, a chain reorg has occurred that
            // orphaned some of those blocks.
            db_cache
                .with_blocks(Some(rewind_height + 1), None, |block| {
                    let meta = BlockMeta {
                        height: block.height(),
                        block_hash: block.hash(),
                        block_time: block.time,
                        // These values don't matter for deletion.
                        sapling_outputs_count: 0,
                        orchard_actions_count: 0,
                    };
                    std::fs::remove_file(get_block_path(fsblockdb_root, &meta))
                        .map_err(|e| ChainError::<(), _>::BlockSource(FsBlockDbError::Fs(e)))
                })
                .map_err(|e| anyhow!("{:?}", e))?;
            db_cache
                .truncate_to_height(rewind_height)
                .map_err(|e| anyhow!("{:?}", e))?;

            // The database was truncated, invalidating prior suggested ranges.
            Ok(true)
        }
        Ok(_) => {
            // If scanning these blocks caused a suggested range to be added that has a
            // higher priority than the current range, invalidate the current ranges.
            let latest_ranges = db_data.suggest_scan_ranges()?;
            #[cfg(feature = "tui")]
            if let Some(handle) = tui_handle {
                if handle.set_scan_ranges(&latest_ranges, chain_tip) {
                    // TUI exited.
                    return Ok(false);
                }
            }

            Ok(if let Some(range) = latest_ranges.first() {
                range.priority() > scan_range.priority()
            } else {
                false
            })
        }
        Err(e) => Err(anyhow!("{:?}", e)),
    }
}
