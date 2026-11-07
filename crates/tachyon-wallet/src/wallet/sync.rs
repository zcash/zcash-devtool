//! Birthday checkpoints and bounded backfills of contiguous public evidence.

use super::*;
use crate::{chain::Block, note::Locator, rpc::RpcError};

pub(super) fn epoch_start(height: u32, activation: u32) -> Result<u32> {
    let offset = height
        .checked_sub(activation)
        .context("height precedes NuTachyon activation")?;
    Ok(height - offset % EPOCH_SIZE)
}

pub(super) fn checkpoint(rpc: &Rpc, height: u32, activation: u32) -> Result<Block> {
    rpc.control.stage(format!(
        "Loading trusted epoch checkpoint at height {height}…"
    ))?;
    let block = fetch_block(rpc, height)?;
    block.validate_checkpoint(activation)?;
    ensure!(
        rpc.hash(height)? == block.hash,
        "checkpoint changed during initialization; retry"
    );
    Ok(block)
}

fn fetch_block(rpc: &Rpc, height: u32) -> Result<Block> {
    rpc.block(height).with_context(|| format!(
        "cannot obtain Tachyon evidence at height {height}; if it has been pruned, use an archive node (proof-service recovery is not implemented)"
    ))
}

#[derive(Default)]
pub(crate) struct SyncCache {
    blocks: std::collections::BTreeMap<u32, Block>,
    validated: std::collections::BTreeSet<(u32, String, String)>,
    fetches: usize,
    validations: usize,
}

impl SyncCache {
    fn fetch(&mut self, rpc: &Rpc, height: u32) -> Result<Block> {
        let hash = rpc.hash(height)?;
        if let Some(block) = self.blocks.get(&height)
            && block.hash == hash
        {
            return Ok(block.clone());
        }
        let block = rpc.block(height).with_context(|| format!(
            "cannot obtain Tachyon evidence at height {height}; if it has been pruned, use an archive node (proof-service recovery is not implemented)"
        ))?;
        ensure!(block.hash == hash, "Tachyon block changed during fetch");
        self.blocks.insert(height, block.clone());
        self.fetches += 1;
        Ok(block)
    }

    fn validate(&mut self, block: &Block, previous: Option<&Block>, activation: u32) -> Result<()> {
        let key = (
            block.height,
            block.hash.clone(),
            previous.map(|block| block.hash.clone()).unwrap_or_default(),
        );
        if self.validated.contains(&key) {
            return Ok(());
        }
        block.validate(previous, activation)?;
        self.validated.insert(key);
        self.validations += 1;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn stats(&self) -> (usize, usize) {
        (self.fetches, self.validations)
    }
}

/// Hints only narrow the search. Aggregation can put a leaf transaction's
/// commitment in another transaction's stamp in the same block.
fn contains_receipt(block: &Block, receipt: &Receipt, locator: &Locator) -> Result<bool> {
    let cm = receipt.id()?;
    Ok(block.transactions.contains(&locator.txid)
        && block
            .stamps
            .iter()
            .any(|stamp| stamp.tachygrams.contains(&cm)))
}

fn located_block(
    rpc: &Rpc,
    height: u32,
    receipt: &Receipt,
    locator: &Locator,
    config: &Config,
    tip: u32,
) -> Result<Option<Block>> {
    if height < config.activation || height > tip {
        return Ok(None);
    }
    // Check the cheap, retained block metadata first. A stale height hint must
    // not require the payload of an unrelated, potentially pruned block.
    let hash = rpc.hash(height)?;
    let header: Value = rpc.call("getblock", json!([hash, 1]))?;
    ensure!(
        header["hash"] == hash && header["height"] == height,
        "receipt block identity mismatch"
    );
    let transactions = header["tx"]
        .as_array()
        .context("receipt block has no transaction list")?;
    if !transactions
        .iter()
        .any(|id| id.as_str() == Some(locator.txid.as_str()))
    {
        return Ok(None);
    }
    let block = fetch_block(rpc, height)?;
    // The subsequent contiguous sync validates the transitions from our
    // checkpoint. This lookup alone never makes a note spendable.
    ensure!(
        hash == block.hash && rpc.hash(height)? == block.hash,
        "receipt block changed during lookup; retry sync"
    );
    Ok(contains_receipt(&block, receipt, locator)?.then_some(block))
}

pub(super) fn locate(
    rpc: &Rpc,
    receipt: &Receipt,
    config: &Config,
    tip: u32,
) -> Result<Option<Block>> {
    let Some(locator) = &receipt.locator else {
        return Ok(None);
    };
    if let Some(height) = locator.height
        && let Some(block) = located_block(rpc, height, receipt, locator, config, tip)?
    {
        return Ok(Some(block));
    }
    // A reorg can move the same transaction to another height. Ignore the
    // stale hint and resolve the txid against the node's current chain.
    let result: Value = match rpc.call("getrawtransaction", json!([locator.txid, 1])) {
        Ok(result) => result,
        Err(error) if error.downcast_ref::<RpcError>().is_some_and(|error| error.code == Some(-5)) => return Ok(None),
        Err(error) => return Err(error.context("cannot locate receipt transaction; supply --txid/--height if the node lacks historical transaction lookup")),
    };
    let Some(hash) = result["blockhash"].as_str() else {
        return Ok(None);
    };
    bytes32(hash)?;
    let header: Value = rpc.call("getblock", json!([hash, 1]))?;
    let height = u32::try_from(
        header["height"]
            .as_u64()
            .context("receipt block has no height")?,
    )?;
    if height > tip || height < config.activation || rpc.hash(height)? != hash {
        return Ok(None); // Mempool, side-chain, or newer than this sync snapshot.
    }
    ensure!(header["hash"] == hash, "receipt block identity mismatch");
    let block = located_block(rpc, height, receipt, locator, config, tip)?;
    ensure!(
        block.is_some(),
        "receipt transaction does not contain the note commitment in its block; correct its locator"
    );
    Ok(block)
}

pub(super) fn progress(height: u32, first: u32, stop: u32, tip: u32) -> String {
    format!("Fetching block {height} (batch heights {first}–{stop}; node tip {tip})…")
}

pub(super) fn sync(
    store: &Store,
    config: &Config,
    max_blocks: u32,
    from_height: Option<u32>,
    control: &Control,
) -> Result<Value> {
    let cache = std::sync::Arc::new(std::sync::Mutex::new(SyncCache::default()));
    sync_with_cache(store, config, max_blocks, from_height, control, &cache)
}

pub(crate) fn sync_with_cache(
    store: &Store,
    config: &Config,
    max_blocks: u32,
    from_height: Option<u32>,
    control: &Control,
    cache: &std::sync::Arc<std::sync::Mutex<SyncCache>>,
) -> Result<Value> {
    store.check_evidence_identity(config)?;
    let rpc = rpc(config, control)?;
    let funding_address = transaction::funding_address(config.seed)?;
    let funding = AddressUtxos::fetch(&rpc, &funding_address)?;
    let tip = funding.height;
    ensure!(
        tip >= config.activation,
        "node tip precedes NuTachyon activation"
    );
    control.stage("Loading saved chain inputs…")?;
    let initial_start = store.first_height()?.context("wallet has no checkpoint")?;
    let original_last = store.tip()?.context("wallet has no checkpoint")?;
    let original_hash = if original_last.height <= tip {
        Some(rpc.hash(original_last.height)?)
    } else {
        None
    };
    if !(store.network_identity_valid(config)?
        && original_hash.as_deref() == Some(original_last.hash.as_str()))
    {
        ensure!(
            rpc.hash(0)? == config.genesis
                && rpc.hash(config.activation)? == config.activation_hash,
            "network identity changed (including possible regenesis); use a separate wallet directory"
        );
        store.mark_network_identity_valid(config)?;
    }
    let mut reorg = false;
    let mut first = initial_start;
    let mut last = Some(original_last.clone());
    while let Some(candidate) = last.clone() {
        control.check()?;
        let matches = if candidate.height > tip {
            false
        } else {
            let hash = if candidate.height == original_last.height {
                original_hash.clone().expect("original tip was hashed")
            } else {
                rpc.hash(candidate.height)?
            };
            hash == candidate.hash
        };
        if matches {
            break;
        }
        last = if candidate.height == initial_start {
            None
        } else {
            store.block(candidate.height - 1)?
        };
    }
    if let Some(last) = last.clone() {
        if last.height != original_last.height {
            store.rewind(last.height)?;
            reorg = true;
        }
    } else {
        // A checkpoint is pinned to a block, not an eternally trusted height.
        // Re-bootstrap on the configured node after a reorg crossing it.
        reorg = true;
        let height = epoch_start(initial_start.min(tip), config.activation)?;
        let block = checkpoint(&rpc, height, config.activation)?;
        store.clear_chain()?;
        store.put_block(&block)?;
        first = height;
        last = Some(block);
    }
    let last = last.expect("checkpoint was retained or reloaded");
    let mut needed_start = first;
    if let Some(height) = from_height {
        ensure!(height <= tip, "search height is above the node tip");
        needed_start = needed_start.min(epoch_start(height, config.activation)?);
    }
    for mut receipt in store.unresolved_notes()? {
        control.check()?;
        receipt.check_owner(&SpendingKey::from(config.seed), &config.network_id)?;
        if let Some(block) = locate(&rpc, &receipt, config, tip)? {
            needed_start = needed_start.min(epoch_start(block.height, config.activation)?);
            let locator = receipt
                .locator
                .as_mut()
                .expect("located receipts have a locator");
            locator.height = Some(block.height);
            locator.block_hash = Some(block.hash);
            store.put_note(&receipt)?;
        }
    }
    let backfill = needed_start < first;
    let mut previous = if backfill {
        let block = checkpoint(&rpc, needed_start, config.activation)?;
        store.put_block(&block)?;
        store.clear_funding_snapshot()?;
        // Keep the cached suffix on disk and reconnect it as the bounded
        // backfill advances. No wallet notes or reservations are discarded.
        Some(block)
    } else {
        Some(last)
    };
    let start = previous.as_ref().expect("sync has a checkpoint").height;
    let stop = start.saturating_add(max_blocks).min(tip);
    control.stage(format!(
        "Syncing heights {}–{stop} (node tip {tip})…",
        start.saturating_add(1).min(stop)
    ))?;
    for height in start.saturating_add(1)..=stop {
        control.stage(progress(height, start.saturating_add(1), stop, tip))?;
        let block = if let Some(cached) = store.block(height)? {
            if rpc.hash(height)? == cached.hash {
                cached
            } else {
                store.rewind(height - 1)?;
                reorg = true;
                cache.lock().unwrap().fetch(&rpc, height)?
            }
        } else {
            cache.lock().unwrap().fetch(&rpc, height)?
        };
        control.stage(format!("Validating block {height}…"))?;
        cache
            .lock()
            .unwrap()
            .validate(&block, previous.as_ref(), config.activation)?;
        control.check()?;
        store.put_block(&block)?;
        previous = Some(block);
    }
    let last = previous.expect("sync has a checkpoint");
    if last.height == tip {
        control.stage("Validating transparent funding snapshot…")?;
        store.put_funding_snapshot(&funding.into_snapshot(&rpc, &funding_address, store)?)?;
    }
    ensure!(
        rpc.hash(last.height)? == last.hash,
        "chain reorganized during sync; retry"
    );
    super::refresh_note_nullifiers(store, config, last.epoch)?;
    let unresolved = store.unresolved_notes()?.len();
    Ok(
        json!({"height":last.height,"hash":last.hash,"epoch":last.epoch,"caught_up":last.height == tip,
        "reorg":reorg,
        "birthday_height":config.birthday_height.unwrap_or(config.activation),
        "sync_start_height":if backfill { needed_start } else { first },
        "unresolved_receipts":unresolved,
        "transparent_synced_height":store.funding_snapshot()?.map(|snapshot| snapshot.height)}),
    )
}
