use super::*;
use crate::tests::{SEED, mine};

fn advance(node: &Node, height: u32) -> Result<()> {
    let mut data = node.data.lock().unwrap();
    while data.blocks.last().unwrap().height < height {
        mine(&mut data.blocks, None)?;
    }
    Ok(())
}

fn init(node: &Node, birthday_height: Option<u32>, sync_from_activation: bool) -> Operation {
    Operation::Init {
        rpc_url: node.url.clone(),
        activation_height: 8,
        cookie_file: None,
        accept_mock_proofs: true,
        birthday_height,
        sync_from_activation,
    }
}

fn sync_batch(dir: &std::path::Path, max_blocks: u32) -> Result<Value> {
    command(
        dir,
        Operation::Sync {
            max_blocks,
            from_height: None,
        },
    )
}

fn downloaded(node: &Node) -> Vec<u32> {
    node.data
        .lock()
        .unwrap()
        .requests
        .iter()
        .filter(|(method, _)| method == "gettachyonblock")
        .map(|(_, params)| params[0].as_str().unwrap().parse().unwrap())
        .collect()
}

#[test]
fn network_identity_check_reuses_canonical_tip() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    init_wallet(&node, &dir)?;
    command(
        &dir,
        Operation::Sync {
            max_blocks: 1000,
            from_height: None,
        },
    )?;
    node.data.lock().unwrap().requests.clear();
    command(
        &dir,
        Operation::Sync {
            max_blocks: 1000,
            from_height: None,
        },
    )?;
    let hashes: Vec<u64> = node
        .data
        .lock()
        .unwrap()
        .requests
        .iter()
        .filter(|(method, _)| method == "getblockhash")
        .map(|(_, params)| params[0].as_u64().unwrap())
        .collect();
    assert!(!hashes.contains(&0));
    assert_eq!(hashes.iter().filter(|height| **height == 8).count(), 2);
    Ok(())
}

#[test]
fn sync_many_command_returns_each_wallet_result() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let alice = temp.path().join("alice");
    let bob = temp.path().join("bob");
    init_wallet(&node, &alice)?;
    init_wallet(&node, &bob)?;
    advance(&node, 9)?;
    node.data.lock().unwrap().requests.clear();
    let result = crate::wallet::SyncManyCommand {
        wallet_dirs: vec![alice, bob],
        max_blocks: 1000,
        workers: 2,
        quiet: true,
    }
    .execute()?;
    assert_eq!(result["wallets"]["alice"]["height"], 9);
    assert_eq!(result["wallets"]["bob"]["height"], 9);
    let fetches = node
        .data
        .lock()
        .unwrap()
        .requests
        .iter()
        .filter(|(method, _)| method == "gettachyonblock")
        .count();
    assert_eq!(fetches, 1);
    Ok(())
}

#[test]
fn sync_many_shares_block_fetch_and_validation() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let alice = temp.path().join("alice");
    let bob = temp.path().join("bob");
    init_wallet(&node, &alice)?;
    init_wallet(&node, &bob)?;
    advance(&node, 9)?;
    node.data.lock().unwrap().requests.clear();
    let cache = std::sync::Arc::new(std::sync::Mutex::new(
        crate::wallet::sync::SyncCache::default(),
    ));
    let control = Control::new(true);
    for dir in [&alice, &bob] {
        let store = Store::open(dir, false)?;
        let config = store.config()?;
        crate::wallet::sync::sync_with_cache(&store, &config, 1000, None, &control, &cache)?;
        store.commit()?;
    }
    assert_eq!(cache.lock().unwrap().stats(), (1, 1));
    let fetches = node
        .data
        .lock()
        .unwrap()
        .requests
        .iter()
        .filter(|(method, _)| method == "gettachyonblock")
        .count();
    assert_eq!(fetches, 1);
    Ok(())
}

#[test]
fn new_wallet_only_downloads_current_epoch_even_when_old_payloads_are_pruned() -> Result<()> {
    let node = Node::start()?;
    let start = 8 + 2 * EPOCH_SIZE;
    advance(&node, start + 3)?;
    node.data.lock().unwrap().pruned_heights.extend(8..start);
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    let result = command(&dir, init(&node, None, false))?;
    assert_eq!(result["birthday_height"], start + 3);
    assert_eq!(result["sync_start_height"], start);
    assert_eq!(result["trusted_checkpoint"], true);
    let result = sync_batch(&dir, 2)?;
    assert_eq!(result["height"], start + 2);
    assert_eq!(result["caught_up"], false);
    assert_eq!(sync_batch(&dir, 2)?["caught_up"], true);
    assert_eq!(downloaded(&node), (start..=start + 3).collect::<Vec<_>>());
    Ok(())
}

#[test]
fn birthday_and_full_replay_select_epoch_boundaries_and_reject_invalid_heights() -> Result<()> {
    let node = Node::start()?;
    let start = 8 + EPOCH_SIZE;
    advance(&node, start + 3)?;
    let temp = tempfile::tempdir()?;
    let result = command(
        &temp.path().join("birthday"),
        init(&node, Some(start + 2), false),
    )?;
    assert_eq!(result["sync_start_height"], start);
    let result = command(&temp.path().join("full"), init(&node, None, true))?;
    assert_eq!(result["sync_start_height"], 8);
    assert_eq!(result["trusted_checkpoint"], false);
    for height in [7, start + 4] {
        let dir = temp.path().join(format!("invalid-{height}"));
        assert!(command(&dir, init(&node, Some(height), false)).is_err());
        assert!(!dir.exists());
    }
    Ok(())
}

#[test]
fn legacy_wallet_keeps_activation_history_and_receipt_metadata_is_additive() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    command(&dir, init(&node, None, true))?;
    let connection = rusqlite::Connection::open(dir.join("tachyon.sqlite"))?;
    connection.execute(
        "UPDATE config SET data=json_remove(data, '$.birthday_height')",
        [],
    )?;
    drop(connection);
    advance(&node, 10)?;
    let result = sync_batch(&dir, 10)?;
    assert_eq!(result["birthday_height"], 8);
    assert_eq!(result["sync_start_height"], 8);
    let store = Store::open(&dir, false)?;
    assert!(store.config()?.birthday_height.is_none());
    let legacy = crate::tests::own(100_000);
    assert!(serde_json::to_value(&legacy)?.get("locator").is_none());
    store.put_note(&legacy)?;
    let mut enriched = legacy.clone();
    enriched.locator = Some(Locator {
        txid: "ab".repeat(32),
        height: Some(9),
        block_hash: None,
    });
    assert_eq!(legacy.id()?, enriched.id()?);
    store.put_note(&enriched)?;
    store.put_note(&legacy)?;
    assert_eq!(store.notes()?, vec![enriched.clone()]);
    enriched.network_id = "wrong-network".into();
    assert!(store.put_note(&enriched).is_err());
    enriched.locator.as_mut().unwrap().txid = "invalid".into();
    assert!(enriched.note().is_err());
    Ok(())
}

/// A recovered wallet whose keys predate its current public-history checkpoint.
fn restore(node: &Node, dir: &std::path::Path, start: u32) -> Result<Receipt> {
    let data = node.data.lock().unwrap();
    let genesis = hex::encode([0; 32]);
    let activation_hash = data.blocks[0].hash.clone();
    let identity = Sha256::new()
        .chain_update(bytes32(&genesis)?)
        .chain_update(8u32.to_le_bytes())
        .chain_update(bytes32(&activation_hash)?)
        .finalize();
    let config = Config {
        version: 1,
        rpc_url: node.url.clone(),
        cookie_file: None,
        activation: 8,
        activation_hash,
        genesis,
        network_id: hex::encode(identity),
        seed: SEED,
        birthday_height: Some(start),
    };
    let receipt = Receipt::new(
        &config.network_id,
        &note::address(&SpendingKey::from(SEED)),
        1_000_000,
    )?;
    let store = Store::open(dir, true)?;
    store.set_config(&config)?;
    store.put_block(data.blocks.iter().find(|b| b.height == start).unwrap())?;
    store.commit()?;
    Ok(receipt)
}

#[test]
fn old_receipt_backfills_its_epoch_resumes_a_gap_and_reuses_cached_suffix() -> Result<()> {
    let node = Node::start()?;
    let start = 8 + EPOCH_SIZE;
    advance(&node, start)?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    let mut receipt = restore(&node, &dir, start)?;
    // Publish the receipt in the preceding epoch, then rebuild the fixture chain.
    {
        let mut data = node.data.lock().unwrap();
        data.blocks.truncate(1);
        let tx = crate::tests::shield(&data.blocks, &receipt)?;
        receipt.locator = Some(Locator {
            txid: tx.txid().to_string(),
            height: None,
            block_hash: None,
        });
        mine(&mut data.blocks, Some(&tx))?;
    }
    advance(&node, start + 2)?;
    {
        let data = node.data.lock().unwrap();
        let store = Store::open(&dir, false)?;
        store.clear_chain()?;
        for block in data.blocks.iter().filter(|b| b.height >= start) {
            store.put_block(block)?;
        }
        store.put_note(&receipt)?;
        store.commit()?;
    }
    let result = sync_batch(&dir, 1)?;
    assert_eq!(result["sync_start_height"], 8);
    assert_eq!(result["height"], 9);
    assert_eq!(result["caught_up"], false);
    assert_eq!(result["unresolved_receipts"], 0);
    {
        let store = Store::open(&dir, false)?;
        assert_eq!(store.blocks()?.last().unwrap().height, 9);
        assert!(store.block(start)?.is_some()); // Gap hides, but does not discard, cached suffix.
        assert_eq!(store.notes()?[0].locator.as_ref().unwrap().height, Some(9));
        // Model previously cached public evidence with one block still missing.
        // This keeps the integration test fast without 4096 round-trip HTTP requests.
        let data = node.data.lock().unwrap();
        for block in data
            .blocks
            .iter()
            .filter(|b| (11..start).contains(&b.height))
        {
            store.put_block(block)?;
        }
        store.commit()?;
    }
    node.data.lock().unwrap().requests.clear();
    sync_batch(&dir, 1)?;
    assert_eq!(downloaded(&node), vec![10]);
    assert_eq!(sync_batch(&dir, 10)?["caught_up"], true);
    assert_eq!(
        command(&dir, Operation::Balance)?["available_zat"],
        receipt.value_zat
    );
    let store = Store::open(&dir, false)?;
    let blocks = store.blocks()?;
    let sent = transaction::build(
        Payment {
            seed: SEED,
            blocks: (&blocks).into(),
            spend: Some(&receipt),
            funding: None,
            outputs: &[Receipt::new(
                &receipt.network_id,
                &note::address(&SpendingKey::from(SEED)),
                950_000,
            )?],
            transparent_output: None,
            expiry: start + 20,
        },
        &Control::new(true),
    )?;
    transaction::verify_for_test(&sent, None)?;
    Ok(())
}

#[test]
fn locator_follows_stale_height_and_aggregate_stamp_but_rejects_wrong_commitment() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    let mut receipt = restore(&node, &dir, 8)?;
    let leaf_txid = "ab".repeat(32);
    {
        let mut data = node.data.lock().unwrap();
        mine(&mut data.blocks, None)?;
        let tx = crate::tests::shield(&data.blocks, &receipt)?;
        mine(&mut data.blocks, Some(&tx))?;
        let block = data.blocks.last_mut().unwrap();
        block.transactions.push(leaf_txid.clone());
        // Commitment is carried by an aggregate's stamp, not the leaf's stamp.
        assert_ne!(block.stamps[0].txid, leaf_txid);
        data.pruned_heights.insert(9); // Stale hint must not download this payload.
    }
    receipt.locator = Some(Locator {
        txid: leaf_txid,
        height: Some(9),
        block_hash: Some("ff".repeat(32)),
    });
    let store = Store::open(&dir, false)?;
    let config = store.config()?;
    let rpc = rpc(&config, &Control::new(true))?;
    assert_eq!(
        sync::locate(&rpc, &receipt, &config, 10)?.unwrap().height,
        10
    );
    let mut unrelated = Receipt::new(
        &config.network_id,
        &note::address(&SpendingKey::from(SEED)),
        123,
    )?;
    unrelated.locator = receipt.locator.clone();
    assert!(
        sync::locate(&rpc, &unrelated, &config, 10)
            .unwrap_err()
            .to_string()
            .contains("note commitment")
    );
    receipt.locator.as_mut().unwrap().txid = "cd".repeat(32);
    assert!(sync::locate(&rpc, &receipt, &config, 10)?.is_none());
    assert!(!downloaded(&node).contains(&9));
    Ok(())
}

#[test]
fn missing_history_and_cancelled_backfill_preserve_wallet_and_checkpoint() -> Result<()> {
    let node = Node::start()?;
    let start = 8 + EPOCH_SIZE;
    advance(&node, start)?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    let receipt = restore(&node, &dir, start)?;
    {
        let store = Store::open(&dir, false)?;
        store.put_note(&receipt)?; // Legacy receipt: no locator, explicit search height below.
        store.commit()?;
    }
    node.data.lock().unwrap().pruned_heights.insert(9);
    let operation = || Operation::Sync {
        max_blocks: 2,
        from_height: Some(9),
    };
    let error = command(&dir, operation()).unwrap_err();
    assert!(format!("{error:#}").contains("archive node"));
    node.data.lock().unwrap().pruned_heights.clear();
    let control = Control::new(true);
    node.data.lock().unwrap().cancel_request = Some((
        "gettachyonblock".into(),
        Some(json!(["9"])),
        control.clone(),
    ));
    assert!(
        Command {
            wallet_dir: dir.clone(),
            quiet: true,
            operation_id: None,
            expected_tip: None,
            command: operation()
        }
        .execute_with_control(&control)
        .is_err()
    );
    let store = Store::open(&dir, false)?;
    assert_eq!(store.blocks()?.len(), 1);
    assert_eq!(store.blocks()?[0].height, start);
    assert_eq!(store.notes()?, vec![receipt]);
    Ok(())
}

#[test]
fn reorg_crossing_recent_checkpoint_reloads_it_without_losing_receipts() -> Result<()> {
    let node = Node::start()?;
    let start = 8 + EPOCH_SIZE;
    advance(&node, start + 2)?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    command(&dir, init(&node, None, false))?;
    sync_batch(&dir, 10)?;
    let receipt = {
        let store = Store::open(&dir, false)?;
        let config = store.config()?;
        let receipt = Receipt::new(
            &config.network_id,
            &note::address(&SpendingKey::from(config.seed)),
            123,
        )?;
        store.put_note(&receipt)?;
        store.commit()?;
        receipt
    };
    {
        let mut data = node.data.lock().unwrap();
        data.blocks.truncate(usize::try_from(start - 8 + 1)?);
        data.blocks.last_mut().unwrap().hash = "cc".repeat(32);
    }
    advance(&node, start + 1)?;
    // The synthetic miner hashes heights only; real descendant hashes also
    // change when their predecessor changes.
    node.data.lock().unwrap().blocks.last_mut().unwrap().hash = "dd".repeat(32);
    let result = sync_batch(&dir, 10)?;
    assert_eq!(result["caught_up"], true);
    let store = Store::open(&dir, false)?;
    assert_eq!(store.blocks()?[0].hash, "cc".repeat(32));
    assert_eq!(store.blocks()?.last().unwrap().height, start + 1);
    assert_eq!(store.funding_snapshot()?.unwrap().height, start + 1);
    assert_eq!(store.notes()?, vec![receipt]);
    Ok(())
}

#[test]
fn progress_uses_actual_batch_heights() {
    assert_eq!(
        sync::progress(15_635, 10_009, 20_008, 30_000),
        "Fetching block 15635 (batch heights 10009–20008; node tip 30000)…"
    );
    assert_eq!(sync::epoch_start(32_789, 8).unwrap(), 32_776);
}
