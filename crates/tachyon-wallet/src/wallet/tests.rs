use super::*;
use crate::chain::Block;
use primitives::transaction::{Authorized, TransactionData};
use protocol::{consensus::BlockHeight, value::Zatoshis};
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
use transparent::bundle::{Bundle, TxOut};
use zcash_tachyon::TachyonBundle;

mod sync_cases;

struct NodeData {
    blocks: Vec<Block>,
    raw_funding: String,
    raw_transactions: BTreeMap<String, String>,
    txout_overrides: BTreeMap<(String, u32), Value>,
    mempool: Vec<String>,
    fail_submission: bool,
    submissions: usize,
    funding_utxos: Vec<Value>,
    fail_funding_sync: bool,
    funding_hash_override: Option<String>,
    earlier_blocks: BTreeMap<u32, Value>,
    cancel_request: Option<(String, Option<Value>, Control)>,
    requests: Vec<(String, Value)>,
    pruned_heights: BTreeSet<u32>,
}
struct Node {
    url: String,
    data: Arc<Mutex<NodeData>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Drop for Node {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}
impl Node {
    fn start() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let url = format!("http://{}", listener.local_addr()?);
        let data = Arc::new(Mutex::new(NodeData {
            blocks: vec![crate::tests::genesis()],
            raw_funding: String::new(),
            raw_transactions: BTreeMap::new(),
            txout_overrides: BTreeMap::new(),
            mempool: vec![],
            fail_submission: false,
            submissions: 0,
            funding_utxos: vec![],
            fail_funding_sync: false,
            funding_hash_override: None,
            earlier_blocks: BTreeMap::new(),
            cancel_request: None,
            requests: vec![],
            pruned_heights: BTreeSet::new(),
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_data = data.clone();
        let thread_stop = stop.clone();
        let worker = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                let (stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(e) => panic!("mock listener: {e}"),
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(stream);
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap();
                    }
                }
                assert!(length < 16 * 1024 * 1024);
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let request: Value = serde_json::from_slice(&body).unwrap();
                let mut data = thread_data.lock().unwrap();
                let params = &request["params"];
                data.requests
                    .push((request["method"].as_str().unwrap().into(), params.clone()));
                let mut error = Value::Null;
                let result = match request["method"].as_str().unwrap() {
                    "getblockchaininfo" => json!({"chain":"test"}),
                    "getblockcount" => json!(data.blocks.last().unwrap().height),
                    "getaddressutxos" => {
                        assert_eq!(params[0]["chainInfo"], true);
                        if data.fail_funding_sync {
                            error = json!({"code": -1, "message": "simulated UTXO index error"});
                        }
                        let tip = data.blocks.last().unwrap();
                        json!({"height": tip.height, "hash": data.funding_hash_override.as_ref().unwrap_or(&tip.hash),
                            "utxos": data.funding_utxos.iter().filter(|output| output["address"] == params[0]["addresses"][0]).collect::<Vec<_>>()})
                    }
                    "getblockhash" => {
                        let h = params[0].as_u64().unwrap();
                        if h == 0 {
                            json!(hex::encode([0; 32]))
                        } else {
                            json!(
                                data.blocks
                                    .iter()
                                    .find(|b| u64::from(b.height) == h)
                                    .unwrap()
                                    .hash
                            )
                        }
                    }
                    "gettachyonblock" => {
                        let h: u32 = params[0].as_str().unwrap().parse().unwrap();
                        if data.pruned_heights.contains(&h) {
                            error = json!({"code":-1,"message":"tachygram payload pruned"});
                            Value::Null
                        } else {
                            serde_json::to_value(
                                data.blocks.iter().find(|b| b.height == h).unwrap(),
                            )
                            .unwrap()
                        }
                    }
                    "getblock" => {
                        let id = params[0].as_str().unwrap();
                        if let Some(block) = id
                            .parse::<u32>()
                            .ok()
                            .and_then(|height| data.earlier_blocks.get(&height))
                        {
                            block.clone()
                        } else {
                            let block = data
                                .blocks
                                .iter()
                                .find(|b| b.hash == id || Some(b.height) == id.parse::<u32>().ok())
                                .unwrap();
                            json!({"hash":block.hash,"height":block.height,"tx":block.transactions})
                        }
                    }
                    "gettxout" => {
                        assert_eq!(params[2], true);
                        let key = (
                            params[0].as_str().unwrap().to_owned(),
                            u32::try_from(params[1].as_u64().unwrap()).unwrap(),
                        );
                        data.txout_overrides
                            .get(&key)
                            .cloned()
                            .unwrap_or_else(|| json!({"confirmations":100,"coinbase":false}))
                    }
                    "getrawtransaction" if params[1] == 1 => {
                        let txid = params[0].as_str().unwrap();
                        if let Some(block) = data
                            .blocks
                            .iter()
                            .find(|block| block.transactions.iter().any(|id| id == txid))
                        {
                            json!({"txid":txid,"blockhash":block.hash})
                        } else if data.mempool.iter().any(|raw| {
                            Transaction::read(&hex::decode(raw).unwrap()[..], BranchId::NuTachyon)
                                .unwrap()
                                .txid()
                                .to_string()
                                == txid
                        }) {
                            json!({"txid":txid})
                        } else {
                            error = json!({"code":-5,"message":"Transaction not found in mempool or best chain"});
                            Value::Null
                        }
                    }
                    "getrawtransaction" => json!(
                        data.raw_transactions
                            .get(params[0].as_str().unwrap())
                            .unwrap_or(&data.raw_funding)
                    ),
                    "sendrawtransaction" => {
                        data.submissions += 1;
                        let raw = params[0].as_str().unwrap().to_owned();
                        let tx =
                            Transaction::read(&hex::decode(&raw).unwrap()[..], BranchId::NuTachyon)
                                .unwrap();
                        if !data.mempool.contains(&raw) {
                            data.mempool.push(raw);
                        }
                        if data.fail_submission {
                            error = json!({"code":-1,"message":"simulated ambiguous broadcast"});
                        }
                        json!(tx.txid().to_string())
                    }
                    other => panic!("unexpected RPC {other}"),
                };
                if let Some((method, params, control)) = &data.cancel_request
                    && request["method"] == *method
                    && params
                        .as_ref()
                        .is_none_or(|params| request["params"] == *params)
                {
                    control.cancellation.cancel();
                }
                drop(data);
                let response = serde_json::to_vec(
                    &json!({"jsonrpc":"2.0","id":1,"result":result,"error":error}),
                )
                .unwrap();
                let mut stream = reader.into_inner();
                // Cancellation can drop the HTTP connection before the reply.
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                    response.len()
                );
                let _ = stream
                    .write_all(reply.as_bytes())
                    .and_then(|_| stream.write_all(&response));
            }
        });
        Ok(Self {
            url,
            data,
            stop,
            worker: Some(worker),
        })
    }
    fn mine(&self) -> Result<()> {
        let mut data = self.data.lock().unwrap();
        let raw = data.mempool.remove(0);
        let tx = Transaction::read(&hex::decode(&raw)?[..], BranchId::NuTachyon)?;
        data.raw_transactions.insert(tx.txid().to_string(), raw);
        if let Some(bundle) = tx.transparent_bundle() {
            for input in &bundle.vin {
                let txid =
                    primitives::transaction::TxId::from_bytes(*input.prevout().hash()).to_string();
                data.funding_utxos.retain(|output| {
                    output["txid"] != txid || output["outputIndex"] != input.prevout().n()
                });
            }
        }
        crate::tests::mine(&mut data.blocks, Some(&tx))?;
        let block = data.blocks.last_mut().unwrap();
        block.transactions.insert(0, "55".repeat(32));
        for stamp in &mut block.stamps {
            stamp.transaction_index += 1;
        }
        Ok(())
    }
    fn mine_to(&self, addresses: &[&str]) -> Result<Transaction> {
        let tx = {
            let mut data = self.data.lock().unwrap();
            let tx = Transaction::read(&hex::decode(&data.mempool[0])?[..], BranchId::NuTachyon)?;
            let height = data.blocks.last().unwrap().height + 1;
            if let Some(bundle) = tx.transparent_bundle() {
                for (index, output) in bundle.vout.iter().enumerate() {
                    for address in addresses {
                        if *output.script_pubkey() == transaction::transparent_script(address)? {
                            data.funding_utxos.push(funding_utxo(
                                address,
                                &tx.txid().to_string(),
                                u32::try_from(index)?,
                                height,
                                output.value().into_u64(),
                            )?);
                        }
                    }
                }
            }
            tx
        };
        self.mine()?;
        Ok(tx)
    }
}

fn command(dir: &std::path::Path, command: Operation) -> Result<Value> {
    command_with_id(dir, command, None)
}
fn command_with_id(dir: &std::path::Path, command: Operation, id: Option<&str>) -> Result<Value> {
    Command {
        wallet_dir: dir.into(),
        operation_id: id.map(str::to_owned),
        expected_tip: None,
        quiet: true,
        command,
    }
    .execute()
}

fn transparent_send(to: &str, amount_zat: u64) -> Operation {
    Operation::TransparentSend {
        to: to.into(),
        amount_zat,
    }
}

#[test]
fn consolidate_combines_multiple_notes_into_one() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    let address = init_wallet(&node, &dir)?;
    install_funding(&node, &address, &[200_000, 300_000])?;
    for _ in 0..2 {
        command(
            &dir,
            Operation::Shield {
                amount_zat: Some(100_000),
                txid: None,
                index: None,
            },
        )?;
        node.mine()?;
    }
    command(
        &dir,
        Operation::Sync {
            max_blocks: 1000,
            from_height: None,
        },
    )?;
    assert_eq!(
        command(&dir, Operation::BalanceSummary)?["notes"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    command(&dir, Operation::Consolidate { max_inputs: 16 })?;
    node.mine()?;
    command(
        &dir,
        Operation::Sync {
            max_blocks: 1000,
            from_height: None,
        },
    )?;
    let balance = command(&dir, Operation::BalanceSummary)?;
    assert_eq!(balance["available_zat"], 150_000);
    assert_eq!(balance["notes"].as_array().unwrap().len(), 1);
    Ok(())
}

#[test]
fn send_combines_notes_when_no_single_note_is_sufficient() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    let funding_address = init_wallet(&node, &dir)?;
    install_funding(&node, &funding_address, &[200_000, 300_000])?;
    for _ in 0..2 {
        command(
            &dir,
            Operation::Shield {
                amount_zat: Some(100_000),
                txid: None,
                index: None,
            },
        )?;
        node.mine()?;
    }
    command(
        &dir,
        Operation::Sync {
            max_blocks: 1000,
            from_height: None,
        },
    )?;
    let own = command(&dir, Operation::Address)?["tachyon_address"]
        .as_str()
        .unwrap()
        .to_owned();
    command(
        &dir,
        Operation::Send {
            to: own,
            amount_zat: 150_000,
        },
    )?;
    assert_eq!(
        command(&dir, Operation::BalanceSummary)?["available_zat"],
        0
    );
    node.mine()?;
    command(
        &dir,
        Operation::Sync {
            max_blocks: 1000,
            from_height: None,
        },
    )?;
    let balance = command(&dir, Operation::BalanceSummary)?;
    assert_eq!(balance["available_zat"], 150_000, "{balance}");
    Ok(())
}

#[test]
fn balance_summary_allows_unconfirmed_notes_without_nullifiers() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    let address = init_wallet(&node, &dir)?;
    install_funding(&node, &address, &[150_000])?;
    command(
        &dir,
        Operation::Shield {
            amount_zat: Some(100_000),
            txid: None,
            index: None,
        },
    )?;
    let result = command(&dir, Operation::BalanceSummary)?;
    assert_eq!(result["available_zat"], 0);
    assert!(result["notes"].as_array().unwrap().is_empty());
    Ok(())
}

#[test]
fn balance_summary_exposes_validated_funding_candidates() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    let address = init_wallet(&node, &dir)?;
    let funding = install_funding(&node, &address, &[100_000, 200_000])?;
    command(
        &dir,
        Operation::Sync {
            max_blocks: 1000,
            from_height: None,
        },
    )?;
    let result = command(&dir, Operation::BalanceSummary)?;
    let candidates = result["transparent"]["funding_candidates"]
        .as_array()
        .context("funding candidates must be an array")?;
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0]["satoshis"], 100_000);
    assert_eq!(candidates[1]["satoshis"], 200_000);
    assert!(
        candidates
            .iter()
            .all(|candidate| candidate["coinbase"] == false)
    );
    assert!(
        candidates
            .iter()
            .all(|candidate| { candidate["txid"] == funding.txid().to_string() })
    );
    Ok(())
}

#[test]
fn expected_tip_skips_redundant_sync_and_rejects_stale_tip() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    let address = init_wallet(&node, &dir)?;
    install_funding(&node, &address, &[150_000])?;
    command(
        &dir,
        Operation::Shield {
            amount_zat: Some(100_000),
            txid: None,
            index: None,
        },
    )?;
    node.mine()?;
    let synced = command(
        &dir,
        Operation::Sync {
            max_blocks: 1000,
            from_height: None,
        },
    )?;
    let tip = synced["hash"].as_str().unwrap().to_string();
    node.data.lock().unwrap().requests.clear();
    let result = Command {
        wallet_dir: dir.clone(),
        operation_id: None,
        expected_tip: Some(tip.clone()),
        quiet: true,
        command: Operation::Send {
            to: note::address(&SpendingKey::from([9; 32])),
            amount_zat: 50_000,
        },
    }
    .execute()?;
    assert_eq!(result["status"], "submitted");
    let requests = node.data.lock().unwrap().requests.clone();
    assert!(
        !requests
            .iter()
            .any(|(method, _)| method == "getaddressutxos")
    );
    assert!(
        !requests
            .iter()
            .any(|(method, _)| method == "gettachyonblock")
    );

    node.data.lock().unwrap().requests.clear();
    let error = Command {
        wallet_dir: dir,
        operation_id: None,
        expected_tip: Some(hex::encode([0; 32])),
        quiet: true,
        command: Operation::Send {
            to: note::address(&SpendingKey::from([9; 32])),
            amount_zat: 50_000,
        },
    }
    .execute()
    .unwrap_err();
    assert!(error.to_string().contains("does not match expected tip"));
    Ok(())
}

#[test]
fn transparent_payments_return_change_cycle_between_wallets_and_reshield() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let alice = temp.path().join("alice");
    let bob = temp.path().join("bob");
    let alice_address = init_wallet(&node, &alice)?;
    let bob_address = init_wallet(&node, &bob)?;
    let funding = install_funding(&node, &alice_address, &[250_000, 550_000, 150_000])?;
    let result = command_with_id(
        &alice,
        transparent_send(&bob_address, 150_000),
        Some("round-1:alice"),
    )?;
    assert_eq!(result["operation_id"], "round-1:alice");
    assert_eq!(result["reused"], false);
    let tx = node.mine_to(&[&alice_address, &bob_address])?;
    assert!(matches!(tx.tachyon_bundle(), TachyonBundle::NoBundle));
    let bundle = tx.transparent_bundle().unwrap();
    assert_eq!(bundle.vin[0].prevout().n(), 0);
    assert_eq!(bundle.vout.len(), 2);
    assert_eq!(bundle.vout[0].value().into_u64(), 150_000);
    assert_eq!(bundle.vout[1].value().into_u64(), 50_000);
    transaction::verify_for_test(
        &tx,
        Some(funding.transparent_bundle().unwrap().vout[0].clone()),
    )?;
    assert_eq!(
        synced_balance(&alice)?["transparent"]["available_zat"],
        750_000
    );
    let balance = synced_balance(&bob)?;
    assert_eq!(balance["transparent"]["available_zat"], 150_000);
    assert_eq!(balance["available_zat"], 0);
    assert_eq!(
        command(
            &alice,
            Operation::Lookup {
                id: "round-1:alice".into()
            }
        )?["status"],
        "mined"
    );
    command(&bob, transparent_send(&alice_address, 100_000))?;
    let returned = node.mine_to(&[&alice_address, &bob_address])?;
    assert_eq!(returned.transparent_bundle().unwrap().vout.len(), 1); // Exact funding: no change.
    transaction::verify_for_test(&returned, Some(bundle.vout[0].clone()))?;
    assert_eq!(synced_balance(&bob)?["transparent"]["total_zat"], 0);
    command_with_id(
        &alice,
        Operation::Shield {
            amount_zat: None,
            txid: Some(returned.txid().to_string()),
            index: Some(0),
        },
        Some("reshield"),
    )?;
    node.mine_to(&[&alice_address, &bob_address])?;
    assert_eq!(synced_balance(&alice)?["available_zat"], 50_000);
    assert_eq!(
        command(
            &alice,
            Operation::Lookup {
                id: "reshield".into()
            }
        )?["request"]["kind"],
        "shield"
    );
    Ok(())
}

#[test]
fn operation_id_recovers_ambiguous_broadcast_and_replays_without_network() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    let address = init_wallet(&node, &dir)?;
    install_funding(&node, &address, &[250_000])?;
    let to = transaction::funding_address(crate::tests::SEED)?;
    node.data.lock().unwrap().fail_submission = true;
    assert!(command_with_id(&dir, transparent_send(&to, 100_000), Some("job:1")).is_err());
    let saved = command(&dir, Operation::Lookup { id: "job:1".into() })?;
    assert_eq!(saved["status"], "pending");
    let pending = Store::open(&dir, false)?.pending()?;
    assert_eq!(pending.len(), 1);
    assert_eq!(saved["txid"], pending[0].txid);
    assert_eq!(pending[0].raw, node.data.lock().unwrap().mempool[0]);
    assert_eq!(
        command(&dir, Operation::Balance)?["transparent"]["reserved_zat"],
        250_000
    );
    let reused = command_with_id(&dir, transparent_send(&to, 100_000), Some("job:1"))?;
    assert_eq!(reused["txid"], saved["txid"]);
    assert_eq!(reused["reused"], true);
    assert_eq!(node.data.lock().unwrap().submissions, 1);
    drop(node);
    // Neither lookup nor replay require the node, even after the ambiguous submission.
    assert_eq!(
        command(&dir, Operation::Lookup { id: "job:1".into() })?,
        saved
    );
    assert_eq!(
        command_with_id(&dir, transparent_send(&to, 100_000), Some("job:1"))?,
        reused
    );
    for operation in [
        transparent_send(&to, 100_001),
        transparent_send(&address, 100_000),
        Operation::Unshield {
            to: to.clone(),
            amount_zat: 100_000,
        },
    ] {
        let error = command_with_id(&dir, operation, Some("job:1")).unwrap_err();
        assert!(error.to_string().contains("different payment request"));
    }
    assert_eq!(Store::open(&dir, false)?.pending()?.len(), 1);
    assert_eq!(
        command(&dir, Operation::Transactions)?["transactions"][0]["operation_id"],
        "job:1"
    );
    let selected = command(
        &dir,
        Operation::TransactionStatus {
            ids: vec!["job:1".into()],
        },
    )?;
    assert_eq!(selected["transactions"].as_array().unwrap().len(), 1);
    assert_eq!(selected["transactions"][0]["operation_id"], "job:1");
    let unknown = command(
        &dir,
        Operation::TransactionStatus {
            ids: vec!["job:missing".into()],
        },
    )?;
    assert!(unknown["transactions"].as_array().unwrap().is_empty());
    Ok(())
}

#[test]
fn operation_id_and_reserved_transaction_commit_or_roll_back_together() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    let pending = Pending {
        txid: "11".repeat(32),
        raw: "00".into(),
        expiry: 20,
        source: "outpoint:test:0".into(),
        receipt: None,
        request: Value::Null,
    };
    let operation = StoredOperation {
        id: "atomic".into(),
        txid: pending.txid.clone(),
        request: json!({"kind":"test"}),
    };
    {
        let store = Store::open(&dir, true)?;
        store.commit()?;
    }
    {
        let store = Store::open(&dir, false)?;
        assert!(store.operation("atomic")?.is_none()); // Old v1 schema is readable.
        store.reserve(&pending)?;
        store.put_note(&crate::tests::own(100_000))?;
        store.put_operation(&operation)?;
        // Simulate interruption before COMMIT. No signed transaction could have been broadcast.
    }
    {
        let store = Store::open(&dir, false)?;
        assert!(store.pending()?.is_empty());
        assert!(store.notes()?.is_empty());
        assert!(store.operation("atomic")?.is_none());
        store.reserve(&pending)?;
        store.put_operation(&operation)?;
        store.commit()?;
    }
    // Simulate a restart after COMMIT but before broadcast: the same bytes remain recoverable.
    {
        let store = Store::open(&dir, false)?;
        assert_eq!(store.operation("atomic")?.unwrap().txid, pending.txid);
        assert_eq!(store.pending()?[0].raw, pending.raw);
        let replacement = Pending {
            txid: "22".repeat(32),
            ..pending
        };
        store.reserve(&replacement)?;
        assert!(
            store
                .put_operation(&StoredOperation {
                    txid: replacement.txid,
                    ..operation
                })
                .is_err()
        );
    }
    assert_eq!(Store::open(&dir, false)?.pending()?.len(), 1);
    Ok(())
}

#[test]
fn operation_id_survives_mining_reorg_and_expiry_without_becoming_reusable() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    let address = init_wallet(&node, &dir)?;
    let funding = install_funding(&node, &address, &[250_000])?;
    let to = transaction::funding_address(crate::tests::SEED)?;
    let original = command_with_id(&dir, transparent_send(&to, 100_000), Some("stable"))?;
    node.mine_to(&[&address])?;
    synced_balance(&dir)?;
    assert_eq!(
        command_with_id(&dir, transparent_send(&to, 100_000), Some("stable"))?["status"],
        "mined"
    );
    {
        let mut data = node.data.lock().unwrap();
        data.blocks.pop();
        crate::tests::mine(&mut data.blocks, None)?;
        data.blocks.last_mut().unwrap().hash = "99".repeat(32);
        data.funding_utxos = vec![funding_utxo(
            &address,
            &funding.txid().to_string(),
            0,
            8,
            250_000,
        )?];
    }
    synced_balance(&dir)?;
    assert_eq!(
        command(
            &dir,
            Operation::Lookup {
                id: "stable".into()
            }
        )?["status"],
        "pending"
    );
    {
        let mut data = node.data.lock().unwrap();
        while u64::from(data.blocks.last().unwrap().height)
            <= original["expiry_height"].as_u64().unwrap()
        {
            crate::tests::mine(&mut data.blocks, None)?;
        }
    }
    synced_balance(&dir)?;
    let expired = command_with_id(&dir, transparent_send(&to, 100_000), Some("stable"))?;
    assert_eq!(expired["status"], "expired");
    assert_eq!(expired["txid"], original["txid"]);
    assert_eq!(node.data.lock().unwrap().submissions, 1);
    assert!(
        command(
            &dir,
            Operation::Submit {
                txid: original["txid"].as_str().unwrap().into()
            }
        )
        .is_err()
    );
    assert_eq!(
        command(&dir, Operation::Balance)?["transparent"]["available_zat"],
        250_000
    );
    command_with_id(&dir, transparent_send(&to, 100_000), Some("replacement"))?;
    assert_eq!(Store::open(&dir, false)?.pending()?.len(), 2);
    Ok(())
}

#[test]
fn transparent_send_rejects_coinbase_inputs_even_with_exact_funding() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    let address = init_wallet(&node, &dir)?;
    let funding = install_funding(&node, &address, &[150_000])?;
    node.data.lock().unwrap().txout_overrides.insert(
        (funding.txid().to_string(), 0),
        json!({"coinbase":true,"confirmations":100}),
    );
    let error =
        command_with_id(&dir, transparent_send(&address, 100_000), Some("coinbase")).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("coinbase outputs must be shielded")
    );
    assert!(Store::open(&dir, false)?.operation("coinbase")?.is_none());
    assert_eq!(node.data.lock().unwrap().submissions, 0);
    Ok(())
}

#[test]
fn operation_ids_are_bounded_and_only_apply_to_payments() -> Result<()> {
    use clap::Parser;
    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        wallet: Command,
    }
    let args = [
        "test",
        "--wallet-dir",
        "unused",
        "transparent-send",
        "--to",
        "ADDRESS",
        "--amount-zat",
        "100000",
        "--operation-id",
        "round:1",
    ];
    assert_eq!(
        Cli::try_parse_from(args)?.wallet.operation_id.as_deref(),
        Some("round:1")
    );
    let args = [
        "test",
        "--wallet-dir",
        "unused",
        "--operation-id",
        "round:1",
        "shield",
        "100000",
    ];
    assert_eq!(
        Cli::try_parse_from(args)?.wallet.operation_id.as_deref(),
        Some("round:1")
    );
    let args = ["test", "--wallet-dir", "unused", "operation", "round:1"];
    assert!(matches!(
        Cli::try_parse_from(args)?.wallet.command,
        Operation::Lookup { .. }
    ));
    for id in [
        "".to_owned(),
        "x".repeat(129),
        "has space".into(),
        "has\nnewline".into(),
        "unicode💫".into(),
    ] {
        assert!(validate_operation_id(&id).is_err());
    }
    assert!(validate_operation_id(&"x".repeat(128)).is_ok());
    let error = command_with_id(
        std::path::Path::new("unused"),
        Operation::Balance,
        Some("round:1"),
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("only supported for payment creation")
    );
    Ok(())
}

#[test]
fn transparent_send_is_not_blocked_by_a_tachyon_epoch_boundary() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    let address = init_wallet(&node, &dir)?;
    install_funding(&node, &address, &[150_000])?;
    {
        let mut data = node.data.lock().unwrap();
        while data.blocks.last().unwrap().height < 8 + EPOCH_SIZE - 1 {
            crate::tests::mine(&mut data.blocks, None)?;
        }
        let store = Store::open(&dir, false)?;
        for block in &data.blocks[1..] {
            store.put_block(block)?;
        }
        store.commit()?;
    }
    let result = command(&dir, transparent_send(&address, 100_000))?;
    assert_eq!(result["expiry_height"], 8 + EPOCH_SIZE - 1 + 20);
    let tx = node.mine_to(&[&address])?;
    assert!(matches!(tx.tachyon_bundle(), TachyonBundle::NoBundle));
    assert_eq!(
        synced_balance(&dir)?["transparent"]["available_zat"],
        100_000
    );
    Ok(())
}
fn synced_balance(dir: &std::path::Path) -> Result<Value> {
    command(
        dir,
        Operation::Sync {
            max_blocks: 1000,
            from_height: None,
        },
    )?;
    command(dir, Operation::Balance)
}

fn funding_utxo(address: &str, txid: &str, index: u32, height: u32, amount: u64) -> Result<Value> {
    Ok(
        json!({"address": address, "txid": txid, "outputIndex": index, "height": height,
        "satoshis": amount, "script": hex::encode(transaction::transparent_script(address)?.0.0)}),
    )
}

fn init_wallet(node: &Node, dir: &std::path::Path) -> Result<String> {
    let result = command(
        dir,
        Operation::Init {
            rpc_url: node.url.clone(),
            activation_height: 8,
            cookie_file: None,
            accept_mock_proofs: true,
            birthday_height: None,
            sync_from_activation: false,
        },
    )?;
    Ok(result["funding_address"].as_str().unwrap().into())
}

fn install_funding(node: &Node, address: &str, amounts: &[u64]) -> Result<Transaction> {
    let funding = TransactionData::<Authorized>::from_parts_v7(
        BranchId::NuTachyon,
        0,
        BlockHeight::from_u32(0),
        Zatoshis::ZERO,
        Some(Bundle {
            vin: vec![],
            vout: amounts
                .iter()
                .map(|amount| {
                    Ok(TxOut::new(
                        Zatoshis::from_u64(*amount)?,
                        transaction::transparent_script(address)?,
                    ))
                })
                .collect::<Result<_>>()?,
            authorization: transparent::bundle::Authorized,
        }),
        None,
        None,
        None,
        TachyonBundle::NoBundle,
    )
    .freeze()?;
    let mut raw = Vec::new();
    funding.write(&mut raw)?;
    let mut data = node.data.lock().unwrap();
    data.raw_transactions
        .insert(funding.txid().to_string(), hex::encode(raw));
    data.blocks[0].transactions = vec!["44".repeat(32), funding.txid().to_string()];
    for (index, amount) in amounts.iter().enumerate() {
        data.funding_utxos.push(funding_utxo(
            address,
            &funding.txid().to_string(),
            u32::try_from(index)?,
            8,
            *amount,
        )?);
    }
    Ok(funding)
}

#[test]
fn shield_cli_accepts_amount_or_paired_outpoint_only() {
    use clap::Parser;
    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        wallet: Command,
    }
    let parse = |args: &[&str]| {
        Cli::try_parse_from(
            ["test", "--wallet-dir", "unused", "shield"]
                .into_iter()
                .chain(args.iter().copied()),
        )
    };
    for args in [
        vec!["100000"],
        vec!["100000", "--txid", "aa", "--index", "0"],
        vec!["--txid", "aa", "--index", "1"],
    ] {
        assert!(parse(&args).is_ok(), "{args:?}");
    }
    for args in [
        vec![],
        vec!["0"],
        vec!["-1"],
        vec!["1.5"],
        vec!["18446744073709551616"],
        vec!["--txid", "aa"],
        vec!["--index", "0"],
        vec!["100000", "--txid", "aa"],
        vec!["100000", "--index", "0"],
    ] {
        assert!(parse(&args).is_err(), "{args:?}");
    }
}

#[test]
fn automatic_shield_selects_smallest_eligible_output_and_returns_transparent_change() -> Result<()>
{
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    let address = init_wallet(&node, &dir)?;
    let funding = install_funding(
        &node,
        &address,
        &[
            400_000, 200_000, 150_000, 100_000, 225_000, 250_000, 275_000,
        ],
    )?;
    let txid = funding.txid().to_string();
    {
        let store = Store::open(&dir, false)?;
        store.reserve(&Pending {
            txid: "66".repeat(32),
            raw: "00".into(),
            expiry: 20,
            source: format!("outpoint:{txid}:1"),
            receipt: None,
            request: Value::Null,
        })?;
        store.commit()?;
        let mut data = node.data.lock().unwrap();
        data.txout_overrides.insert((txid.clone(), 2), Value::Null);
        data.txout_overrides.insert(
            (txid.clone(), 4),
            json!({"coinbase":true,"confirmations":99}),
        );
        data.txout_overrides.insert(
            (txid.clone(), 5),
            json!({"coinbase":true,"confirmations":100}),
        );
        data.fail_submission = true;
    }
    let error = command(
        &dir,
        Operation::Shield {
            amount_zat: Some(100_000),
            txid: None,
            index: None,
        },
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("broadcast outcome may be ambiguous"));
    let tx = Transaction::read(
        &hex::decode(&node.data.lock().unwrap().mempool[0])?[..],
        BranchId::NuTachyon,
    )?;
    let transparent = tx.transparent_bundle().unwrap();
    assert_eq!(transparent.vin.len(), 1);
    assert_eq!(transparent.vin[0].prevout().n(), 6);
    assert_eq!(transparent.vout.len(), 1);
    assert_eq!(transparent.vout[0].value().into_u64(), 125_000);
    assert_eq!(
        transparent.vout[0].script_pubkey(),
        &transaction::transparent_script(&address)?
    );
    transaction::verify_for_test(
        &tx,
        Some(funding.transparent_bundle().unwrap().vout[6].clone()),
    )?;
    assert_eq!(
        command(&dir, Operation::Balance)?["transparent"]["reserved_zat"],
        475_000
    );
    let error = command(
        &dir,
        Operation::Shield {
            amount_zat: Some(100_000),
            txid: Some(txid),
            index: Some(6),
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("already reserved"));
    node.data.lock().unwrap().fail_submission = false;
    command(
        &dir,
        Operation::Submit {
            txid: tx.txid().to_string(),
        },
    )?;
    assert_eq!(node.data.lock().unwrap().mempool.len(), 1);
    node.data.lock().unwrap().funding_utxos.push(funding_utxo(
        &address,
        &tx.txid().to_string(),
        0,
        9,
        125_000,
    )?);
    node.mine()?;
    let balance = synced_balance(&dir)?;
    assert_eq!(balance["available_zat"], 100_000);
    assert_eq!(balance["transparent"]["reserved_zat"], 200_000);
    assert_eq!(balance["transparent"]["total_zat"], 1_450_000);
    Ok(())
}

#[test]
fn automatic_shield_absorbs_dust_change_into_fee() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    let address = init_wallet(&node, &dir)?;
    let funding = install_funding(&node, &address, &[150_005])?;
    node.data.lock().unwrap().fail_submission = true;
    let error = command(
        &dir,
        Operation::Shield {
            amount_zat: Some(100_000),
            txid: None,
            index: None,
        },
    )
    .unwrap_err();
    assert!(
        format!("{error:#}").contains("broadcast outcome may be ambiguous"),
        "{error:#}"
    );
    let tx = Transaction::read(
        &hex::decode(&node.data.lock().unwrap().mempool[0])?[..],
        BranchId::NuTachyon,
    )?;
    assert!(tx.transparent_bundle().unwrap().vout.is_empty());
    transaction::verify_for_test(
        &tx,
        Some(funding.transparent_bundle().unwrap().vout[0].clone()),
    )?;
    Ok(())
}

#[test]
fn explicit_shield_amount_overrides_selection_and_legacy_sweeps_the_output() -> Result<()> {
    for (amount, index, expected_note, expected_change) in [
        (Some(100_000), 0, 100_000, Some(350_000)),
        (Some(100_000), 1, 100_000, None),
        (None, 0, 450_000, None),
    ] {
        let node = Node::start()?;
        let temp = tempfile::tempdir()?;
        let dir = temp.path().join("wallet");
        let address = init_wallet(&node, &dir)?;
        let funding = install_funding(&node, &address, &[500_000, 150_000])?;
        command(
            &dir,
            Operation::Shield {
                amount_zat: amount,
                txid: Some(funding.txid().to_string().to_uppercase()),
                index: Some(index),
            },
        )?;
        let tx = Transaction::read(
            &hex::decode(&node.data.lock().unwrap().mempool[0])?[..],
            BranchId::NuTachyon,
        )?;
        let transparent = tx.transparent_bundle().unwrap();
        assert_eq!(transparent.vin[0].prevout().n(), index);
        assert_eq!(
            transparent.vout.first().map(|out| out.value().into_u64()),
            expected_change
        );
        transaction::verify_for_test(
            &tx,
            Some(funding.transparent_bundle().unwrap().vout[usize::try_from(index)?].clone()),
        )?;
        node.mine()?;
        assert_eq!(synced_balance(&dir)?["available_zat"], expected_note);
    }
    Ok(())
}

#[test]
fn shield_rejects_invalid_amounts_insufficient_single_outputs_and_partial_coinbase() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    let address = init_wallet(&node, &dir)?;
    let funding = install_funding(&node, &address, &[150_000, 150_000])?;
    for amount in [0, u64::MAX, 2_100_000_000_000_000] {
        assert!(
            command(
                &dir,
                Operation::Shield {
                    amount_zat: Some(amount),
                    txid: None,
                    index: None
                }
            )
            .is_err()
        );
    }
    let error = command(
        &dir,
        Operation::Shield {
            amount_zat: Some(200_000),
            txid: None,
            index: None,
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("no single eligible UTXO"));
    let error = command(
        &dir,
        Operation::Shield {
            amount_zat: Some(200_000),
            txid: Some(funding.txid().to_string()),
            index: Some(0),
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("cannot cover amount plus fee"));
    {
        let mut data = node.data.lock().unwrap();
        for index in 0..2 {
            data.txout_overrides.insert(
                (funding.txid().to_string(), index),
                json!({"coinbase":true,"confirmations":100}),
            );
        }
    }
    let error = command(
        &dir,
        Operation::Shield {
            amount_zat: Some(50_000),
            txid: Some(funding.txid().to_string()),
            index: Some(0),
        },
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("coinbase outputs must be shielded in full")
    );
    let error = command(
        &dir,
        Operation::Shield {
            amount_zat: Some(50_000),
            txid: None,
            index: None,
        },
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("coinbase outputs must be shielded in full")
    );
    assert!(node.data.lock().unwrap().mempool.is_empty());
    assert!(Store::open(&dir, false)?.pending()?.is_empty());
    // An exact amount may consume a mature coinbase output without transparent change.
    command(
        &dir,
        Operation::Shield {
            amount_zat: Some(100_000),
            txid: None,
            index: None,
        },
    )?;
    let tx = Transaction::read(
        &hex::decode(&node.data.lock().unwrap().mempool[0])?[..],
        BranchId::NuTachyon,
    )?;
    assert!(tx.transparent_bundle().unwrap().vout.is_empty());
    transaction::verify_for_test(
        &tx,
        Some(funding.transparent_bundle().unwrap().vout[0].clone()),
    )?;
    Ok(())
}

#[test]
fn existing_wallet_upgrades_on_sync_and_balance_stays_offline() -> Result<()> {
    let node = Node::start()?;
    node.data.lock().unwrap().blocks[0].transactions = vec!["44".repeat(32)];
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    let address = init_wallet(&node, &dir)?;
    // Initialization still creates the original v1 schema, with no funding table.
    let conn = rusqlite::Connection::open(dir.join("tachyon.sqlite"))?;
    let table_count: u32 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE name='funding_snapshot'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(table_count, 0);
    assert!(command(&dir, Operation::Balance)?["transparent"].is_null());
    node.data.lock().unwrap().funding_utxos =
        vec![funding_utxo(&address, &"11".repeat(32), 0, 8, 700_000)?];
    let balance = synced_balance(&dir)?;
    assert_eq!(balance["available_zat"], 0);
    assert_eq!(balance["transparent"]["available_zat"], 700_000);
    assert_eq!(balance["transparent"]["address"], address);
    drop(node);
    assert_eq!(command(&dir, Operation::Balance)?, balance);
    let summary = command(&dir, Operation::BalanceSummary)?;
    assert_eq!(summary["notes"], serde_json::json!([]));
    assert_eq!(summary["available_zat"], balance["available_zat"]);
    assert_eq!(summary["transparent"], balance["transparent"]);
    Ok(())
}

#[test]
fn partial_sync_keeps_canonical_snapshots_and_reorgs_replace_them() -> Result<()> {
    let node = Node::start()?;
    node.data.lock().unwrap().blocks[0].transactions = vec!["44".repeat(32)];
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    let address = init_wallet(&node, &dir)?;
    {
        let mut data = node.data.lock().unwrap();
        data.funding_utxos = vec![funding_utxo(&address, &"11".repeat(32), 0, 8, 1000)?];
        for _ in 0..2 {
            crate::tests::mine(&mut data.blocks, None)?;
        }
    }
    let partial = command(
        &dir,
        Operation::Sync {
            max_blocks: 1,
            from_height: None,
        },
    )?;
    assert_eq!(partial["height"], 9);
    assert_eq!(partial["caught_up"], false);
    assert!(partial["transparent_synced_height"].is_null());
    assert!(command(&dir, Operation::Balance)?["transparent"].is_null());
    assert_eq!(synced_balance(&dir)?["transparent"]["total_zat"], 1000);
    {
        let mut data = node.data.lock().unwrap();
        data.funding_utxos.clear();
        for _ in 0..2 {
            crate::tests::mine(&mut data.blocks, None)?;
        }
    }
    command(
        &dir,
        Operation::Sync {
            max_blocks: 1,
            from_height: None,
        },
    )?;
    let partial = command(&dir, Operation::Balance)?;
    assert_eq!(partial["synced_height"], 11);
    assert_eq!(partial["transparent"]["synced_height"], 10);
    assert_eq!(partial["transparent"]["total_zat"], 1000);
    assert_eq!(synced_balance(&dir)?["transparent"]["total_zat"], 0);

    // Same-height replacement must not reuse the old tip's UTXO snapshot.
    {
        let mut data = node.data.lock().unwrap();
        let tip = data.blocks.last_mut().unwrap();
        tip.hash = "ee".repeat(32);
        tip.transactions = vec!["44".repeat(32), "22".repeat(32)];
        data.funding_utxos = vec![funding_utxo(&address, &"22".repeat(32), 0, 12, 2000)?];
    }
    let replaced = synced_balance(&dir)?;
    assert_eq!(replaced["transparent"]["synced_hash"], "ee".repeat(32));
    assert_eq!(replaced["transparent"]["available_zat"], 2000);

    // A deeper reorg plus partial catch-up invalidates the old snapshot entirely.
    {
        let mut data = node.data.lock().unwrap();
        data.blocks.truncate(3);
        data.funding_utxos.clear();
        for hash in ["aa", "bb"] {
            crate::tests::mine(&mut data.blocks, None)?;
            data.blocks.last_mut().unwrap().hash = hash.repeat(32);
        }
    }
    command(
        &dir,
        Operation::Sync {
            max_blocks: 1,
            from_height: None,
        },
    )?;
    assert!(command(&dir, Operation::Balance)?["transparent"].is_null());
    assert_eq!(synced_balance(&dir)?["transparent"]["total_zat"], 0);
    Ok(())
}

#[test]
fn cancelled_sync_rolls_back_blocks_and_funding_snapshot_and_can_resume() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    init_wallet(&node, &dir)?;
    let before = synced_balance(&dir)?;
    let control = Control::new(true);
    {
        let mut data = node.data.lock().unwrap();
        crate::tests::mine(&mut data.blocks, None)?;
        // Interrupt the final consistency check, after the new block and
        // funding snapshot have been written inside the open transaction.
        data.cancel_request = Some(("getblockhash".into(), Some(json!([9])), control.clone()));
    }
    let error = Command {
        wallet_dir: dir.clone(),
        operation_id: None,
        expected_tip: None,
        quiet: true,
        command: Operation::Sync {
            max_blocks: 1000,
            from_height: None,
        },
    }
    .execute_with_control(&control)
    .unwrap_err();
    assert!(format!("{error:#}").contains("cancelled"));
    assert_eq!(command(&dir, Operation::Balance)?, before);
    node.data.lock().unwrap().cancel_request = None;
    assert_eq!(synced_balance(&dir)?["synced_height"], 9);
    Ok(())
}

#[test]
fn cancelled_broadcast_retains_signed_payment_and_reservation() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    let address = init_wallet(&node, &dir)?;
    install_funding(&node, &address, &[250_000])?;
    let control = Control::new(true);
    node.data.lock().unwrap().cancel_request =
        Some(("sendrawtransaction".into(), None, control.clone()));
    let error = Command {
        wallet_dir: dir.clone(),
        operation_id: Some("cancelled-payment".into()),
        expected_tip: None,
        quiet: true,
        command: transparent_send(&address, 100_000),
    }
    .execute_with_control(&control)
    .unwrap_err();
    assert!(format!("{error:#}").contains("input remains reserved"));
    assert!(format!("{error:#}").contains("cancelled"));
    node.data.lock().unwrap().cancel_request = None;
    let saved = command(
        &dir,
        Operation::Lookup {
            id: "cancelled-payment".into(),
        },
    )?;
    assert_eq!(saved["status"], "pending");
    let balance = synced_balance(&dir)?;
    assert_eq!(balance["transparent"]["reserved_zat"], 250_000);
    assert_eq!(balance["transparent"]["available_zat"], 0);
    let replay = command_with_id(
        &dir,
        transparent_send(&address, 100_000),
        Some("cancelled-payment"),
    )?;
    assert_eq!(replay["txid"], saved["txid"]);
    assert_eq!(replay["reused"], true);
    assert_eq!(node.data.lock().unwrap().submissions, 1);
    Ok(())
}

#[test]
fn funding_rpc_failures_and_tip_mismatches_roll_back_sync() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    init_wallet(&node, &dir)?;
    let before = synced_balance(&dir)?;
    {
        let mut data = node.data.lock().unwrap();
        crate::tests::mine(&mut data.blocks, None)?;
        data.fail_funding_sync = true;
    }
    let error = command(
        &dir,
        Operation::Sync {
            max_blocks: 1000,
            from_height: None,
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("getaddressutxos"));
    assert_eq!(command(&dir, Operation::Balance)?, before);
    {
        let mut data = node.data.lock().unwrap();
        data.fail_funding_sync = false;
        data.funding_hash_override = Some("ff".repeat(32));
    }
    let error = command(
        &dir,
        Operation::Sync {
            max_blocks: 1000,
            from_height: None,
        },
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("does not match the synced chain")
    );
    // Block 9 was downloaded but must also roll back, not just the funding data.
    assert_eq!(command(&dir, Operation::Balance)?, before);
    node.data.lock().unwrap().funding_hash_override = None;
    assert_eq!(synced_balance(&dir)?["transparent"]["synced_height"], 9);
    Ok(())
}

#[test]
fn recent_pre_activation_funding_is_classified_without_tachyon_history() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    let address = init_wallet(&node, &dir)?;
    {
        let mut data = node.data.lock().unwrap();
        data.earlier_blocks.insert(
            7,
            json!({"height":7,"hash":"77".repeat(32),"tx":["11".repeat(32),"22".repeat(32)]}),
        );
        data.funding_utxos = vec![
            funding_utxo(&address, &"11".repeat(32), 0, 7, 1000)?,
            funding_utxo(&address, &"22".repeat(32), 0, 7, 2000)?,
        ];
    }
    let balance = synced_balance(&dir)?;
    assert_eq!(balance["transparent"]["immature_zat"], 1000);
    assert_eq!(balance["transparent"]["available_zat"], 2000);
    assert_eq!(balance["transparent"]["total_zat"], 3000);
    Ok(())
}

#[test]
fn transparent_reservations_survive_restart_until_after_expiry() -> Result<()> {
    let node = Node::start()?;
    node.data.lock().unwrap().blocks[0].transactions = vec!["44".repeat(32)];
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    let address = init_wallet(&node, &dir)?;
    node.data.lock().unwrap().funding_utxos =
        vec![funding_utxo(&address, &"11".repeat(32), 0, 8, 700_000)?];
    synced_balance(&dir)?;
    {
        let store = Store::open(&dir, false)?;
        store.reserve(&Pending {
            txid: "22".repeat(32),
            raw: "00".into(),
            expiry: 9,
            source: format!("outpoint:{}:0", "11".repeat(32)),
            receipt: None,
            request: Value::Null,
        })?;
        store.commit()?;
    }
    let reserved = command(&dir, Operation::Balance)?;
    assert_eq!(reserved["transparent"]["reserved_zat"], 700_000);
    assert_eq!(reserved["transparent"]["available_zat"], 0);
    crate::tests::mine(&mut node.data.lock().unwrap().blocks, None)?;
    assert_eq!(
        synced_balance(&dir)?["transparent"]["reserved_zat"],
        700_000
    );
    crate::tests::mine(&mut node.data.lock().unwrap().blocks, None)?;
    let expired = synced_balance(&dir)?;
    assert_eq!(expired["transparent"]["reserved_zat"], 0);
    assert_eq!(expired["transparent"]["available_zat"], 700_000);
    Ok(())
}

#[test]
fn two_wallet_rpc_flow_recovers_broadcast_failure_and_reorg() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let alice = temp.path().join("alice");
    let bob = temp.path().join("bob");
    for dir in [&alice, &bob] {
        command(
            dir,
            Operation::Init {
                rpc_url: node.url.clone(),
                activation_height: 8,
                cookie_file: None,
                accept_mock_proofs: true,
                birthday_height: None,
                sync_from_activation: false,
            },
        )?;
    }
    let alice_address = command(&alice, Operation::Address)?;
    let funding_output = TxOut::new(
        Zatoshis::from_u64(1_050_000)?,
        transaction::transparent_script(alice_address["funding_address"].as_str().unwrap())?,
    );
    let funding = TransactionData::<Authorized>::from_parts_v7(
        BranchId::NuTachyon,
        0,
        BlockHeight::from_u32(0),
        Zatoshis::ZERO,
        Some(Bundle {
            vin: vec![],
            vout: vec![funding_output.clone()],
            authorization: transparent::bundle::Authorized,
        }),
        None,
        None,
        None,
        TachyonBundle::NoBundle,
    )
    .freeze()?;
    let mut raw = Vec::new();
    funding.write(&mut raw)?;
    node.data.lock().unwrap().raw_funding = hex::encode(raw);
    {
        let mut data = node.data.lock().unwrap();
        // The funding transaction is a regular transfer, not the first transaction in the block.
        data.blocks[0].transactions = vec!["44".repeat(32), funding.txid().to_string()];
        data.funding_utxos.push(funding_utxo(
            alice_address["funding_address"].as_str().unwrap(),
            &funding.txid().to_string(),
            0,
            8,
            1_050_000,
        )?);
    }
    assert_eq!(
        synced_balance(&alice)?["transparent"]["available_zat"],
        1_050_000
    );
    node.data.lock().unwrap().fail_submission = true;
    let error = command_with_id(
        &alice,
        Operation::Shield {
            amount_zat: None,
            txid: Some(funding.txid().to_string()),
            index: Some(0),
        },
        Some("initial-shield"),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("broadcast outcome may be ambiguous"));
    node.data.lock().unwrap().fail_submission = false;
    // A fresh command must still reserve the UTXO after an ambiguous broadcast.
    assert_eq!(
        command(&alice, Operation::Balance)?["transparent"]["reserved_zat"],
        1_050_000
    );
    assert_eq!(
        command(&alice, Operation::Balance)?["transparent"]["available_zat"],
        0
    );
    {
        let data = node.data.lock().unwrap();
        let tx = Transaction::read(&hex::decode(&data.mempool[0])?[..], BranchId::NuTachyon)?;
        transaction::verify_for_test(&tx, Some(funding_output))?;
    }
    node.mine()?;
    assert_eq!(synced_balance(&alice)?["available_zat"], 1_000_000);
    assert_eq!(
        command(&alice, Operation::Balance)?["transparent"]["total_zat"],
        0
    );
    let bob_address = command(&bob, Operation::Address)?["tachyon_address"]
        .as_str()
        .unwrap()
        .to_owned();
    node.data.lock().unwrap().fail_submission = true;
    assert!(
        command_with_id(
            &alice,
            Operation::Send {
                to: bob_address.clone(),
                amount_zat: 300_000
            },
            Some("alice-to-bob"),
        )
        .is_err()
    );
    // Every command reopens SQLite: reservation and raw bytes survive process boundaries.
    assert_eq!(command(&alice, Operation::Balance)?["available_zat"], 0);
    let saved = command(
        &alice,
        Operation::Lookup {
            id: "alice-to-bob".into(),
        },
    )?;
    assert_eq!(saved["has_receipt"], true);
    assert_eq!(saved["request"]["kind"], "send");
    let replay = command_with_id(
        &alice,
        Operation::Send {
            to: bob_address.clone(),
            amount_zat: 300_000,
        },
        Some("alice-to-bob"),
    )?;
    assert_eq!(replay["txid"], saved["txid"]);
    assert_eq!(replay["reused"], true);
    assert!(
        command(
            &alice,
            Operation::Send {
                to: bob_address.clone(),
                amount_zat: 300_000
            }
        )
        .is_err()
    );
    let transactions = command(&alice, Operation::Transactions)?;
    let txid = transactions["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["status"] == "pending")
        .unwrap()["txid"]
        .as_str()
        .unwrap()
        .to_owned();
    let receipt_file = temp.path().join("payment.json");
    command(
        &alice,
        Operation::ExportReceipt {
            txid: txid.clone(),
            out: receipt_file.clone(),
            legacy: false,
        },
    )?;
    let mut exported: Receipt = serde_json::from_slice(&std::fs::read(&receipt_file)?)?;
    assert_eq!(exported.locator.as_ref().unwrap().txid, txid);
    assert!(exported.locator.as_ref().unwrap().height.is_none());
    let legacy_file = temp.path().join("legacy-payment.json");
    command(
        &alice,
        Operation::ExportReceipt {
            txid: txid.clone(),
            out: legacy_file.clone(),
            legacy: true,
        },
    )?;
    let legacy: Value = serde_json::from_slice(&std::fs::read(legacy_file)?)?;
    assert!(legacy.get("locator").is_none());
    exported.locator.as_mut().unwrap().txid = txid.to_uppercase();
    std::fs::write(&receipt_file, serde_json::to_vec(&exported)?)?;
    command(
        &bob,
        Operation::Receive {
            receipt: receipt_file.clone(),
            txid: None,
            height: None,
        },
    )?;
    assert_eq!(synced_balance(&bob)?["available_zat"], 0);
    node.data.lock().unwrap().fail_submission = false;
    command(&alice, Operation::Submit { txid: txid.clone() })?;
    assert_eq!(node.data.lock().unwrap().mempool.len(), 1); // Retry did not create a replacement.
    node.mine()?;
    assert_eq!(synced_balance(&bob)?["available_zat"], 300_000);
    assert_eq!(synced_balance(&alice)?["available_zat"], 650_000);
    let received = command(&bob, Operation::Transactions)?;
    let received = received["transactions"].as_array().unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0]["kind"], "receive");
    assert_eq!(received[0]["txid"], txid);
    assert_eq!(received[0]["note_id"], exported.id()?);
    assert_eq!(received[0]["amount_zat"], 300_000);
    assert_eq!(received[0]["status"], "mined");
    assert_eq!(received[0]["height"], 10);
    let sent = command(&alice, Operation::Transactions)?;
    let sent = sent["transactions"].as_array().unwrap();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0]["kind"], "shield");
    assert_eq!(sent[0]["amount_zat"], 1_000_000);
    assert_eq!(sent[0]["height"], 9);
    assert_eq!(sent[1]["kind"], "send");
    assert_eq!(sent[1]["to"], bob_address);
    assert_eq!(sent[1]["amount_zat"], 300_000);
    assert_eq!(sent[1]["operation_id"], "alice-to-bob");
    assert_eq!(sent[1]["status"], "mined");
    let mined_file = temp.path().join("mined-payment.json");
    command(
        &alice,
        Operation::ExportReceipt {
            txid: txid.clone(),
            out: mined_file.clone(),
            legacy: false,
        },
    )?;
    let exported: Receipt = serde_json::from_slice(&std::fs::read(mined_file)?)?;
    let locator = exported.locator.unwrap();
    assert_eq!(
        locator.height,
        Some(node.data.lock().unwrap().blocks.last().unwrap().height)
    );
    assert_eq!(
        locator.block_hash.as_ref(),
        Some(&node.data.lock().unwrap().blocks.last().unwrap().hash)
    );
    // Same-height reorg: remove the payment, replace it with an empty block.
    {
        let mut data = node.data.lock().unwrap();
        data.blocks.pop();
        crate::tests::mine(&mut data.blocks, None)?;
        data.blocks.last_mut().unwrap().hash = hex::encode([99; 32]);
    }
    assert_eq!(synced_balance(&bob)?["available_zat"], 0);
    assert_eq!(synced_balance(&alice)?["available_zat"], 0); // Original note is reserved again.
    command(&alice, Operation::Submit { txid })?;
    node.mine()?;
    assert_eq!(synced_balance(&bob)?["available_zat"], 300_000);
    command_with_id(
        &bob,
        Operation::Unshield {
            to: alice_address["funding_address"].as_str().unwrap().into(),
            amount_zat: 100_000,
        },
        Some("bob-unshield"),
    )?;
    assert_eq!(
        command(
            &bob,
            Operation::Lookup {
                id: "bob-unshield".into()
            }
        )?["request"]["kind"],
        "unshield"
    );
    {
        let mut data = node.data.lock().unwrap();
        let tx = Transaction::read(&hex::decode(&data.mempool[0])?[..], BranchId::NuTachyon)?;
        transaction::verify_for_test(&tx, None)?;
        let height = data.blocks.last().unwrap().height + 1;
        data.funding_utxos.push(funding_utxo(
            alice_address["funding_address"].as_str().unwrap(),
            &tx.txid().to_string(),
            0,
            height,
            100_000,
        )?);
    }
    node.mine()?;
    assert_eq!(synced_balance(&bob)?["available_zat"], 150_000);
    assert_eq!(
        synced_balance(&alice)?["transparent"]["available_zat"],
        100_000
    );
    Ok(())
}

#[test]
fn reservations_survive_restarts_and_expire_only_after_expiry_height() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let wallet_dir = dir.path().join("wallet");
    let store = Store::open(&wallet_dir, true)?;
    let receipt = crate::tests::own(1_000_000);
    let mut blocks = vec![crate::tests::genesis()];
    let tx = crate::tests::shield(&blocks, &receipt)?;
    crate::tests::mine(&mut blocks, Some(&tx))?;
    for block in &blocks {
        store.put_block(block)?;
    }
    store.put_note(&receipt)?;
    store.reserve(&Pending {
        txid: hex::encode([3; 32]),
        raw: "00".into(),
        expiry: 10,
        source: format!("note:{}", receipt.id()?),
        receipt: None,
        request: Value::Null,
    })?;
    store.commit()?;
    drop(store);
    let store = Store::open(&wallet_dir, false)?;
    let config = Config {
        version: 1,
        rpc_url: String::new(),
        cookie_file: None,
        activation: 8,
        activation_hash: blocks[0].hash.clone(),
        genesis: hex::encode([0; 32]),
        network_id: crate::tests::NETWORK.into(),
        seed: crate::tests::SEED,
        birthday_height: None,
    };
    assert_eq!(
        note_states(&store, &config, &Control::new(true), true)?[0].1,
        "reserved"
    );
    crate::tests::mine(&mut blocks, None)?;
    store.put_block(blocks.last().unwrap())?;
    assert_eq!(
        note_states(&store, &config, &Control::new(true), true)?[0].1,
        "reserved"
    );
    crate::tests::mine(&mut blocks, None)?;
    store.put_block(blocks.last().unwrap())?;
    assert_eq!(
        note_states(&store, &config, &Control::new(true), true)?[0].1,
        "available"
    );
    Ok(())
}
