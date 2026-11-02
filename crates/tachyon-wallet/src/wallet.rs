//! Scriptable, single-note development wallet commands. No background scheduler.

use crate::{
    chain::{Block, bytes32},
    control::{self, Control},
    funding_balance::{AddressUtxos, COINBASE_MATURITY},
    note::{self, Locator, Receipt},
    rpc::Rpc,
    store::{Config, Pending, Store, StoredOperation, write_private},
    transaction::{self, FEE, Funding, Payment},
};
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use ff::PrimeField;
use pasta_curves::Fp;
use primitives::transaction::Transaction;
use protocol::consensus::BranchId;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::PathBuf,
};
use zcash_tachyon::{EpochIndex, constants::EPOCH_SIZE, keys::private::SpendingKey};

mod sync;
use sync::sync;

#[derive(Debug, Args)]
pub struct Command {
    /// Separate, private directory for this experimental wallet (not the ordinary wallet DB).
    #[arg(long, value_hint = clap::ValueHint::DirPath)]
    wallet_dir: PathBuf,
    /// Optional wallet-local idempotency key for shield/send/unshield/transparent-send.
    #[arg(long, global = true)]
    operation_id: Option<String>,
    /// Suppress progress on stderr (errors and interruption notices remain visible).
    #[arg(long, short = 'q', global = true)]
    quiet: bool,
    #[command(subcommand)]
    command: Operation,
}

#[derive(Debug, Subcommand)]
enum Operation {
    /// Create a mock-proof wallet for a private development network. Keys are NOT encrypted.
    Init {
        #[arg(long)]
        rpc_url: String,
        #[arg(long)]
        activation_height: u32,
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        cookie_file: Option<PathBuf>,
        /// Required acknowledgement: test funds only; neither proofs nor storage are production-safe.
        #[arg(long)]
        accept_mock_proofs: bool,
        /// Earliest relevant height; defaults to the node tip for a new wallet.
        #[arg(long, conflicts_with = "sync_from_activation")]
        birthday_height: Option<u32>,
        /// Replay from NuTachyon activation instead of trusting a recent epoch checkpoint.
        #[arg(long)]
        sync_from_activation: bool,
    },
    /// Print Tachyon payment and transparent funding addresses.
    Address,
    /// Show Tachyon notes and confirmed transparent funding from the last successful sync, offline.
    Balance,
    /// Validate and persist chain inputs; repeat until caught_up is true.
    Sync {
        #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u32).range(1..=10000))]
        max_blocks: u32,
        /// Extend history to this height's epoch, for older/legacy note receipts.
        #[arg(long)]
        from_height: Option<u32>,
    },
    /// Import a confidential payment receipt received out of band.
    Receive {
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        receipt: PathBuf,
        /// Supply or correct the originating transaction ID in a legacy receipt.
        #[arg(long)]
        txid: Option<String>,
        /// Optional mined-height hint; verified against the canonical chain.
        #[arg(long)]
        height: Option<u32>,
    },
    /// Shield an amount in zatoshis, or an entire explicit output less the fee.
    Shield {
        /// Exact amount entering Tachyon, excluding the fee. Automatically selects one UTXO.
        #[arg(value_name = "AMOUNT_ZAT", required_unless_present = "txid", value_parser = clap::value_parser!(u64).range(1..))]
        amount_zat: Option<u64>,
        /// Funding transaction ID; requires --index. Omit the amount to shield its full output.
        #[arg(long, requires = "index")]
        txid: Option<String>,
        /// Zero-based output index within the funding transaction; requires --txid.
        #[arg(long, requires = "txid")]
        index: Option<u32>,
    },
    /// Spend one sufficiently large Tachyon note, returning change to this wallet.
    Send {
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount_zat: u64,
    },
    /// Spend one Tachyon note to a transparent testnet address, with Tachyon change.
    Unshield {
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount_zat: u64,
    },
    /// Send transparent funds from one confirmed non-coinbase UTXO, with transparent change.
    TransparentSend {
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount_zat: u64,
    },
    /// Look up a saved operation ID offline; status is based on the last successful sync.
    #[command(name = "operation")]
    Lookup { id: String },
    /// Export the recipient's confidential note receipt, including after a failed broadcast.
    ExportReceipt {
        #[arg(long)]
        txid: String,
        #[arg(long, value_hint = clap::ValueHint::FilePath)]
        out: PathBuf,
        /// Omit location metadata for older receivers that reject extra JSON fields.
        #[arg(long)]
        legacy: bool,
    },
    /// Retry broadcasting the exact stored transaction, without creating a replacement.
    Submit {
        #[arg(long)]
        txid: String,
    },
    /// List mined, pending, or expired transactions (receipts and keys are not printed).
    Transactions,
}

impl Command {
    /// Run with OS signal handling and periodic progress for long proof/RPC steps.
    pub async fn run_interruptible(self) -> Result<()> {
        control::run(self.quiet, move |control| self.run_with_control(&control)).await
    }

    /// Synchronous entry point without OS signal handling.
    pub fn run(self) -> Result<()> {
        let control = Control::new(self.quiet);
        self.run_with_control(&control)
    }

    fn run_with_control(self, control: &Control) -> Result<()> {
        let result = self.execute_with_control(control)?;
        println!("{}", serde_json::to_string(&result)?);
        Ok(())
    }

    #[cfg(test)]
    fn execute(self) -> Result<Value> {
        let control = Control::new(self.quiet);
        self.execute_with_control(&control)
    }

    fn execute_with_control(self, control: &Control) -> Result<Value> {
        control.check()?;
        if let Some(id) = &self.operation_id {
            validate_operation_id(id)?;
            ensure!(
                matches!(
                    self.command,
                    Operation::Shield { .. }
                        | Operation::Send { .. }
                        | Operation::Unshield { .. }
                        | Operation::TransparentSend { .. }
                ),
                "--operation-id is only supported for payment creation; use operation <id> for lookup"
            );
        }
        if let Operation::Init {
            rpc_url,
            activation_height,
            cookie_file,
            accept_mock_proofs,
            birthday_height,
            sync_from_activation,
        } = self.command
        {
            ensure!(
                accept_mock_proofs,
                "init requires --accept-mock-proofs; NEVER use real funds"
            );
            ensure!(
                activation_height > 0,
                "NuTachyon must activate after genesis"
            );
            let rpc = Rpc::new(&rpc_url, cookie_file.clone(), control)?;
            let info: Value = rpc.call("getblockchaininfo", json!([]))?;
            ensure!(
                matches!(info["chain"].as_str(), Some("test" | "regtest")),
                "only test/regtest networks are supported"
            );
            let genesis = rpc.hash(0)?;
            let tip = rpc.height()?;
            ensure!(tip >= activation_height, "node has not activated NuTachyon");
            let activation_hash = rpc.hash(activation_height)?;
            let birthday_height = if sync_from_activation {
                activation_height
            } else {
                birthday_height.unwrap_or(tip)
            };
            ensure!(
                birthday_height <= tip,
                "wallet birthday is above the node tip"
            );
            let start = sync::epoch_start(birthday_height, activation_height)?;
            let checkpoint = sync::checkpoint(&rpc, start, activation_height)?;
            let identity = Sha256::new()
                .chain_update(bytes32(&genesis)?)
                .chain_update(activation_height.to_le_bytes())
                .chain_update(bytes32(&activation_hash)?)
                .finalize();
            let config = Config {
                version: 1,
                rpc_url,
                cookie_file,
                activation: activation_height,
                activation_hash,
                genesis,
                network_id: hex::encode(identity),
                seed: note::random_seed(),
                birthday_height: Some(birthday_height),
            };
            // Finish this short initialization transaction once started, rather
            // than leaving a newly-created wallet without its configuration.
            control.stage("Initializing wallet database…")?;
            let store = Store::open(&self.wallet_dir, true)?;
            store.set_config(&config)?;
            store.put_block(&checkpoint)?;
            store.commit()?;
            let mut result = addresses(&config)?;
            result["sync_start_height"] = json!(start);
            result["trusted_checkpoint"] = json!(start != activation_height);
            return Ok(result);
        }
        control.stage("Opening wallet database…")?;
        let store = Store::open(&self.wallet_dir, false)?;
        let config = store.config()?;
        let key = SpendingKey::from(config.seed);
        let result = match self.command {
            Operation::Init { .. } => unreachable!("init returned above"),
            Operation::Address => addresses(&config)?,
            Operation::Balance => {
                let blocks = store.blocks()?;
                let states = note_states(&store, &config, &blocks, control)?;
                let available = states
                    .iter()
                    .filter(|(_, s)| *s == "available")
                    .try_fold(0u64, |total, (r, _)| {
                        total.checked_add(r.value_zat).context("balance overflow")
                    })?;
                let snapshot = store.funding_snapshot()?;
                let reserved = store
                    .pending()?
                    .into_iter()
                    .filter(|p| pending_status(p, &blocks) != "expired")
                    .map(|p| p.source)
                    .collect();
                let transparent = snapshot
                    .as_ref()
                    .map(|snapshot| {
                        ensure!(
                            blocks.iter().any(|block| block.height == snapshot.height
                                && block.hash == snapshot.hash),
                            "transparent snapshot is no longer on the synced chain; run sync"
                        );
                        snapshot.balance(&reserved)
                    })
                    .transpose()?;
                json!({"synced_height":blocks.last().map(|b| b.height), "available_zat":available,
                    "transparent":transparent,
                    "notes":states.into_iter().map(|(r,s)| Ok(json!({"id":r.id()?,"value_zat":r.value_zat,"status":s}))).collect::<Result<Vec<_>>>()?})
            }
            Operation::Sync {
                max_blocks,
                from_height,
            } => sync(&store, &config, max_blocks, from_height, control)?,
            Operation::Receive {
                receipt,
                txid,
                height,
            } => {
                let mut data = Vec::new();
                std::fs::File::open(receipt)?
                    .take(16_385)
                    .read_to_end(&mut data)?;
                ensure!(data.len() <= 16_384, "receipt exceeds 16 KiB");
                let mut receipt: Receipt = serde_json::from_slice(&data)?;
                if let Some(txid) = txid {
                    receipt.locator = Some(Locator {
                        txid: hex::encode(bytes32(&txid)?),
                        height,
                        block_hash: None,
                    });
                } else if let Some(height) = height {
                    let locator = receipt
                        .locator
                        .as_mut()
                        .context("--height needs a receipt locator or --txid")?;
                    locator.height = Some(height);
                    locator.block_hash = None;
                }
                if let Some(locator) = receipt.locator.as_mut() {
                    locator.txid = hex::encode(bytes32(&locator.txid)?);
                    locator.block_hash = locator
                        .block_hash
                        .as_deref()
                        .map(|hash| bytes32(hash).map(hex::encode))
                        .transpose()?;
                }
                receipt.check_owner(&key, &config.network_id)?;
                store.put_note(&receipt)?;
                json!({"note_id":receipt.id()?, "status":"imported; sync to confirm",
                    "locator":receipt.locator,
                    "hint":if receipt.locator.is_none() { Some("Legacy receipt: supply --txid/--height, or sync --from-height for notes older than the downloaded history") } else { None }})
            }
            Operation::ExportReceipt { txid, out, legacy } => {
                let pending = find_pending(&store, &txid)?;
                let mut receipt = pending
                    .receipt
                    .context("this transaction has no recipient receipt")?;
                receipt.locator = if legacy {
                    None
                } else {
                    let blocks = store.blocks()?;
                    let block = blocks
                        .iter()
                        .find(|block| block.transactions.contains(&txid));
                    Some(Locator {
                        txid: hex::encode(bytes32(&txid)?),
                        height: block.map(|block| block.height),
                        block_hash: block.map(|block| block.hash.clone()),
                    })
                };
                write_private(&out, &serde_json::to_vec_pretty(&receipt)?)?;
                json!({"txid":txid,"receipt":out})
            }
            Operation::Transactions => {
                let blocks = store.blocks()?;
                let ids = store.operation_ids()?;
                json!({"transactions":store.pending()?.into_iter().map(|p| {
                    json!({"txid":p.txid,"operation_id":ids.get(&p.txid),"expiry_height":p.expiry,"status":pending_status(&p,&blocks)})
                }).collect::<Vec<_>>()})
            }
            Operation::Lookup { id } => {
                validate_operation_id(&id)?;
                let saved = store.operation(&id)?.context("unknown operation ID")?;
                operation_result(&store, &saved)?
            }
            Operation::Submit { txid } => {
                ensure!(
                    sync(&store, &config, 1000, None, control)?["caught_up"] == true,
                    "run sync until caught up before submitting"
                );
                let pending = find_pending(&store, &txid)?;
                let blocks = store.blocks()?;
                let status = pending_status(&pending, &blocks);
                ensure!(
                    status != "expired",
                    "transaction expired; create a new payment"
                );
                control.check()?;
                store.commit()?;
                if status != "mined" {
                    rpc(&config, control)?.submit(&txid, &pending.raw)?;
                }
                return Ok(
                    json!({"txid":txid,"status":if status == "mined" {"mined"} else {"submitted"}}),
                );
            }
            operation @ (Operation::Shield { .. }
            | Operation::Send { .. }
            | Operation::Unshield { .. }
            | Operation::TransparentSend { .. }) => {
                return pay(
                    &store,
                    &config,
                    operation,
                    self.operation_id.as_deref(),
                    control,
                );
            }
        };
        control.stage("Committing wallet updates…")?;
        store.commit()?;
        Ok(result)
    }
}

fn rpc(config: &Config, control: &Control) -> Result<Rpc> {
    Rpc::new(&config.rpc_url, config.cookie_file.clone(), control)
}
fn addresses(config: &Config) -> Result<Value> {
    Ok(
        json!({"network_id":config.network_id,"birthday_height":config.birthday_height.unwrap_or(config.activation),"tachyon_address":note::address(&SpendingKey::from(config.seed)),
        "funding_address":transaction::funding_address(config.seed)?,"warning":"mock proofs; unencrypted keys; test funds only"}),
    )
}

fn pending_status(pending: &Pending, blocks: &[Block]) -> &'static str {
    if blocks
        .iter()
        .any(|b| b.transactions.contains(&pending.txid))
    {
        "mined"
    } else if blocks.last().is_some_and(|b| b.height > pending.expiry) {
        "expired"
    } else {
        "pending"
    }
}

fn find_pending(store: &Store, txid: &str) -> Result<Pending> {
    store
        .pending()?
        .into_iter()
        .find(|p| p.txid == txid)
        .context("unknown wallet transaction")
}

fn note_states(
    store: &Store,
    config: &Config,
    blocks: &[Block],
    control: &Control,
) -> Result<Vec<(Receipt, &'static str)>> {
    control.stage("Checking note states…")?;
    let key = SpendingKey::from(config.seed);
    let reserved: BTreeSet<_> = store
        .pending()?
        .into_iter()
        .filter(|p| pending_status(p, blocks) != "expired")
        .map(|p| p.source)
        .collect();
    let mut epoch_members: BTreeMap<u32, BTreeSet<&str>> = BTreeMap::new();
    for block in blocks {
        control.check()?;
        let members = epoch_members.entry(block.epoch).or_default();
        members.extend(
            block
                .stamps
                .iter()
                .flat_map(|s| s.tachygrams.iter().map(String::as_str)),
        );
    }
    store
        .notes()?
        .into_iter()
        .map(|receipt| {
            control.check()?;
            receipt.check_owner(&key, &config.network_id)?;
            let id = receipt.id()?;
            let note = receipt.note()?;
            let master = key.derive_nullifier_private().derive_note_private(note.psi);
            let mined = epoch_members
                .values()
                .any(|members| members.contains(id.as_str()));
            let spent = epoch_members.iter().any(|(epoch, members)| {
                let nf = hex::encode(
                    Fp::from(master.derive_nullifier(EpochIndex::new(*epoch))).to_repr(),
                );
                members.contains(nf.as_str())
            });
            let status = if spent {
                "spent"
            } else if !mined {
                "unconfirmed"
            } else if reserved.contains(&format!("note:{id}")) {
                "reserved"
            } else {
                "available"
            };
            Ok((receipt, status))
        })
        .collect()
}

fn validate_operation_id(id: &str) -> Result<()> {
    ensure!(
        !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b)),
        "operation ID must be 1-128 ASCII letters, digits, '-', '_', '.', or ':'"
    );
    Ok(())
}

fn operation_result(store: &Store, saved: &StoredOperation) -> Result<Value> {
    let pending = find_pending(store, &saved.txid)?;
    let blocks = store.blocks()?;
    Ok(
        json!({"operation_id":saved.id,"txid":saved.txid,"request":saved.request,
        "status":pending_status(&pending,&blocks),"synced_height":blocks.last().map(|b| b.height),
        "expiry_height":pending.expiry,"fee_zat":FEE,"has_receipt":pending.receipt.is_some()}),
    )
}

fn payment_request(operation: &Operation) -> Result<Value> {
    let request = match operation {
        Operation::Shield {
            amount_zat,
            txid,
            index,
        } => {
            ensure!(
                txid.is_some() == index.is_some(),
                "--txid and --index must be provided together"
            );
            ensure!(
                amount_zat.is_some() || txid.is_some(),
                "provide an amount or both --txid and --index"
            );
            if let Some(txid) = txid {
                bytes32(txid)?;
            }
            json!({"kind":"shield","amount_zat":amount_zat,"txid":txid.as_ref().map(|id| id.to_ascii_lowercase()),"index":index})
        }
        Operation::Send { to, amount_zat } => {
            note::decode_address(to)?;
            json!({"kind":"send","to":to,"amount_zat":amount_zat})
        }
        Operation::Unshield { to, amount_zat } | Operation::TransparentSend { to, amount_zat } => {
            transaction::transparent_script(to)?;
            let kind = if matches!(operation, Operation::Unshield { .. }) {
                "unshield"
            } else {
                "transparent-send"
            };
            json!({"kind":kind,"to":to,"amount_zat":amount_zat})
        }
        _ => anyhow::bail!("not a payment operation"),
    };
    if let Some(amount) = request["amount_zat"].as_u64() {
        ensure!(amount > 0, "amount must be positive");
        protocol::value::Zatoshis::from_u64(
            amount
                .checked_add(FEE)
                .context("amount plus fee overflow")?,
        )
        .context("amount plus fee exceeds the monetary range")?;
    }
    Ok(request)
}

fn pay(
    store: &Store,
    config: &Config,
    operation: Operation,
    operation_id: Option<&str>,
    control: &Control,
) -> Result<Value> {
    let request = payment_request(&operation)?;
    if let Some(id) = operation_id
        && let Some(saved) = store.operation(id)?
    {
        ensure!(
            saved.request == request,
            "operation ID already belongs to a different payment request"
        );
        let mut result = operation_result(store, &saved)?;
        result["reused"] = json!(true);
        control.check()?;
        store.commit()?;
        return Ok(result); // Offline: never reselect inputs, rebuild proofs, or rebroadcast.
    }
    ensure!(
        sync(store, config, 1000, None, control)?["caught_up"] == true,
        "run sync until caught up before creating transactions"
    );
    let blocks = store.blocks()?;
    let tip = blocks.last().context("wallet has not synced")?;
    let epoch_end = config
        .activation
        .checked_add(
            tip.epoch
                .checked_add(1)
                .and_then(|e| e.checked_mul(EPOCH_SIZE))
                .context("epoch overflow")?,
        )
        .and_then(|h| h.checked_sub(1))
        .context("height overflow")?;
    let transparent_only = matches!(operation, Operation::TransparentSend { .. });
    ensure!(
        transparent_only || tip.height < epoch_end,
        "wait for the next epoch's first block before sending"
    );
    let expiry = if transparent_only {
        tip.height.saturating_add(20)
    } else {
        tip.height.saturating_add(20).min(epoch_end)
    };
    let own_address = note::address(&SpendingKey::from(config.seed));
    let mut outputs = Vec::new();
    let mut spend = None;
    let mut funding = None;
    let mut transparent_output = None;
    let mut recipient = None;
    let source;
    let rpc = rpc(config, control)?;
    match operation {
        Operation::Shield {
            amount_zat,
            txid,
            index,
        } => {
            let (txid, index) = match (txid, index) {
                (Some(txid), Some(index)) => (hex::encode(bytes32(&txid)?), index),
                (None, None) => select_funding_outpoint(
                    store,
                    &blocks,
                    &rpc,
                    amount_zat
                        .context("automatic selection requires an amount")?
                        .checked_add(FEE)
                        .context("amount plus fee overflow")?,
                    FundingPurpose::Shield,
                )?,
                _ => anyhow::bail!("--txid and --index must be provided together"),
            };
            source = format!("outpoint:{txid}:{index}");
            ensure!(
                !store
                    .pending()?
                    .iter()
                    .any(|p| p.source == source && pending_status(p, &blocks) != "expired"),
                "funding output is already reserved"
            );
            let (selected, coinbase) = load_funding(&rpc, config.seed, &txid, index)?;
            let after_fee = selected
                .output
                .value()
                .into_u64()
                .checked_sub(FEE)
                .context("funding output cannot pay fee")?;
            let amount = amount_zat.unwrap_or(after_fee);
            ensure!(amount > 0, "funding output must exceed the fee");
            let change = after_fee
                .checked_sub(amount)
                .context("funding output cannot cover amount plus fee")?;
            ensure!(
                !coinbase || change == 0,
                "coinbase outputs must be shielded in full minus the fee; omit the amount with --txid/--index, or use a non-coinbase UTXO"
            );
            if change > 0 {
                transparent_output = Some((transaction::funding_address(config.seed)?, change));
            }
            outputs.push(Receipt::new(&config.network_id, &own_address, amount)?);
            funding = Some(selected);
        }
        Operation::TransparentSend { to, amount_zat } => {
            let needed = amount_zat
                .checked_add(FEE)
                .context("amount plus fee overflow")?;
            let (txid, index) = select_funding_outpoint(
                store,
                &blocks,
                &rpc,
                needed,
                FundingPurpose::TransparentSend,
            )?;
            source = format!("outpoint:{txid}:{index}");
            let (selected, coinbase) = load_funding(&rpc, config.seed, &txid, index)?;
            ensure!(
                !coinbase,
                "coinbase outputs must be shielded before transparent transfers"
            );
            funding = Some(selected);
            transparent_output = Some((to, amount_zat));
        }
        Operation::Send { to, amount_zat } | Operation::Unshield { to, amount_zat } => {
            ensure!(amount_zat > 0, "amount must be positive");
            let needed = amount_zat.checked_add(FEE).context("amount overflow")?;
            let selected = note_states(store, config, &blocks, control)?.into_iter().filter(|(r,s)| *s == "available" && r.value_zat >= needed)
                .min_by_key(|(r,_)| r.value_zat).map(|(r,_)| r).context("no single available note covers amount plus fee; this wallet does not consolidate notes")?;
            source = format!("note:{}", selected.id()?);
            // The command-specific address format was checked before accessing the node.
            if to.starts_with("tachyon-test:") {
                let receipt = Receipt::new(&config.network_id, &to, amount_zat)?;
                outputs.push(receipt.clone());
                recipient = Some(receipt);
            } else {
                transaction::transparent_script(&to)?;
                transparent_output = Some((to, amount_zat));
            }
            let change = selected.value_zat - needed;
            if change > 0 {
                outputs.push(Receipt::new(&config.network_id, &own_address, change)?);
            }
            spend = Some(selected);
        }
        _ => anyhow::bail!("not a payment operation"),
    }
    control.stage("Building payment…")?;
    let tx = if transparent_only {
        let (to, amount) = transparent_output.context("transparent payment has a recipient")?;
        transaction::build_transparent(
            config.seed,
            funding.context("transparent payment has funding")?,
            &to,
            amount,
            expiry,
        )?
    } else {
        transaction::build(
            Payment {
                seed: config.seed,
                blocks: &blocks,
                spend: spend.as_ref(),
                funding,
                outputs: &outputs,
                transparent_output,
                expiry,
            },
            control,
        )?
    };
    ensure!(
        rpc.hash(tip.height)? == tip.hash && rpc.height()? <= expiry,
        "chain changed or transaction expired during proving; sync and retry"
    );
    let txid = tx.txid().to_string();
    let locator = Locator {
        txid: txid.clone(),
        height: None,
        block_hash: None,
    };
    if let Some(receipt) = recipient.as_mut() {
        receipt.locator = Some(locator.clone());
    }
    let mut raw = Vec::new();
    tx.write(&mut raw)?;
    for mut output in outputs {
        if output.payment_key == note::payment_key(&SpendingKey::from(config.seed)) {
            output.locator = Some(locator.clone());
            store.put_note(&output)?;
        }
    }
    let pending = Pending {
        txid: txid.clone(),
        raw: hex::encode(raw),
        expiry,
        source,
        receipt: recipient,
    };
    store.reserve(&pending)?;
    if let Some(id) = operation_id {
        store.put_operation(&StoredOperation {
            id: id.into(),
            txid: txid.clone(),
            request,
        })?;
    }
    // A timeout is not a rejection: commit both change receipts and the reservation BEFORE broadcast.
    control.stage("Persisting signed transaction and input reservation before broadcast…")?;
    store.commit()?;
    rpc.submit(&txid, &pending.raw).with_context(|| {
        format!("transaction {txid} saved; use transactions/submit/export-receipt to recover")
    })?;
    Ok(
        json!({"txid":txid,"operation_id":operation_id,"reused":false,"status":"submitted","fee_zat":FEE,"expiry_height":expiry,"has_receipt":pending.receipt.is_some()}),
    )
}

#[derive(Clone, Copy)]
enum FundingPurpose {
    Shield,
    TransparentSend,
}

fn load_funding(rpc: &Rpc, seed: [u8; 32], txid: &str, index: u32) -> Result<(Funding, bool)> {
    let available: Value = rpc.call("gettxout", json!([txid, index, true]))?;
    ensure!(
        !available.is_null(),
        "funding output is unavailable or already spent"
    );
    let confirmations = available["confirmations"]
        .as_u64()
        .context("missing confirmations")?;
    let coinbase = available["coinbase"]
        .as_bool()
        .context("missing coinbase flag")?;
    ensure!(
        confirmations >= if coinbase { COINBASE_MATURITY } else { 1 },
        "funding output is not mature/confirmed"
    );
    let raw: String = rpc.call("getrawtransaction", json!([txid, 0]))?;
    let bytes = hex::decode(raw)?;
    let previous = Transaction::read(&bytes[..], BranchId::NuTachyon)?;
    ensure!(
        previous.txid().to_string() == txid,
        "funding transaction ID mismatch"
    );
    let output = previous
        .transparent_bundle()
        .and_then(|bundle| bundle.vout.get(usize::try_from(index).ok()?))
        .context("funding output missing")?
        .clone();
    ensure!(
        *output.script_pubkey()
            == transaction::transparent_script(&transaction::funding_address(seed)?)?,
        "funding output is not owned by this wallet"
    );
    Ok((
        Funding {
            outpoint: transparent::bundle::OutPoint::new(*previous.txid().as_ref(), index),
            output,
        },
        coinbase,
    ))
}

fn select_funding_outpoint(
    store: &Store,
    blocks: &[Block],
    rpc: &Rpc,
    needed: u64,
    purpose: FundingPurpose,
) -> Result<(String, u32)> {
    let snapshot = store
        .funding_snapshot()?
        .context("run sync until caught up before selecting funding")?;
    let reserved = store
        .pending()?
        .into_iter()
        .filter(|pending| pending_status(pending, blocks) != "expired")
        .map(|pending| pending.source)
        .collect();
    // Avoid an RPC per mining reward when all of them would require forbidden transparent change.
    let coinbases: BTreeSet<_> = blocks
        .iter()
        .filter_map(|block| block.transactions.first())
        .map(String::as_str)
        .collect();
    for (txid, index, value) in snapshot.candidates(needed, &reserved) {
        let allow_coinbase = matches!(purpose, FundingPurpose::Shield) && value == needed;
        if !allow_coinbase && coinbases.contains(txid) {
            continue;
        }
        let available: Value = rpc.call("gettxout", json!([txid, index, true]))?;
        if available.is_null() {
            continue; // Spent in the mempool, or since the captured UTXO snapshot.
        }
        let coinbase = available["coinbase"]
            .as_bool()
            .context("missing coinbase flag")?;
        let confirmations = available["confirmations"]
            .as_u64()
            .context("missing confirmations")?;
        if confirmations < if coinbase { COINBASE_MATURITY } else { 1 }
            || (coinbase && !allow_coinbase)
        {
            continue;
        }
        return Ok((txid.into(), index));
    }
    anyhow::bail!(
        "no single eligible UTXO covers amount plus fee; inputs are not combined, reserved/immature outputs are excluded, and coinbase outputs must be shielded in full minus the fee"
    )
}

#[cfg(test)]
mod tests;
