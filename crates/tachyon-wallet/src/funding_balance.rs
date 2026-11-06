//! Confirmed transparent funding snapshots, independent of Tachyon note balances.

use anyhow::{Context, Result, ensure};
use protocol::value::Zatoshis;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

use crate::{chain::bytes32, rpc::Rpc, store::Store, transaction};

pub const COINBASE_MATURITY: u64 = 100;

#[derive(Debug, Deserialize)]
pub struct AddressUtxos {
    pub height: u32,
    pub hash: String,
    utxos: Vec<AddressUtxo>,
}

#[derive(Debug, Deserialize)]
struct AddressUtxo {
    address: String,
    txid: String,
    #[serde(rename = "outputIndex")]
    index: u32,
    script: String,
    satoshis: u64,
    height: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub height: u32,
    pub hash: String,
    address: String,
    utxos: Vec<Utxo>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Utxo {
    txid: String,
    index: u32,
    value_zat: u64,
    /// Maturity is evaluated at the snapshot height, not the current wall-clock time.
    immature_coinbase: bool,
}

#[derive(Debug, Serialize)]
pub struct Balance<'a> {
    address: &'a str,
    synced_height: u32,
    synced_hash: &'a str,
    total_zat: u64,
    available_zat: u64,
    immature_zat: u64,
    reserved_zat: u64,
    utxo_count: usize,
}

impl AddressUtxos {
    pub fn fetch(rpc: &Rpc, address: &str) -> Result<Self> {
        let snapshot: Self = rpc
            .call(
                "getaddressutxos",
                json!([{ "addresses": [address], "chainInfo": true }]),
            )
            .context("transparent funding sync requires getaddressutxos with chainInfo")?;
        bytes32(&snapshot.hash)?;
        Ok(snapshot)
    }

    pub fn into_snapshot(self, rpc: &Rpc, address: &str, store: &Store) -> Result<Snapshot> {
        let tip = store
            .block(self.height)?
            .context("transparent snapshot tip is missing from the synced chain")?;
        ensure!(
            tip.height == self.height && tip.hash == self.hash,
            "transparent snapshot does not match the synced chain; retry sync"
        );
        let expected_script = transaction::transparent_script(address)?;
        let mut seen = BTreeSet::new();
        let mut utxos = Vec::with_capacity(self.utxos.len());
        for output in self.utxos {
            rpc.control.check()?;
            let txid = hex::encode(bytes32(&output.txid)?);
            ensure!(
                seen.insert((txid.clone(), output.index)),
                "duplicate funding outpoint"
            );
            ensure!(
                output.address == address && hex::decode(&output.script)? == expected_script.0.0,
                "funding UTXO does not belong to the wallet's funding address"
            );
            Zatoshis::from_u64(output.satoshis).context("invalid funding UTXO amount")?;
            ensure!(
                output.height <= self.height,
                "funding output is above the snapshot tip"
            );
            let confirmations = u64::from(self.height - output.height) + 1;
            let immature_coinbase = if confirmations < COINBASE_MATURITY {
                let coinbase_txid = if let Some(block) = store.block(output.height)? {
                    block.transactions.first().cloned()
                } else {
                    // Recent pre-activation funding is outside the Tachyon feed;
                    // fetch only this missing block's transaction IDs.
                    let response: Value =
                        rpc.call("getblock", json!([output.height.to_string(), 1]))?;
                    ensure!(
                        response["height"].as_u64() == Some(u64::from(output.height)),
                        "funding block height mismatch"
                    );
                    let hash = response["hash"]
                        .as_str()
                        .context("funding block has no hash")?;
                    bytes32(hash)?;
                    response["tx"]
                        .as_array()
                        .and_then(|transactions| transactions.first())
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                };
                coinbase_txid.as_ref() == Some(&txid)
            } else {
                false
            };
            utxos.push(Utxo {
                txid,
                index: output.index,
                value_zat: output.satoshis,
                immature_coinbase,
            });
        }
        Ok(Snapshot {
            height: self.height,
            hash: self.hash,
            address: address.into(),
            utxos,
        })
    }
}

impl Snapshot {
    /// Eligible outpoints in deterministic smallest-first order; callers must recheck with gettxout.
    pub fn candidates(&self, minimum: u64, reserved: &BTreeSet<String>) -> Vec<(&str, u32, u64)> {
        let mut candidates: Vec<_> = self
            .utxos
            .iter()
            .filter(|output| {
                output.value_zat >= minimum
                    && !output.immature_coinbase
                    && !reserved.contains(&format!("outpoint:{}:{}", output.txid, output.index))
            })
            .map(|output| (output.txid.as_str(), output.index, output.value_zat))
            .collect();
        candidates.sort_unstable_by_key(|&(txid, index, value)| (value, txid, index));
        candidates
    }

    pub fn balance(&self, reserved: &BTreeSet<String>) -> Result<Balance<'_>> {
        let mut balance = Balance {
            address: &self.address,
            synced_height: self.height,
            synced_hash: &self.hash,
            total_zat: 0,
            available_zat: 0,
            immature_zat: 0,
            reserved_zat: 0,
            utxo_count: self.utxos.len(),
        };
        for output in &self.utxos {
            balance.total_zat = balance
                .total_zat
                .checked_add(output.value_zat)
                .context("transparent balance overflow")?;
            let bucket = if reserved.contains(&format!("outpoint:{}:{}", output.txid, output.index))
            {
                &mut balance.reserved_zat
            } else if output.immature_coinbase {
                &mut balance.immature_zat
            } else {
                &mut balance.available_zat
            };
            *bucket = bucket
                .checked_add(output.value_zat)
                .context("transparent balance overflow")?;
        }
        Ok(balance)
    }
}

#[cfg(test)]
mod tests;
