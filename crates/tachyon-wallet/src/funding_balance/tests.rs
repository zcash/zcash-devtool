use super::*;
use crate::{chain::Block, control::Control, store::Store};

fn store_with(blocks: &[Block]) -> Result<(tempfile::TempDir, Store)> {
    let directory = tempfile::tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let store = Store::open(directory.path(), true)?;
    for block in blocks {
        store.put_block(block)?;
    }
    Ok((directory, store))
}

fn snapshot(height: u32, output_height: u32, coinbase: bool) -> Result<Snapshot> {
    let address = transaction::funding_address(crate::tests::SEED)?;
    let txid = "11".repeat(32);
    let mut origin = crate::tests::genesis();
    origin.height = output_height;
    origin.transactions = vec![
        if coinbase {
            txid.clone()
        } else {
            "22".repeat(32)
        },
        txid.clone(),
    ];
    let mut tip = origin.clone();
    tip.height = height;
    let response: AddressUtxos = serde_json::from_value(json!({
        "height": height, "hash": tip.hash,
        "utxos": [{"address": address, "txid": txid, "outputIndex": 0,
            "script": hex::encode(transaction::transparent_script(&address)?.0.0),
            "satoshis": 625_000_000, "height": output_height}]
    }))?;
    let (_directory, store) = store_with(&[origin, tip])?;
    response.into_snapshot(
        &Rpc::new("http://127.0.0.1:1", None, &Control::new(true))?,
        &address,
        &store,
    )
}

#[test]
fn coinbase_maturity_matches_shield_at_99_and_100_confirmations() -> Result<()> {
    let immature = snapshot(106, 8, true)?;
    let balance = immature.balance(&BTreeSet::new())?;
    assert_eq!(balance.immature_zat, 625_000_000);
    assert_eq!(balance.available_zat, 0);
    let mature = snapshot(107, 8, true)?;
    let balance = mature.balance(&BTreeSet::new())?;
    assert_eq!(balance.immature_zat, 0);
    assert_eq!(balance.available_zat, 625_000_000);
    Ok(())
}

#[test]
fn regular_receipts_are_available_with_one_confirmation() -> Result<()> {
    let receipt = snapshot(8, 8, false)?;
    let balance = receipt.balance(&BTreeSet::new())?;
    assert_eq!(balance.available_zat, 625_000_000);
    assert_eq!(balance.total_zat, balance.available_zat);
    Ok(())
}

#[test]
fn reservations_are_disjoint_from_available_and_immature_funds() -> Result<()> {
    let receipt = snapshot(8, 8, true)?;
    let balance = receipt.balance(&BTreeSet::from([format!("outpoint:{}:0", "11".repeat(32))]))?;
    assert_eq!(balance.reserved_zat, 625_000_000);
    assert_eq!(balance.available_zat, 0);
    assert_eq!(balance.immature_zat, 0);
    assert_eq!(balance.total_zat, balance.reserved_zat);
    Ok(())
}

#[test]
fn rejects_duplicate_foreign_future_and_malformed_outputs() -> Result<()> {
    let address = transaction::funding_address(crate::tests::SEED)?;
    let mut tip = crate::tests::genesis();
    tip.height = 108;
    let output = json!({"address": address, "txid": "11".repeat(32), "outputIndex": 0,
        "script": hex::encode(transaction::transparent_script(&address)?.0.0),
        "satoshis": 10, "height": 8});
    let mut invalid = vec![vec![output.clone(), output.clone()]];
    for (field, value) in [
        ("address", json!("foreign")),
        ("script", json!("00")),
        ("txid", json!("not-a-txid")),
        ("height", json!(109)),
        ("satoshis", json!(u64::MAX)),
    ] {
        let mut changed = output.clone();
        changed[field] = value;
        invalid.push(vec![changed]);
    }
    for utxos in invalid {
        let response: AddressUtxos = serde_json::from_value(
            json!({"height": tip.height, "hash": tip.hash, "utxos": utxos}),
        )?;
        let (_directory, store) = store_with(std::slice::from_ref(&tip))?;
        assert!(
            response
                .into_snapshot(
                    &Rpc::new("http://127.0.0.1:1", None, &Control::new(true))?,
                    &address,
                    &store
                )
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn accumulation_never_wraps() -> Result<()> {
    let mut snapshot = snapshot(108, 8, false)?;
    snapshot.utxos[0].value_zat = u64::MAX;
    snapshot.utxos.push(Utxo {
        txid: "22".repeat(32),
        index: 0,
        value_zat: 1,
        immature_coinbase: false,
        coinbase: Some(false),
    });
    assert!(snapshot.balance(&BTreeSet::new()).is_err());
    Ok(())
}
