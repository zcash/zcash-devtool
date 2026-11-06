use anyhow::Result;
use primitives::transaction::Transaction;
use protocol::{consensus::BranchId, value::Zatoshis};
use sha2::{Digest, Sha256};
use transparent::bundle::{OutPoint, TxOut};
use udon::field::Field;
use zcash_tachyon::pasta::Fp;
use zcash_tachyon::{
    Anchor, EpochIndex, QrClassRoot, Tachygram, TachygramSetPoly, TachyonBundle,
    constants::EPOCH_SIZE, keys::private::SpendingKey,
};

use crate::{
    chain::{self, Block, Stamp},
    control::Control,
    note::{self, Receipt},
    transaction::{self, FEE, Funding, Payment},
};

pub(crate) const SEED: [u8; 32] = [7; 32];
pub(crate) const NETWORK: &str = "test-network";

fn build(payment: Payment<'_>) -> Result<Transaction> {
    transaction::build(payment, &Control::new(true))
}

pub(crate) fn genesis() -> Block {
    let anchor = chain::anchor_hex(Anchor::default());
    Block {
        hash: hex::encode([1; 32]),
        previous_block_hash: hex::encode([0; 32]),
        height: 8,
        activation_height: 8,
        pool_height: 0,
        epoch: 0,
        epoch_length: EPOCH_SIZE,
        anchor_before: anchor.clone(),
        epoch_start_anchor: Some(anchor.clone()),
        anchor_after: anchor,
        stamps: vec![],
        transactions: vec![],
    }
}

pub(crate) fn mine(blocks: &mut Vec<Block>, tx: Option<&Transaction>) -> Result<()> {
    let parent = blocks.last().unwrap();
    let height = parent.height + 1;
    let pool_height = height - 8;
    let epoch = pool_height / EPOCH_SIZE;
    let before = chain::anchor(&parent.anchor_after)?;
    let entry = if epoch != parent.epoch {
        before.next_epoch(EpochIndex::new(epoch))?
    } else {
        before
    };
    let mut after = entry;
    let mut stamps = Vec::new();
    if let Some(tx) = tx.filter(|tx| !matches!(tx.tachyon_bundle(), TachyonBundle::NoBundle)) {
        let TachyonBundle::Proven(bundle) = tx.tachyon_bundle() else {
            panic!("expected proven bundle")
        };
        after = entry.next_stamp(EpochIndex::new(epoch), &bundle.stamp.tachygram_set)?;
        let mut commitment = Vec::new();
        bundle.stamp.tachygram_set.write(&mut commitment)?;
        stamps.push(Stamp {
            transaction_index: 0,
            txid: tx.txid().to_string(),
            tachygram_set: hex::encode(commitment),
            tachygrams: bundle
                .stamp
                .tachygrams
                .iter()
                .map(|t| hex::encode(Fp::from(*t).to_bytes()))
                .collect(),
        });
    }
    let block = Block {
        hash: hex::encode(Sha256::digest(height.to_le_bytes())),
        previous_block_hash: parent.hash.clone(),
        height,
        activation_height: 8,
        pool_height,
        epoch,
        epoch_length: EPOCH_SIZE,
        anchor_before: parent.anchor_after.clone(),
        epoch_start_anchor: (epoch != parent.epoch).then(|| chain::anchor_hex(entry)),
        anchor_after: chain::anchor_hex(after),
        stamps,
        transactions: tx.map(|t| vec![t.txid().to_string()]).unwrap_or_default(),
    };
    block.validate(Some(parent), 8)?;
    blocks.push(block);
    Ok(())
}

pub(crate) fn own(value: u64) -> Receipt {
    Receipt::new(NETWORK, &note::address(&SpendingKey::from(SEED)), value).unwrap()
}

pub(crate) fn shield(blocks: &[Block], receipt: &Receipt) -> Result<Transaction> {
    build(Payment {
        seed: SEED,
        blocks: blocks.into(),
        spend: None,
        funding: Some(Funding {
            outpoint: OutPoint::new([2; 32], 0),
            output: TxOut::new(
                Zatoshis::from_u64(receipt.value_zat + FEE)?,
                transaction::transparent_script(&transaction::funding_address(SEED)?)?,
            ),
        }),
        outputs: std::slice::from_ref(receipt),
        transparent_output: None,
        expiry: blocks.last().unwrap().height + 20,
    })
}

#[test]
fn transparent_payment_signatures_cover_recipient_and_change_and_reject_foreign_funding()
-> Result<()> {
    let output = TxOut::new(
        Zatoshis::from_u64(250_000)?,
        transaction::transparent_script(&transaction::funding_address(SEED)?)?,
    );
    let recipient = bs58::encode([&[0x1c, 0xba][..], &[9; 20]].concat())
        .with_check()
        .into_string();
    let tx = transaction::build_transparent(
        SEED,
        Funding {
            outpoint: OutPoint::new([2; 32], 0),
            output: output.clone(),
        },
        &recipient,
        100_000,
        28,
    )?;
    assert!(matches!(tx.tachyon_bundle(), TachyonBundle::NoBundle));
    let bundle = tx.transparent_bundle().unwrap();
    assert_eq!(bundle.vout.len(), 2);
    assert_eq!(
        bundle.vout[0].script_pubkey(),
        &transaction::transparent_script(&recipient)?
    );
    assert_eq!(bundle.vout[1].value().into_u64(), 100_000);
    let mut bytes = Vec::new();
    tx.write(&mut bytes)?;
    let decoded = Transaction::read(&bytes[..], BranchId::NuTachyon)?;
    assert_eq!(decoded.txid(), tx.txid());
    transaction::verify_for_test(&decoded, Some(output.clone()))?;
    for index in [0, 1] {
        let mut changed = bundle.clone();
        changed.vout[index] = TxOut::new(
            Zatoshis::from_u64(99_999)?,
            changed.vout[index].script_pubkey().clone(),
        );
        let tampered = primitives::transaction::TransactionData::<
            primitives::transaction::Authorized,
        >::from_parts_v7(
            BranchId::NuTachyon,
            0,
            tx.expiry_height(),
            Zatoshis::ZERO,
            Some(changed),
            None,
            None,
            None,
            TachyonBundle::NoBundle,
        )
        .freeze()?;
        assert!(transaction::verify_for_test(&tampered, Some(output.clone())).is_err());
    }
    assert!(
        transaction::build_transparent(
            [8; 32],
            Funding {
                outpoint: OutPoint::new([2; 32], 0),
                output
            },
            &recipient,
            100_000,
            28
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn receipts_are_canonical_and_bound_to_owner_and_network() -> Result<()> {
    let receipt = own(100_000);
    receipt.check_owner(&SpendingKey::from(SEED), NETWORK)?;
    assert!(
        receipt
            .check_owner(&SpendingKey::from([8; 32]), NETWORK)
            .is_err()
    );
    assert!(
        receipt
            .check_owner(&SpendingKey::from(SEED), "other-chain")
            .is_err()
    );
    let mut broken = receipt.clone();
    broken.rcm = hex::encode([0; 32]);
    assert!(broken.note().is_err());
    broken.rcm = hex::encode([255; 32]);
    assert!(broken.note().is_err());
    assert!(Receipt::new(NETWORK, "tachyon-test:deadbeef", 1).is_err());
    assert!(Receipt::new(NETWORK, &note::address(&SpendingKey::from(SEED)), 0).is_err());
    Ok(())
}

#[test]
fn chain_rejects_corrupt_inputs_and_discontinuities() -> Result<()> {
    let mut blocks = vec![genesis()];
    blocks[0].validate(None, 8)?;
    let tx = shield(&blocks, &own(1_000_000))?;
    mine(&mut blocks, Some(&tx))?;
    let mut bad = blocks[1].clone();
    bad.stamps[0].tachygrams.pop();
    assert!(bad.validate(Some(&blocks[0]), 8).is_err());
    let mut bad = blocks[1].clone();
    bad.previous_block_hash = hex::encode([9; 32]);
    assert!(bad.validate(Some(&blocks[0]), 8).is_err());
    let mut bad = blocks[1].clone();
    bad.epoch_start_anchor = Some(bad.anchor_before.clone());
    assert!(bad.validate(Some(&blocks[0]), 8).is_err());
    let mut bad = blocks[1].clone();
    bad.epoch_length /= 2;
    assert!(bad.validate(Some(&blocks[0]), 8).is_err());
    let mut bad = blocks[1].clone();
    // Reject before constructing a polynomial, including under mock Ragu.
    bad.stamps[0].tachygrams = vec![hex::encode([0; 32]); chain::max_polynomial_members() + 1];
    assert!(
        bad.validate(Some(&blocks[0]), 8)
            .unwrap_err()
            .to_string()
            .contains("polynomial capacity")
    );
    Ok(())
}

#[test]
fn shield_transfer_change_and_unshield_roundtrip_with_valid_authorization() -> Result<()> {
    let mut blocks = vec![genesis()];
    let funded = own(1_000_000);
    let tx = shield(&blocks, &funded)?;
    transaction::verify_for_test(
        &tx,
        Some(TxOut::new(
            Zatoshis::from_u64(1_000_000 + FEE)?,
            transaction::transparent_script(&transaction::funding_address(SEED)?)?,
        )),
    )?;
    mine(&mut blocks, Some(&tx))?;
    // A later unrelated stamp forces the spending stamp to lift within the active epoch.
    let unrelated = shield(&blocks, &own(200_000))?;
    mine(&mut blocks, Some(&unrelated))?;
    let recipient = Receipt::new(
        NETWORK,
        &note::address(&SpendingKey::from([8; 32])),
        300_000,
    )?;
    let change = own(650_000);
    let sent = build(Payment {
        seed: SEED,
        blocks: (&blocks).into(),
        spend: Some(&funded),
        funding: None,
        outputs: &[recipient, change.clone()],
        transparent_output: None,
        expiry: 30,
    })?;
    transaction::verify_for_test(&sent, None)?;
    let TachyonBundle::Proven(bundle) = sent.tachyon_bundle() else {
        panic!()
    };
    assert_eq!(bundle.descriptors().len(), 3); // Spend + recipient + change, not output-only.
    assert_eq!(
        bundle.stamp.anchor,
        chain::anchor(&blocks.last().unwrap().anchor_after)?
    );
    mine(&mut blocks, Some(&sent))?;
    let unshield = build(Payment {
        seed: SEED,
        blocks: (&blocks).into(),
        spend: Some(&change),
        funding: None,
        outputs: &[],
        transparent_output: Some((transaction::funding_address(SEED)?, 600_000)),
        expiry: 30,
    })?;
    transaction::verify_for_test(&unshield, None)?;
    assert_eq!(
        unshield.transparent_bundle().unwrap().vout[0]
            .value()
            .into_u64(),
        600_000
    );
    let mut bytes = Vec::new();
    unshield.write(&mut bytes)?;
    let decoded = Transaction::read(&bytes[..], BranchId::NuTachyon)?;
    assert_eq!(decoded.txid(), unshield.txid());
    transaction::verify_for_test(&decoded, None)?;
    Ok(())
}

#[test]
fn old_note_spends_after_populated_and_empty_closed_epochs() -> Result<()> {
    let mut blocks = vec![genesis()];
    let receipt = own(1_000_000);
    let tx = shield(&blocks, &receipt)?;
    mine(&mut blocks, Some(&tx))?;
    // Epoch zero contains the minted note; epoch one has no stamps at all.
    while blocks.last().unwrap().epoch < 2 {
        mine(&mut blocks, None)?;
    }
    let sent = build(Payment {
        seed: SEED,
        blocks: (&blocks).into(),
        spend: Some(&receipt),
        funding: None,
        outputs: &[own(950_000)],
        transparent_output: None,
        expiry: blocks.last().unwrap().height + 20,
    })?;
    transaction::verify_for_test(&sent, None)?;
    Ok(())
}

#[test]
fn checkpoint_history_supports_spends_before_and_after_creation_epoch_closes() -> Result<()> {
    let mut blocks = vec![genesis()];
    while blocks.last().unwrap().epoch < 1 {
        mine(&mut blocks, None)?;
    }
    let checkpoint = blocks.last().unwrap().clone();
    checkpoint.validate_checkpoint(8)?;
    assert!(checkpoint.validate(None, 8).is_err());
    blocks = vec![checkpoint]; // No public data from epoch zero is needed.
    let receipt = own(1_000_000);
    let tx = shield(&blocks, &receipt)?;
    mine(&mut blocks, Some(&tx))?;
    for target_epoch in [1, 2] {
        while blocks.last().unwrap().epoch < target_epoch {
            mine(&mut blocks, None)?;
        }
        let sent = build(Payment {
            seed: SEED,
            blocks: (&blocks).into(),
            spend: Some(&receipt),
            funding: None,
            outputs: &[own(950_000)],
            transparent_output: None,
            expiry: blocks.last().unwrap().height + 20,
        })?;
        transaction::verify_for_test(&sent, None)?;
    }
    Ok(())
}

/// Add distinct public stamp inputs without generating thousands of payments.
/// Each stamp fits individually; their union deliberately exceeds one polynomial.
fn populate_epoch(blocks: &mut Vec<Block>, count: usize) -> Result<()> {
    mine(blocks, None)?;
    let parent_index = blocks.len() - 2;
    let mut block = blocks.last().unwrap().clone();
    let epoch = EpochIndex::new(block.epoch);
    let mut anchor = block.entry()?;
    let existing: std::collections::BTreeSet<_> = blocks
        .iter()
        .filter(|b| b.epoch == block.epoch)
        .flat_map(|b| &b.stamps)
        .map(Stamp::members)
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();
    let members: Vec<_> = (1u64..)
        .map(|i| Tachygram::from(Fp::from(i)))
        .filter(|member| !existing.contains(member))
        .take(count)
        .collect();
    for (index, members) in members.chunks(64).enumerate() {
        let commitment = members
            .iter()
            .copied()
            .collect::<TachygramSetPoly>()
            .commit();
        anchor = anchor.next_stamp(epoch, &commitment)?;
        let mut bytes = Vec::new();
        commitment.write(&mut bytes)?;
        block.stamps.push(Stamp {
            transaction_index: index,
            txid: hex::encode(Sha256::digest(index.to_le_bytes())),
            tachygram_set: hex::encode(bytes),
            tachygrams: members
                .iter()
                .map(|m| hex::encode(Fp::from(*m).to_bytes()))
                .collect(),
        });
    }
    block.anchor_after = chain::anchor_hex(anchor);
    block.validate(Some(&blocks[parent_index]), 8)?;
    *blocks.last_mut().unwrap() = block;
    Ok(())
}

#[test]
fn spends_after_epoch_with_more_tachygrams_than_polynomial_capacity() -> Result<()> {
    let mut blocks = vec![genesis()];
    let key = SpendingKey::from(SEED);
    let older = own(1_000_000);
    let funded = shield(&blocks, &older)?;
    mine(&mut blocks, Some(&funded))?;
    while blocks.last().unwrap().epoch < 1 {
        mine(&mut blocks, None)?;
    }
    // Force creation membership and nullifier absence into different QR buckets.
    let receipt = (0..64)
        .map(|_| own(1_000_000))
        .find(|r| {
            let note = r.note().unwrap();
            let nf = key
                .derive_nullifier_private()
                .derive_note_private(note.psi)
                .derive_nullifier(EpochIndex::new(1));
            QrClassRoot::of(note.commitment().into(), Fp::from(1)).0
                != QrClassRoot::of(nf.into(), Fp::from(1)).0
        })
        .expect("one of 64 random notes routes differently from its nullifier");
    let funded = shield(&blocks, &receipt)?;
    mine(&mut blocks, Some(&funded))?;
    populate_epoch(&mut blocks, chain::max_polynomial_members() + 19)?;
    while blocks.last().unwrap().epoch < 2 {
        mine(&mut blocks, None)?;
    }
    assert_eq!(blocks.last().unwrap().height, 8200);
    // Exercise both routed creation and lifting an older note through a large epoch.
    for receipt in [&receipt, &older] {
        let sent = build(Payment {
            seed: SEED,
            blocks: (&blocks).into(),
            spend: Some(receipt),
            funding: None,
            outputs: &[own(950_000)],
            transparent_output: None,
            expiry: blocks.last().unwrap().height + 20,
        })?;
        transaction::verify_for_test(&sent, None)?;
    }
    Ok(())
}

#[test]
fn store_indexes_new_blocks_and_rewinds_without_rescanning() -> Result<()> {
    let directory = tempfile::tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let store = crate::store::Store::open(directory.path(), true)?;
    let mut blocks = vec![genesis()];
    let receipt = own(1_000_000);
    let funded = shield(&blocks, &receipt)?;
    mine(&mut blocks, Some(&funded))?;
    for block in &blocks {
        store.put_block(block)?;
    }
    assert_eq!(store.tip()?.map(|block| block.height), Some(9));
    assert_eq!(store.tachygram_height(&receipt.id()?)?, Some(9));
    assert!(store.has_transaction(&funded.txid().to_string())?);
    assert_eq!(store.blocks_range(8, 8)?.len(), 1);
    store.rewind(8)?;
    assert_eq!(store.tachygram_height(&receipt.id()?)?, None);
    assert!(!store.has_transaction(&funded.txid().to_string())?);
    Ok(())
}

#[test]
fn cached_spendability_advances_only_across_new_epochs() -> Result<()> {
    let directory = tempfile::tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let store = crate::store::Store::open(directory.path(), true)?;
    let mut blocks = vec![genesis()];
    let receipt = own(1_000_000);
    let funded = shield(&blocks, &receipt)?;
    mine(&mut blocks, Some(&funded))?;
    while blocks.last().unwrap().epoch < 2 {
        mine(&mut blocks, None)?;
    }
    for block in &blocks {
        store.put_block(block)?;
    }
    let chain = crate::store::ChainData::Store(&store);
    let control = Control::new(true);
    let key = SpendingKey::from(SEED);
    let first = crate::proofs::spendable(&chain, &key, receipt.note()?, &control)?;
    let cached = store
        .spendable_proof(&receipt.id()?)?
        .expect("spendability proof is cached");
    assert!(!cached.is_empty());
    let second = crate::proofs::spendable(&chain, &key, receipt.note()?, &control)?;
    assert_eq!(second.data(), first.data());
    assert!(
        store
            .bucket_proof(0, zcash_tachyon::QrProfile::ROOT)?
            .is_some_and(|(pcd, _)| !pcd.is_empty())
    );
    store.put_spendable_proof(&receipt.id()?, &[0u8; 32])?;
    let recovered = crate::proofs::spendable(&chain, &key, receipt.note()?, &control)?;
    assert_eq!(recovered.data(), first.data());
    assert_ne!(store.spendable_proof(&receipt.id()?)?, Some(vec![0u8; 32]));
    while blocks.last().unwrap().epoch < 3 {
        mine(&mut blocks, None)?;
    }
    for block in &blocks {
        if store.block(block.height)?.is_none() {
            store.put_block(block)?;
        }
    }
    let third = crate::proofs::spendable(&chain, &key, receipt.note()?, &control)?;
    assert!(third.data().1 > second.data().1);
    Ok(())
}

#[test]
fn spent_note_cannot_produce_closed_epoch_absence_evidence() -> Result<()> {
    let mut blocks = vec![genesis()];
    let receipt = own(1_000_000);
    let funded = shield(&blocks, &receipt)?;
    mine(&mut blocks, Some(&funded))?;
    let sent = build(Payment {
        seed: SEED,
        blocks: (&blocks).into(),
        spend: Some(&receipt),
        funding: None,
        outputs: &[own(950_000)],
        transparent_output: None,
        expiry: 30,
    })?;
    mine(&mut blocks, Some(&sent))?;
    while blocks.last().unwrap().epoch < 1 {
        mine(&mut blocks, None)?;
    }
    assert!(
        crate::proofs::spendable(
            &crate::store::ChainData::Blocks(&blocks),
            &SpendingKey::from(SEED),
            receipt.note()?,
            &Control::new(true)
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn spent_note_cannot_hide_in_another_routed_bucket() -> Result<()> {
    let mut blocks = vec![genesis()];
    let receipt = own(1_000_000);
    let funded = shield(&blocks, &receipt)?;
    mine(&mut blocks, Some(&funded))?;
    let sent = build(Payment {
        seed: SEED,
        blocks: (&blocks).into(),
        spend: Some(&receipt),
        funding: None,
        outputs: &[own(950_000)],
        transparent_output: None,
        expiry: 30,
    })?;
    mine(&mut blocks, Some(&sent))?;
    populate_epoch(&mut blocks, chain::max_polynomial_members() + 19)?;
    while blocks.last().unwrap().epoch < 1 {
        mine(&mut blocks, None)?;
    }
    let error = crate::proofs::spendable(
        &crate::store::ChainData::Blocks(&blocks),
        &SpendingKey::from(SEED),
        receipt.note()?,
        &Control::new(true),
    )
    .err()
    .expect("a spent note must fail absence verification");
    assert!(
        error.to_string().contains("found nullifier in the bucket"),
        "{error}"
    );
    Ok(())
}
