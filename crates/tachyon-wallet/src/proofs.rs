//! Rebuild spendability from durable public inputs, including closed/empty epochs.
//! Proofs are deliberately ephemeral; restarting never depends on serializing mock PCDs.

use anyhow::{Context, Result, ensure};
use ragu::Pcd as RaguPcd;
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::pasta::Pasta;
use zcash_tachyon::{
    EpochIndex, Note, Tachygram,
    keys::private::SpendingKey,
    nullifier::NF_DERIVATION_WIDTH,
    stamp::proof::{PROOF_SYSTEM, delegation, pool, qr, spendable},
    witness,
};

use crate::{chain::anchor, control::Control, store::ChainData};
use udon::field::Field;
use zcash_tachyon::pasta::Fp;

type Pcd<H> = RaguPcd<Pasta, ProductionRank, H>;
type ProofStamp = zcash_tachyon::ProofStamp<zcash_tachyon::stamp::Uncompressed>;

mod epoch;
use epoch::bucket;

fn trivial() -> Pcd<()> {
    PROOF_SYSTEM.bootstrap_proof().clone().carry(())
}

fn verify_proof<H: ragu::header::Header<Fp>>(proof: &Pcd<H>) -> Result<bool> {
    let compressed = PROOF_SYSTEM.compress(proof, &mut rand::rng())?;
    Ok(PROOF_SYSTEM.verify_compressed(&compressed)?)
}

pub fn secret(
    key: &SpendingKey,
    note: Note,
    control: &Control,
) -> Result<Pcd<delegation::NoteSecret>> {
    control.stage("Proving note secret…")?;
    Ok(PROOF_SYSTEM
        .seed(
            &mut rand::rng(),
            delegation::NoteSeed,
            witness::note_seed(((), ()), note, key.derive_proof_private()),
        )?
        .0)
}

fn derivation(
    secret: &Pcd<delegation::NoteSecret>,
    epoch: u32,
    control: &Control,
) -> Result<Pcd<delegation::NoteNullifiers>> {
    control.stage(format!("Proving nullifier derivation for epoch {epoch}…"))?;
    let width = u32::try_from(NF_DERIVATION_WIDTH)?;
    let start = EpochIndex::new(epoch - epoch % width);
    Ok(PROOF_SYSTEM
        .fuse(
            &mut rand::rng(),
            delegation::NullifierDerive,
            witness::nullifier_derive((*secret.data(), ()), start),
            secret.clone(),
            trivial(),
        )?
        .0)
}

pub fn spendable(
    chain: &ChainData<'_>,
    key: &SpendingKey,
    note: Note,
    control: &Control,
) -> Result<Pcd<spendable::NoteSpendable>> {
    let cm = Tachygram::from(note.commitment());
    let note_id = hex::encode(Fp::from(cm).to_bytes());
    let current = chain.tip()?.epoch;
    if let Some(bytes) = chain.spendable_proof_bytes(&note_id)?
        && let Ok(cached) = Pcd::<spendable::NoteSpendable>::from_bytes(&bytes)
        && Tachygram::from(cached.data().0) == cm
        && u32::from(cached.data().1) <= current
        && verify_proof(&cached)?
    {
        if cached.data().1 == EpochIndex::new(current) {
            control.stage("Reusing cached spendability proof…")?;
            return Ok(cached);
        }
        let mut lineage = cached;
        for epoch in u32::from(lineage.data().1)..current {
            lineage = lift_closed_epoch(chain, key, note, epoch, lineage, control)?;
            cache_spendable(chain, &note_id, &lineage)?;
        }
        return Ok(lineage);
    }

    let (created, before, members) = chain
        .creation(cm)?
        .context("note commitment has not been mined")?;
    ensure!(created <= current, "note creation epoch is above the tip");
    let secret = secret(key, note, control)?;
    if created == current {
        let derived = derivation(&secret, current, control)?;
        control.stage("Proving spendability in the current epoch…")?;
        let lineage = PROOF_SYSTEM
            .fuse(
                &mut rand::rng(),
                spendable::SpendableInit,
                witness::spendable_init(
                    (*derived.data(), ()),
                    before,
                    &members,
                    EpochIndex::new(current),
                ),
                derived,
                trivial(),
            )?
            .0;
        cache_spendable(chain, &note_id, &lineage)?;
        return Ok(lineage);
    }

    let master = key.derive_nullifier_private().derive_note_private(note.psi);
    let mut lineage = None;
    for epoch in created..current {
        control.stage(format!(
            "Proving closed epoch {epoch} ({}/{})…",
            epoch - created + 1,
            current - created
        ))?;
        let nf = master.derive_nullifier(EpochIndex::new(epoch));
        let (absence_bucket, members) = bucket(chain, epoch, nf.into(), control)?;
        control.stage("Proving unspent evidence…")?;
        let (arbitrary, ()) = PROOF_SYSTEM.fuse(
            &mut rand::rng(),
            qr::QrUnspentInit,
            witness::qr_unspent_init((*absence_bucket.data(), ()), nf.into()),
            absence_bucket.clone(),
            trivial(),
        )?;
        let derived = derivation(&secret, epoch, control)?;
        let (_, first, last) = *derived.data();
        let window: Vec<_> = (u32::from(first)..=u32::from(last))
            .map(|e| master.derive_nullifier(EpochIndex::new(e)))
            .collect();
        control.stage("Binding unspent evidence…")?;
        let (unspent, ()) = PROOF_SYSTEM.fuse(
            &mut rand::rng(),
            pool::UnspentBind,
            witness::unspent_bind((*arbitrary.data(), *derived.data()), &window, &[nf]),
            arbitrary,
            derived,
        )?;
        lineage = Some(match lineage {
            None => {
                // The note commitment need not route to its nullifier's bucket.
                // Both proofs cover the same complete epoch and anchor bounds.
                let (creation_bucket, _) = if members.contains(&cm) {
                    (absence_bucket, members)
                } else {
                    bucket(chain, epoch, cm, control)?
                };
                control.stage("Proving initial closed-epoch spendability…")?;
                PROOF_SYSTEM
                    .fuse(
                        &mut rand::rng(),
                        spendable::QrSpendableInit,
                        (),
                        unspent,
                        creation_bucket,
                    )?
                    .0
            }
            Some(left) => {
                control.stage("Lifting spendability across epochs…")?;
                PROOF_SYSTEM
                    .fuse(
                        &mut rand::rng(),
                        spendable::SpendableLift,
                        (),
                        left,
                        unspent,
                    )?
                    .0
            }
        });
        if let Some(proof) = lineage.as_ref() {
            cache_spendable(chain, &note_id, proof)?;
        }
    }
    lineage.context("closed creation epoch must produce a spendable proof")
}

fn cache_spendable(
    chain: &ChainData<'_>,
    note_id: &str,
    proof: &Pcd<spendable::NoteSpendable>,
) -> Result<()> {
    let bytes = proof
        .to_bytes()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    chain.put_spendable_proof_bytes(note_id, &bytes)
}

fn lift_closed_epoch(
    chain: &ChainData<'_>,
    key: &SpendingKey,
    note: Note,
    epoch: u32,
    left: Pcd<spendable::NoteSpendable>,
    control: &Control,
) -> Result<Pcd<spendable::NoteSpendable>> {
    control.stage(format!(
        "Lifting cached spendability through epoch {epoch}…"
    ))?;
    let secret = secret(key, note, control)?;
    let master = key.derive_nullifier_private().derive_note_private(note.psi);
    let nf = master.derive_nullifier(EpochIndex::new(epoch));
    let (absence_bucket, _members) = bucket(chain, epoch, nf.into(), control)?;
    control.stage("Proving unspent evidence…")?;
    let (arbitrary, ()) = PROOF_SYSTEM.fuse(
        &mut rand::rng(),
        qr::QrUnspentInit,
        witness::qr_unspent_init((*absence_bucket.data(), ()), nf.into()),
        absence_bucket,
        trivial(),
    )?;
    let derived = derivation(&secret, epoch, control)?;
    let (_, first, last) = *derived.data();
    let window: Vec<_> = (u32::from(first)..=u32::from(last))
        .map(|e| master.derive_nullifier(EpochIndex::new(e)))
        .collect();
    control.stage("Binding unspent evidence…")?;
    let (unspent, ()) = PROOF_SYSTEM.fuse(
        &mut rand::rng(),
        pool::UnspentBind,
        witness::unspent_bind((*arbitrary.data(), *derived.data()), &window, &[nf]),
        arbitrary,
        derived,
    )?;
    Ok(PROOF_SYSTEM
        .fuse(
            &mut rand::rng(),
            spendable::SpendableLift,
            (),
            left,
            unspent,
        )?
        .0)
}

pub fn anchor_spans(
    chain: &ChainData<'_>,
    start: zcash_tachyon::Anchor,
    target: zcash_tachyon::Anchor,
    control: &Control,
) -> Result<Vec<Pcd<pool::AnchorSpan>>> {
    if start == target {
        return Ok(Vec::new());
    }
    let tip = chain.tip()?;
    let mut cursor = start;
    let mut span: Option<Pcd<pool::AnchorSpan>> = None;
    let mut span_members = Vec::new();
    let current_blocks = chain.epoch_blocks(tip.epoch)?;
    'blocks: for block in current_blocks.iter().filter(|b| b.epoch == tip.epoch) {
        control.check()?;
        let mut before = block.entry()?;
        for published in &block.stamps {
            control.check()?;
            if cursor == target {
                break 'blocks;
            }
            let members = published.members()?;
            let commitment = published.commitment()?;
            let after = before.next_stamp(EpochIndex::new(tip.epoch), &commitment)?;
            if before == cursor {
                control.stage("Proving anchor span…")?;
                let (seed, ()) = PROOF_SYSTEM.seed(
                    &mut rand::rng(),
                    pool::AnchorSpanSeed,
                    witness::anchor_span_seed(
                        ((), ()),
                        before,
                        EpochIndex::new(tip.epoch),
                        &members,
                    ),
                )?;
                span = Some(match span.take() {
                    None => seed,
                    Some(left) => {
                        PROOF_SYSTEM
                            .fuse(
                                &mut rand::rng(),
                                pool::AnchorSpanFuse,
                                witness::anchor_span_fuse(
                                    (*left.data(), *seed.data()),
                                    &span_members,
                                    &[after],
                                ),
                                left,
                                seed,
                            )?
                            .0
                    }
                });
                span_members.push(after);
                cursor = after;
            }
            before = after;
        }
    }
    ensure!(cursor == target, "cannot reach the requested anchor");
    let span = span.context("no anchor span reaches the requested anchor")?;
    control.check()?;
    Ok(vec![span])
}

pub fn lift_stamp(
    chain: &ChainData<'_>,
    stamp: ProofStamp,
    descriptors: &std::collections::BTreeSet<zcash_tachyon::action::Descriptor>,
    fee_descriptors: &std::collections::BTreeSet<zcash_tachyon::fee::Descriptor>,
    control: &Control,
) -> Result<ProofStamp> {
    control.stage("Lifting stamp to the synced anchor…")?;
    let target = anchor(&chain.tip()?.anchor_after)?;
    let spans = anchor_spans(chain, stamp.anchor, target, control)?;
    if spans.is_empty() {
        return Ok(stamp);
    }
    Ok(stamp.lift(&mut rand::rng(), descriptors, fee_descriptors, spans)?)
}
