//! Complete closed-epoch evidence, routed before merging to bound polynomial size.

use std::collections::BTreeSet;

use anyhow::{Context, Result, ensure};
use ragu::Pcd;
use zcash_tachyon::pasta::Fp;
use zcash_tachyon::{
    Anchor, EpochIndex, QrClassRoot, QrDiscriminant, QrProfile, Tachygram,
    stamp::proof::{PROOF_SYSTEM, qr},
    witness,
};

use super::trivial;
use crate::chain::{MAX_EPOCH_MEMBERS, anchor, max_polynomial_members};
use crate::control::Control;
use crate::store::ChainData;
use udon::field::Field;

struct Intake {
    proof: Pcd<qr::QrIntake>,
    members: Vec<Tachygram>,
}

/// Choose one common QR path for the query across all stamps, without first
/// constructing the (potentially oversized) whole-epoch polynomial.
fn routing_path(
    mut members: Vec<Tachygram>,
    query: Tachygram,
    discriminant: QrDiscriminant,
    control: &Control,
) -> Result<Vec<bool>> {
    let mut path = Vec::new();
    while members.len() > max_polynomial_members() {
        control.check()?;
        ensure!(
            path.len() < QrProfile::MAX_DEPTH,
            "epoch cannot be routed within Tachyon's polynomial capacity"
        );
        let shift = discriminant.at(u32::try_from(path.len())?);
        let side = QrClassRoot::of(query.into(), shift).0;
        members.retain(|member| QrClassRoot::of((*member).into(), shift).0 == side);
        path.push(side);
    }
    Ok(path)
}

impl Intake {
    fn route(
        mut self,
        path: &[bool],
        discriminant: QrDiscriminant,
        control: &Control,
    ) -> Result<Self> {
        for (depth, &side) in path.iter().enumerate() {
            control.check()?;
            let (sides, ()) = PROOF_SYSTEM.fuse(
                &mut rand::rng(),
                qr::QrIntakeSplit,
                witness::qr_intake_split((*self.proof.data(), ()), &self.members),
                self.proof,
                trivial(),
            )?;
            control.check()?;
            self.proof = PROOF_SYSTEM
                .fuse(
                    &mut rand::rng(),
                    qr::QrSideDescend,
                    // The witness needs the entire pre-split set, including the
                    // sibling whose exclusion from this path it certifies.
                    witness::qr_side_descend((*sides.data(), ()), &self.members, side),
                    sides,
                    trivial(),
                )?
                .0;
            let shift = discriminant.at(u32::try_from(depth)?);
            self.members
                .retain(|member| QrClassRoot::of((*member).into(), shift).0 == side);
        }
        Ok(self)
    }

    fn merge(mut self, right: Self, control: &Control) -> Result<Self> {
        control.check()?;
        ensure!(
            self.members.len() + right.members.len() <= max_polynomial_members(),
            "routed epoch bucket exceeds Tachyon's polynomial capacity"
        );
        self.proof = PROOF_SYSTEM
            .fuse(
                &mut rand::rng(),
                qr::QrIntakeMerge,
                witness::qr_intake_merge(
                    (*self.proof.data(), *right.proof.data()),
                    &self.members,
                    &right.members,
                ),
                self.proof,
                right.proof,
            )?
            .0;
        self.members.extend(right.members);
        Ok(self)
    }
}

pub(super) fn bucket(
    chain: &ChainData<'_>,
    epoch: u32,
    query: Tachygram,
    control: &Control,
) -> Result<(Pcd<qr::QrBucket>, Vec<Tachygram>)> {
    control.stage(format!("Collecting public evidence for epoch {epoch}…"))?;
    let blocks = chain.epoch_blocks(epoch)?;
    let mut epoch_blocks = blocks.iter().filter(|b| b.epoch == epoch).peekable();
    let first = *epoch_blocks.peek().context("missing epoch inputs")?;
    let next_epoch = epoch.checked_add(1).context("epoch overflow")?;
    let next = blocks
        .iter()
        .find(|b| b.epoch == next_epoch)
        .context("epoch has not closed")?;
    let epoch_index = EpochIndex::new(epoch);
    let discriminant = QrDiscriminant(Fp::from(1));
    let mut stamps = Vec::new();
    let mut all_members = BTreeSet::new();
    for block in epoch_blocks {
        control.check()?;
        let mut cursor = block.entry()?;
        for stamp in &block.stamps {
            control.check()?;
            let members = stamp.members()?;
            ensure!(
                all_members.len() + members.len() <= MAX_EPOCH_MEMBERS
                    && stamps.len() < MAX_EPOCH_MEMBERS,
                "epoch exceeds wallet's experimental evidence budget"
            );
            for member in &members {
                ensure!(
                    all_members.insert(*member),
                    "duplicate tachygrams in an epoch"
                );
            }
            stamps.push((cursor, members));
            cursor = cursor.next_stamp(epoch_index, &stamp.commitment()?)?;
        }
    }
    let path = routing_path(
        all_members.into_iter().collect(),
        query,
        discriminant,
        control,
    )?;
    let profile = path
        .iter()
        .fold(QrProfile::ROOT, |profile, &side| profile.descend(side));
    if let Some((pcd, members)) = chain.bucket_proof(epoch, profile)? {
        let cached = Pcd::<qr::QrBucket>::from_bytes(&pcd)
            .ok()
            .and_then(|bucket| {
                (bucket.data().0 == EpochIndex::new(epoch) && bucket.data().4 == profile)
                    .then_some(bucket)
            })
            .filter(|bucket| {
                PROOF_SYSTEM
                    .verify(bucket, rand::rng())
                    .is_ok_and(|valid| valid)
            });
        if let Some(bucket) = cached
            && let Some(members) = decode_members(&members)
        {
            control.stage(format!("Reusing cached epoch {epoch} bucket…"))?;
            return Ok((bucket, members));
        }
    }
    let mut intakes = Vec::new();
    let total = stamps.len();
    for (index, (before, members)) in stamps.into_iter().enumerate() {
        control.stage(format!(
            "Proving epoch {epoch} stamp intake {}/{total}…",
            index + 1
        ))?;
        let (proof, ()) = PROOF_SYSTEM.seed(
            &mut rand::rng(),
            qr::QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(((), ()), before, epoch_index, discriminant, &members),
        )?;
        // Keep even empty routed intakes: each still covers its original stamp's
        // anchor transition. Dropping one would leave a gap in epoch evidence.
        intakes.push(Intake { proof, members }.route(&path, discriminant, control)?);
    }
    if intakes.is_empty() {
        control.stage(format!("Proving empty epoch {epoch}…"))?;
        let (proof, ()) = PROOF_SYSTEM.seed(
            &mut rand::rng(),
            qr::QrEmptyIntakeSeed,
            witness::qr_empty_intake_seed(((), ()), first.entry()?, epoch_index, discriminant),
        )?;
        intakes.push(Intake {
            proof,
            members: Vec::new(),
        });
    }
    // Balanced, adjacent merges avoid rebuilding an ever-growing prefix for
    // every stamp, while preserving the original anchor order.
    while intakes.len() > 1 {
        control.stage(format!("Merging {} epoch {epoch} intakes…", intakes.len()))?;
        let mut merged = Vec::new();
        let mut pairs = intakes.into_iter();
        while let Some(left) = pairs.next() {
            merged.push(match pairs.next() {
                Some(right) => left.merge(right, control)?,
                None => left,
            });
        }
        intakes = merged;
    }
    let Intake { proof, members } = intakes.pop().context("missing epoch intake")?;
    let predecessor = if epoch == 0 {
        Anchor(Fp::from(0))
    } else {
        anchor(&first.anchor_before)?
    };
    control.stage(format!("Sealing epoch {epoch} bucket…"))?;
    let (bucket, ()) = PROOF_SYSTEM.fuse(
        &mut rand::rng(),
        qr::QrBucketSeal,
        witness::qr_bucket_seal((*proof.data(), ()), predecessor),
        proof,
        trivial(),
    )?;
    ensure!(
        bucket.data().2 == next.entry()?,
        "epoch evidence does not meet the next entry anchor"
    );
    let pcd = bucket
        .to_bytes()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    chain.put_bucket_proof(epoch, profile, &pcd, &encode_members(&members))?;
    Ok((bucket, members))
}

fn encode_members(members: &[Tachygram]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(members.len() * 32);
    for member in members {
        bytes.extend_from_slice(Fp::from(*member).to_bytes().as_ref());
    }
    bytes
}

fn decode_members(bytes: &[u8]) -> Option<Vec<Tachygram>> {
    if !bytes.len().is_multiple_of(32) {
        return None;
    }
    bytes
        .chunks_exact(32)
        .map(|chunk| {
            let mut repr = Fp::ZERO.to_bytes();
            repr.as_mut_slice().copy_from_slice(chunk);
            Fp::from_bytes(repr).map(Tachygram::from)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use zcash_tachyon::TachygramSetPoly;

    use super::*;

    #[test]
    fn empty_routed_stamps_still_cover_their_anchor_transitions() -> Result<()> {
        let epoch = EpochIndex::new(0);
        let discriminant = QrDiscriminant(Fp::from(1));
        let query = Tachygram::from(Fp::from(7));
        let side = QrClassRoot::of(query.into(), discriminant.at(0)).0;
        let excluded: Vec<_> = (1u64..)
            .map(|i| Tachygram::from(Fp::from(i)))
            .filter(|value| QrClassRoot::of((*value).into(), discriminant.at(0)).0 != side)
            .take(2)
            .collect();
        let mut anchor = Anchor::default();
        let mut intakes = Vec::new();
        for members in [vec![excluded[0]], vec![excluded[1]], vec![query]] {
            let (proof, ()) = PROOF_SYSTEM.seed(
                &mut rand::rng(),
                qr::QrStampIntakeSeed,
                witness::qr_stamp_intake_seed(((), ()), anchor, epoch, discriminant, &members),
            )?;
            anchor = anchor.next_stamp(
                epoch,
                &members
                    .iter()
                    .copied()
                    .collect::<TachygramSetPoly>()
                    .commit(),
            )?;
            intakes.push(Intake { proof, members }.route(
                &[side],
                discriminant,
                &Control::new(true),
            )?);
        }
        assert!(intakes[0].members.is_empty());
        assert!(intakes[1].members.is_empty());
        assert_eq!(intakes[2].members, vec![query]);
        let mut intakes = intakes.into_iter();
        let intake = intakes
            .next()
            .unwrap()
            .merge(intakes.next().unwrap(), &Control::new(true))?
            .merge(intakes.next().unwrap(), &Control::new(true))?;
        assert_eq!(intake.proof.data().1, Anchor::default());
        assert_eq!(intake.proof.data().2, anchor);
        let (bucket, ()) = PROOF_SYSTEM.fuse(
            &mut rand::rng(),
            qr::QrBucketSeal,
            witness::qr_bucket_seal((*intake.proof.data(), ()), Anchor(Fp::from(0))),
            intake.proof,
            trivial(),
        )?;
        assert_eq!(bucket.data().2, anchor.next_epoch(EpochIndex::new(1))?);
        // Absence from a different bucket does not prove absence from the epoch:
        // QrUnspentInit must bind the tested value to the selected path.
        let result = PROOF_SYSTEM.fuse(
            &mut rand::rng(),
            qr::QrUnspentInit,
            witness::qr_unspent_init((*bucket.data(), ()), excluded[0], &intake.members),
            bucket,
            trivial(),
        );
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn routing_stops_at_capacity_and_descends_further_for_skewed_members() -> Result<()> {
        let discriminant = QrDiscriminant(Fp::from(1));
        let query = Tachygram::from(Fp::from(7));
        let side = QrClassRoot::of(query.into(), discriminant.at(0)).0;
        let members: Vec<_> = (1u64..)
            .map(|i| Tachygram::from(Fp::from(i)))
            .filter(|v| QrClassRoot::of((*v).into(), discriminant.at(0)).0 == side)
            .take(max_polynomial_members() + 1)
            .collect();
        assert!(
            routing_path(
                members[..max_polynomial_members()].to_vec(),
                query,
                discriminant,
                &Control::new(true)
            )?
            .is_empty()
        );
        let path = routing_path(members, query, discriminant, &Control::new(true))?;
        assert_eq!(path.len(), 2);
        assert_eq!(path[0], side);
        assert_eq!(path[1], QrClassRoot::of(query.into(), discriminant.at(1)).0);
        Ok(())
    }
}
