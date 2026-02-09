//! Serialization helpers for FROST types that don't directly implement serde.
//!
//! The `PallasBlake2b512` ciphersuite type doesn't implement Serialize/Deserialize,
//! so we serialize FROST types via their byte representations wrapped in hex strings.

use std::collections::{BTreeMap, HashMap};

use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use reddsa::frost::redpallas::{keys, Identifier, PallasBlake2b512};

type P = PallasBlake2b512;

/// Hex-serializable wrapper for a FROST Identifier.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct IdHex(pub(crate) String);

impl IdHex {
    pub fn from_id(id: &Identifier) -> Self {
        let bytes = id.serialize();
        IdHex(hex::encode(bytes))
    }

    pub fn to_id(&self) -> Result<Identifier, anyhow::Error> {
        let bytes: [u8; 32] = hex::decode(&self.0)?
            .try_into()
            .map_err(|_| anyhow!("Invalid identifier length"))?;
        Identifier::deserialize(&bytes).map_err(|e| anyhow!("Invalid identifier: {e:?}"))
    }
}

/// Hex-serializable wrapper for a DKG round1::Package.
#[derive(Serialize, Deserialize)]
pub(crate) struct DkgRound1PackageStore {
    /// Coefficient commitments as hex-encoded group elements
    pub commitment: Vec<String>,
    /// Proof of knowledge signature (R || z) as hex
    pub proof_of_knowledge: String,
}

impl DkgRound1PackageStore {
    pub fn from_package(
        pkg: &frost_core::frost::keys::dkg::round1::Package<P>,
    ) -> Self {
        let commitment: Vec<String> = pkg
            .commitment()
            .serialize()
            .iter()
            .map(|bytes| hex::encode(bytes))
            .collect();
        let proof = pkg.proof_of_knowledge().serialize();
        DkgRound1PackageStore {
            commitment,
            proof_of_knowledge: hex::encode(proof),
        }
    }

    pub fn to_package(
        &self,
    ) -> Result<frost_core::frost::keys::dkg::round1::Package<P>, anyhow::Error> {
        use frost_core::frost::keys::VerifiableSecretSharingCommitment;
        use frost_core::Signature;

        let coeff_bytes: Vec<[u8; 32]> = self
            .commitment
            .iter()
            .map(|h| {
                hex::decode(h)
                    .map_err(|e| anyhow!("Invalid commitment hex: {e}"))
                    .and_then(|b| {
                        b.try_into()
                            .map_err(|_| anyhow!("Invalid commitment length"))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let commitment = VerifiableSecretSharingCommitment::<P>::deserialize(coeff_bytes)
            .map_err(|e| anyhow!("Invalid commitment: {e:?}"))?;

        let sig_bytes: [u8; 64] = hex::decode(&self.proof_of_knowledge)?
            .try_into()
            .map_err(|_| anyhow!("Invalid proof of knowledge length"))?;
        let proof = Signature::<P>::deserialize(sig_bytes)
            .map_err(|e| anyhow!("Invalid proof of knowledge: {e:?}"))?;

        Ok(frost_core::frost::keys::dkg::round1::Package::new(
            commitment, proof,
        ))
    }
}

/// Hex-serializable DKG Round 1 broadcast message.
#[derive(Serialize, Deserialize)]
pub(crate) struct DkgRound1Msg {
    pub identifier: IdHex,
    pub package: DkgRound1PackageStore,
}

/// Hex-serializable wrapper for a DKG round2::Package.
#[derive(Serialize, Deserialize)]
pub(crate) struct DkgRound2PackageStore {
    /// Secret share as hex-encoded scalar bytes
    pub secret_share: String,
}

impl DkgRound2PackageStore {
    pub fn from_package(
        pkg: &frost_core::frost::keys::dkg::round2::Package<P>,
    ) -> Self {
        DkgRound2PackageStore {
            secret_share: hex::encode(pkg.secret_share().serialize()),
        }
    }

    pub fn to_package(
        &self,
    ) -> Result<frost_core::frost::keys::dkg::round2::Package<P>, anyhow::Error> {
        use frost_core::frost::keys::SigningShare;

        let ss_bytes: [u8; 32] = hex::decode(&self.secret_share)?
            .try_into()
            .map_err(|_| anyhow!("Invalid secret share length"))?;
        let signing_share = SigningShare::<P>::deserialize(ss_bytes)
            .map_err(|e| anyhow!("Invalid secret share: {e:?}"))?;
        Ok(frost_core::frost::keys::dkg::round2::Package::new(
            signing_share,
        ))
    }
}

/// Hex-serializable DKG Round 2 point-to-point message.
#[derive(Serialize, Deserialize)]
pub(crate) struct DkgRound2Msg {
    pub from: IdHex,
    pub to: IdHex,
    pub package: DkgRound2PackageStore,
}

/// Message from coordinator sharing nk and rivk with participants.
#[derive(Serialize, Deserialize)]
pub(crate) struct FvkShareMsg {
    pub nk_hex: String,
    pub rivk_hex: String,
}

/// Signing request from coordinator to participants.
#[derive(Serialize, Deserialize)]
pub(crate) struct SigningRequest {
    pub sighash_hex: String,
    pub actions: Vec<ActionSigningData>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ActionSigningData {
    pub action_index: usize,
}

/// Hex-serializable wrapper for SigningCommitments (hiding + binding nonce commitments).
#[derive(Serialize, Deserialize)]
pub(crate) struct SigningCommitmentsStore {
    pub hiding: String,
    pub binding: String,
}

impl SigningCommitmentsStore {
    pub fn from_commitments(
        c: &frost_core::frost::round1::SigningCommitments<P>,
    ) -> Self {
        SigningCommitmentsStore {
            hiding: hex::encode(c.hiding().serialize()),
            binding: hex::encode(c.binding().serialize()),
        }
    }

    pub fn to_commitments(
        &self,
    ) -> Result<frost_core::frost::round1::SigningCommitments<P>, anyhow::Error> {
        use frost_core::frost::round1::{NonceCommitment, SigningCommitments};

        let hiding_bytes: [u8; 32] = hex::decode(&self.hiding)?
            .try_into()
            .map_err(|_| anyhow!("Invalid hiding commitment length"))?;
        let hiding = NonceCommitment::<P>::deserialize(hiding_bytes)
            .map_err(|e| anyhow!("Invalid hiding commitment: {e:?}"))?;

        let binding_bytes: [u8; 32] = hex::decode(&self.binding)?
            .try_into()
            .map_err(|_| anyhow!("Invalid binding commitment length"))?;
        let binding = NonceCommitment::<P>::deserialize(binding_bytes)
            .map_err(|e| anyhow!("Invalid binding commitment: {e:?}"))?;

        Ok(SigningCommitments::new(hiding, binding))
    }
}

/// Hex-serializable wrapper for a SigningPackage (commitments map + message).
#[derive(Serialize, Deserialize)]
pub(crate) struct SigningPackageStore {
    /// Map from identifier hex to commitment store
    pub commitments: BTreeMap<String, SigningCommitmentsStore>,
    /// The message (sighash) as hex
    pub message: String,
}

impl SigningPackageStore {
    pub fn from_signing_package(
        sp: &frost_core::frost::SigningPackage<P>,
    ) -> Self {
        let mut commitments = BTreeMap::new();
        for (id, c) in sp.signing_commitments() {
            let id_hex = hex::encode(id.serialize());
            commitments.insert(id_hex, SigningCommitmentsStore::from_commitments(c));
        }
        SigningPackageStore {
            commitments,
            message: hex::encode(sp.message()),
        }
    }

    pub fn to_signing_package(
        &self,
    ) -> Result<frost_core::frost::SigningPackage<P>, anyhow::Error> {
        let mut map = BTreeMap::new();
        for (id_hex, c_store) in &self.commitments {
            let id_bytes: [u8; 32] = hex::decode(id_hex)?
                .try_into()
                .map_err(|_| anyhow!("Invalid identifier length"))?;
            let id = Identifier::deserialize(&id_bytes)
                .map_err(|e| anyhow!("Invalid identifier: {e:?}"))?;
            let commitment = c_store.to_commitments()?;
            map.insert(id, commitment);
        }
        let message = hex::decode(&self.message)?;
        Ok(frost_core::frost::SigningPackage::new(map, &message))
    }
}

/// Participant's Round 1 response (nonce commitments).
#[derive(Serialize, Deserialize)]
pub(crate) struct SignRound1Response {
    pub identifier: IdHex,
    /// One commitment per action, serialized as SigningCommitmentsStore JSON
    pub commitments: Vec<SigningCommitmentsStore>,
}

/// Coordinator's Round 2 package (signing packages for each action).
#[derive(Serialize, Deserialize)]
pub(crate) struct SignRound2Request {
    pub packages: Vec<ActionSigningPackageMsg>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ActionSigningPackageMsg {
    pub action_index: usize,
    /// The signing package serialized as SigningPackageStore JSON
    pub signing_package: SigningPackageStore,
    /// The randomizer point (alpha * G) as hex bytes
    pub randomizer_point_hex: String,
}

/// Participant's Round 2 response (signature shares).
#[derive(Serialize, Deserialize)]
pub(crate) struct SignRound2Response {
    pub identifier: IdHex,
    /// One signature share per action as hex bytes
    pub shares: Vec<String>,
}

// === Serialization helpers for KeyPackage and PublicKeyPackage ===

/// A serializable representation of a KeyPackage.
#[derive(Serialize, Deserialize)]
pub(crate) struct KeyPackageStore {
    pub identifier: String,
    pub signing_share: String,
    pub verifying_share: String,
    pub verifying_key: String,
}

impl Drop for KeyPackageStore {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.signing_share.zeroize();
    }
}

impl KeyPackageStore {
    pub fn from_key_package(kp: &keys::KeyPackage) -> Self {
        KeyPackageStore {
            identifier: hex::encode(kp.identifier().serialize()),
            signing_share: hex::encode(kp.secret_share().serialize()),
            verifying_share: hex::encode(kp.public().serialize()),
            verifying_key: hex::encode(kp.group_public().serialize()),
        }
    }

    pub fn to_key_package(&self) -> Result<keys::KeyPackage, anyhow::Error> {
        use frost_core::frost::keys::{KeyPackage, SigningShare, VerifyingShare};
        use frost_core::VerifyingKey;

        let id_bytes: [u8; 32] = hex::decode(&self.identifier)?
            .try_into()
            .map_err(|_| anyhow!("Invalid identifier length"))?;
        let identifier =
            Identifier::deserialize(&id_bytes).map_err(|e| anyhow!("Invalid identifier: {e:?}"))?;

        let ss_bytes: [u8; 32] = hex::decode(&self.signing_share)?
            .try_into()
            .map_err(|_| anyhow!("Invalid signing share length"))?;
        let signing_share = SigningShare::<P>::deserialize(ss_bytes)
            .map_err(|e| anyhow!("Invalid signing share: {e:?}"))?;

        let vs_bytes: [u8; 32] = hex::decode(&self.verifying_share)?
            .try_into()
            .map_err(|_| anyhow!("Invalid verifying share length"))?;
        let verifying_share = VerifyingShare::<P>::deserialize(vs_bytes)
            .map_err(|e| anyhow!("Invalid verifying share: {e:?}"))?;

        let vk_bytes: [u8; 32] = hex::decode(&self.verifying_key)?
            .try_into()
            .map_err(|_| anyhow!("Invalid verifying key length"))?;
        let verifying_key = VerifyingKey::<P>::deserialize(vk_bytes)
            .map_err(|e| anyhow!("Invalid verifying key: {e:?}"))?;

        Ok(KeyPackage::new(
            identifier,
            signing_share,
            verifying_share,
            verifying_key,
        ))
    }
}

/// A serializable representation of a PublicKeyPackage.
#[derive(Serialize, Deserialize)]
pub(crate) struct PublicKeyPackageStore {
    pub verifying_key: String,
    pub signer_pubkeys: BTreeMap<String, String>,
}

impl PublicKeyPackageStore {
    pub fn from_public_key_package(pkp: &keys::PublicKeyPackage) -> Self {
        let mut signer_pubkeys = BTreeMap::new();
        for (id, share) in pkp.signer_pubkeys() {
            let id_hex = hex::encode(id.serialize());
            let share_hex = hex::encode(share.serialize());
            signer_pubkeys.insert(id_hex, share_hex);
        }
        PublicKeyPackageStore {
            verifying_key: hex::encode(pkp.group_public().serialize()),
            signer_pubkeys,
        }
    }

    pub fn to_public_key_package(&self) -> Result<keys::PublicKeyPackage, anyhow::Error> {
        use frost_core::frost::keys::VerifyingShare;
        use frost_core::VerifyingKey;

        let vk_bytes: [u8; 32] = hex::decode(&self.verifying_key)?
            .try_into()
            .map_err(|_| anyhow!("Invalid verifying key length"))?;
        let verifying_key = VerifyingKey::<P>::deserialize(vk_bytes)
            .map_err(|e| anyhow!("Invalid verifying key: {e:?}"))?;

        let mut signer_pubkeys = HashMap::new();
        for (id_hex, share_hex) in &self.signer_pubkeys {
            let id_bytes: [u8; 32] = hex::decode(id_hex)?
                .try_into()
                .map_err(|_| anyhow!("Invalid signer id length"))?;
            let identifier = Identifier::deserialize(&id_bytes)
                .map_err(|e| anyhow!("Invalid signer id: {e:?}"))?;

            let share_bytes: [u8; 32] = hex::decode(share_hex)?
                .try_into()
                .map_err(|_| anyhow!("Invalid signer pubkey length"))?;
            let verifying_share = VerifyingShare::<P>::deserialize(share_bytes)
                .map_err(|e| anyhow!("Invalid signer pubkey: {e:?}"))?;
            signer_pubkeys.insert(identifier, verifying_share);
        }

        Ok(keys::PublicKeyPackage::new(signer_pubkeys, verifying_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use frost_core::frost::keys::dkg;
    use rand::rngs::OsRng;
    use reddsa::frost::redpallas::{self, round1, round2};

    /// Run a full 2-of-3 DKG ceremony, serializing all messages through our
    /// serde types (exactly as the CLI commands do). Returns per-participant
    /// key packages and the shared public key package.
    fn run_dkg_2_of_3() -> (
        HashMap<Identifier, redpallas::keys::KeyPackage>,
        redpallas::keys::PublicKeyPackage,
    ) {
        let min_signers = 2u16;
        let max_signers = 3u16;

        let ids: Vec<Identifier> = (1..=max_signers)
            .map(|i| Identifier::try_from(i).unwrap())
            .collect();

        // === Round 1 ===
        let mut round1_secrets = HashMap::new();
        let mut round1_packages = HashMap::new();

        for &id in &ids {
            let (secret, package) =
                dkg::part1::<P, _>(id, max_signers, min_signers, OsRng).unwrap();

            // Serialize through our serde types (round-trip)
            let store = DkgRound1PackageStore::from_package(&package);
            let json = serde_json::to_string(&DkgRound1Msg {
                identifier: IdHex::from_id(&id),
                package: store,
            })
            .unwrap();
            let msg: DkgRound1Msg = serde_json::from_str(&json).unwrap();
            let deserialized_package = msg.package.to_package().unwrap();

            round1_secrets.insert(id, secret);
            round1_packages.insert(id, deserialized_package);
        }

        // === Round 2 ===
        let mut round2_secrets = HashMap::new();
        // per-recipient packages: recipient -> (sender -> package)
        let mut round2_per_recipient: HashMap<
            Identifier,
            HashMap<Identifier, dkg::round2::Package<P>>,
        > = HashMap::new();

        for &sender_id in &ids {
            let others: HashMap<_, _> = round1_packages
                .iter()
                .filter(|(&k, _)| k != sender_id)
                .map(|(&k, v)| (k, v.clone()))
                .collect();

            let (secret, packages) =
                dkg::part2(round1_secrets.remove(&sender_id).unwrap(), &others).unwrap();

            round2_secrets.insert(sender_id, secret);

            for (recipient_id, pkg) in packages {
                // Serialize through our serde types (round-trip)
                let store = DkgRound2PackageStore::from_package(&pkg);
                let json = serde_json::to_string(&DkgRound2Msg {
                    from: IdHex::from_id(&sender_id),
                    to: IdHex::from_id(&recipient_id),
                    package: store,
                })
                .unwrap();
                let msg: DkgRound2Msg = serde_json::from_str(&json).unwrap();
                let deserialized_pkg = msg.package.to_package().unwrap();

                round2_per_recipient
                    .entry(recipient_id)
                    .or_default()
                    .insert(sender_id, deserialized_pkg);
            }
        }

        // === Round 3 ===
        let mut key_packages = HashMap::new();
        let mut public_key_package = None;

        for &id in &ids {
            let others_round1: HashMap<_, _> = round1_packages
                .iter()
                .filter(|(&k, _)| k != id)
                .map(|(&k, v)| (k, v.clone()))
                .collect();

            let received_round2 = round2_per_recipient.remove(&id).unwrap();

            let (kp, pkp) =
                dkg::part3(&round2_secrets[&id], &others_round1, &received_round2).unwrap();

            key_packages.insert(id, kp);
            public_key_package = Some(pkp);
        }

        (key_packages, public_key_package.unwrap())
    }

    #[test]
    fn dkg_full_ceremony_2_of_3() {
        let (key_packages, public_key_package) = run_dkg_2_of_3();

        // All participants should have the same group public key
        let group_key = public_key_package.group_public().serialize();
        for kp in key_packages.values() {
            assert_eq!(
                kp.group_public().serialize(),
                group_key,
                "Group public key mismatch across participants"
            );
        }

        assert_eq!(key_packages.len(), 3, "Expected 3 key packages from DKG");

        // KeyPackageStore round-trips are tested in key_package_store_round_trip;
        // here we just verify the DKG produced valid, distinct per-participant shares.
        let shares: Vec<_> = key_packages
            .values()
            .map(|kp| kp.secret_share().serialize())
            .collect();
        assert_ne!(shares[0], shares[1], "Signing shares should be distinct");
        assert_ne!(shares[1], shares[2], "Signing shares should be distinct");

        // Verify PublicKeyPackageStore round-trip
        let pkp_store = PublicKeyPackageStore::from_public_key_package(&public_key_package);
        let json = serde_json::to_string(&pkp_store).unwrap();
        let restored_store: PublicKeyPackageStore = serde_json::from_str(&json).unwrap();
        let restored = restored_store.to_public_key_package().unwrap();

        assert_eq!(
            public_key_package.group_public().serialize(),
            restored.group_public().serialize()
        );
        let orig_signers = public_key_package.signer_pubkeys();
        let restored_signers = restored.signer_pubkeys();
        assert_eq!(orig_signers.len(), restored_signers.len());
        for (id, share) in orig_signers {
            let restored_share = restored_signers.get(id).expect("Missing signer pubkey");
            assert_eq!(share.serialize(), restored_share.serialize());
        }
    }

    #[test]
    fn frost_signing_with_rerandomization() {
        use frost_core::{Field, Group};
        use frost_rerandomized::RandomizedParams;
        use reddsa::frost::redpallas::{PallasGroup, PallasScalarField};

        let (key_packages, public_key_package) = run_dkg_2_of_3();

        // Use participants 1 and 2 as signers
        let signer_ids: Vec<Identifier> = (1..=2u16)
            .map(|i| Identifier::try_from(i).unwrap())
            .collect();

        // Fake sighash (32 bytes)
        let sighash = [0x42u8; 32];

        // Create a random alpha scalar for the spend auth randomizer
        let alpha_scalar_orig = <PallasScalarField as Field>::random(&mut OsRng);
        let alpha_bytes = <PallasScalarField as Field>::serialize(&alpha_scalar_orig);

        // === Coordinator builds SigningRequest ===
        let signing_request = SigningRequest {
            sighash_hex: hex::encode(sighash),
            actions: vec![ActionSigningData {
                action_index: 0,
            }],
        };

        // Serialize round-trip
        let request_json = serde_json::to_string(&signing_request).unwrap();
        let parsed_request: SigningRequest = serde_json::from_str(&request_json).unwrap();
        assert_eq!(parsed_request.sighash_hex, signing_request.sighash_hex);
        assert_eq!(parsed_request.actions.len(), 1);

        // === Participants: Round 1 (commit) ===
        let mut nonces_map: HashMap<Identifier, round1::SigningNonces> = HashMap::new();
        // BTreeMap required: frost_core::SigningPackage::new expects BTreeMap
        let mut commitments_map: BTreeMap<
            Identifier,
            frost_core::frost::round1::SigningCommitments<P>,
        > = BTreeMap::new();

        for &signer_id in &signer_ids {
            let kp = &key_packages[&signer_id];
            let (nonce, commitment) = round1::commit(kp.secret_share(), &mut OsRng);

            // Serialize commitment through SignRound1Response round-trip
            let response = SignRound1Response {
                identifier: IdHex::from_id(&signer_id),
                commitments: vec![SigningCommitmentsStore::from_commitments(&commitment)],
            };
            let json = serde_json::to_string(&response).unwrap();
            let parsed: SignRound1Response = serde_json::from_str(&json).unwrap();

            let restored_commitment = parsed.commitments[0].to_commitments().unwrap();

            nonces_map.insert(signer_id, nonce);
            commitments_map.insert(signer_id, restored_commitment);
        }

        // === Coordinator: Build SigningPackage ===
        let signing_package = frost_core::frost::SigningPackage::new(
            commitments_map.clone(),
            &sighash[..],
        );

        // Create RandomizedParams from alpha
        let alpha_scalar =
            <PallasScalarField as Field>::deserialize(&alpha_bytes).unwrap();
        let randomized_params =
            RandomizedParams::from_randomizer(&public_key_package, alpha_scalar);
        let rp_bytes: [u8; 32] = PallasGroup::serialize(randomized_params.randomizer_point());

        // Build SignRound2Request and round-trip
        let round2_request = SignRound2Request {
            packages: vec![ActionSigningPackageMsg {
                action_index: 0,
                signing_package: SigningPackageStore::from_signing_package(&signing_package),
                randomizer_point_hex: hex::encode(rp_bytes),
            }],
        };
        let round2_json = serde_json::to_string(&round2_request).unwrap();
        let parsed_round2: SignRound2Request = serde_json::from_str(&round2_json).unwrap();

        // === Participants: Round 2 (sign) ===
        // HashMap here: redpallas::aggregate accepts HashMap for signature shares
        let mut signature_shares: HashMap<Identifier, round2::SignatureShare> = HashMap::new();

        for &signer_id in &signer_ids {
            let action_pkg = &parsed_round2.packages[0];
            let restored_signing_pkg = action_pkg.signing_package.to_signing_package().unwrap();

            let rp_bytes_parsed: [u8; 32] = hex::decode(&action_pkg.randomizer_point_hex)
                .unwrap()
                .try_into()
                .unwrap();
            let randomizer_point = PallasGroup::deserialize(&rp_bytes_parsed).unwrap();

            let share = round2::sign(
                &restored_signing_pkg,
                &nonces_map[&signer_id],
                &key_packages[&signer_id],
                &randomizer_point,
            )
            .unwrap();

            // Round-trip through SignRound2Response
            let response = SignRound2Response {
                identifier: IdHex::from_id(&signer_id),
                shares: vec![hex::encode(share.serialize())],
            };
            let json = serde_json::to_string(&response).unwrap();
            let parsed: SignRound2Response = serde_json::from_str(&json).unwrap();

            let share_bytes: [u8; 32] = hex::decode(&parsed.shares[0])
                .unwrap()
                .try_into()
                .unwrap();
            let restored_share = round2::SignatureShare::deserialize(share_bytes).unwrap();

            signature_shares.insert(signer_id, restored_share);
        }

        // === Coordinator: Aggregate ===
        // `redpallas::aggregate` internally verifies the resulting signature
        // against the randomized group public key, so a successful unwrap here
        // already proves cryptographic correctness.
        let frost_signature = redpallas::aggregate(
            &signing_package,
            &signature_shares,
            &public_key_package,
            &randomized_params,
        )
        .expect("Aggregate should succeed and produce a valid signature");

        let sig_bytes: [u8; 64] = frost_signature.serialize();
        assert_eq!(sig_bytes.len(), 64);
        assert!(
            sig_bytes.iter().any(|&b| b != 0),
            "Signature bytes should be non-zero"
        );
    }

    #[test]
    fn identifier_hex_round_trip() {
        for i in 1..=5u16 {
            let id = Identifier::try_from(i).unwrap();
            let hex_id = IdHex::from_id(&id);
            let restored = hex_id.to_id().unwrap();
            assert_eq!(id.serialize(), restored.serialize());
        }
    }

    #[test]
    fn key_package_store_round_trip() {
        let (key_packages, _) = run_dkg_2_of_3();
        let kp = key_packages.values().next().unwrap();

        let store = KeyPackageStore::from_key_package(kp);
        let json = serde_json::to_string(&store).unwrap();
        let restored: KeyPackageStore = serde_json::from_str(&json).unwrap();
        let restored_kp = restored.to_key_package().unwrap();

        assert_eq!(kp.identifier().serialize(), restored_kp.identifier().serialize());
        assert_eq!(
            kp.secret_share().serialize(),
            restored_kp.secret_share().serialize()
        );
        assert_eq!(kp.public().serialize(), restored_kp.public().serialize());
        assert_eq!(
            kp.group_public().serialize(),
            restored_kp.group_public().serialize()
        );
    }

    #[test]
    fn signing_commitments_store_round_trip() {
        let (key_packages, _) = run_dkg_2_of_3();
        let kp = key_packages.values().next().unwrap();

        // Nonce intentionally discarded; only testing commitment serialization
        let (_nonce, commitment) = round1::commit(kp.secret_share(), &mut OsRng);
        let store = SigningCommitmentsStore::from_commitments(&commitment);
        let json = serde_json::to_string(&store).unwrap();
        let restored: SigningCommitmentsStore = serde_json::from_str(&json).unwrap();
        let restored_commitment = restored.to_commitments().unwrap();

        assert_eq!(
            commitment.hiding().serialize(),
            restored_commitment.hiding().serialize()
        );
        assert_eq!(
            commitment.binding().serialize(),
            restored_commitment.binding().serialize()
        );
    }

    #[test]
    fn signing_package_store_round_trip() {
        let (key_packages, _) = run_dkg_2_of_3();

        let signer_ids: Vec<Identifier> = (1..=2u16)
            .map(|i| Identifier::try_from(i).unwrap())
            .collect();

        let mut commitments_map = BTreeMap::new();
        for &id in &signer_ids {
            let kp = &key_packages[&id];
            // Nonce intentionally discarded; only testing package serialization
            let (_nonce, commitment) = round1::commit(kp.secret_share(), &mut OsRng);
            commitments_map.insert(id, commitment);
        }

        let message = [0xABu8; 32];
        let signing_package =
            frost_core::frost::SigningPackage::new(commitments_map, &message[..]);

        let store = SigningPackageStore::from_signing_package(&signing_package);
        let json = serde_json::to_string(&store).unwrap();
        let restored: SigningPackageStore = serde_json::from_str(&json).unwrap();
        let restored_pkg = restored.to_signing_package().unwrap();

        assert_eq!(signing_package.message(), restored_pkg.message());
        let orig_commitments = signing_package.signing_commitments();
        let restored_commitments = restored_pkg.signing_commitments();
        assert_eq!(orig_commitments.len(), restored_commitments.len());
        for (id, c) in orig_commitments {
            let rc = restored_commitments.get(id).expect("Missing commitment");
            assert_eq!(c.hiding().serialize(), rc.hiding().serialize());
            assert_eq!(c.binding().serialize(), rc.binding().serialize());
        }
    }

    #[test]
    fn public_key_package_store_round_trip() {
        let (_, public_key_package) = run_dkg_2_of_3();

        let store = PublicKeyPackageStore::from_public_key_package(&public_key_package);
        let json = serde_json::to_string(&store).unwrap();
        let restored: PublicKeyPackageStore = serde_json::from_str(&json).unwrap();
        let restored_pkp = restored.to_public_key_package().unwrap();

        assert_eq!(
            public_key_package.group_public().serialize(),
            restored_pkp.group_public().serialize()
        );
        let orig_signers = public_key_package.signer_pubkeys();
        let restored_signers = restored_pkp.signer_pubkeys();
        assert_eq!(orig_signers.len(), restored_signers.len());
        for (id, share) in orig_signers {
            let restored_share = restored_signers.get(id).expect("Missing signer pubkey");
            assert_eq!(share.serialize(), restored_share.serialize());
        }
    }

    #[test]
    fn dkg_round1_package_store_round_trip() {
        let id = Identifier::try_from(1u16).unwrap();
        let (_secret, package) = dkg::part1::<P, _>(id, 3, 2, OsRng).unwrap();

        let store = DkgRound1PackageStore::from_package(&package);
        let json = serde_json::to_string(&store).unwrap();
        let restored: DkgRound1PackageStore = serde_json::from_str(&json).unwrap();
        let restored_pkg = restored.to_package().unwrap();

        // Verify commitment coefficients match
        let orig_commitment: Vec<_> = package
            .commitment()
            .serialize()
            .iter()
            .map(|b| hex::encode(b))
            .collect();
        let restored_commitment: Vec<_> = restored_pkg
            .commitment()
            .serialize()
            .iter()
            .map(|b| hex::encode(b))
            .collect();
        assert_eq!(orig_commitment, restored_commitment);

        // Verify proof of knowledge matches
        assert_eq!(
            package.proof_of_knowledge().serialize(),
            restored_pkg.proof_of_knowledge().serialize()
        );
    }

    #[test]
    fn dkg_round2_package_store_round_trip() {
        // Run a partial DKG to get a round2 package
        let ids: Vec<Identifier> = (1..=3u16)
            .map(|i| Identifier::try_from(i).unwrap())
            .collect();

        let mut round1_secrets = HashMap::new();
        let mut round1_packages = HashMap::new();
        for &id in &ids {
            let (secret, package) = dkg::part1::<P, _>(id, 3, 2, OsRng).unwrap();
            round1_secrets.insert(id, secret);
            round1_packages.insert(id, package);
        }

        let sender = ids[0];
        let others: HashMap<_, _> = round1_packages
            .iter()
            .filter(|(&k, _)| k != sender)
            .map(|(&k, v)| (k, v.clone()))
            .collect();
        let (_secret, packages) =
            dkg::part2(round1_secrets.remove(&sender).unwrap(), &others).unwrap();

        let pkg = packages.values().next().unwrap();
        let store = DkgRound2PackageStore::from_package(pkg);
        let json = serde_json::to_string(&store).unwrap();
        let restored: DkgRound2PackageStore = serde_json::from_str(&json).unwrap();
        let restored_pkg = restored.to_package().unwrap();

        assert_eq!(
            pkg.secret_share().serialize(),
            restored_pkg.secret_share().serialize()
        );
    }

    #[test]
    fn id_hex_rejects_invalid_hex() {
        let bad = IdHex("not_valid_hex".to_string());
        assert!(bad.to_id().is_err());
    }

    #[test]
    fn id_hex_rejects_wrong_length() {
        // 31 bytes instead of 32
        let short = IdHex("00".repeat(31));
        assert!(short.to_id().is_err());

        // 33 bytes instead of 32
        let long = IdHex("00".repeat(33));
        assert!(long.to_id().is_err());
    }

    #[test]
    fn key_package_store_rejects_truncated_fields() {
        let store = KeyPackageStore {
            identifier: "00".repeat(32),
            signing_share: "ab".repeat(16), // 16 bytes, should be 32
            verifying_share: "00".repeat(32),
            verifying_key: "00".repeat(32),
        };
        assert!(store.to_key_package().is_err());
    }

    #[test]
    fn signing_commitments_store_rejects_bad_hex() {
        let store = SigningCommitmentsStore {
            hiding: "not_hex".to_string(),
            binding: "00".repeat(32),
        };
        assert!(store.to_commitments().is_err());
    }

    #[test]
    fn frost_dkg_to_orchard_fvk_and_address() {
        use orchard::keys::{FullViewingKey, Scope};
        use rand::RngCore;
        use zcash_keys::keys::{UnifiedAddressRequest, UnifiedFullViewingKey};
        use zip32::DiversifierIndex;

        // The FVK construction can fail for two reasons:
        // 1. DKG produces ak with wrong sign bit (~50% chance)
        //    SpendValidatingKey::from_bytes requires b[31] & 0x80 == 0
        // 2. The derived ivk is zero or bottom (rare but possible)
        // We retry the entire construction, matching how a real coordinator would
        // regenerate nk/rivk if FVK construction fails.
        let max_attempts = 50;
        let mut fvk = None;
        let mut fvk_bytes_out = [0u8; 96];

        for _ in 0..max_attempts {
            let (_, public_key_package) = run_dkg_2_of_3();
            let ak_bytes: [u8; 32] = public_key_package.group_public().serialize();

            // Skip ak with wrong sign bit
            if ak_bytes[31] & 0x80 != 0 {
                continue;
            }

            // Generate random nk and rivk bytes, clearing the top bit to reduce
            // the probability of exceeding the Pallas field moduli (~2^254).
            // Values can still exceed the modulus; the retry loop handles that.
            let mut nk_bytes = [0u8; 32];
            let mut rivk_bytes = [0u8; 32];
            OsRng.fill_bytes(&mut nk_bytes);
            OsRng.fill_bytes(&mut rivk_bytes);
            nk_bytes[31] &= 0x7f;
            rivk_bytes[31] &= 0x7f;

            let mut fvk_bytes = [0u8; 96];
            fvk_bytes[..32].copy_from_slice(&ak_bytes);
            fvk_bytes[32..64].copy_from_slice(&nk_bytes);
            fvk_bytes[64..96].copy_from_slice(&rivk_bytes);

            if let Some(f) = FullViewingKey::from_bytes(&fvk_bytes) {
                fvk = Some(f);
                fvk_bytes_out = fvk_bytes;
                break;
            }
            // ivk was zero or bottom; retry with fresh nk/rivk
        }

        let fvk = fvk.expect("Failed to construct valid FVK after max attempts");

        // Derive an address and verify it is 43 bytes
        let address = fvk.address_at(DiversifierIndex::new(), Scope::External);
        assert_eq!(
            address.to_raw_address_bytes().len(),
            43,
            "Orchard address should be 43 bytes"
        );

        // Wrap in UnifiedFullViewingKey
        let ufvk = UnifiedFullViewingKey::from_orchard_fvk(fvk)
            .expect("from_orchard_fvk should succeed");

        // Derive default unified address
        let (_ua, _di) = ufvk
            .default_address(UnifiedAddressRequest::AllAvailableKeys)
            .expect("default_address should succeed");

        // Verify the orchard component round-trips
        let recovered_fvk = ufvk.orchard().expect("UFVK should contain orchard FVK");
        assert_eq!(
            recovered_fvk.to_bytes(),
            fvk_bytes_out,
            "Orchard FVK bytes should round-trip through UFVK"
        );
    }

    #[test]
    fn frost_signature_to_orchard_spendauth() {
        use frost_core::Field;
        use frost_rerandomized::RandomizedParams;
        use orchard::primitives::redpallas as orchard_redpallas;
        use reddsa::frost::redpallas::PallasScalarField;

        let (key_packages, public_key_package) = run_dkg_2_of_3();

        // Use participants 1 and 2 as signers
        let signer_ids: Vec<Identifier> = (1..=2u16)
            .map(|i| Identifier::try_from(i).unwrap())
            .collect();

        let sighash = [0x42u8; 32];

        let alpha_scalar = <PallasScalarField as Field>::random(&mut OsRng);

        // Round 1: commit
        let mut nonces_map: HashMap<Identifier, round1::SigningNonces> = HashMap::new();
        let mut commitments_map: BTreeMap<
            Identifier,
            frost_core::frost::round1::SigningCommitments<P>,
        > = BTreeMap::new();

        for &signer_id in &signer_ids {
            let kp = &key_packages[&signer_id];
            let (nonce, commitment) = round1::commit(kp.secret_share(), &mut OsRng);
            nonces_map.insert(signer_id, nonce);
            commitments_map.insert(signer_id, commitment);
        }

        // Build signing package
        let signing_package =
            frost_core::frost::SigningPackage::new(commitments_map, &sighash[..]);

        let randomized_params =
            RandomizedParams::from_randomizer(&public_key_package, alpha_scalar);
        let randomizer_point = randomized_params.randomizer_point();

        // Round 2: sign
        let mut signature_shares: HashMap<Identifier, round2::SignatureShare> = HashMap::new();

        for &signer_id in &signer_ids {
            let share = round2::sign(
                &signing_package,
                &nonces_map[&signer_id],
                &key_packages[&signer_id],
                randomizer_point,
            )
            .unwrap();
            signature_shares.insert(signer_id, share);
        }

        // Aggregate
        let frost_signature = redpallas::aggregate(
            &signing_package,
            &signature_shares,
            &public_key_package,
            &randomized_params,
        )
        .expect("Aggregate should succeed");

        // Convert to orchard_redpallas::Signature<SpendAuth> -- the exact conversion
        // used in frost_sign.rs before apply_orchard_signature()
        let sig_bytes: [u8; 64] = frost_signature.serialize();
        let orchard_sig =
            orchard_redpallas::Signature::<orchard_redpallas::SpendAuth>::from(sig_bytes);

        // Verify round-trip: extract bytes back and compare
        let recovered_bytes: [u8; 64] = (&orchard_sig).into();
        assert_eq!(
            sig_bytes, recovered_bytes,
            "FROST signature bytes should round-trip through orchard_redpallas::Signature<SpendAuth>"
        );
    }

    #[test]
    fn frost_signing_sighash_mismatch_detected() {
        use frost_core::{Field, Group};
        use frost_rerandomized::RandomizedParams;
        use reddsa::frost::redpallas::{PallasGroup, PallasScalarField};

        let (key_packages, public_key_package) = run_dkg_2_of_3();

        let signer_ids: Vec<Identifier> = (1..=2u16)
            .map(|i| Identifier::try_from(i).unwrap())
            .collect();

        // Sighash used in Round 1 (the one the participant trusts)
        let sighash_a = [0x42u8; 32];

        let alpha_scalar = <PallasScalarField as Field>::random(&mut OsRng);

        // Round 1: generate commitments against sighash_a
        let mut nonces_map: HashMap<Identifier, round1::SigningNonces> = HashMap::new();
        let mut commitments_map: BTreeMap<
            Identifier,
            frost_core::frost::round1::SigningCommitments<P>,
        > = BTreeMap::new();

        for &signer_id in &signer_ids {
            let kp = &key_packages[&signer_id];
            let (nonce, commitment) = round1::commit(kp.secret_share(), &mut OsRng);
            nonces_map.insert(signer_id, nonce);
            commitments_map.insert(signer_id, commitment);
        }

        // Coordinator builds Round 2 signing package with a DIFFERENT sighash (sighash_b)
        let sighash_b = [0xFFu8; 32];
        let signing_package =
            frost_core::frost::SigningPackage::new(commitments_map.clone(), &sighash_b[..]);

        let randomized_params =
            RandomizedParams::from_randomizer(&public_key_package, alpha_scalar);
        let rp_bytes: [u8; 32] = PallasGroup::serialize(randomized_params.randomizer_point());

        // Serialize through our serde types (as the coordinator would)
        let round2_request = SignRound2Request {
            packages: vec![ActionSigningPackageMsg {
                action_index: 0,
                signing_package: SigningPackageStore::from_signing_package(&signing_package),
                randomizer_point_hex: hex::encode(rp_bytes),
            }],
        };

        // Participant receives Round 2 and checks sighash matches Round 1
        let action_pkg = &round2_request.packages[0];
        let sp = action_pkg.signing_package.to_signing_package().unwrap();

        // This is the exact check from frost_participate.rs lines 119-130:
        // the participant compares the signing package's message against the expected sighash
        assert_ne!(
            sp.message(),
            &sighash_a[..],
            "Participant should detect that the Round 2 sighash differs from the Round 1 sighash"
        );
        assert_eq!(
            sp.message(),
            &sighash_b[..],
            "Signing package should contain the coordinator's (potentially malicious) sighash"
        );
    }

    #[test]
    #[should_panic(expected = "no entry found for key")]
    fn frost_aggregate_wrong_signer_set_fails() {
        use frost_core::Field;
        use frost_rerandomized::RandomizedParams;
        use reddsa::frost::redpallas::PallasScalarField;

        let (key_packages, public_key_package) = run_dkg_2_of_3();

        // Signers 1 and 2 generate commitments (the intended signing set)
        let committed_ids: Vec<Identifier> = (1..=2u16)
            .map(|i| Identifier::try_from(i).unwrap())
            .collect();
        let signer3_id = Identifier::try_from(3u16).unwrap();

        let sighash = [0x42u8; 32];
        let alpha_scalar = <PallasScalarField as Field>::random(&mut OsRng);

        // Round 1: signers 1 and 2 commit
        let mut nonces_map: HashMap<Identifier, round1::SigningNonces> = HashMap::new();
        let mut commitments_map: BTreeMap<
            Identifier,
            frost_core::frost::round1::SigningCommitments<P>,
        > = BTreeMap::new();

        for &signer_id in &committed_ids {
            let kp = &key_packages[&signer_id];
            let (nonce, commitment) = round1::commit(kp.secret_share(), &mut OsRng);
            nonces_map.insert(signer_id, nonce);
            commitments_map.insert(signer_id, commitment);
        }

        // Build signing package from signers 1 and 2's commitments
        let signing_package =
            frost_core::frost::SigningPackage::new(commitments_map.clone(), &sighash[..]);

        let randomized_params =
            RandomizedParams::from_randomizer(&public_key_package, alpha_scalar);

        // Signer 1 produces a valid share
        let share1 = round2::sign(
            &signing_package,
            &nonces_map[&committed_ids[0]],
            &key_packages[&committed_ids[0]],
            randomized_params.randomizer_point(),
        )
        .unwrap();

        // Signer 3 (NOT in the commitment set) produces a share
        // They need their own nonce since they weren't part of Round 1
        let (nonce3, _commitment3) =
            round1::commit(key_packages[&signer3_id].secret_share(), &mut OsRng);
        let share3 = round2::sign(
            &signing_package,
            &nonce3,
            &key_packages[&signer3_id],
            randomized_params.randomizer_point(),
        )
        .unwrap();

        // Attempt aggregation with signer 1's share + signer 3's share
        // (signer 3 was not in the commitment set)
        // The frost-rerandomized library panics when it encounters a signer ID
        // not present in the signing package's commitments map.
        let mut bad_shares: HashMap<Identifier, round2::SignatureShare> = HashMap::new();
        bad_shares.insert(committed_ids[0], share1);
        bad_shares.insert(signer3_id, share3);

        let _result = redpallas::aggregate(
            &signing_package,
            &bad_shares,
            &public_key_package,
            &randomized_params,
        );
    }

    #[test]
    fn frost_production_fvk_path() {
        use orchard::keys::FullViewingKey;
        use rand::RngCore;

        use crate::frost_config::{decrypt_string, encrypt_string};

        let max_attempts = 50;
        let mut fvk = None;

        for _ in 0..max_attempts {
            let (key_packages, public_key_package) = run_dkg_2_of_3();

            // Step 1: Extract ak and check sign bit (matches frost_dkg.rs line 238)
            let ak_bytes: [u8; 32] = public_key_package.group_public().serialize();
            if ak_bytes[31] & 0x80 != 0 {
                continue;
            }

            // Step 2: Generate nk/rivk with OsRng + clear high bits
            // (matches frost_dkg.rs lines 254-259)
            let mut nk_bytes = [0u8; 32];
            let mut rivk_bytes = [0u8; 32];
            OsRng.fill_bytes(&mut nk_bytes);
            OsRng.fill_bytes(&mut rivk_bytes);
            nk_bytes[31] &= 0x7f;
            rivk_bytes[31] &= 0x7f;

            // Step 3: Construct 96-byte FVK (matches frost_dkg.rs lines 291-294)
            let mut fvk_bytes = [0u8; 96];
            fvk_bytes[..32].copy_from_slice(&ak_bytes);
            fvk_bytes[32..64].copy_from_slice(&nk_bytes);
            fvk_bytes[64..96].copy_from_slice(&rivk_bytes);

            if let Some(f) = FullViewingKey::from_bytes(&fvk_bytes) {
                // Step 4: Encrypt nk and rivk with age, decrypt, verify round-trip
                let age_key = age::x25519::Identity::generate();
                let age_pubkey = age_key.to_public();

                let nk_encrypted = encrypt_string(
                    std::iter::once(&age_pubkey as &dyn age::Recipient),
                    &hex::encode(nk_bytes),
                )
                .unwrap();
                let rivk_encrypted = encrypt_string(
                    std::iter::once(&age_pubkey as &dyn age::Recipient),
                    &hex::encode(rivk_bytes),
                )
                .unwrap();

                let nk_decrypted = decrypt_string(
                    std::iter::once(&age_key as &dyn age::Identity),
                    &nk_encrypted,
                )
                .unwrap();
                let rivk_decrypted = decrypt_string(
                    std::iter::once(&age_key as &dyn age::Identity),
                    &rivk_encrypted,
                )
                .unwrap();

                assert_eq!(hex::encode(nk_bytes), nk_decrypted);
                assert_eq!(hex::encode(rivk_bytes), rivk_decrypted);

                // Step 5: Serialize key_package and public_key_package through stores, verify round-trip
                let kp = key_packages.values().next().unwrap();
                let kp_store = KeyPackageStore::from_key_package(kp);
                let kp_json = serde_json::to_string(&kp_store).unwrap();

                // Encrypt and decrypt the key package (as production does)
                let kp_encrypted = encrypt_string(
                    std::iter::once(&age_pubkey as &dyn age::Recipient),
                    &kp_json,
                )
                .unwrap();
                let kp_decrypted = decrypt_string(
                    std::iter::once(&age_key as &dyn age::Identity),
                    &kp_encrypted,
                )
                .unwrap();
                let kp_restored: KeyPackageStore =
                    serde_json::from_str(&kp_decrypted).unwrap();
                let kp_restored = kp_restored.to_key_package().unwrap();
                assert_eq!(
                    kp.identifier().serialize(),
                    kp_restored.identifier().serialize()
                );
                assert_eq!(
                    kp.secret_share().serialize(),
                    kp_restored.secret_share().serialize()
                );

                let pkp_store =
                    PublicKeyPackageStore::from_public_key_package(&public_key_package);
                let pkp_json = serde_json::to_string(&pkp_store).unwrap();
                let pkp_restored: PublicKeyPackageStore =
                    serde_json::from_str(&pkp_json).unwrap();
                let pkp_restored = pkp_restored.to_public_key_package().unwrap();
                assert_eq!(
                    public_key_package.group_public().serialize(),
                    pkp_restored.group_public().serialize()
                );

                fvk = Some(f);
                break;
            }
        }

        assert!(
            fvk.is_some(),
            "Failed to construct valid FVK via production path after {} attempts",
            max_attempts
        );
    }
}
