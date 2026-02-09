use std::collections::{BTreeMap, HashMap};
use std::io::{self, BufRead};
use std::path::PathBuf;

use anyhow::anyhow;
use clap::Args;
use tokio::io::{stdout, AsyncWriteExt};
use uuid::Uuid;

use frost_rerandomized::RandomizedParams;
use reddsa::frost::redpallas::{self, PallasBlake2b512, PallasGroup};

use orchard::primitives::redpallas as orchard_redpallas;
use pczt::roles::signer::Signer;
use pczt::Pczt;

use crate::frost_config::FrostConfig;
use crate::frost_serde::{
    ActionSigningData, ActionSigningPackageMsg, PublicKeyPackageStore, SignRound1Response,
    SignRound2Request, SignRound2Response, SigningPackageStore,
    SigningRequest,
};

// Options accepted for the `pczt frost-sign` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// Path to the PCZT file to sign (stdin is reserved for interactive JSON)
    pczt_file: PathBuf,

    /// Number of signers participating in this ceremony
    #[arg(long)]
    num_signers: u16,

    /// Account UUID to sign with (optional if only one FROST account exists)
    #[arg(long)]
    account: Option<Uuid>,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        // Read PCZT from file (stdin is reserved for interactive JSON exchange)
        let buf = std::fs::read(&self.pczt_file).map_err(|e| {
            anyhow!("Failed to read PCZT file '{}': {e}", self.pczt_file.display())
        })?;
        let pczt = Pczt::parse(&buf).map_err(|e| anyhow!("Failed to parse PCZT: {:?}", e))?;

        // Load FROST config
        let frost_config = FrostConfig::read(wallet_dir.as_ref())?;

        let account_config = frost_config.resolve_account(
            self.account.as_ref().map(|u| u.to_string()).as_deref(),
        )?;

        let pkp_store: PublicKeyPackageStore =
            serde_json::from_str(&account_config.public_key_package)?;
        let public_key_package = pkp_store.to_public_key_package()?;

        if self.num_signers < account_config.min_signers {
            return Err(anyhow!(
                "num_signers ({}) is less than threshold ({})",
                self.num_signers,
                account_config.min_signers,
            ));
        }

        if self.num_signers > account_config.max_signers {
            return Err(anyhow!(
                "num_signers ({}) exceeds max_signers ({})",
                self.num_signers,
                account_config.max_signers,
            ));
        }

        // Extract alpha values from the Orchard actions before consuming the PCZT into a Signer.
        // This avoids re-parsing the PCZT just to read action fields.
        let action_alphas: Vec<(usize, [u8; 32])> = {
            let actions = pczt.orchard().actions();
            let mut alphas = Vec::new();
            // HACK: The pczt crate's Spend type stores alpha as `pub(crate)` with no
            // public getter (only nullifier, rk, and proprietary have #[getset(get = "pub")]).
            // We work around this by serializing to serde_json::Value and extracting the
            // "alpha" key. This breaks if the pczt crate changes its serde representation.
            // Upstream fix: add #[getset(get = "pub")] to the `alpha` field in pczt::orchard::Spend.
            for (i, action) in actions.iter().enumerate() {
                let spend_value = serde_json::to_value(action.spend())?;
                let alpha_bytes: [u8; 32] = match spend_value.get("alpha") {
                    Some(serde_json::Value::Array(arr)) => {
                        let bytes: Vec<u8> = arr
                            .iter()
                            .map(|v| {
                                v.as_u64()
                                    .and_then(|n| u8::try_from(n).ok())
                                    .ok_or_else(|| anyhow!("Orchard action {} alpha contains non-u8 value", i))
                            })
                            .collect::<Result<Vec<u8>, _>>()?;
                        bytes
                            .try_into()
                            .map_err(|_| anyhow!("Orchard action {} alpha has wrong length", i))?
                    }
                    Some(serde_json::Value::Null) | None => {
                        return Err(anyhow!(
                            "Orchard action {} missing alpha (spend_auth_randomizer)",
                            i
                        ));
                    }
                    other => {
                        return Err(anyhow!(
                            "Orchard action {} unexpected alpha format: {:?}",
                            i,
                            other
                        ));
                    }
                };
                alphas.push((i, alpha_bytes));
            }
            alphas
        };

        // Now consume the PCZT into a Signer to extract the sighash
        let signer =
            Signer::new(pczt).map_err(|e| anyhow!("Failed to initialize Signer: {:?}", e))?;

        let sighash = signer.shielded_sighash();
        let sighash_hex = hex::encode(sighash);

        let num_actions = action_alphas.len();

        if num_actions == 0 {
            eprintln!("No Orchard actions to sign.");
            let pczt = signer.finish();
            stdout().write_all(&pczt.serialize()).await?;
            return Ok(());
        }

        eprintln!(
            "FROST signing ceremony for {} Orchard action(s) with {}-of-{} threshold",
            num_actions, account_config.min_signers, account_config.max_signers,
        );

        // Build and output the signing request
        let signing_request = SigningRequest {
            sighash_hex,
            actions: action_alphas
                .iter()
                .map(|(idx, _)| ActionSigningData {
                    action_index: *idx,
                })
                .collect(),
        };

        let request_json = serde_json::to_string(&signing_request)?;
        eprintln!("\n=== Round 1: Collect commitments ===");
        eprintln!(
            "Send this signing request to all {} participants:",
            self.num_signers
        );
        eprintln!("{request_json}");

        // Collect Round 1 commitments from participants
        let num_signers = self.num_signers as usize;
        eprintln!(
            "\nPaste {} Round 1 response(s) from participants (one per line):",
            num_signers
        );

        // Per-action: BTreeMap of identifier -> commitment (BTreeMap required by frost-core)
        let mut all_commitments: Vec<
            BTreeMap<
                frost_core::frost::Identifier<PallasBlake2b512>,
                redpallas::round1::SigningCommitments,
            >,
        > = vec![BTreeMap::new(); num_actions];

        let mut received_r1 = 0usize;
        let io_stdin = io::stdin();
        for line in io_stdin.lock().lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            let response: SignRound1Response = serde_json::from_str(line.trim())
                .map_err(|e| anyhow!("Failed to parse Round 1 response: {e}"))?;

            let their_id = response.identifier.to_id()?;

            if response.commitments.len() != num_actions {
                return Err(anyhow!(
                    "Participant provided {} commitments, expected {}",
                    response.commitments.len(),
                    num_actions
                ));
            }

            for (action_idx, commitment_store) in response.commitments.iter().enumerate() {
                let commitment = commitment_store.to_commitments().map_err(|e| {
                    anyhow!("Failed to parse commitment for action {}: {e}", action_idx)
                })?;
                if all_commitments[action_idx].insert(their_id, commitment).is_some() {
                    return Err(anyhow!("Duplicate Round 1 commitment from participant {}", response.identifier.0));
                }
            }

            eprintln!("  Received commitments from participant {}", response.identifier.0);
            received_r1 += 1;
            if received_r1 >= num_signers {
                break;
            }
        }

        // Build signing packages for each action
        eprintln!("\n=== Round 2: Generate signing packages ===");

        let mut signing_packages: Vec<redpallas::SigningPackage> = Vec::new();
        let mut randomized_params_list: Vec<RandomizedParams<PallasBlake2b512>> = Vec::new();

        for (action_idx, (_, alpha_bytes)) in action_alphas.iter().enumerate() {
            let commitments = &all_commitments[action_idx];

            let signing_package = frost_core::frost::SigningPackage::new(
                commitments.clone(),
                &sighash[..],
            );
            signing_packages.push(signing_package);

            // Create randomized params from alpha
            let alpha_scalar =
                <reddsa::frost::redpallas::PallasScalarField as frost_core::Field>::deserialize(
                    alpha_bytes,
                )
                .map_err(|_| anyhow!("Invalid alpha scalar in action {}", action_idx))?;

            let randomized_params =
                RandomizedParams::from_randomizer(&public_key_package, alpha_scalar);
            randomized_params_list.push(randomized_params);
        }

        let round2_request = SignRound2Request {
            packages: signing_packages
                .iter()
                .zip(action_alphas.iter())
                .zip(randomized_params_list.iter())
                .map(|((sp, (idx, _)), rp)| {
                    let rp_bytes: [u8; 32] =
                        <PallasGroup as frost_core::Group>::serialize(rp.randomizer_point());
                    ActionSigningPackageMsg {
                        action_index: *idx,
                        signing_package: SigningPackageStore::from_signing_package(sp),
                        randomizer_point_hex: hex::encode(rp_bytes),
                    }
                })
                .collect(),
        };

        let round2_json = serde_json::to_string(&round2_request)?;
        eprintln!("Send this Round 2 package to all participants:");
        eprintln!("{round2_json}");

        // Collect Round 2 signature shares
        eprintln!(
            "\nPaste {} Round 2 response(s) from participants (one per line):",
            num_signers
        );

        let mut all_shares: Vec<
            HashMap<
                frost_core::frost::Identifier<PallasBlake2b512>,
                redpallas::round2::SignatureShare,
            >,
        > = vec![HashMap::new(); num_actions];

        let mut received_r2 = 0usize;
        let io_stdin = io::stdin();
        for line in io_stdin.lock().lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            let response: SignRound2Response = serde_json::from_str(line.trim())
                .map_err(|e| anyhow!("Failed to parse Round 2 response: {e}"))?;

            let their_id = response.identifier.to_id()?;

            if response.shares.len() != num_actions {
                return Err(anyhow!(
                    "Participant provided {} shares, expected {}",
                    response.shares.len(),
                    num_actions
                ));
            }

            for (action_idx, share_hex) in response.shares.iter().enumerate() {
                let share_bytes: [u8; 32] = hex::decode(share_hex)?
                    .try_into()
                    .map_err(|_| anyhow!("Invalid share length for action {}", action_idx))?;
                let share =
                    redpallas::round2::SignatureShare::deserialize(share_bytes).map_err(|e| {
                        anyhow!("Failed to parse share for action {}: {:?}", action_idx, e)
                    })?;
                if all_shares[action_idx].insert(their_id, share).is_some() {
                    return Err(anyhow!("Duplicate Round 2 share from participant {}", response.identifier.0));
                }
            }

            eprintln!("  Received shares from participant {}", response.identifier.0);
            received_r2 += 1;
            if received_r2 >= num_signers {
                break;
            }
        }

        // Cross-round participant validation
        for (action_idx, (commitments, shares)) in all_commitments.iter().zip(all_shares.iter()).enumerate() {
            let commit_ids: std::collections::HashSet<_> = commitments.keys().collect();
            let share_ids: std::collections::HashSet<_> = shares.keys().collect();
            if commit_ids != share_ids {
                return Err(anyhow!(
                    "Participant mismatch in action {}: Round 1 and Round 2 have different signers",
                    action_idx
                ));
            }
        }

        // Aggregate signatures and apply to PCZT
        eprintln!("\n=== Aggregating signatures ===");

        // Re-parse PCZT for applying signatures
        let pczt =
            Pczt::parse(&buf).map_err(|e| anyhow!("PCZT re-parse failed: {:?}", e))?;
        let mut signer =
            Signer::new(pczt).map_err(|e| anyhow!("Failed to initialize Signer: {:?}", e))?;

        for (action_idx, ((signing_package, randomized_params), shares)) in signing_packages
            .iter()
            .zip(randomized_params_list.iter())
            .zip(all_shares.iter())
            .enumerate()
        {
            let frost_signature = redpallas::aggregate(
                signing_package,
                shares,
                &public_key_package,
                randomized_params,
            )
            .map_err(|e| {
                anyhow!(
                    "Failed to aggregate signature for action {}: {:?}",
                    action_idx,
                    e
                )
            })?;

            // Convert FROST Signature to redpallas::Signature<SpendAuth>
            // Both are [R (32 bytes) || z (32 bytes)] = 64 bytes
            let sig_bytes: [u8; 64] = frost_signature.serialize();
            let orchard_sig = orchard_redpallas::Signature::<orchard_redpallas::SpendAuth>::from(sig_bytes);

            signer
                .apply_orchard_signature(action_idx, orchard_sig)
                .map_err(|e| {
                    anyhow!(
                        "Failed to apply FROST signature to action {}: {:?}",
                        action_idx,
                        e
                    )
                })?;

            eprintln!("  Action {} signed successfully", action_idx);
        }

        let pczt = signer.finish();
        stdout().write_all(&pczt.serialize()).await?;

        eprintln!("\nFROST signing complete!");

        Ok(())
    }
}
