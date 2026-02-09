use std::io::{self, BufRead};

use anyhow::anyhow;
use clap::Args;
use rand::rngs::OsRng;
use uuid::Uuid;

use frost_core::Group;
use reddsa::frost::redpallas::{round1, round2, PallasGroup};

use crate::frost_config::{self, FrostConfig};
use crate::frost_serde::{
    IdHex, KeyPackageStore, SignRound1Response, SignRound2Request, SignRound2Response,
    SigningCommitmentsStore, SigningRequest,
};

// Options accepted for the `pczt frost-participate` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// age identity file to decrypt FROST key material
    #[arg(short, long)]
    identity: String,

    /// Account UUID to sign with (optional if only one FROST account exists)
    account: Option<Uuid>,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        // Load FROST config
        let frost_config = FrostConfig::read(wallet_dir.as_ref())?;

        let account_config = match self.account {
            Some(uuid) => frost_config
                .find_account(&uuid.to_string())
                .ok_or_else(|| anyhow!("No FROST account found for UUID {}", uuid))?,
            None => {
                if frost_config.accounts.len() == 1 {
                    &frost_config.accounts[0]
                } else if frost_config.accounts.is_empty() {
                    return Err(anyhow!("No FROST accounts found in frost.toml"));
                } else {
                    return Err(anyhow!(
                        "Multiple FROST accounts found; please specify account UUID"
                    ));
                }
            }
        };

        // Decrypt key package
        let identities = age::IdentityFile::from_file(self.identity)?.into_identities()?;
        let kp_json = frost_config::decrypt_string(
            identities.iter().map(|i| i.as_ref() as &dyn age::Identity),
            &account_config.key_package,
        )?;
        let kp_store: KeyPackageStore = serde_json::from_str(&kp_json)?;
        let key_package = kp_store.to_key_package()?;

        let my_id_hex = IdHex(account_config.identifier.clone());

        eprintln!(
            "FROST participant ready (account '{}', {}-of-{})",
            account_config.name,
            account_config.min_signers,
            account_config.max_signers,
        );

        // === Round 1: Receive signing request, generate commitments ===
        eprintln!("\n=== Round 1: Paste the signing request from the coordinator ===");

        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        let signing_request: SigningRequest = serde_json::from_str(line.trim())
            .map_err(|e| anyhow!("Failed to parse signing request: {e}"))?;

        let num_actions = signing_request.actions.len();
        eprintln!(
            "Signing request received for {} action(s)",
            num_actions
        );

        // Generate nonces and commitments for each action
        let mut nonces: Vec<round1::SigningNonces> = Vec::new();
        let mut commitments: Vec<SigningCommitmentsStore> = Vec::new();

        for _ in &signing_request.actions {
            let (nonce, commitment) =
                round1::commit(key_package.secret_share(), &mut OsRng);
            nonces.push(nonce);
            commitments.push(SigningCommitmentsStore::from_commitments(&commitment));
        }

        let round1_response = SignRound1Response {
            identifier: my_id_hex.clone(),
            commitments,
        };

        let response_json = serde_json::to_string(&round1_response)?;
        eprintln!("\nYour Round 1 response (send to coordinator):");
        println!("{response_json}");

        // === Round 2: Receive signing packages, generate signature shares ===
        eprintln!("\n=== Round 2: Paste the Round 2 package from the coordinator ===");

        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        let round2_request: SignRound2Request = serde_json::from_str(line.trim())
            .map_err(|e| anyhow!("Failed to parse Round 2 request: {e}"))?;

        if round2_request.packages.len() != num_actions {
            return Err(anyhow!(
                "Mismatch: {} signing packages vs {} actions",
                round2_request.packages.len(),
                num_actions,
            ));
        }

        let mut shares: Vec<String> = Vec::new();

        for (i, action_pkg) in round2_request.packages.iter().enumerate() {
            // Deserialize the signing package
            let signing_package = action_pkg.signing_package.to_signing_package().map_err(|e| {
                anyhow!("Failed to parse signing package for action {}: {e}", i)
            })?;

            // Parse the randomizer point
            let rp_bytes: [u8; 32] = hex::decode(&action_pkg.randomizer_point_hex)?
                .try_into()
                .map_err(|_| anyhow!("Invalid randomizer point length"))?;
            let randomizer_point = PallasGroup::deserialize(&rp_bytes)
                .map_err(|_| anyhow!("Invalid randomizer point"))?;

            let share = round2::sign(
                &signing_package,
                &nonces[i],
                &key_package,
                &randomizer_point,
            )
            .map_err(|e| {
                anyhow!(
                    "Failed to generate signature share for action {}: {:?}",
                    i,
                    e
                )
            })?;

            shares.push(hex::encode(share.serialize()));
        }

        let round2_response = SignRound2Response {
            identifier: my_id_hex,
            shares,
        };

        let response_json = serde_json::to_string(&round2_response)?;
        eprintln!("\nYour Round 2 response (send to coordinator):");
        println!("{response_json}");

        eprintln!("\nDone! The coordinator will aggregate your signature share.");

        Ok(())
    }
}
