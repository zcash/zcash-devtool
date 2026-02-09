use std::collections::HashMap;
use std::io::{self, BufRead};

use anyhow::anyhow;
use clap::Args;
use rand::rngs::OsRng;

use frost_core::frost::keys::dkg;
use reddsa::frost::redpallas::{Identifier, PallasBlake2b512};

use orchard::keys::FullViewingKey;
use zcash_client_backend::{
    data_api::{Account as _, AccountBirthday, AccountPurpose, WalletWrite},
    proto::service,
};
use zcash_client_sqlite::{util::SystemClock, WalletDb};
use zcash_keys::keys::UnifiedFullViewingKey;

use crate::{
    data::get_db_paths,
    error,
    frost_config::{self, FrostAccountConfig, FrostConfig},
    frost_serde::{
        DkgRound1Msg, DkgRound1PackageStore, DkgRound2Msg, DkgRound2PackageStore, FvkShareMsg,
        IdHex, KeyPackageStore, PublicKeyPackageStore,
    },
    remote::ConnectionArgs,
};

// Options accepted for the `wallet frost-dkg` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// A name for the FROST account
    #[arg(long)]
    name: String,

    /// Minimum number of signers (threshold)
    #[arg(long)]
    min_signers: u16,

    /// Maximum number of signers (total participants)
    #[arg(long)]
    max_signers: u16,

    /// age identity file for encrypting FROST key material
    #[arg(short, long)]
    identity: String,

    /// This participant's 1-based index (1..=max_signers)
    #[arg(long)]
    participant_index: u16,

    /// Whether this participant is the coordinator (generates nk/rivk)
    #[arg(long, default_value = "false")]
    coordinator: bool,

    /// The wallet birthday height
    #[arg(long)]
    birthday: u32,

    #[command(flatten)]
    connection: ConnectionArgs,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        if self.min_signers < 2 {
            return Err(anyhow!("min_signers must be at least 2"));
        }
        if self.max_signers < self.min_signers {
            return Err(anyhow!("max_signers must be >= min_signers"));
        }
        if self.participant_index < 1 || self.participant_index > self.max_signers {
            return Err(anyhow!(
                "participant_index must be between 1 and max_signers"
            ));
        }

        let my_identifier = Identifier::try_from(self.participant_index)?;
        let my_id_hex = IdHex::from_id(&my_identifier);

        eprintln!(
            "Starting FROST DKG for '{}' (threshold {}-of-{}), participant #{}{}",
            self.name,
            self.min_signers,
            self.max_signers,
            self.participant_index,
            if self.coordinator {
                " [coordinator]"
            } else {
                ""
            },
        );

        // === DKG Round 1 ===
        eprintln!("\n=== DKG Round 1: Generating commitments ===");

        let (round1_secret, round1_package) = dkg::part1::<PallasBlake2b512, _>(
            my_identifier,
            self.max_signers,
            self.min_signers,
            OsRng,
        )?;

        let my_round1_msg = DkgRound1Msg {
            identifier: my_id_hex.clone(),
            package: DkgRound1PackageStore::from_package(&round1_package),
        };
        let my_round1_json = serde_json::to_string(&my_round1_msg)?;
        eprintln!("\nYour Round 1 package (send to all other participants):");
        println!("{my_round1_json}");

        // Collect Round 1 packages from other participants
        let other_count = (self.max_signers - 1) as usize;
        eprintln!(
            "\nPaste {other_count} Round 1 package(s) from other participants (one per line):"
        );
        let mut round1_packages: HashMap<
            frost_core::frost::Identifier<PallasBlake2b512>,
            dkg::round1::Package<PallasBlake2b512>,
        > = HashMap::new();

        let stdin = io::stdin();
        for line in stdin.lock().lines().take(other_count) {
            let line = line?;
            let msg: DkgRound1Msg = serde_json::from_str(&line)
                .map_err(|e| anyhow!("Failed to parse Round 1 package: {e}"))?;
            let their_id = msg.identifier.to_id()?;
            if their_id == my_identifier {
                return Err(anyhow!("Received our own Round 1 package"));
            }
            let pkg = msg
                .package
                .to_package()
                .map_err(|e| anyhow!("Failed to parse Round 1 package data: {e}"))?;
            eprintln!(
                "  Received Round 1 package from participant {}",
                msg.identifier.0
            );
            round1_packages.insert(their_id, pkg);
        }

        if round1_packages.len() != other_count {
            return Err(anyhow!(
                "Expected {} Round 1 packages, got {}",
                other_count,
                round1_packages.len()
            ));
        }

        // === DKG Round 2 ===
        eprintln!("\n=== DKG Round 2: Computing secret shares ===");

        let (round2_secret, round2_packages) = dkg::part2(round1_secret, &round1_packages)?;

        // Output Round 2 packages (each is for a specific recipient)
        for (recipient_id, package) in &round2_packages {
            let msg = DkgRound2Msg {
                from: my_id_hex.clone(),
                to: IdHex::from_id(recipient_id),
                package: DkgRound2PackageStore::from_package(package),
            };
            let json = serde_json::to_string(&msg)?;
            eprintln!(
                "\nRound 2 package for participant {} (send privately):",
                IdHex::from_id(recipient_id).0
            );
            println!("{json}");
        }

        // Collect Round 2 packages addressed to us
        eprintln!(
            "\nPaste {other_count} Round 2 package(s) addressed to you (one per line):"
        );
        let mut received_round2: HashMap<
            frost_core::frost::Identifier<PallasBlake2b512>,
            dkg::round2::Package<PallasBlake2b512>,
        > = HashMap::new();

        let stdin = io::stdin();
        for line in stdin.lock().lines().take(other_count) {
            let line = line?;
            let msg: DkgRound2Msg = serde_json::from_str(&line)
                .map_err(|e| anyhow!("Failed to parse Round 2 package: {e}"))?;
            let to_id = msg.to.to_id()?;
            if to_id != my_identifier {
                return Err(anyhow!("Round 2 package not addressed to us"));
            }
            let from_id = msg.from.to_id()?;
            let pkg = msg
                .package
                .to_package()
                .map_err(|e| anyhow!("Failed to parse Round 2 package data: {e}"))?;
            eprintln!(
                "  Received Round 2 package from participant {}",
                msg.from.0
            );
            received_round2.insert(from_id, pkg);
        }

        if received_round2.len() != other_count {
            return Err(anyhow!(
                "Expected {} Round 2 packages, got {}",
                other_count,
                received_round2.len()
            ));
        }

        // === DKG Round 3: Finalize ===
        eprintln!("\n=== DKG Round 3: Finalizing key generation ===");

        let (key_package, public_key_package) =
            dkg::part3(&round2_secret, &round1_packages, &received_round2)?;

        // Get the group verifying key (this is the Orchard spend validating key / ak)
        let ak_bytes: [u8; 32] = public_key_package.group_public().serialize();

        eprintln!(
            "DKG complete. Group public key (ak): {}",
            hex::encode(ak_bytes)
        );

        // === Exchange nk/rivk ===
        let (nk_bytes, rivk_bytes) = if self.coordinator {
            eprintln!("\n=== Coordinator: Generating shared nk and rivk ===");

            let mut nk = [0u8; 32];
            let mut rivk = [0u8; 32];
            use rand::RngCore;
            OsRng.fill_bytes(&mut nk);
            OsRng.fill_bytes(&mut rivk);

            let fvk_share = FvkShareMsg {
                nk_hex: hex::encode(nk),
                rivk_hex: hex::encode(rivk),
            };
            let json = serde_json::to_string(&fvk_share)?;
            eprintln!("\nFVK share message (send to all participants via secure channel):");
            println!("{json}");

            (nk, rivk)
        } else {
            eprintln!("\n=== Waiting for FVK share from coordinator ===");
            eprintln!("Paste the FVK share message from the coordinator:");

            let mut line = String::new();
            io::stdin().lock().read_line(&mut line)?;
            let msg: FvkShareMsg = serde_json::from_str(line.trim())
                .map_err(|e| anyhow!("Failed to parse FVK share: {e}"))?;

            let nk: [u8; 32] = hex::decode(&msg.nk_hex)?
                .try_into()
                .map_err(|_| anyhow!("Invalid nk length"))?;
            let rivk: [u8; 32] = hex::decode(&msg.rivk_hex)?
                .try_into()
                .map_err(|_| anyhow!("Invalid rivk length"))?;

            eprintln!("Received FVK share from coordinator.");
            (nk, rivk)
        };

        // === Construct Orchard FullViewingKey ===
        let mut fvk_bytes = [0u8; 96];
        fvk_bytes[..32].copy_from_slice(&ak_bytes);
        fvk_bytes[32..64].copy_from_slice(&nk_bytes);
        fvk_bytes[64..96].copy_from_slice(&rivk_bytes);

        let orchard_fvk = FullViewingKey::from_bytes(&fvk_bytes)
            .ok_or_else(|| anyhow!("Failed to construct Orchard FVK from DKG output"))?;

        let ufvk = UnifiedFullViewingKey::from_orchard_fvk(orchard_fvk)
            .map_err(|e| anyhow!("Failed to create UFVK: {e:?}"))?;

        eprintln!("\n=== Importing wallet account ===");

        let params = crate::config::get_wallet_network(wallet_dir.as_ref())?;
        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let mut db_data = WalletDb::for_path(db_data, params, SystemClock, OsRng)?;

        let birthday = {
            let mut client = self.connection.connect(params, wallet_dir.as_ref()).await?;
            let tip_height = client
                .get_latest_block(service::ChainSpec::default())
                .await?
                .get_ref()
                .height
                .try_into()
                .expect("block heights must fit into u32");

            let request = service::BlockId {
                height: (self.birthday - 1).into(),
                ..Default::default()
            };
            let treestate = client.get_tree_state(request).await?.into_inner();
            AccountBirthday::from_treestate(treestate, Some(tip_height))
                .map_err(error::Error::from)?
        };

        let purpose = AccountPurpose::ViewOnly;
        let account =
            db_data.import_account_ufvk(&self.name, &ufvk, &birthday, purpose, Some("frost"))?;
        let account_uuid = format!("{:?}", account.id());

        eprintln!("Account '{}' imported (UUID: {})", self.name, account_uuid);

        // === Store FROST key material ===
        let age_recipients = frost_config::load_age_recipients(&self.identity)?;

        let kp_store = KeyPackageStore::from_key_package(&key_package);
        let kp_json = serde_json::to_string(&kp_store)?;
        let encrypted_kp = frost_config::encrypt_string(
            age_recipients.iter().map(|r| r as &dyn age::Recipient),
            &kp_json,
        )?;

        let pkp_store = PublicKeyPackageStore::from_public_key_package(&public_key_package);
        let pkp_json = serde_json::to_string(&pkp_store)?;

        let frost_account = FrostAccountConfig {
            name: self.name.clone(),
            account_uuid,
            min_signers: self.min_signers,
            max_signers: self.max_signers,
            key_package: encrypted_kp,
            public_key_package: pkp_json,
            nk_bytes: hex::encode(nk_bytes),
            rivk_bytes: hex::encode(rivk_bytes),
            identifier: my_id_hex.0,
        };

        let mut frost_config_data = FrostConfig::read(wallet_dir.as_ref())?;
        frost_config_data.accounts.push(frost_account);
        frost_config_data.write(wallet_dir.as_ref())?;

        eprintln!("\nFROST key material saved to frost.toml");
        eprintln!(
            "DKG complete! Account '{}' is ready for chain scanning.",
            self.name
        );

        Ok(())
    }
}
