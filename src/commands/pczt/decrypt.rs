use anyhow::anyhow;
use clap::Args;
use orchard::note_encryption::OrchardDomain;
use pczt::{roles::verifier::Verifier, Pczt};
use secrecy::ExposeSecret;
use tokio::io::{stdin, AsyncReadExt};
use zcash_address::unified::{self, Encoding};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_note_encryption::{try_note_decryption, try_output_recovery_with_ovk};
use zcash_protocol::consensus::{NetworkConstants, Parameters};
use zip32::{fingerprint::SeedFingerprint, Scope};

use crate::config::WalletConfig;

/// Verifies and displays information about a diversified Orchard address
///
/// The `scope` parameter represents how the note was decrypted:
/// - `Some(Scope::External)`: Decrypted with external IVK (incoming to external address)
/// - `Some(Scope::Internal)`: Decrypted with internal IVK (incoming to internal/change address)  
/// - `None`: Decrypted with OVK (outgoing, created by sender)
fn verify_diversified_address(
    recipient: &orchard::Address,
    orchard_fvk: &orchard::keys::FullViewingKey,
    scope: Option<orchard::keys::Scope>,
    network: &impl Parameters,
) {
    // Determine which IVK to use based on scope
    let scope_type = scope.unwrap_or(orchard::keys::Scope::External);

    let ivk = orchard_fvk.to_ivk(scope_type);

    // Get the diversifier index for this address
    match ivk.diversifier_index(recipient) {
        Some(diversifier_index) => {
            println!("  Address verification:");
            println!("    Scope: {:?}", scope_type);
            println!("    Diversifier index: {}", u128::from(diversifier_index));

            // Reconstruct the address from the FVK and diversifier index
            let reconstructed = ivk.address_at(diversifier_index);

            // Verify it matches
            if reconstructed.to_raw_address_bytes() == recipient.to_raw_address_bytes() {
                println!("    ✓ Address successfully reconstructed from FVK + diversifier");
                println!("      This cryptographically proves the address belongs to your wallet.");
            } else {
                println!("    ✗ WARNING: Address reconstruction mismatch!");
                println!(
                    "      Expected: {}",
                    hex::encode(recipient.to_raw_address_bytes())
                );
                println!(
                    "      Got:      {}",
                    hex::encode(reconstructed.to_raw_address_bytes())
                );
            }

            // Try to display as unified address (Orchard-only)
            match unified::Address::try_from_items(vec![unified::Receiver::Orchard(
                recipient.to_raw_address_bytes(),
            )]) {
                Ok(ua) => {
                    println!(
                        "    Address (Orchard-only UA): {}",
                        ua.encode(&network.network_type())
                    );
                }
                Err(_) => {
                    println!(
                        "    Address (raw bytes): {}",
                        hex::encode(recipient.to_raw_address_bytes())
                    );
                }
            }
        }
        None => {
            println!("  Address verification:");
            println!("    ⚠ Could not determine diversifier index");
            println!("    (This address may not belong to this FVK + scope combination)");
        }
    }

    println!();
}

// Options accepted for the `pczt decrypt` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// age identity file to decrypt the mnemonic phrase with (if a wallet is provided)
    #[arg(short, long)]
    identity: Option<String>,

    /// UFVK to use for decrypting notes
    #[arg(short, long)]
    ufvk: String,
}

/// Attempts to decrypt an Orchard action's note using the provided viewing keys.
/// Tries external IVK, then internal IVK, then external OVK, then internal OVK, then all-zeros OVK.
///
/// Returns a tuple of (note, recipient, memo_bytes, scope) where scope is:
/// - `Some(Scope::External)`: Decrypted with external IVK
/// - `Some(Scope::Internal)`: Decrypted with internal IVK
/// - `None`: Decrypted with OVK (outgoing)
fn decrypt_orchard_action(
    action: &orchard::pczt::Action,
    ivk_external: &orchard::keys::PreparedIncomingViewingKey,
    ivk_internal: &orchard::keys::PreparedIncomingViewingKey,
    ovk_external: &orchard::keys::OutgoingViewingKey,
    ovk_internal: &orchard::keys::OutgoingViewingKey,
    ovk_dummy: &orchard::keys::OutgoingViewingKey,
) -> Option<(
    orchard::Note,
    orchard::Address,
    [u8; 512],
    Option<orchard::keys::Scope>,
)> {
    let domain = OrchardDomain::for_pczt_action(action);

    // Try external IVK (incoming to external address)
    if let Some((note, recipient, memo_bytes)) = try_note_decryption(&domain, ivk_external, action)
    {
        return Some((
            note,
            recipient,
            memo_bytes,
            Some(orchard::keys::Scope::External),
        ));
    }

    // Try internal IVK (incoming to internal/change address)
    if let Some((note, recipient, memo_bytes)) = try_note_decryption(&domain, ivk_internal, action)
    {
        return Some((
            note,
            recipient,
            memo_bytes,
            Some(orchard::keys::Scope::Internal),
        ));
    }

    // Try external OVK (outgoing note created by this wallet to an external address)
    if let Some((note, recipient, memo_bytes)) = try_output_recovery_with_ovk(
        &domain,
        ovk_external,
        action,
        action.cv_net(),
        &action.output().encrypted_note().out_ciphertext,
    ) {
        return Some((note, recipient, memo_bytes, None));
    }

    // Try internal OVK (change output created by this wallet)
    if let Some((note, recipient, memo_bytes)) = try_output_recovery_with_ovk(
        &domain,
        ovk_internal,
        action,
        action.cv_net(),
        &action.output().encrypted_note().out_ciphertext,
    ) {
        return Some((note, recipient, memo_bytes, None));
    }

    // Try all-zeros OVK (dummy notes)
    if let Some((note, recipient, memo_bytes)) = try_output_recovery_with_ovk(
        &domain,
        ovk_dummy,
        action,
        action.cv_net(),
        &action.output().encrypted_note().out_ciphertext,
    ) {
        return Some((note, recipient, memo_bytes, None));
    }

    None
}

/// Displays comprehensive information about an Orchard action
fn display_orchard_action(
    action_index: usize,
    action: &orchard::pczt::Action,
    decrypted: Option<&(
        orchard::Note,
        orchard::Address,
        [u8; 512],
        Option<orchard::keys::Scope>,
    )>,
    network: &impl Parameters,
    seed_fp: Option<&(SeedFingerprint, zip32::ChildIndex)>,
    orchard_fvk: &orchard::keys::FullViewingKey,
) {
    println!("--- Action {} ---", action_index);

    // Display spend information
    if let Some(spend_value) = action.spend().value() {
        if spend_value.inner() == 0 {
            println!("  Spend: Zero value (likely a dummy)");
        } else {
            println!("  Spend: {} zatoshis", spend_value.inner());
        }
    }

    // Display output information
    if let Some(output_value) = action.output().value() {
        if output_value.inner() == 0 {
            println!("  Output: Zero value (likely a dummy)");
        } else {
            println!("  Output: {} zatoshis", output_value.inner());

            // Show user address if available
            if let Some(user_addr) = action.output().user_address() {
                println!("    To: {}", user_addr);
            }

            // Show if this is change
            if let Some((derivation, (fp, coin_type))) =
                action.output().zip32_derivation().as_ref().zip(seed_fp)
            {
                if let Some(account_idx) = derivation.extract_account_index(fp, *coin_type) {
                    println!(
                        "    (change to ZIP 32 account index {})",
                        u32::from(account_idx)
                    );
                }
            }
        }
    }

    println!();

    // Display decryption result
    match decrypted {
        Some((note, recipient, memo_bytes, scope)) => {
            let scope_str = match scope {
                Some(orchard::keys::Scope::External) => "External",
                Some(orchard::keys::Scope::Internal) => "Internal",
                None => "Outgoing (created by sender)",
            };
            println!("  ✓ Decrypted (scope: {})", scope_str);

            // Add explanation for internal scope
            if matches!(scope, Some(orchard::keys::Scope::Internal)) {
                println!("    (This is an internal/change address from your wallet)");
            } else if scope.is_none() {
                println!("    (This note was created by you using your OVK)");
            }

            println!();

            println!("  Note details:");
            println!("    Value: {} zatoshis", note.value().inner());
            println!("    Rho: {:?}", note.rho());
            println!("    Rseed: {:?}", note.rseed());
            println!();

            // Parse and display the memo
            display_memo(memo_bytes);

            println!();

            // Verify the diversified address
            verify_diversified_address(recipient, orchard_fvk, *scope, network);
        }
        None => {
            println!("  ✗ Could not decrypt note (not owned by this UFVK)");
        }
    }

    println!();
}

/// Displays a memo in a human-readable format
fn display_memo(memo_bytes: &[u8; 512]) {
    match zcash_protocol::memo::MemoBytes::from_bytes(memo_bytes) {
        Ok(memo) => match memo.try_into() {
            Ok(zcash_protocol::memo::Memo::Text(text)) => {
                println!("    Memo: {}", String::from(text));
            }
            Ok(zcash_protocol::memo::Memo::Empty) => {
                println!("    Memo: (empty)");
            }
            Ok(zcash_protocol::memo::Memo::Arbitrary(bytes)) => {
                println!("    Memo: (arbitrary data, {} bytes)", bytes.len());
            }
            Ok(zcash_protocol::memo::Memo::Future(_)) => {
                println!("    Memo: (future memo type)");
            }
            Err(_) => {
                println!("    Memo: (raw bytes)");
            }
        },
        Err(_) => {
            println!("    Memo: (invalid memo bytes)");
        }
    }
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        // Allow the user to optionally provide the wallet dir, to inspect the PCZT in the
        // context of a wallet.
        let mut config = match (WalletConfig::read(wallet_dir.as_ref()), wallet_dir) {
            (Err(_), None) => Ok(None),
            (res, _) => res.map(Some),
        }?;

        let mut buf = vec![];
        stdin().read_to_end(&mut buf).await?;

        let pczt = Pczt::parse(&buf).map_err(|e| anyhow!("Failed to read PCZT: {:?}", e))?;

        let network = &zcash_protocol::consensus::MAIN_NETWORK;

        // Parse UFVK
        let ufvk = UnifiedFullViewingKey::decode(network, &self.ufvk)
            .map_err(|error| anyhow::anyhow!("malformed UFVK string: {error:?}"))?;

        // Extract Orchard FVK
        let orchard_fvk = ufvk
            .orchard()
            .ok_or_else(|| anyhow::anyhow!("UFVK does not contain an Orchard key"))?;

        // Create prepared incoming viewing keys for external and internal scopes
        let ivk_external = orchard::keys::PreparedIncomingViewingKey::new(
            &orchard_fvk.to_ivk(orchard::keys::Scope::External),
        );
        let ivk_internal = orchard::keys::PreparedIncomingViewingKey::new(
            &orchard_fvk.to_ivk(orchard::keys::Scope::Internal),
        );

        // Create outgoing viewing keys for external and internal scopes
        let ovk_external = orchard_fvk.to_ovk(Scope::External);
        let ovk_internal = orchard_fvk.to_ovk(Scope::Internal);

        // All-zeros OVK for detecting dummy notes
        let ovk_dummy = orchard::keys::OutgoingViewingKey::from([0u8; 32]);

        let seed_fp = config
            .as_mut()
            .zip(self.identity)
            .map(|(config, identity)| {
                // Decrypt the mnemonic to access the seed.
                let identities = age::IdentityFile::from_file(identity)?.into_identities()?;

                let seed = config
                    .decrypt_seed(identities.iter().map(|i| i.as_ref() as _))?
                    .ok_or(anyhow!(
                        "Identity provided for a wallet that doesn't have a seed"
                    ))?;

                SeedFingerprint::from_seed(seed.expose_secret())
                    .ok_or_else(|| anyhow!("Invalid seed length"))
                    .map(|seed_fp| {
                        (
                            seed_fp,
                            zip32::ChildIndex::hardened(
                                config.network().network_type().coin_type(),
                            ),
                        )
                    })
            })
            .transpose()?;

        // Process Orchard actions
        Verifier::new(pczt)
            .with_orchard(|bundle| {
                if !bundle.actions().is_empty() {
                    println!("{} Orchard actions:", bundle.actions().len());
                    println!();
                }

                // Display each action's comprehensive information
                for (idx, action) in bundle.actions().iter().enumerate() {
                    // Check if this is a dummy note first
                    if action.spend().dummy_sk().is_some() {
                        println!("--- Action {} ---", idx);
                        println!("  ⚠ Dummy note (has dummy_sk in spend)");
                        if let Some(value) = action.spend().value() {
                            println!("  Value: {} zatoshis", value.inner());
                        }
                        println!();
                        continue;
                    }

                    // Try to decrypt the action
                    let decrypted = decrypt_orchard_action(
                        action,
                        &ivk_external,
                        &ivk_internal,
                        &ovk_external,
                        &ovk_internal,
                        &ovk_dummy,
                    );

                    // Display unified action information
                    display_orchard_action(
                        idx,
                        action,
                        decrypted.as_ref(),
                        network,
                        seed_fp.as_ref(),
                        &orchard_fvk,
                    );
                }

                Ok::<_, pczt::roles::verifier::OrchardError<()>>(())
            })
            .expect("no error");

        Ok(())
    }
}
