use std::collections::BTreeMap;

use anyhow::anyhow;
use clap::Args;
use orchard::note_encryption::OrchardDomain;
use pczt::{roles::verifier::Verifier, Pczt};
use secrecy::ExposeSecret;
use tokio::io::{stdin, AsyncReadExt};

use ::transparent::sighash::SighashType;
use transparent::address::TransparentAddress;
use zcash_keys::encoding::AddressCodec;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_note_encryption::{try_note_decryption, try_output_recovery_with_ovk};
use zcash_primitives::transaction::{
    sighash::SignableInput,
    sighash_v5::v5_signature_hash,
    txid::{to_txid, TxIdDigester},
    TxVersion,
};
use zcash_protocol::consensus::{NetworkConstants, Parameters};
use zcash_script::solver;
use zip32::{fingerprint::SeedFingerprint, Scope};

use crate::config::WalletConfig;
use zcash_address::unified::{self, Encoding};

// Options accepted for the `pczt inspect` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// age identity file to decrypt the mnemonic phrase with (if a wallet is provided)
    #[arg(short, long)]
    identity: Option<String>,

    /// Optional UFVK to use for decrypting Orchard notes
    #[arg(short, long)]
    ufvk: Option<String>,
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

        // Parse UFVK if provided and extract the Orchard full viewing key
        let orchard_fvk = self
            .ufvk
            .as_ref()
            .map(|ufvk_str| {
                let ufvk = UnifiedFullViewingKey::decode(
                    &zcash_protocol::consensus::MAIN_NETWORK,
                    ufvk_str,
                )
                .map_err(|error| anyhow::anyhow!("malformed UFVK string: {error:?}"))?;

                ufvk.orchard()
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("UFVK does not contain an Orchard key"))
            })
            .transpose()?;

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

        let mut transparent_inputs = vec![];
        let mut transparent_outputs = vec![];
        let mut sapling_spends = vec![];
        let mut sapling_outputs = vec![];
        let mut orchard_actions = vec![];

        let pczt = Verifier::new(pczt)
            .with_transparent(|bundle| {
                transparent_inputs = bundle
                    .inputs()
                    .iter()
                    .map(|input| {
                        (
                            *input.sighash_type(),
                            input.redeem_script().clone(),
                            input.script_pubkey().clone(),
                            *input.value(),
                            input
                                .bip32_derivation()
                                .iter()
                                .map(|(pubkey, derivation)| {
                                    (
                                        *pubkey,
                                        (
                                            *derivation.seed_fingerprint(),
                                            derivation.derivation_path().clone(),
                                        ),
                                    )
                                })
                                .collect::<BTreeMap<_, _>>(),
                            input.partial_signatures().clone(),
                        )
                    })
                    .collect();
                transparent_outputs = bundle
                    .outputs()
                    .iter()
                    .map(|output| (output.user_address().clone(), *output.value()))
                    .collect();
                Ok::<_, pczt::roles::verifier::TransparentError<()>>(())
            })
            .expect("no error")
            .with_sapling(|bundle| {
                sapling_spends = bundle.spends().iter().map(|spend| *spend.value()).collect();
                sapling_outputs = bundle
                    .outputs()
                    .iter()
                    .map(|output| {
                        (
                            output.user_address().clone(),
                            *output.value(),
                            output
                                .zip32_derivation()
                                .as_ref()
                                .zip(seed_fp.as_ref())
                                .and_then(|(derivation, (seed_fp, coin_type))| {
                                    derivation.extract_account_index(seed_fp, *coin_type)
                                }),
                        )
                    })
                    .collect();
                Ok::<_, pczt::roles::verifier::SaplingError<()>>(())
            })
            .expect("no error")
            .with_orchard(|bundle| {
                orchard_actions = bundle
                    .actions()
                    .iter()
                    .map(|action| {
                        // Try to decrypt the action if UFVK was provided
                        let decrypted = orchard_fvk
                            .as_ref()
                            .and_then(|fvk| decrypt_orchard_action(action, fvk));

                        (
                            *action.spend().value(),
                            action.output().user_address().clone(),
                            *action.output().value(),
                            action
                                .output()
                                .zip32_derivation()
                                .as_ref()
                                .zip(seed_fp.as_ref())
                                .and_then(|(derivation, (seed_fp, coin_type))| {
                                    derivation.extract_account_index(seed_fp, *coin_type)
                                }),
                            decrypted,
                        )
                    })
                    .collect();
                Ok::<_, pczt::roles::verifier::OrchardError<()>>(())
            })
            .expect("no error")
            .finish();

        if !pczt.transparent().inputs().is_empty() {
            println!("{} transparent inputs", pczt.transparent().inputs().len());
            for (
                index,
                (
                    hash_type,
                    redeem_script,
                    script_pubkey,
                    value,
                    bip32_derivation,
                    partial_signatures,
                ),
            ) in transparent_inputs.iter().enumerate()
            {
                println!(
                    "- {index}: {} zatoshis{}, {}",
                    value.into_u64(),
                    match (
                        &config,
                        script_pubkey
                            .refine()
                            .ok()
                            .as_ref()
                            .and_then(solver::standard)
                    ) {
                        (Some(config), Some(solver::ScriptKind::PubKeyHash { hash })) => format!(
                            " from {}",
                            TransparentAddress::PublicKeyHash(hash).encode(&config.network())
                        ),
                        (Some(config), Some(solver::ScriptKind::ScriptHash { hash })) => format!(
                            " from {}",
                            TransparentAddress::ScriptHash(hash).encode(&config.network())
                        ),
                        _ => "".into(),
                    },
                    if hash_type == &SighashType::ALL {
                        "SIGHASH_ALL"
                    } else if hash_type == &SighashType::ALL_ANYONECANPAY {
                        "SIGHASH_ALL_ANYONECANPAY"
                    } else if hash_type == &SighashType::NONE {
                        "SIGHASH_NONE"
                    } else if hash_type == &SighashType::NONE_ANYONECANPAY {
                        "SIGHASH_NONE_ANYONECANPAY"
                    } else if hash_type == &SighashType::SINGLE {
                        "SIGHASH_SINGLE"
                    } else if hash_type == &SighashType::SINGLE_ANYONECANPAY {
                        "SIGHASH_SINGLE_ANYONECANPAY"
                    } else {
                        unreachable!()
                    },
                );
                println!("  Signatures present: {}", partial_signatures.len());
                match redeem_script
                    .as_ref()
                    .unwrap_or(script_pubkey)
                    .refine()
                    .ok()
                    .as_ref()
                    .and_then(solver::standard)
                {
                    Some(script) => match script {
                        solver::ScriptKind::PubKeyHash { .. } => {
                            println!("  Pay-to-PubKey-Hash (P2PKH)");
                        }
                        solver::ScriptKind::ScriptHash { .. } => {
                            // This case should never occur; `redeem_script` is only
                            // omitted from P2PKH inputs of PCZTs, and P2SH-in-P2SH does
                            // not make sense.
                            println!("  Pay-to-Script-Hash (weird P2SH-in-P2SH)");
                        }
                        solver::ScriptKind::MultiSig { required, pubkeys } => {
                            println!("  {required}-of-{} Pay-to-MultiSig (P2MS)", pubkeys.len());
                            for pubkey in pubkeys {
                                println!("  - {}", hex::encode(&pubkey));
                                if let Ok(pubkey) = <[u8; 33]>::try_from(pubkey.as_slice()) {
                                    if let Some((_, derivation_path)) =
                                        bip32_derivation.get(&pubkey)
                                    {
                                        print!("    m");
                                        for i in derivation_path {
                                            print!(
                                                "/{}{}",
                                                i.index(),
                                                if i.is_hardened() { "'" } else { "" },
                                            );
                                        }
                                        println!();
                                    }
                                    if let Some(sig) = partial_signatures.get(&pubkey) {
                                        println!("    Signature: {}", hex::encode(sig));
                                    }
                                }
                            }
                        }
                        solver::ScriptKind::NullData { .. } => println!("  Null data (OP_RETURN)"),
                        solver::ScriptKind::PubKey { .. } => println!("  Pay-to-PubKey (P2PK)"),
                    },
                    None => println!("  Non-standard script"),
                }
            }
        }

        if !pczt.transparent().outputs().is_empty() {
            println!("{} transparent outputs", pczt.transparent().outputs().len());
            for (index, (user_address, value)) in transparent_outputs.iter().enumerate() {
                println!(
                    "- {index}: {} zatoshis{}",
                    value.into_u64(),
                    match user_address {
                        Some(addr) => format!(" to {addr}"),
                        None => "".into(),
                    }
                );
            }
        }

        if !pczt.sapling().spends().is_empty() {
            println!("{} Sapling spends", pczt.sapling().spends().len());
            for (index, value) in sapling_spends.iter().enumerate() {
                if let Some(value) = value {
                    if value.inner() == 0 {
                        println!("- {index}: Zero value (likely a dummy)");
                    } else {
                        println!("- {index}: {} zatoshis", value.inner());
                    }
                }
            }
        }

        if !pczt.sapling().outputs().is_empty() {
            println!("{} Sapling outputs", pczt.sapling().outputs().len());
            for (index, (user_address, value, account_index)) in sapling_outputs.iter().enumerate()
            {
                if let Some(value) = value {
                    if value.inner() == 0 {
                        println!("- {index}: Zero value (likely a dummy)");
                    } else {
                        println!(
                            "- {index}: {} zatoshis{}{}",
                            value.inner(),
                            match user_address {
                                Some(addr) => format!(" to {addr}"),
                                None => "".into(),
                            },
                            match account_index {
                                Some(idx) =>
                                    format!(" (change to ZIP 32 account index {})", u32::from(*idx)),
                                None => "".into(),
                            }
                        );
                    }
                } else if let Some(addr) = user_address {
                    println!("- {index}: {addr}");
                } else if let Some(idx) = account_index {
                    println!(
                        "- {index}: change to ZIP 32 account index {}",
                        u32::from(*idx)
                    );
                }
            }
        }

        if !pczt.orchard().actions().is_empty() {
            println!("{} Orchard actions:", pczt.orchard().actions().len());
            for (
                index,
                (spend_value, output_user_address, output_value, output_account_index, decrypted),
            ) in orchard_actions.iter().enumerate()
            {
                println!("- {index}:");
                if let Some(value) = spend_value {
                    if value.inner() == 0 {
                        println!("  - Spend: Zero value (likely a dummy)");
                    } else {
                        println!("  - Spend: {} zatoshis", value.inner());
                    }
                }
                if let Some(value) = output_value {
                    if value.inner() == 0 {
                        println!("  - Output: Zero value (likely a dummy)");
                    } else {
                        println!(
                            "  - Output: {} zatoshis{}{}",
                            value.inner(),
                            match output_user_address {
                                Some(addr) => format!(" to {addr}"),
                                None => "".into(),
                            },
                            match output_account_index {
                                Some(idx) =>
                                    format!(" (change to ZIP 32 account index {})", u32::from(*idx)),
                                None => "".into(),
                            }
                        );
                    }
                } else if let Some(addr) = output_user_address {
                    println!("  - Output: {addr}");
                } else if let Some(idx) = output_account_index {
                    println!(
                        "- {index}: change to ZIP 32 account index {}",
                        u32::from(*idx)
                    );
                }

                // Display decrypted note information if available
                if let Some((note, recipient, memo_bytes, scope)) = decrypted {
                    println!("  - Decrypted note:");
                    println!("    Value: {} zatoshis", note.value().inner());
                    print_verified_recipient_address(
                        recipient,
                        orchard_fvk.as_ref().unwrap(),
                        *scope,
                    );
                    // Parse and display the memo
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
            }
        }

        match pczt.into_effects() {
            None => println!("Not enough information to build the transaction's effects"),
            Some(tx_data) => {
                println!();

                let txid_parts = tx_data.digest(TxIdDigester);

                let txid = to_txid(
                    tx_data.version(),
                    tx_data.consensus_branch_id(),
                    &txid_parts,
                );
                println!("TxID: {txid}");
                println!("Version: {:?}", tx_data.version());

                if matches!(tx_data.version(), TxVersion::V5) {
                    if tx_data.sapling_bundle().is_some() || tx_data.orchard_bundle().is_some() {
                        let shielded_sighash =
                            v5_signature_hash(&tx_data, &SignableInput::Shielded, &txid_parts);
                        println!(
                            "Sighash for shielded components: {}",
                            hex::encode(shielded_sighash)
                        );
                    }

                    if tx_data.transparent_bundle().is_some() {
                        println!("Sighashes for each transparent input:");
                        for (index, (hash_type, redeem_script, script_pubkey, value, _, _)) in
                            transparent_inputs.into_iter().enumerate()
                        {
                            let sighash = v5_signature_hash(
                                &tx_data,
                                &SignableInput::Transparent(
                                    transparent::sighash::SignableInput::from_parts(
                                        hash_type,
                                        index,
                                        &redeem_script.as_ref().unwrap_or(&script_pubkey).into(), // for p2pkh, always the same as script_pubkey
                                        &script_pubkey.into(),
                                        value,
                                    ),
                                ),
                                &txid_parts,
                            );

                            println!("- {index}: {}", hex::encode(sighash));
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

/// Verifies and displays information about a diversified Orchard address
fn print_verified_recipient_address(
    recipient: &orchard::Address,
    orchard_fvk: &orchard::keys::FullViewingKey,
    scope: Option<orchard::keys::Scope>,
) {
    let scope_type = scope.unwrap_or(orchard::keys::Scope::External);
    let ivk = orchard_fvk.to_ivk(scope_type);

    println!("    Recipient:");
    println!("      Scope: {:?}", scope_type);

    match ivk.diversifier_index(recipient) {
        Some(diversifier_index) => {
            println!("      Diversifier index: {}", u128::from(diversifier_index));

            // Verify we can reconstruct the address from the diversifier index
            let reconstructed = ivk.address_at(diversifier_index);

            if reconstructed.to_raw_address_bytes() == recipient.to_raw_address_bytes() {
                println!(
                    "      ✓ Address {} belongs to this account",
                    encode_orchard_ua(recipient)
                );
            } else {
                println!(
                    "      ✗ WARNING: unable to reconstruct address from FVK and diversifier index"
                );
                println!("      Expected: {}", encode_orchard_ua(&reconstructed));
                println!("      Got:      {}", encode_orchard_ua(recipient));
            }
        }
        None => {
            println!(
                "      ⚠ Recipient {} is external",
                encode_orchard_ua(recipient)
            );
        }
    }

    println!();
}

/// Helper to encode an Orchard address as a unified address string
fn encode_orchard_ua(address: &orchard::Address) -> String {
    let receiver = unified::Receiver::Orchard(address.to_raw_address_bytes());
    let ua = unified::Address::try_from_items(vec![receiver])
        .expect("Orchard address should always produce valid UA");
    ua.encode(&zcash_protocol::consensus::MAIN_NETWORK.network_type())
}

/// Attempts to decrypt an Orchard action's note using the provided full viewing key.
/// Tries external IVK, then internal IVK, then external OVK.
///
/// Returns a tuple of (note, recipient, memo_bytes, scope)
fn decrypt_orchard_action(
    action: &orchard::pczt::Action,
    orchard_fvk: &orchard::keys::FullViewingKey,
) -> Option<(
    orchard::Note,
    orchard::Address,
    [u8; 512],
    Option<orchard::keys::Scope>,
)> {
    let domain = OrchardDomain::for_pczt_action(action);

    // Derive the viewing keys from the FVK
    let ivk_external = orchard::keys::PreparedIncomingViewingKey::new(
        &orchard_fvk.to_ivk(orchard::keys::Scope::External),
    );
    let ivk_internal = orchard::keys::PreparedIncomingViewingKey::new(
        &orchard_fvk.to_ivk(orchard::keys::Scope::Internal),
    );
    let ovk_external = orchard_fvk.to_ovk(Scope::External);

    // Try external IVK (incoming to external address)
    if let Some((note, recipient, memo_bytes)) = try_note_decryption(&domain, &ivk_external, action)
    {
        return Some((
            note,
            recipient,
            memo_bytes,
            Some(orchard::keys::Scope::External),
        ));
    }

    // Try internal IVK (incoming to internal/change address)
    if let Some((note, recipient, memo_bytes)) = try_note_decryption(&domain, &ivk_internal, action)
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
        &ovk_external,
        action,
        action.cv_net(),
        &action.output().encrypted_note().out_ciphertext,
    ) {
        return Some((note, recipient, memo_bytes, None));
    }

    None
}
