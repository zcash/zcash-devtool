use anyhow::anyhow;
use gumdrop::Options;
use pczt::{roles::verifier::Verifier, Pczt};
use tokio::io::{stdin, AsyncReadExt};
use zcash_primitives::transaction::{
    sighash::{SighashType, SignableInput},
    sighash_v5::v5_signature_hash,
    txid::{to_txid, TxIdDigester},
    TxVersion,
};

// Options accepted for the `pczt inspect` command
#[derive(Debug, Options)]
pub(crate) struct Command {}

impl Command {
    pub(crate) async fn run(self) -> Result<(), anyhow::Error> {
        let mut buf = vec![];
        stdin().read_to_end(&mut buf).await?;

        let pczt = Pczt::parse(&buf).map_err(|e| anyhow!("Failed to read PCZT: {:?}", e))?;

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
                        )
                    })
                    .collect();
                transparent_outputs = bundle
                    .outputs()
                    .iter()
                    .map(|output| *output.value())
                    .collect();
                Ok::<_, pczt::roles::verifier::TransparentError<()>>(())
            })
            .expect("no error")
            .with_sapling(|bundle| {
                sapling_spends = bundle.spends().iter().map(|spend| *spend.value()).collect();
                sapling_outputs = bundle
                    .outputs()
                    .iter()
                    .map(|output| *output.value())
                    .collect();
                Ok::<_, pczt::roles::verifier::SaplingError<()>>(())
            })
            .expect("no error")
            .with_orchard(|bundle| {
                orchard_actions = bundle
                    .actions()
                    .iter()
                    .map(|action| (*action.spend().value(), *action.output().value()))
                    .collect();
                Ok::<_, pczt::roles::verifier::OrchardError<()>>(())
            })
            .expect("no error")
            .finish();

        if !pczt.transparent().inputs().is_empty() {
            println!("{} transparent inputs", pczt.transparent().inputs().len());
            for (index, (hash_type, _, _, value)) in transparent_inputs.iter().enumerate() {
                println!(
                    "- {index}: {} zatoshis, {}",
                    value.into_u64(),
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
            }
        }

        if !pczt.transparent().outputs().is_empty() {
            println!("{} transparent outputs", pczt.transparent().outputs().len());
            for (index, value) in transparent_outputs.iter().enumerate() {
                println!("- {index}: {} zatoshis", value.into_u64());
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
            for (index, value) in sapling_outputs.iter().enumerate() {
                if let Some(value) = value {
                    if value.inner() == 0 {
                        println!("- {index}: Zero value (likely a dummy)");
                    } else {
                        println!("- {index}: {} zatoshis", value.inner());
                    }
                }
            }
        }

        if !pczt.orchard().actions().is_empty() {
            println!("{} Orchard actions:", pczt.orchard().actions().len());
            for (index, (spend_value, output_value)) in orchard_actions.iter().enumerate() {
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
                        println!("  - Output: {} zatoshis", value.inner());
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

                if matches!(tx_data.version(), TxVersion::Zip225) {
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
                        for (index, (hash_type, redeem_script, script_pubkey, value)) in
                            transparent_inputs.into_iter().enumerate()
                        {
                            let sighash = v5_signature_hash(
                                &tx_data,
                                &SignableInput::Transparent {
                                    hash_type: hash_type.encode(),
                                    index,
                                    script_code: redeem_script.as_ref().unwrap_or(&script_pubkey), // for p2pkh, always the same as script_pubkey
                                    script_pubkey: &script_pubkey,
                                    value,
                                },
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
