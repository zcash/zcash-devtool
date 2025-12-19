use std::{collections::BTreeMap, convert::Infallible};

use anyhow::anyhow;
use clap::Args;
use pczt::roles::{creator::Creator, io_finalizer::IoFinalizer, updater::Updater};
use rand::rngs::OsRng;
use tokio::io::{stdout, AsyncWriteExt};

use transparent::{builder::TransparentInputInfo, bundle::TxOut};
use zcash_client_backend::{
    fees::{
        zip317::SingleOutputChangeStrategy, ChangeError, ChangeStrategy as _, DustOutputPolicy,
    },
    proto::service::{ChainSpec, TxFilter},
};
use zcash_keys::address::Address;
use zcash_primitives::transaction::{
    builder::{Builder, PcztResult},
    fees::zip317,
    Transaction,
};
use zcash_protocol::{
    consensus::{self, Parameters as _},
    PoolType, ShieldedProtocol,
};
use zip321::TransactionRequest;

use crate::{
    config::WalletConfig,
    data::Network,
    helpers::pczt::create_manual::{add_inputs, add_recipient, handle_recipient, parse_coins},
    remote::{tor_client, Servers},
};

// Options accepted for the `pczt pay-manual` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// The transparent coins to spend in this transaction.
    ///
    /// This is a JSON array of objects with the following fields:
    /// - `txid`: ID of the transaction in which the coin was created.
    /// - `out_index`: Index of the output within the transaction's `vout`.
    /// - `value` and `script_pubkey`: Fields of the output, as an integer in zatoshis and
    ///   a hex string respectively. If omitted, `txid` will be looked up from the chain.
    /// - `pubkey` or `redeem_script`: The public key (for a P2PKH coin) or the redeem
    ///   script (for a P2SH coin) as a hex string. Only one of these can be set.
    #[arg(long)]
    coins: String,

    /// The ZIP 321 transaction request describing the desired outputs of the transaction.
    #[arg(long)]
    payment_request: String,

    /// The Unified, Sapling or transparent address to which change should be sent. In the case
    /// that coinbase inputs are being spent, this MUST be a shielded address.
    #[arg(long)]
    change_address: String,

    /// The network the coins are from: \"test\" or \"main\".
    ///
    /// If unset, uses the network of the provided wallet.
    #[arg(short, long)]
    #[arg(value_parser = Network::parse)]
    network: Option<Network>,

    /// The server to use for network information (default is \"ecc\")
    #[arg(short, long)]
    #[arg(default_value = "ecc", value_parser = Servers::parse)]
    server: Servers,

    /// Disable connections via TOR
    #[arg(long)]
    disable_tor: bool,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let params = if let Some(network) = self.network {
            consensus::Network::from(network)
        } else {
            let config = WalletConfig::read(wallet_dir.as_ref())?;
            config.network()
        };
        let rng = OsRng;

        let coins = parse_coins(&self.coins)?;

        let server = self.server.pick(params)?;
        let mut client = if self.disable_tor {
            server.connect_direct().await?
        } else {
            server.connect(|| tor_client(wallet_dir.as_ref())).await?
        };

        let latest_block = client.get_latest_block(ChainSpec {}).await?.into_inner();
        let target_height =
            consensus::BlockHeight::from_u32(u32::try_from(latest_block.height)?) + 1;
        let tree_state = client.get_tree_state(latest_block).await?.into_inner();
        let sapling_anchor = Some(tree_state.sapling_tree()?.root().into());
        let orchard_anchor = Some(tree_state.orchard_tree()?.root().into());

        let payment_request = TransactionRequest::from_uri(&self.payment_request)?;
        let change_address = Address::decode(&params, &self.change_address)
            .ok_or_else(|| anyhow!("Unable to decode change address."))?;

        // TODO: we should return an error if any of the UTXOs being spent are outputs of a
        // coinbase transaction and the change address is transparent-only; however, we do not have
        // the information necessary to make such a determination about the inputs here; we don't
        // get that information from the RawTransaction data returned from the light client server.
        //let requires_transparent_change = !change_address
        //    .as_understood_unified_receivers()
        //    .iter()
        //    .any(|r| matches!(r, Receiver::Orchard(_) | Receiver::Sapling(_)));

        let mut transparent_inputs = vec![];
        for input in coins {
            let utxo = input.outpoint()?;
            let spend_info = input.spend_info()?;

            let coin = if let Some(coin) = input.coin()? {
                coin
            } else {
                // Look up the coin on-chain.
                let request = TxFilter {
                    block: None,
                    index: 0,
                    hash: utxo.hash().into(),
                };
                let raw_tx = client.get_transaction(request).await?.into_inner();
                let tx = Transaction::read(
                    raw_tx.data.as_slice(),
                    consensus::BranchId::for_height(
                        &params,
                        // TODO: Handle mempool tx height.
                        consensus::BlockHeight::from_u32(u32::try_from(raw_tx.height)?),
                    ),
                )?;

                if let Some(bundle) = tx.transparent_bundle() {
                    bundle
                        .vout
                        .get(usize::try_from(input.out_index)?)
                        .cloned()
                        .ok_or_else(|| anyhow!("Coin is invalid"))
                } else {
                    Err(anyhow!("Coin is invalid"))
                }?
            };

            let input = TransparentInputInfo::from_parts(utxo, coin, spend_info)
                .map_err(|e| anyhow!("Invalid transparent input data: {}", e))?;
            transparent_inputs.push(input);
        }

        let change_strategy = SingleOutputChangeStrategy::<_, Infallible>::new(
            zip317::FeeRule::standard(),
            None,
            ShieldedProtocol::Orchard,
            DustOutputPolicy::default(),
        );

        let outputs = payment_request
            .payments()
            .iter()
            .map(|(i, p)| {
                p.recipient_address()
                    .clone()
                    .convert_if_network::<Address>(params.network_type())
                    .map_err(|e| anyhow!("Invalid address found for payment index {}: {}", i, e))
                    .and_then(|addr| {
                        Ok((
                            p.amount()
                                .ok_or_else(|| anyhow!("Payment amount missing at index {}", i))?,
                            addr,
                            p.memo(),
                        ))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let transparent_outputs = outputs
            .iter()
            .filter_map(|(value, addr, _)| {
                handle_recipient(
                    addr.clone(),
                    (),
                    |taddr, _| Ok(Some(TxOut::new(*value, taddr.script().into()))),
                    |_, _| Ok(None),
                    |_, _| Ok(None),
                )
                .transpose()
            })
            .collect::<Result<Vec<_>, _>>()?;

        let orchard_output_values = outputs
            .iter()
            .filter_map(|(value, addr, _)| {
                handle_recipient(
                    addr.clone(),
                    (),
                    |_, _| Ok(None),
                    |_, _| Ok(None),
                    |_, _| Ok(Some(*value)),
                )
                .transpose()
            })
            .collect::<Result<Vec<_>, _>>()?;

        let sapling_output_values = outputs
            .iter()
            .filter_map(|(value, addr, _)| {
                handle_recipient(
                    addr.clone(),
                    (),
                    |_, _| Ok(None),
                    |_, _| Ok(Some(*value)),
                    |_, _| Ok(None),
                )
                .transpose()
            })
            .collect::<Result<Vec<_>, _>>()?;

        let balance = change_strategy
            .compute_balance::<_, Infallible>(
                &params,
                target_height.into(),
                &transparent_inputs[..],
                &transparent_outputs,
                &(
                    sapling::builder::BundleType::DEFAULT,
                    &[][..] as &[Infallible],
                    &sapling_output_values[..],
                ),
                &(
                    orchard::builder::BundleType::DEFAULT,
                    &[][..] as &[Infallible],
                    &orchard_output_values[..],
                ),
                None,
                &(),
            )
            .map_err(|e: ChangeError<_, Infallible>| {
                anyhow!("Error in computing balance: {}", e)
            })?;

        let mut builder = Builder::new(
            params,
            target_height,
            zcash_primitives::transaction::builder::BuildConfig::Standard {
                sapling_anchor,
                orchard_anchor,
            },
        );
        add_inputs(&mut builder, transparent_inputs)?;

        let mut output_counts: BTreeMap<PoolType, usize> = BTreeMap::new();
        let mut output_mapping = BTreeMap::new();
        for (i, (value, addr, memo)) in outputs.iter().enumerate() {
            let recipient_pool = add_recipient(&mut builder, addr.clone(), *value, memo.cloned())?;
            let pool_output_index = *output_counts
                .entry(recipient_pool)
                .and_modify(|n| {
                    *n += 1;
                })
                .or_default();
            output_mapping.insert(i, pool_output_index);
        }

        let mut change_mapping = BTreeMap::new();
        for (j, change_output) in balance.proposed_change().iter().enumerate() {
            let recipient_pool = add_recipient(
                &mut builder,
                change_address.clone(),
                change_output.value(),
                change_output.memo().cloned(),
            )?;
            let pool_output_index = *output_counts
                .entry(recipient_pool)
                .and_modify(|n| {
                    *n += 1;
                })
                .or_default();
            change_mapping.insert(j, pool_output_index);
        }

        let PcztResult {
            pczt_parts,
            sapling_meta,
            orchard_meta,
        } = builder.build_for_pczt(rng, &zip317::FeeRule::standard())?;
        let created = Creator::build_from_parts(pczt_parts)
            .ok_or_else(|| anyhow!("Transaction version is incompatible with PCZTs"))?;

        let io_finalized = IoFinalizer::new(created)
            .finalize_io()
            .map_err(|e| anyhow!("{e:?}"))?;

        let set_verification_address =
            |updater: Updater,
             recipient_addr: &Address,
             i: usize,
             mappings: &BTreeMap<usize, usize>| {
                handle_recipient(
                    recipient_addr.clone(),
                    (updater, recipient_addr.encode(&params)),
                    |_, (updater, user_address)| {
                        let t_index = mappings.get(&i).expect(&format!(
                            "Transparent output index was tracked for output {i}"
                        ));
                        updater
                            .update_transparent_with(|mut u| {
                                u.update_output_with(*t_index, |mut ou| {
                                    ou.set_user_address(user_address);
                                    Ok(())
                                })
                            })
                            .map_err(|e| anyhow!("{e:?}"))
                    },
                    |_, (updater, user_address)| {
                        let s_index = mappings
                            .get(&i)
                            .and_then(|i0| sapling_meta.output_index(*i0))
                            .expect(&format!("Sapling output index was tracked for output {i}"));
                        updater
                            .update_sapling_with(|mut u| {
                                u.update_output_with(s_index, |mut ou| {
                                    ou.set_user_address(user_address);
                                    Ok(())
                                })
                            })
                            .map_err(|e| anyhow!("{e:?}"))
                    },
                    |_, (updater, user_address)| {
                        let o_index = mappings
                            .get(&i)
                            .and_then(|i0| orchard_meta.output_action_index(*i0))
                            .expect(&format!("Orchard output index was tracked for output {i}"));
                        updater
                            .update_orchard_with(|mut u| {
                                u.update_action_with(o_index, |mut au| {
                                    au.set_output_user_address(user_address);
                                    Ok(())
                                })
                            })
                            .map_err(|e| anyhow!("{e:?}"))
                    },
                )
            };

        // Add the recipient address metadata to the generated output to permit
        // verification by signers.
        let mut updater = Updater::new(io_finalized);
        for (i, (_, recipient_addr, _)) in outputs.iter().enumerate() {
            updater = set_verification_address(updater, recipient_addr, i, &output_mapping)?;
        }
        for j in 0..balance.proposed_change().len() {
            updater = set_verification_address(updater, &change_address, j, &change_mapping)?;
        }

        let pczt = updater.finish();
        stdout().write_all(&pczt.serialize()).await?;

        Ok(())
    }
}
