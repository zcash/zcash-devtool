use std::{collections::BTreeMap, convert::Infallible, path::PathBuf};

use anyhow::anyhow;
use clap::Args;
use pczt::roles::{creator::Creator, io_finalizer::IoFinalizer, updater::Updater};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use tokio::{
    fs::File,
    io::{AsyncWriteExt, stdout},
};

use transparent::{address::TransparentAddress, builder::TransparentInputInfo, bundle::TxOut};
use zcash_client_backend::{
    data_api::anchor_retention::{AnchorRetentionInterval, PoolMigrationParams},
    data_api::{ChangeReceivers, TransparentChangeKind},
    fees::{
        ChangeError, ChangeStrategy as _, DustOutputPolicy, TransparentChangePolicy,
        zip317::SingleOutputChangeStrategy,
    },
    proto::service::{ChainSpec, TxFilter},
};
use zcash_keys::address::Address;
use zcash_primitives::transaction::{
    Transaction,
    builder::{Builder, PcztResult},
    fees::zip317,
};
use zcash_protocol::{
    PoolType, ShieldedPool,
    consensus::{self, Parameters as _},
};
use zip321::TransactionRequest;

use crate::{
    config::WalletConfig,
    data::Network,
    helpers::pczt::create_manual::{
        add_change_output, add_inputs, add_recipient, handle_recipient, ironwood_active,
        parse_coins,
    },
    remote::ConnectionArgs,
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

    /// The network the coins are from: \"test\", \"main\", or \"regtest\" (requires
    /// the `regtest_support` feature).
    ///
    /// If unset, uses the network of the provided wallet.
    #[arg(short, long)]
    #[arg(value_parser = Network::parse)]
    network: Option<Network>,

    #[command(flatten)]
    connection: ConnectionArgs,

    /// Path to a file to which to write the PCZT. If not provided, writes to stdout.
    #[arg(long)]
    output: Option<PathBuf>,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let params = if let Some(network) = self.network {
            network
        } else {
            let config = WalletConfig::read(wallet_dir.as_ref())?;
            config.network()
        };
        let rng = UnwrapErr(SysRng);

        let coins = parse_coins(&self.coins)?;

        let mut client = self.connection.connect(params, wallet_dir.as_ref()).await?;

        let latest_block = client.get_latest_block(ChainSpec {}).await?.into_inner();
        let target_height =
            consensus::BlockHeight::from_u32(u32::try_from(latest_block.height)?) + 1;
        let tree_state = client.get_tree_state(latest_block).await?.into_inner();
        let sapling_anchor = Some(tree_state.sapling_tree()?.root().into());
        let orchard_anchor = Some(tree_state.orchard_tree()?.root().into());
        // From NU6.3, payments to Orchard receivers are Ironwood outputs.
        let ironwood = ironwood_active(&params, target_height);
        let ironwood_anchor = if ironwood {
            Some(tree_state.ironwood_tree()?.root().into())
        } else {
            None
        };

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

        // The change strategy decides which pool the change goes to, and prices the fee
        // accordingly; the change output is then added to the change address's receiver in
        // that pool (see `add_change_output`). When only transparent flows are involved it
        // falls back to the change address's own pool, and a transparent-only change
        // address may receive transparent change.
        let fallback_change_pool = match &change_address {
            Address::Sapling(_) => ShieldedPool::Sapling,
            Address::Unified(ua) if ua.orchard().is_none() && ua.sapling().is_some() => {
                ShieldedPool::Sapling
            }
            _ if ironwood => ShieldedPool::Ironwood,
            _ => ShieldedPool::Orchard,
        };
        let mut change_strategy = SingleOutputChangeStrategy::<_, Infallible>::new(
            zip317::FeeRule::standard(),
            None,
            fallback_change_pool,
            DustOutputPolicy::default(),
        );
        if matches!(change_address, Address::Transparent(_) | Address::Tex(_)) {
            change_strategy = change_strategy
                .with_transparent_change_policy(TransparentChangePolicy::TransparentChangeAllowed);
        }

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

        let orchard_shaped_output_values = outputs
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
        let (orchard_output_values, ironwood_output_values) = if ironwood {
            (vec![], orchard_shaped_output_values)
        } else {
            (orchard_shaped_output_values, vec![])
        };

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

        // Fee rules depend on the Orchard bundle version, which is fixed by
        // the consensus branch the transaction targets.
        let orchard_bundle_version =
            zcash_primitives::transaction::components::orchard::bundle_version_for_branch(
                consensus::BranchId::for_height(&params, target_height),
                orchard::ValuePool::Orchard,
            )
            .ok_or_else(|| anyhow!("Target height's consensus branch does not support Orchard"))?;

        let balance = change_strategy
            .compute_balance::<_, Infallible>(
                &params,
                target_height.into(),
                target_height,
                &PoolMigrationParams::new(AnchorRetentionInterval::ZIP_318),
                &transparent_inputs[..],
                &transparent_outputs,
                &(
                    sapling::builder::BundleType::DEFAULT,
                    &[][..] as &[Infallible],
                    &sapling_output_values[..],
                ),
                &(
                    orchard_bundle_version,
                    &[][..] as &[Infallible],
                    &orchard_output_values[..],
                ),
                &(
                    orchard::bundle::BundleVersion::ironwood_v3(),
                    &[][..] as &[Infallible],
                    &ironwood_output_values[..],
                ),
                None,
                &change_receivers(&change_address),
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
                ironwood_anchor,
                orchard_padding: zcash_primitives::transaction::builder::BundlePadding::DEFAULT,
                ironwood_padding: zcash_primitives::transaction::builder::BundlePadding::DEFAULT,
            },
        );
        add_inputs(&mut builder, transparent_inputs)?;

        // For each output, the pool it went to, its index among that pool's outputs, and
        // the address to show signers for it.
        let mut output_counts: BTreeMap<PoolType, usize> = BTreeMap::new();
        let mut next_index = |pool: PoolType| {
            let n = output_counts.entry(pool).or_default();
            *n += 1;
            *n - 1
        };
        let mut added_outputs = vec![];
        for (value, addr, memo) in &outputs {
            let pool = add_recipient(&mut builder, addr.clone(), *value, memo.cloned(), ironwood)?;
            added_outputs.push((pool, next_index(pool), addr.encode(&params)));
        }
        for change_output in balance.proposed_change() {
            let pool = change_output.output_pool();
            add_change_output(
                &mut builder,
                &change_address,
                pool,
                change_output.value(),
                change_output.memo().cloned(),
            )?;
            added_outputs.push((pool, next_index(pool), change_address.encode(&params)));
        }

        let PcztResult {
            pczt_parts,
            sapling_meta,
            orchard_meta,
            ironwood_meta,
        } = builder.build_for_pczt(rng, &zip317::FeeRule::standard())?;
        let created = Creator::build_from_parts(pczt_parts)
            .ok_or_else(|| anyhow!("Transaction version is incompatible with PCZTs"))?;

        let io_finalized = IoFinalizer::new(created)
            .finalize_io(UnwrapErr(SysRng))
            .map_err(|e| anyhow!("{e:?}"))?;

        // Add the recipient address metadata to the generated outputs to permit
        // verification by signers.
        let mut updater = Updater::new(io_finalized);
        for (pool, index, user_address) in added_outputs {
            updater = match pool {
                PoolType::Transparent => updater
                    .update_transparent_with(|mut u| {
                        u.update_output_with(index, |mut ou| {
                            ou.set_user_address(user_address);
                            Ok(())
                        })
                    })
                    .map_err(|e| anyhow!("{e:?}"))?,
                PoolType::Shielded(ShieldedPool::Sapling) => {
                    let s_index = sapling_meta
                        .output_index(index)
                        .expect("Sapling output index was tracked");
                    updater
                        .update_sapling_with(|mut u| {
                            u.update_output_with(s_index, |mut ou| {
                                ou.set_user_address(user_address);
                                Ok(())
                            })
                        })
                        .map_err(|e| anyhow!("{e:?}"))?
                }
                PoolType::Shielded(ShieldedPool::Orchard) => {
                    let o_index = orchard_meta
                        .output_action_index(index)
                        .expect("Orchard output index was tracked");
                    updater
                        .update_orchard_with(|mut u| {
                            u.update_action_with(o_index, |mut au| {
                                au.set_output_user_address(user_address);
                                Ok(())
                            })
                        })
                        .map_err(|e| anyhow!("{e:?}"))?
                }
                PoolType::Shielded(ShieldedPool::Ironwood) => {
                    let i_index = ironwood_meta
                        .output_action_index(index)
                        .expect("Ironwood output index was tracked");
                    updater
                        .update_ironwood_with(|mut u| {
                            u.update_action_with(i_index, |mut au| {
                                au.set_output_user_address(user_address);
                                Ok(())
                            })
                        })
                        .map_err(|e| anyhow!("{e:?}"))?
                }
            };
        }

        let pczt = updater.finish();
        let pczt_bytes = pczt
            .serialize()
            .map_err(|e| anyhow!("Failed to serialize PCZT: {:?}", e))?;
        if let Some(output_path) = &self.output {
            let mut file = File::create(output_path).await?;
            file.write_all(&pczt_bytes).await?;
            file.flush().await?;
        } else {
            let mut stdout = stdout();
            stdout.write_all(&pczt_bytes).await?;
            stdout.flush().await?;
        }

        Ok(())
    }
}

/// The outputs the named change address can take.
///
/// `ChangeReceivers::from_uivk` is the wallet's answer, read off an account's viewing
/// key. This command has no wallet and no key: change goes to an address the user named,
/// so what it can receive is what that address can receive.
fn change_receivers(change_address: &Address) -> ChangeReceivers {
    let (sapling, orchard, transparent) = match change_address {
        Address::Sapling(_) => (true, false, None),
        Address::Transparent(TransparentAddress::PublicKeyHash(_)) => {
            (false, false, Some(TransparentChangeKind::P2pkh))
        }
        Address::Transparent(TransparentAddress::ScriptHash(_)) => {
            (false, false, Some(TransparentChangeKind::P2sh))
        }
        // A TEX address is a P2PKH address that may only be paid from a transparent
        // source, which does not change what it can receive.
        Address::Tex(_) => (false, false, Some(TransparentChangeKind::P2pkh)),
        Address::Unified(ua) => (
            ua.sapling().is_some(),
            ua.orchard().is_some(),
            ua.transparent().map(|addr| match addr {
                TransparentAddress::PublicKeyHash(_) => TransparentChangeKind::P2pkh,
                TransparentAddress::ScriptHash(_) => TransparentChangeKind::P2sh,
            }),
        ),
    };
    // `zcash_client_backend`'s `pczt` feature enables its `transparent-inputs` feature, so
    // the transparent receiver is always an argument here.
    ChangeReceivers::new(sapling, orchard, transparent)
}
