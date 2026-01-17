#![allow(deprecated)]
use std::str::FromStr;

use anyhow::anyhow;
use clap::Args;
use pczt::roles::{creator::Creator, io_finalizer::IoFinalizer, updater::Updater};
use rand::rngs::OsRng;
use tokio::io::{stdout, AsyncWriteExt};
use transparent::builder::TransparentInputInfo;

use zcash_address::ZcashAddress;
use zcash_client_backend::proto::service::{ChainSpec, TxFilter};
use zcash_keys::address::Address;
use zcash_primitives::transaction::{
    builder::{Builder, PcztResult},
    fees::zip317,
    Transaction,
};
use zcash_protocol::{
    consensus::{self, Parameters},
    memo::{Memo, MemoBytes},
    value::Zatoshis,
};

use crate::{
    config::WalletConfig,
    data::Network,
    error,
    helpers::pczt::create_manual::{add_inputs, add_recipient, handle_recipient, parse_coins},
    remote::ConnectionArgs,
};

// Options accepted for the `pczt create-manual` command
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

    /// The recipient's Unified, Sapling or transparent address
    #[arg(long)]
    address: String,

    /// The amount in zatoshis
    #[arg(long)]
    value: Option<u64>,

    /// A memo to send to the recipient
    #[arg(long)]
    memo: Option<String>,

    /// The network the coins are from: \"test\" or \"main\".
    ///
    /// If unset, uses the network of the provided wallet.
    #[arg(short, long)]
    #[arg(value_parser = Network::parse)]
    network: Option<Network>,

    #[command(flatten)]
    connection: ConnectionArgs,
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
        let recipient = ZcashAddress::from_str(&self.address)
            .map_err(|_| error::Error::InvalidRecipient)?
            .convert_if_network::<Address>(params.network_type())
            .map_err(|e| anyhow!("{e}"))?;
        let value = self
            .value
            .map(|value| Zatoshis::from_u64(value).map_err(|_| error::Error::InvalidAmount))
            .transpose()?;
        let memo = self
            .memo
            .map(|memo| Memo::from_str(&memo))
            .transpose()?
            .map(MemoBytes::from);

        let mut client = self.connection.connect(params, wallet_dir.as_ref()).await?;

        let latest_block = client.get_latest_block(ChainSpec {}).await?.into_inner();
        let target_height =
            consensus::BlockHeight::from_u32(u32::try_from(latest_block.height)?) + 1;
        let tree_state = client.get_tree_state(latest_block).await?.into_inner();
        let sapling_anchor = Some(tree_state.sapling_tree()?.root().into());
        let orchard_anchor = Some(tree_state.orchard_tree()?.root().into());

        let mut transparent_inputs = vec![];
        let mut value_in = Zatoshis::ZERO;

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

            value_in = (value_in + coin.value).ok_or_else(|| anyhow!("Balance overflow"))?;
            let input = TransparentInputInfo::from_parts(utxo, coin, spend_info)
                .map_err(|e| anyhow!("Invalid transparent input data: {}", e))?;
            transparent_inputs.push(input);
        }

        let prepare_builder = |transparent_inputs: Vec<TransparentInputInfo>,
                               recipient: Address,
                               value: Zatoshis,
                               memo: Option<MemoBytes>|
         -> anyhow::Result<_> {
            let mut builder = Builder::new(
                params,
                target_height,
                zcash_primitives::transaction::builder::BuildConfig::Standard {
                    sapling_anchor,
                    orchard_anchor,
                },
            );
            add_inputs(&mut builder, transparent_inputs)?;
            add_recipient(&mut builder, recipient, value, memo)?;
            Ok(builder)
        };

        // Use a temporary builder instance to determine what the fee will be.
        let fee = {
            let builder = prepare_builder(
                transparent_inputs.clone(),
                recipient.clone(),
                Zatoshis::ZERO,
                memo.clone(),
            )?;
            builder
                .get_fee(&zip317::FeeRule::standard())
                .map_err(|e| anyhow!("{e}"))?
        };

        // TODO: Handle change outputs. For now, you are required to spend it all.
        let value_out = (value_in - fee).ok_or_else(|| anyhow!("Balance underflow"))?;
        if let Some(v) = value {
            if v != value_out {
                return Err(anyhow!(
                    "Change is not currently supported. Don't set --value, or set it to '{}'",
                    value_out.into_u64(),
                ));
            }
        }

        // Now construct the real builder.
        let builder = prepare_builder(transparent_inputs, recipient.clone(), value_out, memo)?;

        let PcztResult { pczt_parts, .. } =
            builder.build_for_pczt(rng, &zip317::FeeRule::standard())?;
        let created = Creator::build_from_parts(pczt_parts)
            .ok_or_else(|| anyhow!("Transaction version is incompatible with PCZTs"))?;

        let io_finalized = IoFinalizer::new(created)
            .finalize_io()
            .map_err(|e| anyhow!("{e:?}"))?;

        // Add the recipient address metadata to the generated output to permit
        // verification by signers.
        let pczt = handle_recipient(
            recipient,
            (Updater::new(io_finalized), self.address),
            |_, (updater, user_address)| {
                updater
                    .update_transparent_with(|mut u| {
                        assert_eq!(u.bundle().outputs().len(), 1);
                        u.update_output_with(0, |mut ou| {
                            ou.set_user_address(user_address);
                            Ok(())
                        })
                    })
                    .map_err(|e| anyhow!("{e:?}"))
            },
            |_, (updater, user_address)| {
                updater
                    .update_sapling_with(|mut u| {
                        assert_eq!(u.bundle().outputs().len(), 1);
                        u.update_output_with(0, |mut ou| {
                            ou.set_user_address(user_address);
                            Ok(())
                        })
                    })
                    .map_err(|e| anyhow!("{e:?}"))
            },
            |_, (updater, user_address)| {
                updater
                    .update_orchard_with(|mut u| {
                        // Because of padding, we need to find the action that contains
                        // the output. We could do this with the Orchard bundle metadata,
                        // but as there is only one real output we can just look for it.
                        assert_eq!(u.bundle().actions().len(), 2);
                        let index =
                            u.bundle()
                                .actions()
                                .iter()
                                .enumerate()
                                .find_map(|(i, action)| {
                                    action.output().value().and_then(|v| {
                                        (v.inner() == value_out.into_u64()).then_some(i)
                                    })
                                })
                                .expect("present");
                        u.update_action_with(index, |mut au| {
                            au.set_output_user_address(user_address);
                            Ok(())
                        })
                    })
                    .map_err(|e| anyhow!("{e:?}"))
            },
        )?
        .finish();

        stdout().write_all(&pczt.serialize()).await?;

        Ok(())
    }
}
