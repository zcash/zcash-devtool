use anyhow::anyhow;
use serde::Deserialize;
use transparent::{
    address::{Script, TransparentAddress},
    bundle::{OutPoint, TxOut},
};
use zcash_keys::address::{Address, Receiver};
use zcash_primitives::transaction::{builder::Builder, fees::zip317};
use zcash_protocol::{consensus, memo::MemoBytes, value::Zatoshis};
use zcash_script::script;

use crate::error;

pub(crate) fn parse_coins(s: &str) -> anyhow::Result<Vec<Coin>> {
    Ok(serde_json::from_str(s)?)
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Coin {
    txid: String,
    pub(crate) out_index: u32,
    pub(crate) value: Option<u64>,
    script_pubkey: Option<String>,
    pubkey: Option<secp256k1::PublicKey>,
    redeem_script: Option<String>,
}

impl Coin {
    /// Returns a pointer to this coin in the Zcash chain.
    pub(crate) fn outpoint(&self) -> anyhow::Result<OutPoint> {
        let hash: [u8; 32] = {
            let mut bytes = hex::decode(&self.txid)?;
            bytes.reverse();
            bytes
                .as_slice()
                .try_into()
                .map_err(|e| anyhow!("Invalid coin outpoint hash: {e}"))?
        };

        Ok(OutPoint::new(hash, self.out_index))
    }

    /// Returns the coin itself, if provided.
    pub(crate) fn coin(&self) -> anyhow::Result<Option<TxOut>> {
        self.value
            .zip(self.script_pubkey.as_ref())
            .map(|(value, script_pubkey)| {
                let value = Zatoshis::from_u64(value).map_err(|_| error::Error::InvalidAmount)?;
                let script_pubkey = Script(script::Code(hex::decode(script_pubkey)?));
                Ok(TxOut::new(value, script_pubkey))
            })
            .transpose()
    }

    /// Returns the information needed to spend this coin.
    pub(crate) fn spend_info(&self) -> anyhow::Result<SpendInfo> {
        match (&self.pubkey, &self.redeem_script) {
            (None, None) => Err(anyhow!("Missing either `pubkey` or `redeem_script")),
            (Some(_), Some(_)) => Err(anyhow!("Cannot provide both `pubkey` and `redeem_script`")),
            (Some(pubkey), None) => Ok(SpendInfo::P2pkh { pubkey: *pubkey }),
            (None, Some(script_hex)) => {
                let script_bytes = hex::decode(script_hex)?;
                let redeem_script = script::FromChain::parse(&script::Code(script_bytes))
                    .map_err(|e| anyhow!("{e:?}"))?;
                Ok(SpendInfo::P2sh { redeem_script })
            }
        }
    }
}

#[derive(Clone)]
pub(crate) enum SpendInfo {
    P2pkh { pubkey: secp256k1::PublicKey },
    P2sh { redeem_script: script::FromChain },
}

pub(crate) fn handle_recipient<C, T>(
    recipient: Address,
    ctx: C,
    on_transparent: impl FnOnce(TransparentAddress, C) -> anyhow::Result<T>,
    on_sapling: impl FnOnce(sapling::PaymentAddress, C) -> anyhow::Result<T>,
    on_orchard: impl FnOnce(orchard::Address, C) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    match recipient {
        Address::Sapling(payment_address) => on_sapling(payment_address, ctx),
        Address::Transparent(transparent_address) => on_transparent(transparent_address, ctx),
        Address::Unified(unified_address) => match unified_address
            .as_understood_receivers()
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Recipient is UA with no understood receivers"))?
        {
            Receiver::Orchard(address) => on_orchard(address, ctx),
            Receiver::Sapling(payment_address) => on_sapling(payment_address, ctx),
            Receiver::Transparent(transparent_address) => on_transparent(transparent_address, ctx),
        },
        // Only supported inputs are transparent, so it's fine to send directly to
        // a TEX address.
        Address::Tex(p2pkh_hash) => {
            on_transparent(TransparentAddress::PublicKeyHash(p2pkh_hash), ctx)
        }
    }
}

pub(crate) fn add_inputs<P: consensus::Parameters, U: sapling::builder::ProverProgress>(
    builder: &mut Builder<'_, P, U>,
    transparent_inputs: Vec<(OutPoint, TxOut, SpendInfo)>,
) -> anyhow::Result<()> {
    for (utxo, coin, spend_info) in transparent_inputs {
        match spend_info {
            SpendInfo::P2pkh { pubkey } => builder
                .add_transparent_input(pubkey, utxo, coin)
                .map_err(|e| anyhow!("{e}"))?,
            SpendInfo::P2sh { redeem_script } => builder
                .add_transparent_p2sh_input(redeem_script, utxo, coin)
                .map_err(|e| anyhow!("{e}"))?,
        }
    }
    Ok(())
}

pub(crate) fn add_recipient<P: consensus::Parameters, U: sapling::builder::ProverProgress>(
    builder: &mut Builder<'_, P, U>,
    recipient: Address,
    value: Zatoshis,
    memo: Option<MemoBytes>,
) -> anyhow::Result<()> {
    handle_recipient(
        recipient,
        (builder, memo),
        |to, (builder, _)| {
            builder
                .add_transparent_output(&to, value)
                .map_err(|e| anyhow!("{e}"))
        },
        |to, (builder, memo)| {
            Ok(builder.add_sapling_output::<zip317::FeeError>(
                None,
                to,
                value,
                memo.unwrap_or(MemoBytes::empty()),
            )?)
        },
        |recipient, (builder, memo)| {
            Ok(builder.add_orchard_output::<zip317::FeeError>(
                None,
                recipient,
                value,
                memo.unwrap_or(MemoBytes::empty()),
            )?)
        },
    )?;
    Ok(())
}
