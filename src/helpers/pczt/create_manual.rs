use anyhow::anyhow;
use serde::Deserialize;
use transparent::{
    address::{Script, TransparentAddress},
    builder::{SpendInfo, TransparentInputInfo},
    bundle::{OutPoint, TxOut},
};
use zcash_keys::address::{Address, Receiver};
use zcash_primitives::transaction::{builder::Builder, fees::zip317};
use zcash_protocol::{PoolType, ShieldedPool, consensus, memo::MemoBytes, value::Zatoshis};
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

pub(crate) fn handle_recipient<C, T>(
    recipient: Address,
    ctx: C,
    on_transparent: impl FnOnce(TransparentAddress, C) -> anyhow::Result<T>,
    on_sapling: impl FnOnce(sapling::PaymentAddress, C) -> anyhow::Result<T>,
    on_orchard: impl FnOnce(orchard::Address, C) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    match recipient {
        Address::Sapling(payment_address) => on_sapling(*payment_address, ctx),
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
    builder: &mut Builder<P, U>,
    transparent_inputs: Vec<TransparentInputInfo>,
) -> anyhow::Result<()> {
    for input in transparent_inputs.into_iter() {
        builder.add_transparent_input(input);
    }
    Ok(())
}

/// Whether a transaction targeting `target_height` must send Orchard-receiver outputs to
/// the Ironwood pool.
///
/// From NU6.3, the Orchard pool only accepts outputs that the transaction creator can
/// spend (ZIP 229), so the builder rejects a payment to someone else's Orchard receiver
/// ("Cross-address transfers are disabled"); such payments go to the Ironwood pool.
pub(crate) fn ironwood_active<P: consensus::Parameters>(
    params: &P,
    target_height: consensus::BlockHeight,
) -> bool {
    zcash_primitives::transaction::components::orchard::bundle_version_for_branch(
        consensus::BranchId::for_height(params, target_height),
        orchard::ValuePool::Ironwood,
    )
    .is_some()
}

pub(crate) fn add_recipient<P: consensus::Parameters, U: sapling::builder::ProverProgress>(
    builder: &mut Builder<P, U>,
    recipient: Address,
    value: Zatoshis,
    memo: Option<MemoBytes>,
    ironwood_active: bool,
) -> anyhow::Result<PoolType> {
    handle_recipient(
        recipient,
        (builder, memo),
        |to, (builder, _)| {
            builder
                .add_transparent_output(&to, value)
                .map_err(|e| anyhow!("{e}"))?;
            Ok(PoolType::Transparent)
        },
        |to, (builder, memo)| {
            builder.add_sapling_output::<zip317::FeeError>(
                None,
                to,
                value,
                memo.unwrap_or(MemoBytes::empty()),
            )?;
            Ok(PoolType::SAPLING)
        },
        |recipient, (builder, memo)| {
            add_orchard_shaped_output(builder, recipient, value, memo, ironwood_active)
        },
    )
}

fn add_orchard_shaped_output<P: consensus::Parameters, U: sapling::builder::ProverProgress>(
    builder: &mut Builder<P, U>,
    recipient: orchard::Address,
    value: Zatoshis,
    memo: Option<MemoBytes>,
    ironwood_active: bool,
) -> anyhow::Result<PoolType> {
    let memo = memo.unwrap_or(MemoBytes::empty());
    if ironwood_active {
        builder.add_ironwood_output::<zip317::FeeError>(None, recipient, value, memo)?;
        Ok(PoolType::IRONWOOD)
    } else {
        builder.add_orchard_output::<zip317::FeeError>(None, recipient, value, memo)?;
        Ok(PoolType::ORCHARD)
    }
}

/// Adds a change output of `value` to `change_address`, in the pool the change strategy
/// chose for it.
///
/// The fee was computed with the change in `pool`, so the output must go there: using the
/// address's first receiver instead can put it in a pool with different padding, and the
/// builder then finds the transaction's balance off by the difference.
pub(crate) fn add_change_output<P: consensus::Parameters, U: sapling::builder::ProverProgress>(
    builder: &mut Builder<P, U>,
    change_address: &Address,
    pool: PoolType,
    value: Zatoshis,
    memo: Option<MemoBytes>,
) -> anyhow::Result<()> {
    let ua = match change_address {
        Address::Unified(ua) => Some(ua),
        _ => None,
    };
    let transparent_only = matches!(change_address, Address::Transparent(_) | Address::Tex(_));
    let missing = || {
        if transparent_only {
            anyhow!(
                "This transaction's change must go to the {pool} pool, but the change address \
                 is transparent; transparent change is only possible when every output is \
                 transparent. Use a Unified or Sapling change address."
            )
        } else {
            anyhow!("The change address has no {pool} receiver for this transaction's change")
        }
    };
    match pool {
        PoolType::Transparent => {
            let to = match change_address {
                Address::Transparent(t) => *t,
                Address::Tex(hash) => TransparentAddress::PublicKeyHash(*hash),
                _ => *ua.and_then(|ua| ua.transparent()).ok_or_else(missing)?,
            };
            builder
                .add_transparent_output(&to, value)
                .map_err(|e| anyhow!("{e}"))?;
        }
        PoolType::Shielded(ShieldedPool::Sapling) => {
            let to = match change_address {
                Address::Sapling(to) => *to,
                _ => *ua.and_then(|ua| ua.sapling()).ok_or_else(missing)?,
            };
            builder.add_sapling_output::<zip317::FeeError>(
                None,
                to,
                value,
                memo.unwrap_or(MemoBytes::empty()),
            )?;
        }
        PoolType::Shielded(ShieldedPool::Orchard) | PoolType::Shielded(ShieldedPool::Ironwood) => {
            let to = *ua.and_then(|ua| ua.orchard()).ok_or_else(missing)?;
            add_orchard_shaped_output(builder, to, value, memo, pool == PoolType::IRONWOOD)?;
        }
    }
    Ok(())
}
