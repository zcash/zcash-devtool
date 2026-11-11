//! V7 signing with explicit prevout context; all amounts are integer zatoshis.

use anyhow::{Context, Result, ensure};
use primitives::transaction::{
    Authorization, Authorized, Transaction, TransactionData,
    sighash::{SignableInput, signature_hash},
    txid::TxIdDigester,
};
use protocol::{
    consensus::{BlockHeight, BranchId},
    value::Zatoshis,
};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use transparent::{
    address::Script,
    bundle::{self, OutPoint, TxIn, TxOut},
    sighash::{SighashType, TransparentAuthorizingContext},
};
use zcash_tachyon::{
    Note, TachyonBundle, action, bundle::Plan, entropy::ActionEntropy, fee,
    keys::private::SpendingKey, note::CommitmentTrapdoor, nullifier, value,
};

use crate::{chain::anchor, control::Control, note::Receipt, proofs, store::ChainData};

pub const FEE: u64 = 50_000;

pub fn funding_key(seed: [u8; 32]) -> Result<SecretKey> {
    let digest = Sha256::new()
        .chain_update(b"devtool-tachyon-funding-v1")
        .chain_update(seed)
        .finalize();
    Ok(SecretKey::from_slice(&digest)?)
}

pub fn funding_address(seed: [u8; 32]) -> Result<String> {
    let public = PublicKey::from_secret_key(&Secp256k1::new(), &funding_key(seed)?);
    let hash = ripemd::Ripemd160::digest(Sha256::digest(public.serialize()));
    let mut payload = vec![0x1d, 0x25]; // Zcash testnet P2PKH prefix.
    payload.extend_from_slice(&hash);
    Ok(bs58::encode(payload).with_check().into_string())
}

pub fn transparent_script(address: &str) -> Result<Script> {
    let data = bs58::decode(address).with_check(None).into_vec()?;
    ensure!(data.len() == 22, "invalid transparent address length");
    let code = match &data[..2] {
        [0x1d, 0x25] => [vec![0x76, 0xa9, 20], data[2..].to_vec(), vec![0x88, 0xac]].concat(),
        [0x1c, 0xba] => [vec![0xa9, 20], data[2..].to_vec(), vec![0x87]].concat(),
        _ => anyhow::bail!("only testnet transparent addresses are accepted"),
    };
    Ok(Script(zcash_script::script::Code(code)))
}

#[derive(Clone, Debug)]
struct Prevouts(Vec<TxOut>);
impl bundle::Authorization for Prevouts {
    type ScriptSig = Script;
}
impl TransparentAuthorizingContext for Prevouts {
    fn input_amounts(&self) -> Vec<Zatoshis> {
        self.0.iter().map(TxOut::value).collect()
    }
    fn input_scriptpubkeys(&self) -> Vec<Script> {
        self.0.iter().map(|o| o.script_pubkey().clone()).collect()
    }
}
struct WithPrevouts;
impl Authorization for WithPrevouts {
    type TransparentAuth = Prevouts;
    type SaplingAuth = <Authorized as Authorization>::SaplingAuth;
    type OrchardAuth = <Authorized as Authorization>::OrchardAuth;
}

pub struct Funding {
    pub outpoint: OutPoint,
    pub output: TxOut,
}

pub struct Payment<'a> {
    pub seed: [u8; 32],
    pub blocks: ChainData<'a>,
    pub spends: Vec<&'a Receipt>,
    pub funding: Option<Funding>,
    pub outputs: &'a [Receipt],
    /// An unshielded payment, or transparent change from shielding a non-coinbase UTXO.
    pub transparent_output: Option<(String, u64)>,
    pub expiry: u32,
}

pub fn build(payment: Payment<'_>, control: &Control) -> Result<Transaction> {
    control.check()?;
    let Payment {
        seed,
        blocks,
        spends,
        funding,
        outputs,
        transparent_output,
        expiry,
    } = payment;
    let tip = blocks.tip()?;
    ensure!(
        spends.is_empty() != funding.is_none(),
        "exactly one funding source is required"
    );
    let incoming = spends.iter().try_fold(0u64, |total, receipt| {
        total
            .checked_add(receipt.value_zat)
            .context("amount overflow")
    })?;
    let incoming = if spends.is_empty() {
        funding
            .as_ref()
            .map(|f| f.output.value().into_u64())
            .unwrap_or(0)
    } else {
        incoming
    };
    let outgoing = outputs.iter().try_fold(
        transparent_output.as_ref().map_or(0, |(_, n)| *n),
        |total, r| total.checked_add(r.value_zat).context("amount overflow"),
    )?;
    let fee = incoming
        .checked_sub(outgoing)
        .context("transaction outputs exceed its inputs")?;
    ensure!(
        (FEE..FEE + 54).contains(&fee),
        "transaction must pay the configured fee plus at most dust change"
    );
    let key = SpendingKey::from(seed);
    let mut rng = rand::rng();
    let mut evidence = Vec::new();
    let mut plan_anchor = anchor(&tip.anchor_after)?;
    let multiple_spends = spends.len() > 1;
    let mut prepared = Vec::with_capacity(spends.len());
    for receipt in spends {
        let note = receipt.note()?;
        let spendable = proofs::spendable(&blocks, &key, note, control)?;
        let secret = proofs::secret(&key, note, control)?;
        prepared.push((note, secret, spendable));
    }
    if prepared.len() == 1 {
        plan_anchor = prepared[0].2.data().2;
    } else if multiple_spends {
        plan_anchor = anchor(&tip.anchor_after)?;
    }
    let mut spends = Vec::with_capacity(prepared.len());
    for (note, secret, spendable) in prepared {
        let spans = if multiple_spends {
            proofs::anchor_spans(&blocks, spendable.data().2, plan_anchor, control)?
        } else {
            Vec::new()
        };
        spends.push(action::Plan::spend(
            note,
            ActionEntropy::random(&mut rng),
            value::Trapdoor::random(&mut rng),
            |alpha| key.derive_proof_private().ak.derive_action_public(&alpha),
        ));
        evidence.push((secret, spendable, spans));
    }
    let outputs = outputs
        .iter()
        .map(|r| {
            Ok(action::Plan::output(
                r.note()?,
                ActionEntropy::random(&mut rng),
                value::Trapdoor::random(&mut rng),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let max_fee_note = Note {
        pk: key.derive_payment_key(),
        value: value::Positive::try_from(FEE)?,
        psi: nullifier::Trapdoor::random(&mut rng),
        rcm: CommitmentTrapdoor::random(&mut rng),
    };
    let plan = Plan::new(spends, outputs, max_fee_note);
    control.stage("Proving transaction stamp…")?;
    let stamp = plan
        .clone()
        .stamp_plan(plan_anchor, value::Positive::try_from(FEE)?)
        .prove(&mut rng, &key.derive_proof_private(), evidence)?;
    let fee_descriptors = std::collections::BTreeSet::from([fee::Descriptor {
        cv_feemax: max_fee_note.cv_feemax(),
        v_fee: value::Positive::try_from(FEE)?,
    }]);
    let stamp = proofs::lift_stamp(
        &blocks,
        stamp,
        &plan.descriptors(),
        &fee_descriptors,
        control,
    )?;
    control.stage("Signing transaction…")?;
    let placeholder = TachyonBundle::Proven(
        {
            let bundle = plan
                .clone()
                .sign(&mut rng, &[0; 32], &key.derive_auth_private())?
                .stamp(stamp.clone());
            let stamp = bundle.stamp.compress(&mut rng)?;
            zcash_tachyon::Bundle {
                actions: bundle.actions,
                value_balance: bundle.value_balance,
                cv_feemax: bundle.cv_feemax,
                binding_sig: bundle.binding_sig,
                memo: bundle.memo,
                stamp,
            }
        },
    );
    let vout = transparent_output
        .map(|(address, amount)| -> Result<_> {
            Ok(TxOut::new(
                Zatoshis::from_u64(amount)?,
                transparent_script(&address)?,
            ))
        })
        .transpose()?
        .into_iter()
        .collect();
    authorize(seed, funding, vout, expiry, placeholder, |hash| {
        let bundle = plan
            .sign(&mut rng, hash, &key.derive_auth_private())?
            .stamp(stamp);
        let stamp = bundle.stamp.compress(&mut rng)?;
        Ok(TachyonBundle::Proven(zcash_tachyon::Bundle {
            actions: bundle.actions,
            value_balance: bundle.value_balance,
            cv_feemax: bundle.cv_feemax,
            binding_sig: bundle.binding_sig,
            memo: bundle.memo,
            stamp,
        }))
    })
}

pub(crate) fn non_dust_change(change: u64) -> Option<u64> {
    // P2PKH outputs are 34 serialized bytes; Zakura's threshold is
    // 3 * (100 * (34 + 148) / 1000) = 54 zatoshis.
    (change >= 54).then_some(change)
}

/// Create a V7 payment with no Tachyon bundle or proofs, using the wallet's funding key.
pub fn build_transparent(
    seed: [u8; 32],
    funding: Funding,
    to: &str,
    amount: u64,
    expiry: u32,
) -> Result<Transaction> {
    ensure!(amount > 0, "amount must be positive");
    let needed = amount
        .checked_add(FEE)
        .context("amount plus fee overflow")?;
    let change = funding
        .output
        .value()
        .into_u64()
        .checked_sub(needed)
        .context("funding output cannot cover amount plus fee")?;
    let mut vout = vec![TxOut::new(
        Zatoshis::from_u64(amount)?,
        transparent_script(to)?,
    )];
    if let Some(change) = non_dust_change(change) {
        vout.push(TxOut::new(
            Zatoshis::from_u64(change)?,
            transparent_script(&funding_address(seed)?)?,
        ));
    }
    authorize(
        seed,
        Some(funding),
        vout,
        expiry,
        TachyonBundle::NoBundle,
        |_| Ok(TachyonBundle::NoBundle),
    )
}

fn authorize(
    seed: [u8; 32],
    funding: Option<Funding>,
    vout: Vec<TxOut>,
    expiry: u32,
    placeholder: TachyonBundle,
    authorize_tachyon: impl FnOnce(&[u8; 32]) -> Result<TachyonBundle>,
) -> Result<Transaction> {
    let vin = funding
        .as_ref()
        .map(|f| {
            vec![TxIn::from_parts(
                f.outpoint.clone(),
                Script::default(),
                u32::MAX,
            )]
        })
        .unwrap_or_default();
    let prevouts = funding
        .as_ref()
        .map(|f| vec![f.output.clone()])
        .unwrap_or_default();
    let transparent = (!vin.is_empty() || !vout.is_empty()).then(|| bundle::Bundle {
        vin: vin.clone(),
        vout: vout.clone(),
        authorization: Prevouts(prevouts),
    });
    let data = TransactionData::<WithPrevouts>::from_parts_v7(
        BranchId::NuTachyon,
        0,
        BlockHeight::from_u32(expiry),
        Zatoshis::ZERO,
        transparent,
        None,
        None,
        None,
        placeholder,
    );
    let digest = data.digest(TxIdDigester);
    let shielded_hash = signature_hash(&data, &SignableInput::Shielded, &digest);
    let tachyon = authorize_tachyon(shielded_hash.as_ref())?;
    let mut signed_vin = Vec::new();
    if let Some(funding) = funding {
        let script = funding.output.script_pubkey();
        ensure!(
            *script == transparent_script(&funding_address(seed)?)?,
            "funding output is not owned by this wallet"
        );
        let input = transparent::sighash::SignableInput::from_parts(
            data.transparent_bundle().context("funding bundle exists")?,
            SighashType::ALL,
            0,
            script,
            script,
            funding.output.value(),
        )?;
        let hash = signature_hash(&data, &SignableInput::Transparent(input), &digest);
        let secp = Secp256k1::new();
        let secret = funding_key(seed)?;
        let mut signature = secp
            .sign_ecdsa(&Message::from_digest_slice(hash.as_ref())?, &secret)
            .serialize_der()
            .to_vec();
        signature.push(SighashType::ALL.encode());
        let public = PublicKey::from_secret_key(&secp, &secret).serialize();
        let mut script_sig = vec![u8::try_from(signature.len())?];
        script_sig.extend(signature);
        script_sig.push(u8::try_from(public.len())?);
        script_sig.extend(public);
        signed_vin.push(TxIn::from_parts(
            funding.outpoint,
            Script(zcash_script::script::Code(script_sig)),
            u32::MAX,
        ));
    }
    let transparent = (!signed_vin.is_empty() || !vout.is_empty()).then_some(bundle::Bundle {
        vin: signed_vin,
        vout,
        authorization: bundle::Authorized,
    });
    Ok(TransactionData::<Authorized>::from_parts_v7(
        BranchId::NuTachyon,
        0,
        BlockHeight::from_u32(expiry),
        Zatoshis::ZERO,
        transparent,
        None,
        None,
        None,
        tachyon,
    )
    .freeze()?)
}

#[cfg(test)]
pub(crate) fn verify_for_test(tx: &Transaction, funding: Option<TxOut>) -> Result<()> {
    let transparent = tx.transparent_bundle().map(|b| bundle::Bundle {
        vin: b
            .vin
            .iter()
            .map(|input| {
                TxIn::from_parts(
                    input.prevout().clone(),
                    input.script_sig().clone(),
                    input.sequence(),
                )
            })
            .collect(),
        vout: b.vout.clone(),
        authorization: Prevouts(funding.clone().into_iter().collect()),
    });
    let data = TransactionData::<WithPrevouts>::from_parts_v7(
        BranchId::NuTachyon,
        0,
        tx.expiry_height(),
        Zatoshis::ZERO,
        transparent,
        None,
        None,
        None,
        tx.tachyon_bundle().clone(),
    );
    let digest = data.digest(TxIdDigester);
    let hash = signature_hash(&data, &SignableInput::Shielded, &digest);
    match tx.tachyon_bundle() {
        TachyonBundle::Proven(bundle) => {
            let mut wtxid = [0; 64];
            wtxid[..32].copy_from_slice(tx.txid().as_ref());
            wtxid[32..].copy_from_slice(tx.auth_commitment().as_bytes());
            bundle.verify(&mut rand::rng(), hash.as_ref(), &wtxid, &[])?;
        }
        TachyonBundle::NoBundle => ensure!(funding.is_some(), "transparent payment needs funding"),
        _ => anyhow::bail!("unexpected bundle type"),
    }
    if let Some(output) = funding {
        let b = data.transparent_bundle().unwrap();
        let input = transparent::sighash::SignableInput::from_parts(
            b,
            SighashType::ALL,
            0,
            output.script_pubkey(),
            output.script_pubkey(),
            output.value(),
        )?;
        let hash = signature_hash(&data, &SignableInput::Transparent(input), &digest);
        let code = &b.vin[0].script_sig().0.0;
        let size = usize::from(code[0]);
        let signature = secp256k1::ecdsa::Signature::from_der(&code[1..size])?;
        let public = PublicKey::from_slice(&code[size + 2..])?;
        Secp256k1::new().verify_ecdsa(
            &Message::from_digest_slice(hash.as_ref())?,
            &signature,
            &public,
        )?;
    }
    Ok(())
}
