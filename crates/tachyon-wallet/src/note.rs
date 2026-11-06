//! Explicit out-of-band receipts: Tachyon has no on-chain note ciphertext to scan.

use anyhow::{Result, ensure};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use udon::field::Field;
use zcash_tachyon::{
    Note, keys::private::SpendingKey, note::CommitmentTrapdoor, nullifier, pasta::Fp, value,
};

use crate::chain::bytes32;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub version: u32,
    pub network_id: String,
    pub payment_key: String,
    pub value_zat: u64,
    pub psi: String,
    pub rcm: String,
    /// Public lookup hints, never evidence of confirmation or ownership.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<Locator>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Locator {
    pub txid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<String>,
}

impl Locator {
    pub fn validate(&self) -> Result<()> {
        bytes32(&self.txid)?;
        if let Some(hash) = &self.block_hash {
            bytes32(hash)?;
        }
        Ok(())
    }
}

fn field(encoded: &str) -> Result<Fp> {
    let mut repr = Fp::ZERO.to_bytes();
    repr.as_mut_slice().copy_from_slice(&bytes32(encoded)?);
    Fp::from_bytes(repr).ok_or_else(|| anyhow::anyhow!("non-canonical field encoding"))
}

pub fn payment_key(key: &SpendingKey) -> String {
    hex::encode(Fp::from(key.derive_payment_key()).to_bytes())
}

pub fn address(key: &SpendingKey) -> String {
    format!("tachyon-test:{}", payment_key(key))
}

pub fn decode_address(address: &str) -> Result<String> {
    let key = address.strip_prefix("tachyon-test:").ok_or_else(|| {
        anyhow::anyhow!("expected experimental tachyon-test:<payment-key> address")
    })?;
    field(key)?;
    Ok(key.to_owned())
}

impl Receipt {
    pub fn new(network_id: &str, recipient: &str, value_zat: u64) -> Result<Self> {
        let pk = decode_address(recipient)?;
        let mut rng = rand::rng();
        let psi: Fp = nullifier::Trapdoor::random(&mut rng).into();
        let mut rcm: Fp = CommitmentTrapdoor::random(&mut rng).into();
        while rcm == Fp::ZERO {
            rcm = CommitmentTrapdoor::random(&mut rng).into();
        }
        let receipt = Self {
            version: 1,
            network_id: network_id.into(),
            payment_key: pk,
            value_zat,
            psi: hex::encode(psi.to_bytes()),
            rcm: hex::encode(rcm.to_bytes()),
            locator: None,
        };
        receipt.note()?;
        Ok(receipt)
    }

    pub fn note(&self) -> Result<Note> {
        ensure!(self.version == 1, "unsupported receipt version");
        if let Some(locator) = &self.locator {
            locator.validate()?;
        }
        ensure!(
            self.value_zat > 0,
            "zero-value notes are not supported by this wallet"
        );
        let rcm = field(&self.rcm)?;
        ensure!(rcm != Fp::ZERO, "zero commitment trapdoor");
        Ok(Note {
            pk: field(&self.payment_key)?.into(),
            value: value::Positive::try_from(self.value_zat)?,
            psi: field(&self.psi)?.into(),
            rcm: rcm.into(),
        })
    }

    pub fn id(&self) -> Result<String> {
        let cm: Fp = self.note()?.commitment().into();
        Ok(hex::encode(cm.to_bytes()))
    }

    pub fn check_owner(&self, key: &SpendingKey, network_id: &str) -> Result<()> {
        self.note()?;
        ensure!(
            self.network_id == network_id,
            "receipt belongs to another network"
        );
        ensure!(
            self.payment_key == payment_key(key),
            "receipt belongs to another wallet"
        );
        Ok(())
    }
}

pub fn random_seed() -> [u8; 32] {
    rand::rng().random()
}
