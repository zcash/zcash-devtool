use anyhow::anyhow;
use blake2b_simd::Hash as Blake2bHash;
use clap::Args;
use pczt::{
    Pczt,
    roles::{low_level_signer, signer::EffectsOnly},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, stdin, stdout};
use zcash_primitives::transaction::{
    TransactionData, TxDigests, sighash::SignableInput, sighash_v5::v5_signature_hash,
    txid::TxIdDigester,
};
use zcash_protocol::PoolType;

// Options accepted for the `pczt update-with-signature` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// The pool that the signature is for.
    #[arg(value_parser = parse_pool_type)]
    pool: PoolType,

    /// The index of the transparent input or shielded spend that the signature is for.
    index: usize,

    /// The hex-encoded signature.
    signature: String,
}

impl Command {
    pub(crate) async fn run(self) -> anyhow::Result<()> {
        let sig_bytes = hex::decode(self.signature)?;

        let mut buf = vec![];
        stdin().read_to_end(&mut buf).await?;

        let pczt = Pczt::parse(&buf).map_err(|e| anyhow!("Failed to read PCZT: {:?}", e))?;

        let tx_data = pczt.clone().into_effects().map_err(|e| anyhow!("{e:?}"))?;
        let txid_parts = tx_data.digest(TxIdDigester);

        let signer = low_level_signer::Signer::new(pczt);

        let signer = match self.pool {
            PoolType::Transparent => {
                add_transparent(signer, &tx_data, &txid_parts, self.index, sig_bytes)
            }
            PoolType::SAPLING => Err(anyhow!("TODO: Maybe support this")),
            PoolType::ORCHARD => Err(anyhow!("TODO: Maybe support this")),
        }
        .map_err(|e| anyhow!("{e:?}"))?;

        let pczt = signer.finish();

        stdout().write_all(&pczt.serialize()).await?;

        Ok(())
    }
}

fn parse_pool_type(s: &str) -> anyhow::Result<PoolType> {
    match s {
        "transparent" => Ok(PoolType::Transparent),
        "sapling" => Ok(PoolType::SAPLING),
        "orchard" => Ok(PoolType::ORCHARD),
        _ => Err(anyhow!(
            "Invalid pool type '{s}', must be one of ['transparent', 'sapling', 'orchard']"
        )),
    }
}

fn add_transparent(
    signer: low_level_signer::Signer,
    tx_data: &TransactionData<EffectsOnly>,
    txid_parts: &TxDigests<Blake2bHash>,
    index: usize,
    sig_bytes: Vec<u8>,
) -> anyhow::Result<low_level_signer::Signer> {
    // Signature has to have the SighashType appended to it.
    let (sighash_type, sig_der) = sig_bytes
        .split_last()
        .ok_or_else(|| anyhow!("Invalid signature bytes"))?;
    let sig = secp256k1::ecdsa::Signature::from_der(sig_der)
        .map_err(|_| anyhow!("Invalid signature bytes"))?;

    let mut found = false;

    let signer = signer
        .sign_transparent_with(|_, bundle, _| {
            if let Some(input) = bundle.inputs_mut().get_mut(index) {
                found = true;
                if *sighash_type != input.sighash_type().encode() {
                    return Err(TempError::Parser(
                        transparent::pczt::ParseError::InvalidSighashType,
                    ));
                }
                input.append_signature(
                    index,
                    |input| {
                        v5_signature_hash(tx_data, &SignableInput::Transparent(input), txid_parts)
                            .as_ref()
                            .try_into()
                            .unwrap()
                    },
                    sig,
                    &secp256k1::Secp256k1::verification_only(),
                )?;
            }
            Ok::<_, TempError>(())
        })
        .map_err(|e| anyhow!("{e:?}"))?;

    if found {
        Ok(signer)
    } else {
        Err(anyhow!("No inputs matched the given derivation path"))
    }
}

#[allow(unused)]
#[derive(Debug)]
enum TempError {
    Parser(transparent::pczt::ParseError),
    Signer(transparent::pczt::SignerError),
}

impl From<transparent::pczt::ParseError> for TempError {
    fn from(e: transparent::pczt::ParseError) -> Self {
        Self::Parser(e)
    }
}

impl From<transparent::pczt::SignerError> for TempError {
    fn from(e: transparent::pczt::SignerError) -> Self {
        Self::Signer(e)
    }
}
