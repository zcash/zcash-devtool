use anyhow::anyhow;
use clap::Args;
use pczt::{roles::updater::Updater, Pczt};
use secrecy::ExposeSecret;
use tokio::io::{stdin, stdout, AsyncReadExt, AsyncWriteExt};
use transparent::{address::TransparentAddress, pczt::Bip32Derivation};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::{consensus::NetworkConstants, PoolType};
use zcash_script::solver;
use zip32::fingerprint::SeedFingerprint;

use crate::config::WalletConfig;

// Options accepted for the `derive-path` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// The age identity file to decrypt the mnemonic phrase with.
    #[arg(short, long)]
    identity: String,

    /// The pool to derive within.
    #[arg(value_parser = parse_pool_type)]
    pool: PoolType,

    /// The ZIP 32 or BIP 44 path to derive.
    path: String,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let path = parse_path(&self.path)?;

        let mut config = WalletConfig::read(wallet_dir.as_ref())?;
        let params = config.network();

        let mut buf = vec![];
        stdin().read_to_end(&mut buf).await?;

        let pczt = Pczt::parse(&buf).map_err(|e| anyhow!("Failed to read PCZT: {:?}", e))?;

        // Decrypt the mnemonic to access the seed.
        let identities = age::IdentityFile::from_file(self.identity)?.into_identities()?;
        let seed = config
            .decrypt_seed(identities.iter().map(|i| i.as_ref() as _))?
            .ok_or(anyhow!(
                "Seed must be present to enable updating a PCZT with a derivation path"
            ))?;

        let seed_fp = SeedFingerprint::from_seed(seed.expose_secret())
            .ok_or_else(|| anyhow!("Invalid seed length"))?;

        let updater = Updater::new(pczt);

        let updater = match self.pool {
            PoolType::Transparent => {
                let derivation = Bip32Derivation::parse(
                    seed_fp.to_bytes(),
                    path.into_iter()
                        .map(|(index, hardened)| {
                            bip32::ChildNumber::new(index, hardened)
                                .map_err(|e| anyhow!("{e}"))
                                .map(|i| i.0)
                        })
                        .collect::<Result<_, _>>()?,
                )
                .map_err(|e| anyhow!("Invalid BIP 32 derivation: {e:?}"))?;

                let (account, scope, address_index) = derivation
                    .extract_bip_44_fields(
                        &seed_fp,
                        bip32::ChildNumber(params.coin_type() | bip32::ChildNumber::HARDENED_FLAG),
                    )
                    .ok_or_else(|| {
                        anyhow!("Path is not a valid BIP 44 path for this wallet's network")
                    })?;

                let pubkey = UnifiedSpendingKey::from_seed(&params, seed.expose_secret(), account)?
                    .transparent()
                    .to_account_pubkey()
                    .derive_address_pubkey(scope, address_index)
                    .map_err(|e| anyhow!("{e}"))?;

                add_transparent(updater, pubkey, derivation)
            }
            PoolType::SAPLING => Err(anyhow!(
                "TODO: Sapling support for whatever might be relevant and useful"
            )),
            PoolType::ORCHARD => Err(anyhow!(
                "TODO: Orchard support for whatever might be relevant and useful"
            )),
        }
        .map_err(|e| anyhow!("{e:?}"))?;

        let pczt = updater.finish();

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

fn parse_path(s: &str) -> anyhow::Result<Vec<(u32, bool)>> {
    s.strip_prefix("m/")
        .ok_or_else(|| anyhow!("Path does not start with m/"))?
        .split('/')
        .map(|index| {
            let (index, hardened) = if let Some(index) = index.strip_suffix('\'') {
                (index, true)
            } else {
                (index, false)
            };
            index
                .parse::<u32>()
                .map_err(|e| anyhow!("Invalid path index: {e}"))
                .map(|index| (index, hardened))
        })
        .collect()
}

fn add_transparent(
    updater: Updater,
    pubkey: secp256k1::PublicKey,
    derivation: Bip32Derivation,
) -> anyhow::Result<Updater> {
    let pubkey_bytes = pubkey.serialize();
    let p2pkh_addr = TransparentAddress::from_pubkey(&pubkey);

    let mut found_none = true;

    let updater = updater
        .update_transparent_with(|mut updater| {
            // Match pubkey to the inputs that use it.
            let inputs_to_update = updater
                .bundle()
                .inputs()
                .iter()
                .enumerate()
                .filter_map(|(index, input)| {
                    input
                        .redeem_script()
                        .as_ref()
                        .unwrap_or(input.script_pubkey())
                        .refine()
                        .ok()
                        .as_ref()
                        .and_then(solver::standard)
                        .and_then(|script| {
                            match script {
                                solver::ScriptKind::PubKeyHash { hash } => {
                                    TransparentAddress::PublicKeyHash(hash) == p2pkh_addr
                                }
                                solver::ScriptKind::MultiSig { pubkeys, .. } => {
                                    pubkeys.iter().any(|pk| pk.as_slice() == &pubkey_bytes)
                                }
                                solver::ScriptKind::PubKey { data } => {
                                    data.as_slice() == pubkey_bytes
                                }
                                _ => false,
                            }
                            .then_some(index)
                        })
                })
                .collect::<Vec<_>>();

            found_none = inputs_to_update.is_empty();

            for index in inputs_to_update {
                updater.update_input_with(index, |mut input_updater| {
                    input_updater.set_bip32_derivation(
                        pubkey_bytes,
                        Bip32Derivation::parse(
                            *derivation.seed_fingerprint(),
                            derivation.derivation_path().iter().map(|i| i.0).collect(),
                        )
                        .expect("valid"),
                    );
                    Ok(())
                })?;
            }

            Ok(())
        })
        .map_err(|e| anyhow!("{e:?}"))?;

    if found_none {
        Err(anyhow!("No inputs matched the given derivation path"))
    } else {
        Ok(updater)
    }
}
