use std::collections::BTreeMap;

use anyhow::anyhow;
use gumdrop::Options;
use pczt::{
    roles::{signer::Signer, updater::Updater},
    Pczt,
};
use secrecy::ExposeSecret;
use tokio::io::{stdin, stdout, AsyncReadExt, AsyncWriteExt};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_primitives::legacy::keys::{NonHardenedChildIndex, TransparentKeyScope};
use zcash_protocol::consensus::{NetworkConstants, Parameters};
use zip32::fingerprint::SeedFingerprint;

use crate::config::WalletConfig;

// Options accepted for the `pczt sign` command
#[derive(Debug, Options)]
pub(crate) struct Command {
    #[options(help = "age identity file to decrypt the mnemonic phrase with")]
    identity: String,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let mut config = WalletConfig::read(wallet_dir.as_ref())?;
        let params = config.network();

        let mut buf = vec![];
        stdin().read_to_end(&mut buf).await?;

        let pczt = Pczt::parse(&buf).map_err(|e| anyhow!("Failed to read PCZT: {:?}", e))?;

        // Decrypt the mnemonic to access the seed.
        let identities = age::IdentityFile::from_file(self.identity)?.into_identities()?;
        config.decrypt(identities.iter().map(|i| i.as_ref() as _))?;

        let seed = config
            .seed()
            .ok_or(anyhow!("Seed must be present to enable signing"))?
            .expose_secret();
        let seed_fp =
            SeedFingerprint::from_seed(seed).ok_or_else(|| anyhow!("Invalid seed length"))?;

        // Find all the spends matching our seed. For now as a hack, we use the Updater
        // role to access the bundle data we need.
        enum KeyRef {
            Orchard {
                index: usize,
            },
            Sapling {
                index: usize,
            },
            Transparent {
                index: usize,
                scope: TransparentKeyScope,
                address_index: NonHardenedChildIndex,
            },
        }
        let mut keys = BTreeMap::<zip32::AccountId, Vec<KeyRef>>::new();
        let pczt = Updater::new(pczt)
            .update_orchard_with(|updater| {
                for (index, action) in updater.bundle().actions().iter().enumerate() {
                    if let Some(derivation) = action.spend().zip32_derivation() {
                        if derivation.seed_fingerprint() == &seed_fp.to_bytes()
                            && derivation.derivation_path().len() == 3
                            && derivation.derivation_path()[0] == zip32::ChildIndex::hardened(32)
                            && derivation.derivation_path()[1]
                                == zip32::ChildIndex::hardened(params.network_type().coin_type())
                        {
                            let account_index = zip32::AccountId::try_from(
                                derivation.derivation_path()[2].index() - (1 << 31),
                            )
                            .expect("valid");

                            keys.entry(account_index)
                                .or_default()
                                .push(KeyRef::Orchard { index });
                        }
                    }
                }
                Ok(())
            })
            .expect("no errors")
            .update_sapling_with(|updater| {
                for (index, spend) in updater.bundle().spends().iter().enumerate() {
                    if let Some(derivation) = spend.zip32_derivation() {
                        if derivation.seed_fingerprint() == &seed_fp.to_bytes()
                            && derivation.derivation_path().len() == 3
                            && derivation.derivation_path()[0] == zip32::ChildIndex::hardened(32)
                            && derivation.derivation_path()[1]
                                == zip32::ChildIndex::hardened(params.network_type().coin_type())
                        {
                            let account_index = zip32::AccountId::try_from(
                                derivation.derivation_path()[2].index() - (1 << 31),
                            )
                            .expect("valid");

                            keys.entry(account_index)
                                .or_default()
                                .push(KeyRef::Sapling { index });
                        }
                    }
                }
                Ok(())
            })
            .expect("no errors")
            .update_transparent_with(|updater| {
                for (index, input) in updater.bundle().inputs().iter().enumerate() {
                    for derivation in input.bip32_derivation().values() {
                        if derivation.seed_fingerprint() == &seed_fp.to_bytes()
                            && derivation.derivation_path().len() == 5
                            && derivation.derivation_path()[0]
                                == bip32::ChildNumber::new(32, true).expect("valid")
                            && derivation.derivation_path()[1]
                                == bip32::ChildNumber::new(params.network_type().coin_type(), true)
                                    .expect("valid")
                            && derivation.derivation_path()[2].is_hardened()
                            && !derivation.derivation_path()[3].is_hardened()
                            && !derivation.derivation_path()[4].is_hardened()
                        {
                            let account_index = zip32::AccountId::try_from(
                                derivation.derivation_path()[2].index() - (1 << 31),
                            )
                            .expect("valid");

                            let scope = TransparentKeyScope::custom(
                                derivation.derivation_path()[3].index(),
                            )
                            .expect("valid");
                            let address_index = NonHardenedChildIndex::from_index(
                                derivation.derivation_path()[4].index(),
                            )
                            .expect("valid");

                            keys.entry(account_index)
                                .or_default()
                                .push(KeyRef::Transparent {
                                    index,
                                    scope,
                                    address_index,
                                });
                        }
                    }
                }
                Ok(())
            })
            .expect("no errors")
            .finish();

        let mut signer =
            Signer::new(pczt).map_err(|e| anyhow!("Failed to initialize Signer: {:?}", e))?;
        for (account_index, spends) in keys {
            let usk = UnifiedSpendingKey::from_seed(&params, seed, account_index)?;
            for keyref in spends {
                match keyref {
                    KeyRef::Orchard { index } => {
                        signer
                            .sign_orchard(
                                index,
                                &orchard::keys::SpendAuthorizingKey::from(usk.orchard()),
                            )
                            .map_err(|e| {
                                anyhow!("Failed to sign Orchard spend {index}: {:?}", e)
                            })?;
                    }
                    KeyRef::Sapling { index } => {
                        signer
                            .sign_sapling(index, &usk.sapling().expsk.ask)
                            .map_err(|e| {
                                anyhow!("Failed to sign Sapling spend {index}: {:?}", e)
                            })?;
                    }
                    KeyRef::Transparent {
                        index,
                        scope,
                        address_index,
                    } => signer
                        .sign_transparent(
                            index,
                            &usk.transparent()
                                .derive_secret_key(scope, address_index)
                                .map_err(|e| {
                                    anyhow!(
                                        "Failed to derive transparent key at .../{:?}/{:?}: {:?}",
                                        scope,
                                        address_index,
                                        e,
                                    )
                                })?,
                        )
                        .map_err(|e| {
                            anyhow!("Failed to sign transparent input {index}: {:?}", e)
                        })?,
                }
            }
        }

        let pczt = signer.finish();

        stdout().write_all(&pczt.serialize()).await?;

        Ok(())
    }
}
