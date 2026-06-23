use anyhow::anyhow;
use bip0039::{English, Mnemonic};
use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::Path;

use secrecy::{ExposeSecret, SecretVec, Zeroize};
use serde::{Deserialize, Serialize};

use zcash_protocol::consensus::{self, BlockHeight, Parameters};

#[cfg(feature = "regtest_support")]
use crate::data::ActivationHeights;
use crate::{
    data::{DEFAULT_WALLET_DIR, Network},
    error,
};

const KEYS_FILE: &str = "keys.toml";

pub(crate) struct WalletConfig {
    network: Network,
    seed_ciphertext: Option<String>,
    birthday: BlockHeight,
}

impl WalletConfig {
    pub(crate) fn init_with_mnemonic<'a, P: AsRef<Path>>(
        wallet_dir: Option<P>,
        recipients: impl Iterator<Item = &'a dyn age::Recipient>,
        mnemonic: &Mnemonic,
        birthday: BlockHeight,
        network: Network,
    ) -> Result<(), anyhow::Error> {
        init_wallet_config(
            wallet_dir,
            Some(encrypt_mnemonic(recipients, mnemonic)?),
            birthday,
            network,
        )
    }

    pub(crate) fn init_without_mnemonic<P: AsRef<Path>>(
        wallet_dir: Option<P>,
        birthday: BlockHeight,
        network: Network,
    ) -> Result<(), anyhow::Error> {
        init_wallet_config(wallet_dir, None, birthday, network)
    }

    pub(crate) fn decrypt_seed<'a>(
        &mut self,
        identities: impl Iterator<Item = &'a dyn age::Identity>,
    ) -> Result<Option<SecretVec<u8>>, anyhow::Error> {
        self.seed_ciphertext
            .as_ref()
            .map(|ciphertext| decrypt_seed(identities, ciphertext))
            .transpose()
    }

    pub(crate) fn decrypt_mnemonic<'a>(
        &mut self,
        identities: impl Iterator<Item = &'a dyn age::Identity>,
    ) -> Result<Option<SecretVec<u8>>, anyhow::Error> {
        self.seed_ciphertext
            .as_ref()
            .map(|ciphertext| decrypt_mnemonic(identities, ciphertext))
            .transpose()
    }

    pub(crate) fn network(&self) -> Network {
        self.network
    }

    pub(crate) fn birthday(&self) -> BlockHeight {
        self.birthday
    }
}

fn init_wallet_config<P: AsRef<Path>>(
    wallet_dir: Option<P>,
    mnemonic: Option<String>,
    birthday: BlockHeight,
    network: Network,
) -> Result<(), anyhow::Error> {
    // Create the wallet directory.
    let wallet_dir = wallet_dir
        .as_ref()
        .map(|p| p.as_ref())
        .unwrap_or(DEFAULT_WALLET_DIR.as_ref());
    fs::create_dir_all(wallet_dir)?;

    // Write the mnemonic phrase to disk along with its birthday.
    let mut keys_file = {
        let mut p = wallet_dir.to_owned();
        p.push(KEYS_FILE);
        fs::OpenOptions::new().create_new(true).write(true).open(p)
    }?;

    let config = ConfigEncoding {
        mnemonic,
        network: Some(network.name().to_string()),
        birthday: Some(u32::from(birthday)),
        #[cfg(feature = "regtest_support")]
        activation_heights: match network {
            Network::Regtest(local) => Some(ActivationHeights::from_local_network(local)),
            _ => None,
        },
    };

    let config_str = toml::to_string(&config)
        .map_err::<anyhow::Error, _>(|_| anyhow!("error writing wallet config"))?;

    write!(&mut keys_file, "{config_str}")?;

    Ok(())
}

impl WalletConfig {
    pub(crate) fn read<P: AsRef<Path>>(wallet_dir: Option<P>) -> Result<Self, anyhow::Error> {
        let mut keys_file = {
            let mut p = wallet_dir
                .as_ref()
                .map(|p| p.as_ref())
                .unwrap_or(DEFAULT_WALLET_DIR.as_ref())
                .to_owned();
            p.push(KEYS_FILE);
            BufReader::new(File::open(p)?)
        };

        let mut conf_str = "".to_string();
        keys_file.read_to_string(&mut conf_str)?;
        let config: ConfigEncoding = toml::from_str(&conf_str)?;

        let network = config.network.as_deref().map_or_else(
            || Ok(Network::Test),
            |network_name| {
                Network::parse(network_name.trim()).map_err(|_| error::Error::InvalidKeysFile)
            },
        )?;

        // For regtest, replace the parsed default heights with the ones
        // persisted at `init` so this command agrees with the wallet's chain.
        #[cfg(feature = "regtest_support")]
        let network = match network {
            Network::Regtest(_) => Network::Regtest(
                config
                    .activation_heights
                    .ok_or(error::Error::InvalidKeysFile)?
                    .to_local_network(),
            ),
            other => other,
        };

        let birthday = config.birthday.map(BlockHeight::from).unwrap_or_else(|| {
            network
                .activation_height(consensus::NetworkUpgrade::Sapling)
                .expect("Sapling activation height is known.")
        });

        Ok(Self {
            network,
            seed_ciphertext: config.mnemonic,
            birthday,
        })
    }
}

#[derive(Deserialize, Serialize)]
struct ConfigEncoding {
    mnemonic: Option<String>,
    network: Option<String>,
    birthday: Option<u32>,
    /// Regtest activation heights, present only for `network = "regtest"`.
    #[cfg(feature = "regtest_support")]
    activation_heights: Option<ActivationHeights>,
}

fn encrypt_mnemonic<'a>(
    recipients: impl Iterator<Item = &'a dyn age::Recipient>,
    mnemonic: &Mnemonic,
) -> Result<String, anyhow::Error> {
    let encryptor = age::Encryptor::with_recipients(recipients)?;
    let mut ciphertext = vec![];
    let mut writer = encryptor.wrap_output(age::armor::ArmoredWriter::wrap_output(
        &mut ciphertext,
        age::armor::Format::AsciiArmor,
    )?)?;
    writer.write_all(mnemonic.phrase().as_bytes())?;
    writer.finish().and_then(|armor| armor.finish())?;
    Ok(String::from_utf8(ciphertext).expect("armor is valid UTF-8"))
}

fn decrypt_mnemonic<'a>(
    identities: impl Iterator<Item = &'a dyn age::Identity>,
    ciphertext: &str,
) -> Result<SecretVec<u8>, anyhow::Error> {
    let decryptor = age::Decryptor::new(age::armor::ArmoredReader::new(ciphertext.as_bytes()))?;
    let mut buf = vec![];
    // We intentionally do not use `?` on the result of the following expression because doing so
    // in the case of a partial failure could result in part of the secret data being read into
    // `buf`, which would not then be properly zeroized. Instead, we take ownership of the buffer
    // in construction of a `SecretVec` to ensure that the memory is zeroed out when we raise
    // the error on the following line.
    let ret = decryptor.decrypt(identities)?.read_to_end(&mut buf);
    let res = SecretVec::new(buf);
    ret?;
    Ok(res)
}

fn decrypt_seed<'a>(
    identities: impl Iterator<Item = &'a dyn age::Identity>,
    ciphertext: &str,
) -> Result<SecretVec<u8>, anyhow::Error> {
    let mnemonic_bytes = decrypt_mnemonic(identities, ciphertext)?;
    let mnemonic = std::str::from_utf8(mnemonic_bytes.expose_secret())?;

    let mut seed_bytes = <Mnemonic<English>>::from_phrase(mnemonic)?.to_seed("");
    let seed = SecretVec::new(seed_bytes.to_vec());
    seed_bytes.zeroize();

    Ok(seed)
}

pub(crate) fn get_wallet_network<P: AsRef<Path>>(
    wallet_dir: Option<P>,
) -> Result<Network, anyhow::Error> {
    Ok(WalletConfig::read(wallet_dir)?.network)
}

pub(crate) fn get_wallet_seed<'a, P: AsRef<Path>>(
    wallet_dir: Option<P>,
    identities: impl Iterator<Item = &'a dyn age::Identity>,
) -> Result<Option<SecretVec<u8>>, anyhow::Error> {
    let mut config = WalletConfig::read(wallet_dir)?;
    config.decrypt_seed(identities)
}

#[cfg(all(test, feature = "regtest_support"))]
mod tests {
    use super::*;
    use zcash_protocol::consensus::NetworkUpgrade;

    /// A regtest wallet config persisted by `init` must carry the activation
    /// heights into `keys.toml` and reconstruct them on read, so commands
    /// after `init` build transactions against the same chain.
    #[test]
    fn regtest_activation_heights_persist_and_reload() {
        let dir =
            std::env::temp_dir().join(format!("zcash-devtool-cfg-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let dir = dir.to_str().unwrap().to_string();

        let heights: ActivationHeights = toml::from_str(
            "overwinter = 1\nsapling = 1\nblossom = 1\nheartwood = 1\ncanopy = 1\n\
             nu5 = 2\nnu6 = 2\nnu6_1 = 5\n",
        )
        .unwrap();
        let network = Network::Regtest(heights.to_local_network());

        WalletConfig::init_without_mnemonic(Some(&dir), BlockHeight::from_u32(0), network).unwrap();

        // The persisted file records the heights as a table.
        let keys_toml = fs::read_to_string(Path::new(&dir).join(KEYS_FILE)).unwrap();
        assert!(keys_toml.contains("[activation_heights]"), "{keys_toml}");

        let reloaded = WalletConfig::read(Some(&dir)).unwrap();
        match reloaded.network {
            Network::Regtest(local) => {
                assert_eq!(
                    local.activation_height(NetworkUpgrade::Nu5),
                    Some(BlockHeight::from_u32(2))
                );
                assert_eq!(
                    local.activation_height(NetworkUpgrade::Nu6_1),
                    Some(BlockHeight::from_u32(5))
                );
                assert_eq!(local.activation_height(NetworkUpgrade::Nu6_2), None);
            }
            other => panic!("expected regtest, got {other:?}"),
        }

        fs::remove_dir_all(&dir).unwrap();
    }
}
