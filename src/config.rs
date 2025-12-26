use anyhow::anyhow;
use bip0039::{English, Mnemonic};
use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::Path;

use secrecy::{ExposeSecret, SecretVec, Zeroize};
use serde::{Deserialize, Serialize};

use zcash_protocol::consensus::{self, BlockHeight, NetworkUpgrade, Parameters};
use zcash_protocol::local_consensus::LocalNetwork;

use crate::{
    data::{Network, NetworkParams, DEFAULT_WALLET_DIR},
    error,
};

const KEYS_FILE: &str = "keys.toml";

pub(crate) struct WalletConfig {
    network_params: NetworkParams,
    seed_ciphertext: Option<String>,
    birthday: BlockHeight,
}

impl WalletConfig {
    pub(crate) fn init_with_mnemonic<'a, P: AsRef<Path>>(
        wallet_dir: Option<P>,
        recipients: impl Iterator<Item = &'a dyn age::Recipient>,
        mnemonic: &Mnemonic,
        birthday: BlockHeight,
        network_params: &NetworkParams,
    ) -> Result<(), anyhow::Error> {
        init_wallet_config(
            wallet_dir,
            Some(encrypt_mnemonic(recipients, mnemonic)?),
            birthday,
            network_params,
        )
    }

    pub(crate) fn init_without_mnemonic<P: AsRef<Path>>(
        wallet_dir: Option<P>,
        birthday: BlockHeight,
        network_params: &NetworkParams,
    ) -> Result<(), anyhow::Error> {
        init_wallet_config(wallet_dir, None, birthday, network_params)
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

    pub(crate) fn network(&self) -> NetworkParams {
        self.network_params.clone()
    }

    pub(crate) fn birthday(&self) -> BlockHeight {
        self.birthday
    }
}

fn init_wallet_config<P: AsRef<Path>>(
    wallet_dir: Option<P>,
    mnemonic: Option<String>,
    birthday: BlockHeight,
    network_params: &NetworkParams,
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

    // Extract network name and activation heights from NetworkParams
    let (network_str, regtest_activations) = match network_params {
        NetworkParams::Consensus(consensus::Network::MainNetwork) => ("main", None),
        NetworkParams::Consensus(consensus::Network::TestNetwork) => ("test", None),
        NetworkParams::Local(local) => {
            let heights = (
                local.activation_height(NetworkUpgrade::Overwinter).map(u32::from),
                local.activation_height(NetworkUpgrade::Sapling).map(u32::from),
                local.activation_height(NetworkUpgrade::Blossom).map(u32::from),
                local.activation_height(NetworkUpgrade::Heartwood).map(u32::from),
                local.activation_height(NetworkUpgrade::Canopy).map(u32::from),
                local.activation_height(NetworkUpgrade::Nu5).map(u32::from),
                local.activation_height(NetworkUpgrade::Nu6).map(u32::from),
                local.activation_height(NetworkUpgrade::Nu6_1).map(u32::from),
            );
            ("regtest", Some(heights))
        }
    };

    let config = ConfigEncoding {
        mnemonic,
        network: Some(network_str.to_string()),
        birthday: Some(u32::from(birthday)),
        regtest_activation_overwinter: regtest_activations.and_then(|h| h.0),
        regtest_activation_sapling: regtest_activations.and_then(|h| h.1),
        regtest_activation_blossom: regtest_activations.and_then(|h| h.2),
        regtest_activation_heartwood: regtest_activations.and_then(|h| h.3),
        regtest_activation_canopy: regtest_activations.and_then(|h| h.4),
        regtest_activation_nu5: regtest_activations.and_then(|h| h.5),
        regtest_activation_nu6: regtest_activations.and_then(|h| h.6),
        regtest_activation_nu6_1: regtest_activations.and_then(|h| h.7),
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

        let network = config.network.map_or_else(
            || Ok(Network::Test),
            |network_name| {
                Network::parse(network_name.trim())
                    .map_err(|_| error::Error::InvalidKeysFile)
            },
        )?;

        let network_params = match network {
            Network::Main => NetworkParams::Consensus(consensus::Network::MainNetwork),
            Network::Test => NetworkParams::Consensus(consensus::Network::TestNetwork),
            Network::Regtest => {
                // Helper to get activation height with default of 1
                let height_or_default = |opt: Option<u32>| {
                    opt.map(BlockHeight::from).or(Some(BlockHeight::from_u32(1)))
                };

                let local_network = LocalNetwork {
                    overwinter: height_or_default(config.regtest_activation_overwinter),
                    sapling: height_or_default(config.regtest_activation_sapling),
                    blossom: height_or_default(config.regtest_activation_blossom),
                    heartwood: height_or_default(config.regtest_activation_heartwood),
                    canopy: height_or_default(config.regtest_activation_canopy),
                    nu5: height_or_default(config.regtest_activation_nu5),
                    nu6: height_or_default(config.regtest_activation_nu6),
                    nu6_1: height_or_default(config.regtest_activation_nu6_1),
                };
                NetworkParams::Local(local_network)
            }
        };

        let birthday = config.birthday.map(BlockHeight::from).unwrap_or_else(|| {
            network_params
                .activation_height(NetworkUpgrade::Sapling)
                .expect("Sapling activation height is known.")
        });

        Ok(Self {
            network_params,
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

    // Regtest activation heights (all optional, default to 1)
    regtest_activation_overwinter: Option<u32>,
    regtest_activation_sapling: Option<u32>,
    regtest_activation_blossom: Option<u32>,
    regtest_activation_heartwood: Option<u32>,
    regtest_activation_canopy: Option<u32>,
    regtest_activation_nu5: Option<u32>,
    regtest_activation_nu6: Option<u32>,
    regtest_activation_nu6_1: Option<u32>,
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
) -> Result<NetworkParams, anyhow::Error> {
    Ok(WalletConfig::read(wallet_dir)?.network_params)
}

pub(crate) fn get_wallet_seed<'a, P: AsRef<Path>>(
    wallet_dir: Option<P>,
    identities: impl Iterator<Item = &'a dyn age::Identity>,
) -> Result<Option<SecretVec<u8>>, anyhow::Error> {
    let mut config = WalletConfig::read(wallet_dir)?;
    config.decrypt_seed(identities)
}
