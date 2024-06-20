use anyhow::anyhow;
use bip0039::{English, Mnemonic};
use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

use secrecy::{SecretVec, Zeroize};
use serde::{Deserialize, Serialize};
use tracing::error;

use zcash_client_sqlite::chain::BlockMeta;
use zcash_primitives::consensus::{self, BlockHeight};
use zcash_protocol::consensus::Parameters;

use crate::error;

const DEFAULT_WALLET_DIR: &str = "./zec_sqlite_wallet";
const KEYS_FILE: &str = "keys.toml";
const BLOCKS_FOLDER: &str = "blocks";
const DATA_DB: &str = "data.sqlite";

#[derive(Clone, Copy, Debug, Default)]
pub(crate) enum Network {
    #[default]
    Test,
    Main,
}

impl Network {
    pub(crate) fn parse(name: &str) -> Result<Network, String> {
        match name {
            "main" => Ok(Network::Main),
            "test" => Ok(Network::Test),
            other => Err(format!("Unsupported network: {}", other)),
        }
    }

    pub(crate) fn name(&self) -> &str {
        match self {
            Network::Test => "test",
            Network::Main => "main",
        }
    }
}

impl From<Network> for consensus::Network {
    fn from(value: Network) -> Self {
        match value {
            Network::Test => consensus::Network::TestNetwork,
            Network::Main => consensus::Network::MainNetwork,
        }
    }
}

pub(crate) fn get_keys_file<P: AsRef<Path>>(
    wallet_dir: Option<P>,
) -> Result<BufReader<File>, anyhow::Error> {
    let mut p = wallet_dir
        .as_ref()
        .map(|p| p.as_ref())
        .unwrap_or(DEFAULT_WALLET_DIR.as_ref())
        .to_owned();
    p.push(KEYS_FILE);
    Ok(BufReader::new(File::open(p)?))
}

pub(crate) struct WalletKeys {
    network: consensus::Network,
    seed: Option<SecretVec<u8>>,
    birthday: BlockHeight,
}

impl WalletKeys {
    pub(crate) fn network(&self) -> consensus::Network {
        self.network
    }

    pub(crate) fn seed(&self) -> Option<&SecretVec<u8>> {
        self.seed.as_ref()
    }

    pub(crate) fn birthday(&self) -> BlockHeight {
        self.birthday
    }
}

#[derive(Deserialize, Serialize)]
struct WalletConfig {
    mnemonic: Option<String>,
    network: Option<String>,
    birthday: Option<u32>,
}

pub(crate) fn init_wallet_config<P: AsRef<Path>>(
    wallet_dir: Option<P>,
    mnemonic: &Mnemonic,
    birthday: u32,
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

    let config = WalletConfig {
        mnemonic: Some(mnemonic.phrase().to_string()),
        network: Some(network.name().to_string()),
        birthday: Some(u32::from(birthday)),
    };

    let config_str = toml::to_string(&config)
        .map_err::<anyhow::Error, _>(|_| anyhow!("error writing wallet config"))?;

    write!(&mut keys_file, "{}", config_str)?;

    Ok(())
}

pub(crate) fn read_config<P: AsRef<Path>>(
    wallet_dir: Option<P>,
) -> Result<WalletKeys, anyhow::Error> {
    let mut keys_file = get_keys_file(wallet_dir)?;
    let mut conf_str = "".to_string();
    keys_file.read_to_string(&mut conf_str)?;
    let mut config: WalletConfig = toml::from_str(&conf_str)?;

    let seed = config
        .mnemonic
        .as_ref()
        .map(|m| {
            let mut seed_bytes = <Mnemonic<English>>::from_phrase(m)?.to_seed("");
            let seed = SecretVec::new(seed_bytes.to_vec());
            seed_bytes.zeroize();
            Ok(seed)
        })
        .transpose()
        .map_err(|_: bip0039::Error| anyhow!("mnemonic did not parse as a valid HD seed"))?;
    config.mnemonic.zeroize();

    let network = config.network.map_or_else(
        || Ok(consensus::Network::TestNetwork),
        |network_name| {
            Network::parse(network_name.trim())
                .map(consensus::Network::from)
                .map_err(|_| error::Error::InvalidKeysFile)
        },
    )?;

    let birthday = config.birthday.map(BlockHeight::from).unwrap_or(
        network
            .activation_height(consensus::NetworkUpgrade::Sapling)
            .expect("Sapling activation height is known."),
    );

    Ok(WalletKeys {
        network,
        seed,
        birthday,
    })
}

pub(crate) fn get_wallet_network<P: AsRef<Path>>(
    wallet_dir: Option<P>,
) -> Result<consensus::Network, anyhow::Error> {
    Ok(read_config(wallet_dir)?.network)
}

pub(crate) fn get_wallet_seed<P: AsRef<Path>>(
    wallet_dir: Option<P>,
) -> Result<Option<SecretVec<u8>>, anyhow::Error> {
    Ok(read_config(wallet_dir)?.seed)
}

pub(crate) fn get_db_paths<P: AsRef<Path>>(wallet_dir: Option<P>) -> (PathBuf, PathBuf) {
    let a = wallet_dir
        .as_ref()
        .map(|p| p.as_ref())
        .unwrap_or(DEFAULT_WALLET_DIR.as_ref())
        .to_owned();
    let mut b = a.clone();
    b.push(DATA_DB);
    (a, b)
}

pub(crate) fn get_block_path(fsblockdb_root: &Path, meta: &BlockMeta) -> PathBuf {
    meta.block_file_path(&fsblockdb_root.join(BLOCKS_FOLDER))
}

pub(crate) async fn erase_wallet_state<P: AsRef<Path>>(wallet_dir: Option<P>) {
    let (fsblockdb_root, db_data) = get_db_paths(wallet_dir);
    let blocks_meta = fsblockdb_root.join("blockmeta.sqlite");
    let blocks_folder = fsblockdb_root.join(BLOCKS_FOLDER);

    if let Err(e) = tokio::fs::remove_dir_all(&blocks_folder).await {
        error!("Failed to remove {:?}: {}", blocks_folder, e);
    }

    if let Err(e) = tokio::fs::remove_file(&blocks_meta).await {
        error!("Failed to remove {:?}: {}", blocks_meta, e);
    }

    if let Err(e) = tokio::fs::remove_file(&db_data).await {
        error!("Failed to remove {:?}: {}", db_data, e);
    }
}
