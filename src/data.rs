use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use secrecy::{SecretVec, Zeroize};
use tracing::error;

use zcash_client_sqlite::chain::BlockMeta;
use zcash_primitives::{
    consensus::{self, BlockHeight},
    zip339::Mnemonic,
};

use crate::error;

const DEFAULT_WALLET_DIR: &str = "./zec_sqlite_wallet";
const KEYS_FILE: &str = "keys.txt";
const BLOCKS_FOLDER: &str = "blocks";
const DATA_DB: &str = "data.sqlite";

#[derive(Clone, Copy, Debug)]
pub(crate) enum Network {
    Test,
    Main,
}

impl Default for Network {
    fn default() -> Self {
        Network::Test
    }
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

pub(crate) fn init_wallet_keys<P: AsRef<Path>>(
    wallet_dir: Option<P>,
    mnemonic: &Mnemonic,
    birthday: u64,
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
    writeln!(
        &mut keys_file,
        "{} # wallet mnemonic phrase",
        mnemonic.phrase()
    )?;
    writeln!(&mut keys_file, "{} # wallet birthday", birthday)?;
    writeln!(&mut keys_file, "{} # network", network.name())?;

    Ok(())
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
    seed: SecretVec<u8>,
    birthday: BlockHeight,
}

impl WalletKeys {
    pub(crate) fn seed(&self) -> &SecretVec<u8> {
        &self.seed
    }

    pub(crate) fn birthday(&self) -> BlockHeight {
        self.birthday
    }
}

pub(crate) fn get_wallet_network<P: AsRef<Path>>(
    wallet_dir: Option<P>,
) -> Result<consensus::Network, anyhow::Error> {
    Ok(read_keys(wallet_dir)?.network)
}

pub(crate) fn get_wallet_seed<P: AsRef<Path>>(
    wallet_dir: Option<P>,
) -> Result<SecretVec<u8>, anyhow::Error> {
    Ok(read_keys(wallet_dir)?.seed)
}

pub(crate) fn read_keys<P: AsRef<Path>>(
    wallet_dir: Option<P>,
) -> Result<WalletKeys, anyhow::Error> {
    let keys_file = get_keys_file(wallet_dir)?;
    let mut keys_file_lines = keys_file.lines();

    let mnemonic = Mnemonic::from_phrase(
        keys_file_lines
            .next()
            .ok_or(error::Error::InvalidKeysFile)??
            .split('#')
            .next()
            .ok_or(error::Error::InvalidKeysFile)?
            .trim(),
    )?;
    let mut seed_bytes = mnemonic.to_seed("");
    let seed = SecretVec::new(seed_bytes.to_vec());
    seed_bytes.zeroize();

    let birthday = keys_file_lines
        .next()
        .ok_or(error::Error::InvalidKeysFile)??
        .split('#')
        .next()
        .ok_or(error::Error::InvalidKeysFile)?
        .trim()
        .parse::<u32>()
        .map(BlockHeight::from)
        .map_err(|_| error::Error::InvalidKeysFile)?;

    let network = keys_file_lines.next().transpose()?.map_or_else(
        || Ok(consensus::Network::TestNetwork),
        |line| {
            let network_name = line
                .split('#')
                .next()
                .ok_or(error::Error::InvalidKeysFile)?;
            Network::parse(network_name.trim())
                .map(consensus::Network::from)
                .map_err(|_| error::Error::InvalidKeysFile)
        },
    )?;

    Ok(WalletKeys {
        network,
        seed,
        birthday,
    })
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
