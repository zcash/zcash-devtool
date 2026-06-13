use rand::rngs::OsRng;
use std::path::{Path, PathBuf};
use zcash_client_sqlite::chain::init::init_blockmeta_db;
use zcash_client_sqlite::util::SystemClock;
use zcash_client_sqlite::wallet::init::init_wallet_db;
use zcash_client_sqlite::{FsBlockDb, WalletDb};

use tracing::error;

use zcash_client_sqlite::chain::BlockMeta;
use zcash_protocol::consensus::{self, BlockHeight, Parameters};
#[cfg(feature = "regtest_support")]
use zcash_protocol::local_consensus::LocalNetwork;

use crate::error;

pub(crate) const DEFAULT_WALLET_DIR: &str = "./zec_sqlite_wallet";
const BLOCKS_FOLDER: &str = "blocks";
const DATA_DB: &str = "data.sqlite";
const TOR_DIR: &str = "tor";

#[derive(Clone, Copy, Debug, Default)]
pub(crate) enum Network {
    #[default]
    Test,
    Main,
    /// Regtest, carrying the caller-chosen activation heights. These are
    /// fixed at `init` (from `--activation-heights`) and persisted in the
    /// wallet config so later commands agree.
    #[cfg(feature = "regtest_support")]
    Regtest(LocalNetwork),
}

impl Network {
    pub(crate) fn parse(name: &str) -> Result<Network, String> {
        match name {
            "main" => Ok(Network::Main),
            "test" => Ok(Network::Test),
            // `-n regtest` on the CLI yields the default heights; `init`
            // overrides them from the required `--activation-heights` file
            // before persisting. Commands that only need the network *type*
            // (e.g. address encoding) are unaffected by the heights.
            #[cfg(feature = "regtest_support")]
            "regtest" => Ok(Network::Regtest(DEFAULT_REGTEST)),
            other => Err(format!("Unsupported network: {other}")),
        }
    }

    pub(crate) fn name(&self) -> &str {
        match self {
            Network::Test => "test",
            Network::Main => "main",
            #[cfg(feature = "regtest_support")]
            Network::Regtest(_) => "regtest",
        }
    }

    /// Regtest with the built-in default activation heights, for CLI paths
    /// (address encoding, UFVK import) that don't take an explicit set.
    #[cfg(feature = "regtest_support")]
    pub(crate) fn default_regtest() -> Network {
        Network::Regtest(DEFAULT_REGTEST)
    }
}

/// Fallback regtest activation heights for CLI paths that don't take an
/// explicit set (see [`Network::default_regtest`]). Wallets created by
/// `init` do NOT use this — they carry the heights from the required
/// `--activation-heights` file. These defaults match the `zcash_local_net`
/// wallet-funding zebrad fixture (pre-NU5 at 1, everything NU5+ at 2).
///
/// Transaction construction picks the consensus branch ID from the active
/// heights, so any drift between a wallet's heights and the launched
/// validator's makes the validator reject transactions built while the tip
/// is inside the drifted window.
#[cfg(feature = "regtest_support")]
const DEFAULT_REGTEST: LocalNetwork = LocalNetwork {
    overwinter: Some(BlockHeight::from_u32(1)),
    sapling: Some(BlockHeight::from_u32(1)),
    blossom: Some(BlockHeight::from_u32(1)),
    heartwood: Some(BlockHeight::from_u32(1)),
    canopy: Some(BlockHeight::from_u32(1)),
    nu5: Some(BlockHeight::from_u32(2)),
    nu6: Some(BlockHeight::from_u32(2)),
    nu6_1: Some(BlockHeight::from_u32(2)),
    nu6_2: Some(BlockHeight::from_u32(2)),
};

/// A `LocalNetwork`-shaped set of regtest activation heights, one optional
/// height per network upgrade (a missing entry means "not active"). This is
/// the schema of the `--activation-heights` TOML file and of the
/// `[activation_heights]` table persisted in the wallet config; the two share
/// this type so a wallet's heights round-trip from the file the operator
/// commits to revision control.
#[cfg(feature = "regtest_support")]
#[derive(Clone, Copy, Debug, Default, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ActivationHeights {
    pub(crate) overwinter: Option<u32>,
    pub(crate) sapling: Option<u32>,
    pub(crate) blossom: Option<u32>,
    pub(crate) heartwood: Option<u32>,
    pub(crate) canopy: Option<u32>,
    pub(crate) nu5: Option<u32>,
    pub(crate) nu6: Option<u32>,
    pub(crate) nu6_1: Option<u32>,
    pub(crate) nu6_2: Option<u32>,
}

#[cfg(feature = "regtest_support")]
impl ActivationHeights {
    pub(crate) fn to_local_network(self) -> LocalNetwork {
        let h = |v: Option<u32>| v.map(BlockHeight::from_u32);
        LocalNetwork {
            overwinter: h(self.overwinter),
            sapling: h(self.sapling),
            blossom: h(self.blossom),
            heartwood: h(self.heartwood),
            canopy: h(self.canopy),
            nu5: h(self.nu5),
            nu6: h(self.nu6),
            nu6_1: h(self.nu6_1),
            nu6_2: h(self.nu6_2),
        }
    }

    pub(crate) fn from_local_network(local: LocalNetwork) -> Self {
        let h = |v: Option<BlockHeight>| v.map(u32::from);
        Self {
            overwinter: h(local.overwinter),
            sapling: h(local.sapling),
            blossom: h(local.blossom),
            heartwood: h(local.heartwood),
            canopy: h(local.canopy),
            nu5: h(local.nu5),
            nu6: h(local.nu6),
            nu6_1: h(local.nu6_1),
            nu6_2: h(local.nu6_2),
        }
    }
}

/// Load a `--activation-heights` TOML file into a `LocalNetwork`.
#[cfg(feature = "regtest_support")]
pub(crate) fn load_activation_heights(path: &Path) -> anyhow::Result<LocalNetwork> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading activation-heights file {path:?}: {e}"))?;
    let heights: ActivationHeights = toml::from_str(&contents)
        .map_err(|e| anyhow::anyhow!("parsing activation-heights file {path:?}: {e}"))?;
    Ok(heights.to_local_network())
}

impl Parameters for Network {
    fn network_type(&self) -> consensus::NetworkType {
        match self {
            Network::Test => consensus::Network::TestNetwork.network_type(),
            Network::Main => consensus::Network::MainNetwork.network_type(),
            #[cfg(feature = "regtest_support")]
            Network::Regtest(local) => local.network_type(),
        }
    }

    fn activation_height(&self, nu: consensus::NetworkUpgrade) -> Option<BlockHeight> {
        match self {
            Network::Test => consensus::Network::TestNetwork.activation_height(nu),
            Network::Main => consensus::Network::MainNetwork.activation_height(nu),
            #[cfg(feature = "regtest_support")]
            Network::Regtest(local) => local.activation_height(nu),
        }
    }
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

pub(crate) fn get_tor_dir<P: AsRef<Path>>(wallet_dir: Option<P>) -> PathBuf {
    wallet_dir
        .as_ref()
        .map(|p| p.as_ref())
        .unwrap_or(DEFAULT_WALLET_DIR.as_ref())
        .join(TOR_DIR)
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

pub(crate) fn init_dbs<P: Parameters + 'static>(
    params: P,
    wallet_dir: Option<&String>,
) -> Result<WalletDb<rusqlite::Connection, P, SystemClock, OsRng>, anyhow::Error> {
    // Initialise the block and wallet DBs.
    let (db_cache, db_data) = get_db_paths(wallet_dir);
    let mut db_cache = FsBlockDb::for_path(db_cache).map_err(error::Error::from)?;
    let mut db_data = WalletDb::for_path(db_data, params, SystemClock, OsRng)?;
    init_blockmeta_db(&mut db_cache)?;
    init_wallet_db(&mut db_data, None)?;

    Ok(db_data)
}

#[cfg(all(test, feature = "regtest_support"))]
mod tests {
    use super::*;
    use consensus::NetworkUpgrade;

    #[test]
    fn activation_heights_toml_maps_to_local_network() {
        // A missing key (here nu6_2) means the upgrade is inactive.
        let toml = "\
overwinter = 1
sapling = 1
blossom = 1
heartwood = 1
canopy = 1
nu5 = 2
nu6 = 2
nu6_1 = 2
";
        let heights: ActivationHeights = toml::from_str(toml).unwrap();
        let local = heights.to_local_network();
        let net = Network::Regtest(local);

        assert_eq!(
            net.activation_height(NetworkUpgrade::Sapling),
            Some(BlockHeight::from_u32(1))
        );
        assert_eq!(
            net.activation_height(NetworkUpgrade::Nu5),
            Some(BlockHeight::from_u32(2))
        );
        assert_eq!(net.activation_height(NetworkUpgrade::Nu6_2), None);
    }

    #[test]
    fn activation_heights_round_trip_through_local_network() {
        let original: ActivationHeights = toml::from_str("nu5 = 7\nnu6 = 9\n").unwrap();
        let restored = ActivationHeights::from_local_network(original.to_local_network());
        // Restoring from the LocalNetwork preserves set and unset upgrades.
        assert_eq!(restored.nu5, Some(7));
        assert_eq!(restored.nu6, Some(9));
        assert_eq!(restored.sapling, None);
    }
}
