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
    /// wallet config so later commands agree. The raw [`ActivationHeights`]
    /// are kept (rather than a [`LocalNetwork`]) so persistence is verbatim:
    /// an explicit `"never"` and an absent key both deactivate an upgrade
    /// but must survive the round-trip distinctly.
    #[cfg(feature = "regtest_support")]
    Regtest(ActivationHeights),
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
const DEFAULT_REGTEST: ActivationHeights = ActivationHeights {
    overwinter: Some(HeightSetting::At(1)),
    sapling: Some(HeightSetting::At(1)),
    blossom: Some(HeightSetting::At(1)),
    heartwood: Some(HeightSetting::At(1)),
    canopy: Some(HeightSetting::At(1)),
    nu5: Some(HeightSetting::At(2)),
    nu6: Some(HeightSetting::At(2)),
    nu6_1: Some(HeightSetting::At(2)),
    nu6_2: Some(HeightSetting::At(2)),
    nu6_3: Some(HeightSetting::At(2)),
    #[cfg(zcash_unstable = "nu7")]
    nu7: Some(HeightSetting::At(2)),
};

/// One entry in the activation-heights schema: activate at a block height, or
/// `"never"` — the operator's explicit statement that the upgrade does not
/// exist on this chain. A key that is absent entirely (`None` around this
/// type) also deactivates the upgrade, but is warned about on load, since
/// absence may only mean the file predates this tool's knowledge of the
/// upgrade.
#[cfg(feature = "regtest_support")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeightSetting {
    At(u32),
    Never,
}

#[cfg(feature = "regtest_support")]
impl serde::Serialize for HeightSetting {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            HeightSetting::At(height) => serializer.serialize_u32(*height),
            HeightSetting::Never => serializer.serialize_str("never"),
        }
    }
}

#[cfg(feature = "regtest_support")]
impl<'de> serde::Deserialize<'de> for HeightSetting {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Height(u32),
            Word(String),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Height(height) => Ok(HeightSetting::At(height)),
            Raw::Word(word) if word == "never" => Ok(HeightSetting::Never),
            Raw::Word(word) => Err(serde::de::Error::custom(format!(
                "invalid activation height {word:?}: expected a block height or \"never\""
            ))),
        }
    }
}

/// A `LocalNetwork`-shaped set of regtest activation heights, one optional
/// [`HeightSetting`] per network upgrade (a missing entry means "not
/// active"). This is the schema of the `--activation-heights` TOML file and
/// of the `[activation_heights]` table persisted in the wallet config; the
/// two share this type so a wallet's heights round-trip verbatim from the
/// file the operator commits to revision control.
#[cfg(feature = "regtest_support")]
#[derive(Clone, Copy, Debug, Default, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ActivationHeights {
    pub(crate) overwinter: Option<HeightSetting>,
    pub(crate) sapling: Option<HeightSetting>,
    pub(crate) blossom: Option<HeightSetting>,
    pub(crate) heartwood: Option<HeightSetting>,
    pub(crate) canopy: Option<HeightSetting>,
    pub(crate) nu5: Option<HeightSetting>,
    pub(crate) nu6: Option<HeightSetting>,
    pub(crate) nu6_1: Option<HeightSetting>,
    pub(crate) nu6_2: Option<HeightSetting>,
    pub(crate) nu6_3: Option<HeightSetting>,
    #[cfg(zcash_unstable = "nu7")]
    pub(crate) nu7: Option<HeightSetting>,
}

#[cfg(feature = "regtest_support")]
impl ActivationHeights {
    /// Consensus queries deliberately route through [`LocalNetwork`] rather
    /// than a local `Parameters` impl: its exhaustive struct literal is the
    /// compile-time tripwire that surfaces new network upgrades at dependency
    /// bumps.
    pub(crate) fn to_local_network(self) -> LocalNetwork {
        let h = |v: Option<HeightSetting>| match v {
            Some(HeightSetting::At(height)) => Some(BlockHeight::from_u32(height)),
            Some(HeightSetting::Never) | None => None,
        };
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
            nu6_3: h(self.nu6_3),
            #[cfg(zcash_unstable = "nu7")]
            nu7: h(self.nu7),
        }
    }

    /// Warn about upgrades this binary knows that `self` leaves implicitly
    /// inactive (key absent). Explicit entries — a height or `"never"` — are
    /// silent.
    pub(crate) fn warn_on_implicitly_inactive(&self, source: &str) {
        let absent: Vec<&str> = [
            ("overwinter", self.overwinter),
            ("sapling", self.sapling),
            ("blossom", self.blossom),
            ("heartwood", self.heartwood),
            ("canopy", self.canopy),
            ("nu5", self.nu5),
            ("nu6", self.nu6),
            ("nu6_1", self.nu6_1),
            ("nu6_2", self.nu6_2),
            ("nu6_3", self.nu6_3),
            #[cfg(zcash_unstable = "nu7")]
            ("nu7", self.nu7),
        ]
        .iter()
        .filter(|(_, setting)| setting.is_none())
        .map(|(key, _)| *key)
        .collect();
        if !absent.is_empty() {
            tracing::warn!(
                "{source} does not mention {}; treating as inactive. State a height or \
                 \"never\" explicitly to silence this warning, and ensure the validator's \
                 configuration agrees.",
                absent.join(", ")
            );
        }
    }
}

/// Load a `--activation-heights` TOML file, warning about upgrades the file
/// leaves implicitly inactive.
#[cfg(feature = "regtest_support")]
pub(crate) fn load_activation_heights(path: &Path) -> anyhow::Result<ActivationHeights> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading activation-heights file {path:?}: {e}"))?;
    let heights: ActivationHeights = toml::from_str(&contents)
        .map_err(|e| anyhow::anyhow!("parsing activation-heights file {path:?}: {e}"))?;
    heights.warn_on_implicitly_inactive(&format!("activation-heights file {path:?}"));
    Ok(heights)
}

impl Parameters for Network {
    fn network_type(&self) -> consensus::NetworkType {
        match self {
            Network::Test => consensus::Network::TestNetwork.network_type(),
            Network::Main => consensus::Network::MainNetwork.network_type(),
            #[cfg(feature = "regtest_support")]
            Network::Regtest(heights) => heights.to_local_network().network_type(),
        }
    }

    fn activation_height(&self, nu: consensus::NetworkUpgrade) -> Option<BlockHeight> {
        match self {
            Network::Test => consensus::Network::TestNetwork.activation_height(nu),
            Network::Main => consensus::Network::MainNetwork.activation_height(nu),
            #[cfg(feature = "regtest_support")]
            Network::Regtest(heights) => heights.to_local_network().activation_height(nu),
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
        // An explicit "never" (here nu6_2) and a missing key (here nu6_3)
        // both leave the upgrade inactive on the resulting chain.
        let toml = "\
overwinter = 1
sapling = 1
blossom = 1
heartwood = 1
canopy = 1
nu5 = 2
nu6 = 2
nu6_1 = 2
nu6_2 = \"never\"
";
        let heights: ActivationHeights = toml::from_str(toml).unwrap();
        let net = Network::Regtest(heights);

        assert_eq!(
            net.activation_height(NetworkUpgrade::Sapling),
            Some(BlockHeight::from_u32(1))
        );
        assert_eq!(
            net.activation_height(NetworkUpgrade::Nu5),
            Some(BlockHeight::from_u32(2))
        );
        assert_eq!(net.activation_height(NetworkUpgrade::Nu6_2), None);
        assert_eq!(net.activation_height(NetworkUpgrade::Nu6_3), None);
    }

    #[test]
    fn activation_heights_round_trip_verbatim() {
        let original: ActivationHeights = toml::from_str("nu5 = 7\nnu6 = \"never\"\n").unwrap();
        assert_eq!(original.nu5, Some(HeightSetting::At(7)));
        assert_eq!(original.nu6, Some(HeightSetting::Never));

        let reserialized = toml::to_string(&original).unwrap();
        let restored: ActivationHeights = toml::from_str(&reserialized).unwrap();
        assert_eq!(restored.nu5, Some(HeightSetting::At(7)));
        assert_eq!(restored.nu6, Some(HeightSetting::Never));
        // An absent key stays absent — implicitly inactive is preserved, not
        // laundered into an explicit "never".
        assert_eq!(restored.nu6_3, None);
    }

    #[test]
    fn activation_heights_reject_words_other_than_never() {
        assert!(toml::from_str::<ActivationHeights>("nu5 = \"nevr\"\n").is_err());
    }

    /// Regression: a heights file written before NU6.3 support (integer
    /// values only, no `nu6_3` key) must keep parsing, with the identical
    /// consensus view it had under the old binary.
    #[test]
    fn legacy_integer_only_heights_file_still_parses() {
        // Verbatim shape of a pre-NU6.3 operator file.
        let legacy = "\
overwinter = 1
sapling = 1
blossom = 1
heartwood = 1
canopy = 1
nu5 = 2
nu6 = 2
nu6_1 = 2
nu6_2 = 2
";
        let heights: ActivationHeights = toml::from_str(legacy).unwrap();
        let net = Network::Regtest(heights);

        for (nu, expected) in [
            (NetworkUpgrade::Overwinter, 1),
            (NetworkUpgrade::Sapling, 1),
            (NetworkUpgrade::Blossom, 1),
            (NetworkUpgrade::Heartwood, 1),
            (NetworkUpgrade::Canopy, 1),
            (NetworkUpgrade::Nu5, 2),
            (NetworkUpgrade::Nu6, 2),
            (NetworkUpgrade::Nu6_1, 2),
            (NetworkUpgrade::Nu6_2, 2),
        ] {
            assert_eq!(
                net.activation_height(nu),
                Some(BlockHeight::from_u32(expected)),
                "{nu:?}"
            );
        }
        assert_eq!(net.activation_height(NetworkUpgrade::Nu6_3), None);
    }

    /// Regression: heights that use no `"never"` entries must serialize in
    /// the legacy integer-only format, so a wallet config that predates
    /// NU6.3 support re-persists byte-compatibly and remains readable by
    /// older binaries (whose `deny_unknown_fields` would reject new keys).
    #[test]
    fn integer_heights_serialize_in_legacy_format() {
        let heights: ActivationHeights = toml::from_str("nu5 = 2\nnu6 = 2\n").unwrap();
        let serialized = toml::to_string(&heights).unwrap();
        assert_eq!(serialized, "nu5 = 2\nnu6 = 2\n");
    }

    /// Regression: unknown keys are still rejected, as before the upgrade.
    #[test]
    fn unknown_upgrade_keys_still_rejected() {
        assert!(toml::from_str::<ActivationHeights>("nu9 = 1\n").is_err());
    }

    /// Regression: the built-in fallback heights still match the
    /// `zcash_local_net` wallet-funding zebrad fixture (pre-NU5 at 1,
    /// everything NU5+ at 2) for all upgrades that predate NU6.3 support,
    /// and the network still reports itself as regtest.
    #[test]
    fn default_regtest_fallback_heights_unchanged() {
        let net = Network::parse("regtest").unwrap();

        assert_eq!(net.network_type(), consensus::NetworkType::Regtest);
        for (nu, expected) in [
            (NetworkUpgrade::Overwinter, 1),
            (NetworkUpgrade::Sapling, 1),
            (NetworkUpgrade::Blossom, 1),
            (NetworkUpgrade::Heartwood, 1),
            (NetworkUpgrade::Canopy, 1),
            (NetworkUpgrade::Nu5, 2),
            (NetworkUpgrade::Nu6, 2),
            (NetworkUpgrade::Nu6_1, 2),
            (NetworkUpgrade::Nu6_2, 2),
        ] {
            assert_eq!(
                net.activation_height(nu),
                Some(BlockHeight::from_u32(expected)),
                "{nu:?}"
            );
        }
    }
}
