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
        // Persisted verbatim from what the operator's file stated, so an
        // explicit "never" and an absent key survive distinctly.
        #[cfg(feature = "regtest_support")]
        activation_heights: match network {
            Network::Regtest(heights) => Some(heights),
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
            Network::Regtest(_) => {
                let heights = config
                    .activation_heights
                    .ok_or(error::Error::InvalidKeysFile)?;
                heights.warn_on_implicitly_inactive("wallet config [activation_heights]");
                Network::Regtest(heights)
            }
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
             nu5 = 2\nnu6 = 2\nnu6_1 = 5\nnu6_2 = \"never\"\n",
        )
        .unwrap();
        let network = Network::Regtest(heights);

        WalletConfig::init_without_mnemonic(Some(&dir), BlockHeight::from_u32(0), network).unwrap();

        // The persisted file records the heights as a table, verbatim: the
        // explicit "never" survives and the absent nu6_3 stays absent.
        let keys_toml = fs::read_to_string(Path::new(&dir).join(KEYS_FILE)).unwrap();
        assert!(keys_toml.contains("[activation_heights]"), "{keys_toml}");
        assert!(keys_toml.contains("nu6_2 = \"never\""), "{keys_toml}");
        assert!(!keys_toml.contains("nu6_3"), "{keys_toml}");

        let reloaded = WalletConfig::read(Some(&dir)).unwrap();
        match reloaded.network {
            net @ Network::Regtest(heights) => {
                assert_eq!(
                    net.activation_height(NetworkUpgrade::Nu5),
                    Some(BlockHeight::from_u32(2))
                );
                assert_eq!(
                    net.activation_height(NetworkUpgrade::Nu6_1),
                    Some(BlockHeight::from_u32(5))
                );
                assert_eq!(net.activation_height(NetworkUpgrade::Nu6_2), None);
                assert_eq!(net.activation_height(NetworkUpgrade::Nu6_3), None);
                assert_eq!(heights.nu6_2, Some(crate::data::HeightSetting::Never));
                assert_eq!(heights.nu6_3, None);
            }
            other => panic!("expected regtest, got {other:?}"),
        }

        fs::remove_dir_all(&dir).unwrap();
    }

    /// Regression: a `keys.toml` persisted by a pre-NU6.3 binary (integer
    /// heights, no `nu6_3` key) must keep loading, with the same consensus
    /// view it had under that binary; the absent `nu6_3` reads as inactive.
    #[test]
    fn legacy_keys_toml_without_nu6_3_loads() {
        let dir = std::env::temp_dir().join(format!(
            "zcash-devtool-cfg-legacy-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Verbatim shape of a wallet config written before NU6.3 support.
        fs::write(
            dir.join(KEYS_FILE),
            "network = \"regtest\"\n\
             birthday = 0\n\
             \n\
             [activation_heights]\n\
             overwinter = 1\n\
             sapling = 1\n\
             blossom = 1\n\
             heartwood = 1\n\
             canopy = 1\n\
             nu5 = 2\n\
             nu6 = 2\n\
             nu6_1 = 2\n\
             nu6_2 = 2\n",
        )
        .unwrap();

        let config = WalletConfig::read(Some(&dir)).unwrap();
        let net = config.network();
        assert_eq!(
            net.activation_height(NetworkUpgrade::Nu6_2),
            Some(BlockHeight::from_u32(2))
        );
        assert_eq!(net.activation_height(NetworkUpgrade::Nu6_3), None);
        assert_eq!(config.birthday(), BlockHeight::from_u32(0));

        fs::remove_dir_all(&dir).unwrap();
    }

    /// Regression: a regtest wallet config with no `[activation_heights]`
    /// table at all is still rejected outright, as before the upgrade.
    #[test]
    fn regtest_keys_toml_missing_heights_table_still_errors() {
        let dir = std::env::temp_dir().join(format!(
            "zcash-devtool-cfg-noheights-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        fs::write(dir.join(KEYS_FILE), "network = \"regtest\"\nbirthday = 0\n").unwrap();
        assert!(WalletConfig::read(Some(&dir)).is_err());

        fs::remove_dir_all(&dir).unwrap();
    }

    /// Regression: non-regtest wallet configs never carried activation
    /// heights and must keep loading without them, defaulting the birthday
    /// to the network's Sapling activation height when unset.
    #[test]
    fn test_network_keys_toml_loads_without_heights() {
        let dir = std::env::temp_dir().join(format!(
            "zcash-devtool-cfg-testnet-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        fs::write(dir.join(KEYS_FILE), "network = \"test\"\n").unwrap();
        let config = WalletConfig::read(Some(&dir)).unwrap();
        assert_eq!(
            Some(config.birthday()),
            config
                .network()
                .activation_height(consensus::NetworkUpgrade::Sapling)
        );

        fs::remove_dir_all(&dir).unwrap();
    }
}

/// Seed encryption is the one place where a dependency upgrade can silently
/// lock users out of an existing wallet, so these tests pin the on-disk
/// format rather than just exercising the current API against itself.
#[cfg(test)]
mod age_compat_tests {
    use super::*;

    /// Test-only key. It protects nothing but the fixture below.
    const TEST_IDENTITY: &str =
        "AGE-SECRET-KEY-1T2376TDD3NNRFPKVU9VAK8E8HP6P5HW6KL0WTYZAFKAFMQX8SKMSHNQELQ";

    /// The same throwaway mnemonic already published in `.github/workflows/speed.yml`.
    const TEST_PHRASE: &str = "wine gesture someone salmon deposit fit depart marble seed chat \
                               sick wood illegal trim coast scheme sword enter shiver disagree \
                               marble short blind carry";

    /// Produced by `encrypt_mnemonic` while this crate was still on age 0.11,
    /// standing in for a `keys.toml` written by an older build of the tool.
    const AGE_0_11_CIPHERTEXT: &str = "\
-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSArei9Ua29rWlg3aFdqSTcx
YzBKbExoWFUxYUhwaFl5Y0xSVzJlaTV2U3hRCjBWMkhRdDVhWjJsM0Q3dVhCZnNE
ZU9VcVV6bW9TTE1DdVNVbEluMi9uL2sKLT4gMlNFc30tZ3JlYXNlIEVgClVKYUhy
Rm9nRjltclg1Vks3SlVyUG5Vc2RWdGNaYmxOS0RtVjlZam0KLS0tIFkrR0dBbjdW
STErSXlNZWhFcnNMaGYxZjN6bTJQd0xROUJKMlZSOWhkYTgK6aEEcSwPN4JRdAhP
2m8mgN+4f/4hIRMsBuiMm1GYQyYJzLQ4z2pK+QMzJVsUYcG7QOGRaDeOr0F9n45k
j3GXXXAowjUwmgG6J34Z2PR904VFX35hdgxoaZZiijrJzvZ2N+6NI9r6FdNq5HWs
YbqDyi3goiJhF8/i5yYqiwrQXvZ/TzK026b7iVHT45qGGzDwYIjy3JDIz8NRXZmB
jRW+ziYGUZgR+/lTdkPqVkIYF3HD73VeQcAN6Q==
-----END AGE ENCRYPTED FILE-----
";

    fn phrase() -> String {
        TEST_PHRASE.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// BIP-39 seed for `TEST_PHRASE` with an empty passphrase, computed
    /// independently of this crate's dependencies as
    /// `PBKDF2-HMAC-SHA512(phrase, "mnemonic", 2048, 64)`. Hard-coded rather
    /// than derived through `bip0039` so that a change in how that crate
    /// derives seeds is caught here instead of cancelling itself out.
    const EXPECTED_SEED_HEX: &str = "9070562a53e5306c09ff0b3f30924658001139798a7a07c42b43c07751fdb43a\
                                     6ac32f5a11f7015025b4558a115ecbee7a6aa62824f698f844d49e97550d20db";

    fn identity() -> age::x25519::Identity {
        TEST_IDENTITY.parse().expect("test identity parses")
    }

    /// A wallet whose seed was encrypted by an age 0.11 build must still open.
    #[test]
    fn ciphertext_written_by_age_0_11_still_decrypts() {
        let id = identity();
        let recovered = decrypt_mnemonic(
            std::iter::once(&id as &dyn age::Identity),
            AGE_0_11_CIPHERTEXT,
        )
        .expect("age 0.11 ciphertext decrypts under the current age release");

        assert_eq!(
            std::str::from_utf8(recovered.expose_secret()).unwrap(),
            phrase(),
        );
    }

    /// ...and must derive the same seed, not merely the same mnemonic bytes.
    #[test]
    fn seed_from_age_0_11_ciphertext_is_unchanged() {
        let id = identity();
        let seed = decrypt_seed(
            std::iter::once(&id as &dyn age::Identity),
            AGE_0_11_CIPHERTEXT,
        )
        .expect("seed derives from the age 0.11 ciphertext");

        assert_eq!(
            hex::encode(seed.expose_secret()),
            EXPECTED_SEED_HEX.split_whitespace().collect::<String>(),
        );
    }

    /// Guard the other direction: what we write today must read back.
    #[test]
    fn encrypt_decrypt_round_trips() {
        let id = identity();
        let recipient = id.to_public();
        let mnemonic = <Mnemonic<English>>::from_phrase(phrase()).unwrap();

        let ciphertext = encrypt_mnemonic(
            std::iter::once(&recipient as &dyn age::Recipient),
            &mnemonic,
        )
        .expect("encryption succeeds");

        let recovered = decrypt_mnemonic(std::iter::once(&id as &dyn age::Identity), &ciphertext)
            .expect("round trip decrypts");

        assert_eq!(
            std::str::from_utf8(recovered.expose_secret()).unwrap(),
            phrase(),
        );
    }
}
