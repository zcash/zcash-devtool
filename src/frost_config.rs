use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use anyhow::anyhow;
use serde::{Deserialize, Serialize};

const FROST_FILE: &str = "frost.toml";

/// Per-account FROST configuration stored in frost.toml.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct FrostAccountConfig {
    /// Wallet account name
    pub name: String,
    /// Links to zcash_client_sqlite account UUID
    pub account_uuid: String,
    /// Threshold (minimum signers required)
    pub min_signers: u16,
    /// Total number of signers
    pub max_signers: u16,
    /// KeyPackage serialized as hex bytes (age-encrypted JSON of the raw byte fields)
    pub key_package: String,
    /// PublicKeyPackage serialized as hex (JSON of raw byte fields)
    pub public_key_package: String,
    /// Shared nullifier key bytes (age-encrypted hex, 32 bytes)
    pub nk_bytes: String,
    /// Shared commit-ivk randomness bytes (age-encrypted hex, 32 bytes)
    pub rivk_bytes: String,
    /// This participant's FROST identifier (hex, 32 bytes scalar serialization)
    pub identifier: String,
}

/// Top-level FROST configuration file.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct FrostConfig {
    #[serde(default)]
    pub accounts: Vec<FrostAccountConfig>,
}

impl FrostConfig {
    /// Read the FROST config from the wallet directory.
    pub fn read<P: AsRef<Path>>(wallet_dir: Option<P>) -> Result<Self, anyhow::Error> {
        let path = frost_file_path(wallet_dir);
        match File::open(&path) {
            Ok(mut file) => {
                let mut contents = String::new();
                file.read_to_string(&mut contents)?;
                let config: FrostConfig = toml::from_str(&contents)?;
                Ok(config)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(FrostConfig::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Write the FROST config to the wallet directory.
    pub fn write<P: AsRef<Path>>(&self, wallet_dir: Option<P>) -> Result<(), anyhow::Error> {
        let path = frost_file_path(wallet_dir);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let contents =
            toml::to_string(self).map_err(|e| anyhow!("error serializing frost config: {e}"))?;

        let mut options = fs::OpenOptions::new();
        options.create(true).write(true).truncate(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let mut file = options.open(&path)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        Ok(())
    }

    /// Find an account config by UUID.
    pub fn find_account(&self, uuid: &str) -> Option<&FrostAccountConfig> {
        self.accounts.iter().find(|a| a.account_uuid == uuid)
    }

    /// Check whether an account with the given UUID already exists.
    pub fn has_account(&self, uuid: &str) -> bool {
        self.accounts.iter().any(|a| a.account_uuid == uuid)
    }
}

fn frost_file_path<P: AsRef<Path>>(wallet_dir: Option<P>) -> std::path::PathBuf {
    let dir = wallet_dir
        .as_ref()
        .map(|p| p.as_ref())
        .unwrap_or(crate::data::DEFAULT_WALLET_DIR.as_ref());
    dir.join(FROST_FILE)
}

pub(crate) fn encrypt_string<'a>(
    recipients: impl Iterator<Item = &'a dyn age::Recipient>,
    plaintext: &str,
) -> Result<String, anyhow::Error> {
    let encryptor = age::Encryptor::with_recipients(recipients)?;
    let mut ciphertext = vec![];
    let mut writer = encryptor.wrap_output(age::armor::ArmoredWriter::wrap_output(
        &mut ciphertext,
        age::armor::Format::AsciiArmor,
    )?)?;
    writer.write_all(plaintext.as_bytes())?;
    writer.finish().and_then(|armor| armor.finish())?;
    String::from_utf8(ciphertext).map_err(|e| anyhow!("age armor produced invalid UTF-8: {e}"))
}

pub(crate) fn decrypt_string<'a>(
    identities: impl Iterator<Item = &'a dyn age::Identity>,
    ciphertext: &str,
) -> Result<String, anyhow::Error> {
    let decryptor = age::Decryptor::new(age::armor::ArmoredReader::new(ciphertext.as_bytes()))?;
    let mut buf = vec![];
    decryptor.decrypt(identities)?.read_to_end(&mut buf)?;
    Ok(String::from_utf8(buf)?)
}

/// Read age x25519 identities from a file and return their public keys as recipients.
pub(crate) fn load_age_recipients(
    identity_path: &str,
) -> Result<Vec<age::x25519::Recipient>, anyhow::Error> {
    let contents = std::fs::read_to_string(identity_path)
        .map_err(|e| anyhow!("Failed to read identity file '{}': {e}", identity_path))?;
    let mut identities = Vec::new();
    for line in contents.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let id: age::x25519::Identity = line
            .parse()
            .map_err(|e| anyhow!("Failed to parse age identity line: {e}"))?;
        identities.push(id);
    }

    if identities.is_empty() {
        return Err(anyhow!(
            "No age x25519 identities found in '{}'",
            identity_path
        ));
    }

    Ok(identities.iter().map(|id| id.to_public()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frost_config_round_trip() {
        let config = FrostConfig {
            accounts: vec![FrostAccountConfig {
                name: "test-frost".to_string(),
                account_uuid: "12345678-1234-1234-1234-123456789012".to_string(),
                min_signers: 2,
                max_signers: 3,
                key_package: "encrypted-key-package-placeholder".to_string(),
                public_key_package: "public-key-package-hex".to_string(),
                nk_bytes: "aa".repeat(32),
                rivk_bytes: "bb".repeat(32),
                identifier: "01".repeat(32),
            }],
        };

        let serialized = toml::to_string(&config).unwrap();
        let deserialized: FrostConfig = toml::from_str(&serialized).unwrap();

        assert_eq!(deserialized.accounts.len(), 1);
        let a = &deserialized.accounts[0];
        assert_eq!(a.name, "test-frost");
        assert_eq!(a.account_uuid, "12345678-1234-1234-1234-123456789012");
        assert_eq!(a.min_signers, 2);
        assert_eq!(a.max_signers, 3);
        assert_eq!(a.key_package, "encrypted-key-package-placeholder");
        assert_eq!(a.public_key_package, "public-key-package-hex");
        assert_eq!(a.nk_bytes, "aa".repeat(32));
        assert_eq!(a.rivk_bytes, "bb".repeat(32));
        assert_eq!(a.identifier, "01".repeat(32));
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = age::x25519::Identity::generate();
        let pubkey = key.to_public();

        let plaintext = "secret key package data";
        let encrypted = encrypt_string(
            std::iter::once(&pubkey as &dyn age::Recipient),
            plaintext,
        )
        .unwrap();

        let decrypted = decrypt_string(
            std::iter::once(&key as &dyn age::Identity),
            &encrypted,
        )
        .unwrap();

        assert_eq!(plaintext, decrypted);
    }
}
