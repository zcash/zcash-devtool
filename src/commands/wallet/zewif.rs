//! Shared pipeline for the `init-zewif` and `import-zewif` commands.
//!
//! In this iteration, imports are strictly view-only: the document handed to
//! the importer never carries a secret store, and every account's purpose is
//! normalized to `ViewOnly`, so the wallet database cannot record spending
//! capability that devtool does not hold. Spending imports await a multi-seed
//! keystore.

use std::fmt;
use std::path::Path;

use zcash_client_sqlite::zewif::ZewifImportError;

/// Errors produced by the ZeWIF import commands.
#[derive(Debug)]
pub(crate) enum ZewifCommandError {
    /// The interchange file could not be read.
    FileRead(std::io::Error),
    /// The file is not a parseable ZeWIF container.
    Parse(::zewif::Error),
    /// The document contains no wallets, so it identifies no network and
    /// nothing can be imported.
    NoWallets,
    /// The document contains no accounts.
    NoAccounts,
    /// The network the wallet parameters describe has no Sapling activation
    /// height, so no birthday can be constructed for it.
    SaplingActivationUnknown,
    /// A lightwalletd RPC failed.
    Rpc(tonic::Status),
    /// The server returned a tree state that could not be interpreted.
    InvalidTreeState(std::io::Error),
    /// The importer rejected the document.
    Import(ZewifImportError<std::convert::Infallible>),
    /// The importer imported none of the document's accounts.
    NothingImported { document_account_count: usize },
}

impl fmt::Display for ZewifCommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZewifCommandError::FileRead(e) => write!(f, "Failed to read the ZeWIF file: {e}"),
            ZewifCommandError::Parse(e) => write!(f, "Failed to parse the ZeWIF file: {e}"),
            ZewifCommandError::NoWallets => {
                write!(f, "The ZeWIF document contains no wallets")
            }
            ZewifCommandError::NoAccounts => {
                write!(f, "The ZeWIF document contains no accounts")
            }
            ZewifCommandError::SaplingActivationUnknown => {
                write!(f, "Sapling activation height is not set for this network")
            }
            ZewifCommandError::Rpc(e) => write!(f, "RPC failed: {e}"),
            ZewifCommandError::InvalidTreeState(e) => {
                write!(f, "Invalid tree state received from server: {e}")
            }
            ZewifCommandError::Import(e) => write!(f, "ZeWIF import failed: {e}"),
            ZewifCommandError::NothingImported {
                document_account_count,
            } => write!(
                f,
                "None of the document's {document_account_count} account(s) could be imported; \
                 see the preceding warnings for the reasons"
            ),
        }
    }
}

impl std::error::Error for ZewifCommandError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ZewifCommandError::FileRead(e) => Some(e),
            ZewifCommandError::Parse(e) => Some(e),
            ZewifCommandError::Rpc(e) => Some(e),
            ZewifCommandError::InvalidTreeState(e) => Some(e),
            ZewifCommandError::Import(e) => Some(e),
            ZewifCommandError::NoWallets
            | ZewifCommandError::NoAccounts
            | ZewifCommandError::SaplingActivationUnknown
            | ZewifCommandError::NothingImported { .. } => None,
        }
    }
}

/// Reads and parses a ZeWIF interchange file.
pub(crate) fn read_zewif_file(path: &Path) -> Result<::zewif::Zewif, ZewifCommandError> {
    let bytes = std::fs::read(path).map_err(ZewifCommandError::FileRead)?;
    ::zewif::Zewif::from_bytes(&bytes).map_err(ZewifCommandError::Parse)
}

#[cfg(test)]
mod tests {
    use super::*;

    use bip0039::{English, Mnemonic};
    use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedSpendingKey};

    use crate::data::Network;

    /// A deterministic test UFVK for the test network.
    fn test_ufvk() -> UnifiedFullViewingKey {
        let mnemonic = <Mnemonic<English>>::from_entropy([0xAB; 32]).unwrap();
        let seed = mnemonic.to_seed("");
        UnifiedSpendingKey::from_seed(&Network::Test, &seed, zip32::AccountId::ZERO)
            .unwrap()
            .to_unified_full_viewing_key()
    }

    /// An account backed by a UFVK, with a birthday height set.
    fn ufvk_account(name: &str) -> ::zewif::Account {
        let mut account = ::zewif::Account::new(::zewif::AccountViewingKey::Ufvk(
            ::zewif::UnifiedFullViewingKey::new(test_ufvk().encode(&Network::Test)),
        ));
        account.set_name(name);
        account.set_birthday_height(::zewif::BlockHeight::from(2_600_000u32));
        account
    }

    /// A testnet document holding the given accounts in a single wallet.
    fn document(accounts: Vec<::zewif::Account>) -> ::zewif::Zewif {
        let mut doc = ::zewif::Zewif::new(
            ::zewif::BlockHeight::from(3_000_000u32),
            ::zewif::BlockHash::from_bytes([0xEE; 32]),
        );
        let mut wallet = ::zewif::ZewifWallet::new(::zewif::Network::Testnet);
        for account in accounts {
            wallet.add_account(account);
        }
        doc.add_wallet(wallet);
        doc
    }

    #[test]
    fn read_zewif_file_round_trips() {
        let doc = document(vec![ufvk_account("round-trip")]);
        let dir =
            std::env::temp_dir().join(format!("devtool-zewif-read-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wallet.zewif");
        std::fs::write(&path, doc.to_bytes().unwrap()).unwrap();

        let parsed = read_zewif_file(&path).unwrap();
        assert_eq!(parsed, doc);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_zewif_file_rejects_garbage() {
        let dir =
            std::env::temp_dir().join(format!("devtool-zewif-garbage-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("garbage.zewif");
        std::fs::write(&path, b"not a zewif file").unwrap();

        assert!(matches!(
            read_zewif_file(&path),
            Err(ZewifCommandError::Parse(_))
        ));

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
