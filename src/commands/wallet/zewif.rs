//! Shared pipeline for the `init-zewif` and `import-zewif` commands.
//!
//! In this iteration, imports are strictly view-only: the document handed to
//! the importer never carries a secret store, and every account's purpose is
//! normalized to `ViewOnly`, so the wallet database cannot record spending
//! capability that devtool does not hold. Spending imports await a multi-seed
//! keystore.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use zcash_client_sqlite::zewif::ZewifImportError;
use zcash_protocol::consensus::BlockHeight;

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

/// The chain state to attach to an account whose document birthday lacked
/// one, keyed in [`BirthdayEnrichments`] by (wallet index, account index).
pub(crate) struct AccountEnrichment {
    /// The tree state as of the block prior to the account's birthday height.
    pub(crate) chain_state: ::zewif::ChainState,
    /// The chain tip at import time, below which no new outputs are expected.
    pub(crate) recover_until: BlockHeight,
}

/// Per-account birthday chain states fetched from the server, keyed by
/// (wallet index, account index) within the source document.
pub(crate) type BirthdayEnrichments = HashMap<(usize, usize), AccountEnrichment>;

/// Rebuilds `document` for a view-only import.
///
/// The result carries no secret store (an encrypted store is dropped without
/// being decrypted), and every account's purpose is set to `ViewOnly`, so the
/// importer cannot record spending capability the wallet does not hold.
/// Accounts with an entry in `enrichments` additionally receive the fetched
/// birthday chain state and recover-until height. Wallets, address books,
/// extensions, and the full transaction table are carried through unchanged.
pub(crate) fn prepare_document(
    document: &::zewif::Zewif,
    enrichments: &BirthdayEnrichments,
) -> ::zewif::Zewif {
    let mut out = ::zewif::Zewif::new(
        document.export_height(),
        document.export_height_block_hash(),
    );

    for (w, wallet) in document.wallets().iter().enumerate() {
        let mut out_wallet = ::zewif::ZewifWallet::new(wallet.network().clone());
        for (a, account) in wallet.accounts().iter().enumerate() {
            let mut account = account.clone();
            account.set_purpose(::zewif::AccountPurpose::ViewOnly);
            if let Some(enrichment) = enrichments.get(&(w, a)) {
                account.set_birthday_chain_state(enrichment.chain_state.clone());
                account.set_recover_until_height(::zewif::BlockHeight::from(u32::from(
                    enrichment.recover_until,
                )));
            }
            out_wallet.add_account(account);
        }
        for entry in wallet.address_book() {
            out_wallet.add_address_book_entry(entry.clone());
        }
        *out_wallet.extensions_mut() = wallet.extensions().clone();
        out.add_wallet(out_wallet);
    }

    out.set_transactions(document.transactions().clone());
    if let Some(export_id) = document.export_id() {
        out.set_export_id(*export_id);
    }
    if let Some(schema) = document.embedded_schema() {
        out.set_embedded_schema(schema);
    }
    *out.extensions_mut() = document.extensions().clone();
    out
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

    /// A plaintext secret store holding one mnemonic seed.
    fn plain_secrets() -> ::zewif::Secrets {
        let mut store = ::zewif::SecretStore::new();
        store.add_seed(::zewif::SeedEntry::new(
            ::zewif::SeedFingerprint::new("test-fingerprint".to_string()),
            ::zewif::SeedMaterial::Bip39Mnemonic(::zewif::Bip39Mnemonic::new(
                <Mnemonic<English>>::from_entropy([0xAB; 32])
                    .unwrap()
                    .phrase(),
                None,
            )),
        ));
        ::zewif::Secrets::Plain(store)
    }

    #[test]
    fn prepare_strips_plain_secrets() {
        let mut doc = document(vec![ufvk_account("plain")]);
        doc.set_secrets(plain_secrets());

        let prepared = prepare_document(&doc, &HashMap::new());
        assert!(prepared.secrets().is_none());
        // Everything else is carried through.
        assert_eq!(prepared.wallets().len(), 1);
        assert_eq!(prepared.wallets()[0].accounts().len(), 1);
        assert_eq!(prepared.export_height(), doc.export_height());
    }

    #[test]
    fn prepare_strips_encrypted_secrets_without_decryption() {
        let mut doc = document(vec![ufvk_account("encrypted")]);
        doc.set_secrets(::zewif::Secrets::Encrypted(::zewif::EncryptedStore::new(
            ::zewif::Data::from_vec(vec![0u8; 16]),
        )));

        let prepared = prepare_document(&doc, &HashMap::new());
        assert!(prepared.secrets().is_none());
    }

    #[test]
    fn prepare_normalizes_purpose_to_view_only() {
        let mut account = ufvk_account("spending");
        account.set_purpose(::zewif::AccountPurpose::Spending);
        let doc = document(vec![account]);

        let prepared = prepare_document(&doc, &HashMap::new());
        assert_eq!(
            prepared.wallets()[0].accounts()[0].purpose(),
            Some(::zewif::AccountPurpose::ViewOnly),
        );
    }

    #[test]
    fn prepare_applies_birthday_enrichment() {
        let doc = document(vec![ufvk_account("enriched")]);

        let mut chain_state = ::zewif::ChainState::new(::zewif::BlockHeight::from(2_599_999u32));
        chain_state.set_block_hash(::zewif::BlockHash::from_bytes([0xBB; 32]));
        chain_state.set_sapling_tree(::zewif::Frontier::Empty);
        chain_state.set_orchard_tree(::zewif::Frontier::Empty);
        let enrichments = HashMap::from([(
            (0, 0),
            AccountEnrichment {
                chain_state,
                recover_until: BlockHeight::from_u32(3_000_000),
            },
        )]);

        let prepared = prepare_document(&doc, &enrichments);
        let account = &prepared.wallets()[0].accounts()[0];
        assert_eq!(
            account
                .birthday_chain_state()
                .map(|cs| u32::from(cs.height())),
            Some(2_599_999),
        );
        assert_eq!(
            account.recover_until_height().map(u32::from),
            Some(3_000_000)
        );
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
