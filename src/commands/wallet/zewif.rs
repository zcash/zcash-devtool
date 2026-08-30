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
use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters};

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

/// Estimates a conservative birthday height for accounts that record none,
/// from the heights of the document's own transactions.
///
/// Expiry heights are typically near the height at which a transaction was
/// created (zcashd's default expiry delta is 40 blocks); subtracting a
/// 1000-block margin from the minimum known height gives a lower bound that
/// cannot skip wallet history. A zero expiry height means "does not expire"
/// and carries no height information.
pub(crate) fn estimate_birthday_height(
    document: &::zewif::Zewif,
    sapling_activation: BlockHeight,
) -> BlockHeight {
    document
        .transactions()
        .values()
        .filter_map(|tx| {
            tx.mined_height()
                .map(u32::from)
                .or_else(|| tx.expiry_height().map(u32::from).filter(|&h| h > 0))
        })
        .min()
        .map(|h| BlockHeight::from_u32(h.saturating_sub(1000)))
        .map_or(sapling_activation, |h| h.max(sapling_activation))
}

/// Computes the earliest account birthday height in the (prepared) document,
/// for use as the wallet config's birthday.
///
/// A recorded chain state describes the block *prior* to the birthday, so its
/// height plus one is the birthday. Accounts without any birthday information
/// contribute Sapling activation (matching the importer's fallback). An
/// account-less document falls back to its export height.
pub(crate) fn min_birthday_height<P: Parameters>(
    params: &P,
    document: &::zewif::Zewif,
) -> BlockHeight {
    let sapling_activation = params
        .activation_height(NetworkUpgrade::Sapling)
        .unwrap_or_else(|| BlockHeight::from_u32(0));
    document
        .wallets()
        .iter()
        .flat_map(|wallet| wallet.accounts())
        .map(|account| {
            account
                .birthday_chain_state()
                .map(|cs| BlockHeight::from_u32(u32::from(cs.height()) + 1))
                .or_else(|| {
                    account
                        .birthday_height()
                        .map(|h| BlockHeight::from_u32(u32::from(h)))
                })
                .unwrap_or(sapling_activation)
        })
        .min()
        .unwrap_or_else(|| BlockHeight::from_u32(u32::from(document.export_height())))
        .max(sapling_activation)
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
    fn birthday_estimate_uses_min_tx_height_with_margin() {
        let mut doc = document(vec![ufvk_account("est")]);
        let mut mined = ::zewif::Transaction::new(::zewif::TxId::from_bytes([1; 32]));
        mined.set_mined_height(::zewif::BlockHeight::from(2_500_000u32));
        doc.add_transaction(mined.txid(), mined);
        let mut unmined = ::zewif::Transaction::new(::zewif::TxId::from_bytes([2; 32]));
        unmined.set_expiry_height(::zewif::BlockHeight::from(2_450_000u32));
        doc.add_transaction(unmined.txid(), unmined);

        let sapling = BlockHeight::from_u32(280_000);
        assert_eq!(
            estimate_birthday_height(&doc, sapling),
            BlockHeight::from_u32(2_449_000), // min(2_500_000, 2_450_000) - 1000
        );
    }

    #[test]
    fn birthday_estimate_ignores_zero_expiry_and_clamps_to_sapling() {
        let mut doc = document(vec![ufvk_account("est2")]);
        let mut zero_expiry = ::zewif::Transaction::new(::zewif::TxId::from_bytes([3; 32]));
        zero_expiry.set_expiry_height(::zewif::BlockHeight::from(0u32));
        doc.add_transaction(zero_expiry.txid(), zero_expiry);

        let sapling = BlockHeight::from_u32(280_000);
        // A zero expiry height carries no information; with no usable
        // transaction heights the estimate falls back to Sapling activation.
        assert_eq!(estimate_birthday_height(&doc, sapling), sapling);

        let mut early = ::zewif::Transaction::new(::zewif::TxId::from_bytes([4; 32]));
        early.set_mined_height(::zewif::BlockHeight::from(280_500u32));
        let mut doc = document(vec![ufvk_account("est3")]);
        doc.add_transaction(early.txid(), early);
        // 280_500 - 1000 clamps up to Sapling activation.
        assert_eq!(estimate_birthday_height(&doc, sapling), sapling);
    }

    #[test]
    fn min_birthday_height_prefers_chain_state_then_height() {
        let mut with_cs = ufvk_account("cs");
        let mut chain_state = ::zewif::ChainState::new(::zewif::BlockHeight::from(2_499_999u32));
        chain_state.set_block_hash(::zewif::BlockHash::from_bytes([0xCC; 32]));
        with_cs.set_birthday_chain_state(chain_state);
        // ufvk_account sets birthday_height 2_600_000 on both accounts; the
        // chain state (birthday 2_500_000) takes precedence on the first.
        let doc = document(vec![with_cs, ufvk_account("height")]);

        assert_eq!(
            min_birthday_height(&Network::Test, &doc),
            BlockHeight::from_u32(2_500_000),
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
