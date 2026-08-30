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

use rand::rngs::OsRng;
use tonic::transport::Channel;

use zcash_client_backend::{
    data_api::chain::ChainState,
    proto::service::{self, compact_tx_streamer_client::CompactTxStreamerClient},
};
use zcash_client_sqlite::{
    WalletDb,
    util::SystemClock,
    zewif::{DiscardSecrets, ZewifImportError, ZewifImportReport},
};
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

/// Returns the network the document's wallets were recorded for.
///
/// The container carries the network per wallet; the first wallet's network
/// identifies the document (the importer separately verifies that *every*
/// wallet matches the wallet database's parameters).
pub(crate) fn document_network(
    document: &::zewif::Zewif,
) -> Result<&::zewif::Network, ZewifCommandError> {
    document
        .wallets()
        .first()
        .map(|wallet| wallet.network())
        .ok_or(ZewifCommandError::NoWallets)
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

/// Server-derived data with which to enrich a document before import.
#[derive(Default)]
pub(crate) struct DocumentEnrichments {
    /// Birthday chain states for accounts that lack them.
    pub(crate) birthdays: BirthdayEnrichments,
    /// Mined heights resolved for transactions that record none, keyed by
    /// txid.
    pub(crate) tx_mined_heights: HashMap<::zewif::TxId, BlockHeight>,
}

/// A document rebuilt for import, along with what the rebuild had to leave
/// behind.
pub(crate) struct PreparedDocument {
    pub(crate) document: ::zewif::Zewif,
    /// Transactions omitted because the importer cannot interpret them: with
    /// no mined height (after enrichment) and no expiry height, a
    /// transaction's consensus branch ID — and thus its parse — is
    /// undetermined.
    pub(crate) transactions_dropped: usize,
}

/// Rebuilds `document` for a view-only import.
///
/// The result carries no secret store (an encrypted store is dropped without
/// being decrypted), and every account's purpose is set to `ViewOnly`, so the
/// importer cannot record spending capability the wallet does not hold.
/// Accounts and transactions with entries in `enrichments` additionally
/// receive the fetched birthday chain states and resolved mined heights.
/// Transactions left with neither a mined height nor an expiry height are
/// omitted (and counted): the importer cannot determine the consensus branch
/// ID under which to parse them, and would abort the entire import. Wallets,
/// address books, and extensions are carried through unchanged.
pub(crate) fn prepare_document(
    document: &::zewif::Zewif,
    enrichments: &DocumentEnrichments,
) -> PreparedDocument {
    let mut out = ::zewif::Zewif::new(
        document.export_height(),
        document.export_height_block_hash(),
    );

    for (w, wallet) in document.wallets().iter().enumerate() {
        let mut out_wallet = ::zewif::ZewifWallet::new(wallet.network().clone());
        for (a, account) in wallet.accounts().iter().enumerate() {
            let mut account = account.clone();
            account.set_purpose(::zewif::AccountPurpose::ViewOnly);
            if let Some(enrichment) = enrichments.birthdays.get(&(w, a)) {
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

    let mut transactions_dropped = 0;
    let transactions = document
        .transactions()
        .iter()
        .filter_map(|(txid, tx)| {
            let mut tx = tx.clone();
            if tx.mined_height().is_none()
                && let Some(height) = enrichments.tx_mined_heights.get(txid)
            {
                tx.set_mined_height(::zewif::BlockHeight::from(u32::from(*height)));
            }
            let has_expiry = tx.expiry_height().map(u32::from).unwrap_or(0) > 0;
            if tx.mined_height().is_none() && !has_expiry {
                transactions_dropped += 1;
                None
            } else {
                Some((*txid, tx))
            }
        })
        .collect();
    out.set_transactions(transactions);

    if let Some(export_id) = document.export_id() {
        out.set_export_id(*export_id);
    }
    if let Some(schema) = document.embedded_schema() {
        out.set_embedded_schema(schema);
    }
    *out.extensions_mut() = document.extensions().clone();
    PreparedDocument {
        document: out,
        transactions_dropped,
    }
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

/// Converts an `incrementalmerkletree` frontier into its ZeWIF representation.
fn to_zewif_frontier<H, const DEPTH: u8>(
    frontier: &incrementalmerkletree::frontier::Frontier<H, DEPTH>,
    node_bytes: impl Fn(&H) -> [u8; 32],
) -> ::zewif::Frontier {
    match frontier.value() {
        None => ::zewif::Frontier::Empty,
        Some(frontier) => ::zewif::Frontier::NonEmpty(::zewif::FrontierData::from_parts(
            u64::from(frontier.position()),
            ::zewif::MerkleNode::new(node_bytes(frontier.leaf())),
            frontier
                .ommers()
                .iter()
                .map(|ommer| ::zewif::MerkleNode::new(node_bytes(ommer)))
                .collect(),
        )),
    }
}

/// Converts a `ChainState` into its ZeWIF representation, preserving the note
/// commitment tree frontiers of every shielded pool.
fn to_zewif_chain_state(chain_state: &ChainState) -> ::zewif::ChainState {
    let mut out = ::zewif::ChainState::new(::zewif::BlockHeight::from(u32::from(
        chain_state.block_height(),
    )));
    out.set_block_hash(::zewif::BlockHash::from_bytes(chain_state.block_hash().0));
    out.set_sapling_tree(to_zewif_frontier(
        chain_state.final_sapling_tree(),
        |node| node.to_bytes(),
    ));
    out.set_orchard_tree(to_zewif_frontier(
        chain_state.final_orchard_tree(),
        |node| node.to_bytes(),
    ));
    out.set_ironwood_tree(to_zewif_frontier(
        chain_state.final_ironwood_tree(),
        |node| node.to_bytes(),
    ));
    out
}

/// Fetches, from the connected lightwalletd server, the mined heights of
/// transactions that record none and birthday chain states for accounts that
/// lack them.
///
/// zcashd records a mined height only for transactions that touched the
/// Orchard commitment tree, so most of a document's transactions arrive
/// without one; each such transaction is resolved by txid. A transaction the
/// server does not know (never mined, or mined on a non-main-chain block)
/// stays unresolved; so does one the server fails to serve, counted and
/// reported as a warning rather than failing the import.
///
/// For accounts, the birthday is the account's recorded birthday height where
/// present, and otherwise a conservative estimate from the document's
/// transactions (see [`estimate_birthday_height`]). The tree state is fetched
/// as of the block prior to the birthday. An account whose birthday does not
/// exceed Sapling activation is left for the importer's own fallback (the
/// server cannot serve tree states below Sapling activation). The
/// recover-until height is the current chain tip.
///
/// NOTE: THIS APPROACH LEAKS THE WALLET'S TRANSACTION IDS AND ACCOUNT
/// BIRTHDAYS TO THE SERVER!
pub(crate) async fn fetch_enrichments<P: Parameters>(
    client: &mut CompactTxStreamerClient<Channel>,
    params: &P,
    document: &::zewif::Zewif,
) -> Result<DocumentEnrichments, ZewifCommandError> {
    let sapling_activation = params
        .activation_height(NetworkUpgrade::Sapling)
        .ok_or(ZewifCommandError::SaplingActivationUnknown)?;
    let chain_tip: u32 = client
        .get_latest_block(service::ChainSpec::default())
        .await
        .map_err(ZewifCommandError::Rpc)?
        .into_inner()
        .height
        .try_into()
        .expect("block heights must fit into u32");

    let mut tx_mined_heights = HashMap::new();
    let mut tx_lookup_failures = 0usize;
    for (txid, tx) in document.transactions() {
        if tx.mined_height().is_some() {
            continue;
        }
        let filter = service::TxFilter {
            hash: txid.as_bytes().to_vec(),
            ..Default::default()
        };
        match client.get_transaction(filter).await {
            Ok(response) => {
                let raw = response.into_inner();
                // A zero or negative height means the transaction is known
                // but not mined in the main chain.
                if let Ok(height) = u32::try_from(raw.height)
                    && height > 0
                {
                    tx_mined_heights.insert(*txid, BlockHeight::from_u32(height));
                }
            }
            Err(status) if status.code() == tonic::Code::NotFound => {}
            // Servers are inconsistent in how they report unknown
            // transactions; treat any other failure as unresolved rather
            // than failing the whole import.
            Err(_) => tx_lookup_failures += 1,
        }
    }
    if tx_lookup_failures > 0 {
        println!(
            "WARNING: the server failed to answer {tx_lookup_failures} transaction lookup(s); \
             the affected transactions are treated as unmined",
        );
    }

    let mut enrichments = BirthdayEnrichments::new();
    for (w, wallet) in document.wallets().iter().enumerate() {
        for (a, account) in wallet.accounts().iter().enumerate() {
            if account.birthday_chain_state().is_some() {
                continue;
            }
            let birthday_height = account
                .birthday_height()
                .map(|h| BlockHeight::from_u32(u32::from(h)))
                .unwrap_or_else(|| estimate_birthday_height(document, sapling_activation))
                .max(sapling_activation);
            if birthday_height <= sapling_activation {
                continue;
            }
            let request = service::BlockId {
                height: u64::from(u32::from(birthday_height) - 1),
                ..Default::default()
            };
            let treestate = client
                .get_tree_state(request)
                .await
                .map_err(ZewifCommandError::Rpc)?
                .into_inner();
            let chain_state = treestate
                .to_chain_state()
                .map_err(ZewifCommandError::InvalidTreeState)?;
            enrichments.insert(
                (w, a),
                AccountEnrichment {
                    chain_state: to_zewif_chain_state(&chain_state),
                    recover_until: BlockHeight::from_u32(chain_tip),
                },
            );
        }
    }
    Ok(DocumentEnrichments {
        birthdays: enrichments,
        tx_mined_heights,
    })
}

/// Prints a human-readable summary of an import report on stdout, including a
/// `WARNING:` line for each item the importer could not represent.
fn print_report(report: &ZewifImportReport) {
    println!("Imported {} account(s):", report.imported_accounts.len());
    for account in &report.imported_accounts {
        println!(
            "  - '{}' as {:?} (birthday basis: {:?})",
            account.name, account.account_uuid, account.birthday_basis,
        );
    }
    for skipped in &report.skipped_accounts {
        println!(
            "WARNING: account '{}' was not imported: {:?}",
            skipped.name, skipped.reason,
        );
    }
    if report.redeem_scripts_registered > 0 {
        println!(
            "Registered {} P2SH redeem scripts",
            report.redeem_scripts_registered,
        );
    }
    if report.redeem_scripts_not_representable > 0 {
        println!(
            "WARNING: skipped {} watch-only redeem scripts that the wallet cannot represent",
            report.redeem_scripts_not_representable,
        );
    }
    println!(
        "Marked {} transparent address(es) with document-recorded exposures as exposed",
        report.addresses_marked_exposed,
    );
    if report.transactions_stored > 0 || report.transactions_without_wallet_relevance > 0 {
        println!(
            "Stored {} wallet transaction(s) ({} were not relevant to any imported account)",
            report.transactions_stored, report.transactions_without_wallet_relevance,
        );
    }
    if report.transactions_without_raw_data > 0 {
        println!(
            "WARNING: {} transaction(s) carried no raw data and were not stored",
            report.transactions_without_raw_data,
        );
    }
    if report.address_book_entries_not_imported > 0 {
        println!(
            "WARNING: the document's address book ({} entries) was not imported; \
             devtool does not store address book entries.",
            report.address_book_entries_not_imported,
        );
    }
}

/// Imports a prepared (view-only) ZeWIF document into the wallet database,
/// printing the import report.
///
/// A document containing no accounts, or from which the importer could import
/// none, is an error; accounts the importer skips are itemized warnings —
/// nothing spendable can be lost by a view-only import, and the source file
/// remains authoritative.
pub(crate) fn import_prepared<P: Parameters>(
    db_data: &mut WalletDb<rusqlite::Connection, P, SystemClock, OsRng>,
    document: &::zewif::Zewif,
) -> Result<ZewifImportReport, ZewifCommandError> {
    let document_account_count: usize = document
        .wallets()
        .iter()
        .map(|wallet| wallet.accounts().len())
        .sum();
    if document_account_count == 0 {
        return Err(ZewifCommandError::NoAccounts);
    }

    let report = zcash_client_sqlite::zewif::import_wallet(db_data, document, &mut DiscardSecrets)
        .map_err(ZewifCommandError::Import)?;
    print_report(&report);

    if report.imported_accounts.is_empty() {
        return Err(ZewifCommandError::NothingImported {
            document_account_count,
        });
    }
    Ok(report)
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

        let prepared = prepare_document(&doc, &DocumentEnrichments::default()).document;
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

        let prepared = prepare_document(&doc, &DocumentEnrichments::default()).document;
        assert!(prepared.secrets().is_none());
    }

    #[test]
    fn prepare_normalizes_purpose_to_view_only() {
        let mut account = ufvk_account("spending");
        account.set_purpose(::zewif::AccountPurpose::Spending);
        let doc = document(vec![account]);

        let prepared = prepare_document(&doc, &DocumentEnrichments::default()).document;
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
        let enrichments = DocumentEnrichments {
            birthdays: HashMap::from([(
                (0, 0),
                AccountEnrichment {
                    chain_state,
                    recover_until: BlockHeight::from_u32(3_000_000),
                },
            )]),
            tx_mined_heights: HashMap::new(),
        };

        let prepared = prepare_document(&doc, &enrichments).document;
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
    fn prepare_backfills_resolved_mined_heights() {
        let mut doc = document(vec![ufvk_account("backfill")]);
        let mut tx = ::zewif::Transaction::new(::zewif::TxId::from_bytes([7; 32]));
        tx.set_expiry_height(::zewif::BlockHeight::from(0u32));
        let txid = tx.txid();
        doc.add_transaction(txid, tx);

        let enrichments = DocumentEnrichments {
            birthdays: HashMap::new(),
            tx_mined_heights: HashMap::from([(txid, BlockHeight::from_u32(1_500_000))]),
        };
        let prepared = prepare_document(&doc, &enrichments);
        assert_eq!(prepared.transactions_dropped, 0);
        assert_eq!(
            prepared
                .document
                .get_transaction(txid)
                .and_then(|tx| tx.mined_height())
                .map(u32::from),
            Some(1_500_000),
        );
    }

    #[test]
    fn prepare_drops_unparseable_transactions() {
        let mut doc = document(vec![ufvk_account("dropper")]);
        // Neither a mined height nor an expiry height: the importer cannot
        // determine the consensus branch ID for this transaction.
        let unparseable = ::zewif::Transaction::new(::zewif::TxId::from_bytes([8; 32]));
        let dropped_txid = unparseable.txid();
        doc.add_transaction(dropped_txid, unparseable);
        // An expiry height suffices.
        let mut with_expiry = ::zewif::Transaction::new(::zewif::TxId::from_bytes([9; 32]));
        with_expiry.set_expiry_height(::zewif::BlockHeight::from(2_400_000u32));
        let kept_txid = with_expiry.txid();
        doc.add_transaction(kept_txid, with_expiry);

        let prepared = prepare_document(&doc, &DocumentEnrichments::default());
        assert_eq!(prepared.transactions_dropped, 1);
        assert!(prepared.document.get_transaction(dropped_txid).is_none());
        assert!(prepared.document.get_transaction(kept_txid).is_some());
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

    use rand::rngs::OsRng;
    use zcash_client_backend::data_api::{
        Account as _, AccountPurpose, AccountSource, WalletRead as _,
    };
    use zcash_client_sqlite::{WalletDb, util::SystemClock, wallet::init::init_wallet_db};

    /// An initialized wallet database over a fresh temporary directory. The
    /// directory (returned for cleanup) holds the SQLite file.
    fn test_wallet_db(
        name: &str,
    ) -> (
        std::path::PathBuf,
        WalletDb<rusqlite::Connection, Network, SystemClock, OsRng>,
    ) {
        let dir =
            std::env::temp_dir().join(format!("devtool-zewif-db-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut db =
            WalletDb::for_path(dir.join("data.sqlite"), Network::Test, SystemClock, OsRng).unwrap();
        init_wallet_db(&mut db, None).unwrap();
        (dir, db)
    }

    #[test]
    fn view_only_account_imports() {
        let (dir, mut db) = test_wallet_db("view-only");
        let doc = document(vec![ufvk_account("primary")]);

        let prepared = prepare_document(&doc, &DocumentEnrichments::default()).document;
        let report = import_prepared(&mut db, &prepared).unwrap();
        assert_eq!(report.imported_accounts.len(), 1);

        let account_uuid = report.imported_accounts[0].account_uuid;
        let imported = db.get_account(account_uuid).unwrap().unwrap();
        assert!(matches!(
            imported.source(),
            AccountSource::Imported {
                purpose: AccountPurpose::ViewOnly,
                ..
            }
        ));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn spending_purpose_document_imports_view_only() {
        // The capability invariant: a document that carries secrets and marks
        // its account for spending must still come out view-only.
        let (dir, mut db) = test_wallet_db("spending-doc");
        let mut account = ufvk_account("spending");
        account.set_purpose(::zewif::AccountPurpose::Spending);
        let mut doc = document(vec![account]);
        doc.set_secrets(plain_secrets());

        let prepared = prepare_document(&doc, &DocumentEnrichments::default()).document;
        let report = import_prepared(&mut db, &prepared).unwrap();
        assert_eq!(report.imported_accounts.len(), 1);

        let account_uuid = report.imported_accounts[0].account_uuid;
        let imported = db.get_account(account_uuid).unwrap().unwrap();
        assert!(matches!(
            imported.source(),
            AccountSource::Imported {
                purpose: AccountPurpose::ViewOnly,
                ..
            }
        ));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn document_without_accounts_is_rejected() {
        let (dir, mut db) = test_wallet_db("no-accounts");
        let doc = document(vec![]);

        let prepared = prepare_document(&doc, &DocumentEnrichments::default()).document;
        assert!(matches!(
            import_prepared(&mut db, &prepared),
            Err(ZewifCommandError::NoAccounts),
        ));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn nothing_imported_is_an_error() {
        let (dir, mut db) = test_wallet_db("nothing-imported");
        // A transparent-address-set account has no viewing key and no seed in
        // a view-only import, so the importer skips it.
        let mut account = ::zewif::Account::new(::zewif::AccountViewingKey::TransparentAddressSet);
        account.set_name("taddrs-only");
        let doc = document(vec![account]);

        let prepared = prepare_document(&doc, &DocumentEnrichments::default()).document;
        assert!(matches!(
            import_prepared(&mut db, &prepared),
            Err(ZewifCommandError::NothingImported {
                document_account_count: 1,
            }),
        ));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn offline_file_to_wallet_end_to_end() {
        let (dir, mut db) = test_wallet_db("end-to-end");
        let mut doc = document(vec![ufvk_account("e2e")]);
        doc.set_secrets(plain_secrets());
        let path = dir.join("wallet.zewif");
        std::fs::write(&path, doc.to_bytes().unwrap()).unwrap();

        let document = read_zewif_file(&path).unwrap();
        let prepared = prepare_document(&document, &DocumentEnrichments::default()).document;
        let report = import_prepared(&mut db, &prepared).unwrap();
        assert_eq!(report.imported_accounts.len(), 1);
        assert_eq!(
            db.get_wallet_birthday().unwrap(),
            Some(BlockHeight::from_u32(2_600_000)),
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn frontier_conversion() {
        use incrementalmerkletree::Hashable as _;
        use incrementalmerkletree::frontier::Frontier;

        let empty: Frontier<::sapling::Node, 32> = Frontier::empty();
        assert!(matches!(
            to_zewif_frontier(&empty, |n| n.to_bytes()),
            ::zewif::Frontier::Empty,
        ));

        let leaf = ::sapling::Node::empty_root(incrementalmerkletree::Level::from(0));
        let frontier =
            Frontier::<::sapling::Node, 32>::from_parts(0u64.into(), leaf, vec![]).unwrap();
        match to_zewif_frontier(&frontier, |n| n.to_bytes()) {
            ::zewif::Frontier::NonEmpty(data) => {
                assert_eq!(data.position(), 0);
                assert_eq!(data.leaf().as_bytes(), &leaf.to_bytes());
                assert!(data.ommers().is_empty());
            }
            ::zewif::Frontier::Empty => panic!("expected a non-empty frontier"),
        }
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
