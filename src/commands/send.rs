#![allow(deprecated)]
use std::{num::NonZeroUsize, str::FromStr};

use anyhow::anyhow;
use gumdrop::Options;
use secrecy::ExposeSecret;

use zcash_address::ZcashAddress;
use zcash_client_backend::{
    data_api::{
        wallet::{
            create_proposed_transactions, input_selection::GreedyInputSelector, propose_transfer,
        },
        Account, AccountSource, WalletRead,
    },
    fees::{standard::MultiOutputChangeStrategy, DustOutputPolicy, SplitPolicy, StandardFeeRule},
    keys::UnifiedSpendingKey,
    proto::service,
    wallet::OvkPolicy,
    ShieldedProtocol,
};
use zcash_client_sqlite::WalletDb;
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::value::Zatoshis;
use zip321::{Payment, TransactionRequest};

use crate::{
    config::WalletConfig,
    data::get_db_paths,
    error,
    remote::{tor_client, Servers},
    MIN_CONFIRMATIONS,
};

// Options accepted for the `send` command
#[derive(Debug, Options)]
pub(crate) struct Command {
    #[options(help = "age identity file to decrypt the mnemonic phrase with")]
    identity: String,

    #[options(
        required,
        help = "the recipient's Unified, Sapling or transparent address"
    )]
    address: String,

    #[options(required, help = "the amount in zatoshis")]
    value: u64,

    #[options(
        help = "the server to send via (default is \"ecc\")",
        default = "ecc",
        parse(try_from_str = "Servers::parse")
    )]
    server: Servers,

    #[options(help = "disable connections via TOR")]
    disable_tor: bool,

    #[options(
        help = "note management: the number of notes to maintain in the wallet",
        default = "4"
    )]
    target_note_count: usize,

    #[options(
        help = "note management: the minimum allowed value for split change amounts",
        default = "10000000"
    )]
    min_split_output_value: u64,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let mut config = WalletConfig::read(wallet_dir.as_ref())?;
        let params = config.network();

        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let mut db_data = WalletDb::for_path(db_data, params)?;
        let account_id = *db_data
            .get_account_ids()?
            .first()
            .ok_or(anyhow!("Wallet has no accounts"))?;
        let account = db_data
            .get_account(account_id)?
            .ok_or(anyhow!("Account missing: {:?}", account_id))?;
        let account_index = match account.source() {
            AccountSource::Derived { account_index, .. } => account_index,
            AccountSource::Imported { .. } => {
                unreachable!("Imported accounts are not yet supported.")
            }
        };

        // Decrypt the mnemonic to access the seed.
        let identities = age::IdentityFile::from_file(self.identity)?.into_identities()?;
        config.decrypt(identities.iter().map(|i| i.as_ref() as _))?;

        let usk = UnifiedSpendingKey::from_seed(
            &params,
            config
                .seed()
                .ok_or(anyhow!("Seed must be present to enable sending"))?
                .expose_secret(),
            account_index,
        )
        .map_err(error::Error::from)?;

        let server = self.server.pick(params)?;
        let mut client = if self.disable_tor {
            server.connect_direct().await?
        } else {
            server.connect(|| tor_client(wallet_dir.as_ref())).await?
        };

        // Create the transaction.
        println!("Creating transaction...");
        let prover =
            LocalTxProver::with_default_location().ok_or(error::Error::MissingParameters)?;
        let change_strategy = MultiOutputChangeStrategy::new(
            StandardFeeRule::Zip317,
            None,
            ShieldedProtocol::Orchard,
            DustOutputPolicy::default(),
            SplitPolicy::with_min_output_value(
                NonZeroUsize::new(self.target_note_count)
                    .ok_or(anyhow!("target note count must be nonzero"))?,
                Zatoshis::from_u64(self.min_split_output_value)?,
            ),
        );
        let input_selector = GreedyInputSelector::new();

        let request = TransactionRequest::new(vec![Payment::without_memo(
            ZcashAddress::from_str(&self.address).map_err(|_| error::Error::InvalidRecipient)?,
            Zatoshis::from_u64(self.value).map_err(|_| error::Error::InvalidAmount)?,
        )])
        .map_err(error::Error::from)?;

        let proposal = propose_transfer(
            &mut db_data,
            &params,
            account.id(),
            &input_selector,
            &change_strategy,
            request,
            MIN_CONFIRMATIONS,
        )
        .map_err(error::Error::from)?;

        let txids = create_proposed_transactions(
            &mut db_data,
            &params,
            &prover,
            &prover,
            &usk,
            OvkPolicy::Sender,
            &proposal,
        )
        .map_err(error::Error::from)?;

        if txids.len() > 1 {
            return Err(anyhow!(
                "Multi-transaction proposals are not yet supported."
            ));
        }

        let txid = *txids.first();

        // Send the transaction.
        println!("Sending transaction...");
        let (txid, raw_tx) = db_data
            .get_transaction(txid)?
            .map(|tx| {
                let mut raw_tx = service::RawTransaction::default();
                tx.write(&mut raw_tx.data).unwrap();
                (tx.txid(), raw_tx)
            })
            .ok_or(anyhow!("Transaction not found for id {:?}", txid))?;
        let response = client.send_transaction(raw_tx).await?.into_inner();

        if response.error_code != 0 {
            Err(error::Error::SendFailed {
                code: response.error_code,
                reason: response.error_message,
            }
            .into())
        } else {
            println!("{}", txid);
            Ok(())
        }
    }
}
