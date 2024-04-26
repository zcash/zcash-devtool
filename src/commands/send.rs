#![allow(deprecated)]
use anyhow::anyhow;
use gumdrop::Options;
use secrecy::ExposeSecret;

use zcash_client_backend::{
    data_api::{
        wallet::{input_selection::GreedyInputSelector, spend},
        Account, AccountSource, WalletRead,
    },
    fees::standard::SingleOutputChangeStrategy,
    keys::UnifiedSpendingKey,
    proto::service,
    wallet::OvkPolicy,
    zip321::{Payment, TransactionRequest},
    ShieldedProtocol,
};
use zcash_client_sqlite::WalletDb;
use zcash_keys::address::Address;
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::value::Zatoshis;

use crate::{
    commands::propose::{parse_fee_rule, FeeRule},
    data::{get_db_paths, read_keys},
    error,
    remote::{connect_to_lightwalletd, Servers},
    MIN_CONFIRMATIONS,
};

// Options accepted for the `send` command
#[derive(Debug, Options)]
pub(crate) struct Command {
    #[options(
        required,
        help = "the recipient's Unified, Sapling or transparent address"
    )]
    address: String,

    #[options(required, help = "the amount in zatoshis")]
    value: u64,

    #[options(
        required,
        help = "fee strategy: \"fixed\" or \"zip317\"",
        parse(try_from_str = "parse_fee_rule")
    )]
    fee_rule: FeeRule,

    #[options(
        help = "the server to send via (default is \"ecc\")",
        default = "ecc",
        parse(try_from_str = "Servers::parse")
    )]
    server: Servers,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let keys = read_keys(wallet_dir.as_ref())?;
        let params = keys.network();

        let (_, db_data) = get_db_paths(wallet_dir);
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
            AccountSource::Imported => unreachable!("Imported accounts are not yet supported."),
        };

        let usk =
            UnifiedSpendingKey::from_seed(&params, keys.seed().expose_secret(), account_index)
                .map_err(error::Error::from)?;

        let mut client = connect_to_lightwalletd(self.server.pick(params)?).await?;

        // Create the transaction.
        println!("Creating transaction...");
        let prover =
            LocalTxProver::with_default_location().ok_or(error::Error::MissingParameters)?;
        let input_selector = GreedyInputSelector::new(
            SingleOutputChangeStrategy::new(self.fee_rule.into(), None, ShieldedProtocol::Orchard),
            Default::default(),
        );

        let request = TransactionRequest::new(vec![Payment {
            recipient_address: Address::decode(&params, &self.address)
                .ok_or(error::Error::InvalidRecipient)?,
            amount: Zatoshis::from_u64(self.value).map_err(|_| error::Error::InvalidAmount)?,
            memo: None,
            label: None,
            message: None,
            other_params: vec![],
        }])
        .map_err(error::Error::from)?;

        let txids = spend(
            &mut db_data,
            &params,
            &prover,
            &prover,
            &input_selector,
            &usk,
            request,
            OvkPolicy::Sender,
            MIN_CONFIRMATIONS,
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
