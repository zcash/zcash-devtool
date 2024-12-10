#![allow(deprecated)]
use std::{num::NonZeroUsize, str::FromStr};

use anyhow::anyhow;
use gumdrop::Options;

use tokio::io::{stdout, AsyncWriteExt};
use zcash_address::ZcashAddress;
use zcash_client_backend::{
    data_api::{
        wallet::{
            create_pczt_from_proposal, input_selection::GreedyInputSelector, propose_transfer,
        },
        WalletRead,
    },
    fees::{standard::MultiOutputChangeStrategy, DustOutputPolicy, SplitPolicy, StandardFeeRule},
    wallet::OvkPolicy,
    ShieldedProtocol,
};
use zcash_client_sqlite::WalletDb;
use zcash_protocol::{
    memo::{Memo, MemoBytes},
    value::Zatoshis,
};
use zip321::{Payment, TransactionRequest};

use crate::{config::WalletConfig, data::get_db_paths, error, MIN_CONFIRMATIONS};

// Options accepted for the `pczt create` command
#[derive(Debug, Options)]
pub(crate) struct Command {
    #[options(
        required,
        help = "the recipient's Unified, Sapling or transparent address"
    )]
    address: String,

    #[options(required, help = "the amount in zatoshis")]
    value: u64,

    #[options(help = "a memo to send to the recipient")]
    memo: Option<String>,

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
        let config = WalletConfig::read(wallet_dir.as_ref())?;
        let params = config.network();

        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let mut db_data = WalletDb::for_path(db_data, params)?;
        let account_id = *db_data
            .get_account_ids()?
            .first()
            .ok_or(anyhow!("Wallet has no accounts"))?;

        // Create the PCZT.
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

        let request = TransactionRequest::new(vec![Payment::new(
            ZcashAddress::from_str(&self.address).map_err(|_| error::Error::InvalidRecipient)?,
            Zatoshis::from_u64(self.value).map_err(|_| error::Error::InvalidAmount)?,
            self.memo
                .map(|memo| Memo::from_str(&memo))
                .transpose()?
                .map(MemoBytes::from),
            None,
            None,
            vec![],
        )
        .ok_or_else(|| anyhow!("Invalid memo"))?])
        .map_err(error::Error::from)?;

        let proposal = propose_transfer(
            &mut db_data,
            &params,
            account_id,
            &input_selector,
            &change_strategy,
            request,
            MIN_CONFIRMATIONS,
        )
        .map_err(error::Error::from)?;

        let pczt = create_pczt_from_proposal(
            &mut db_data,
            &params,
            account_id,
            OvkPolicy::Sender,
            &proposal,
        )
        .map_err(error::Error::from)?;

        stdout().write_all(&pczt.serialize()).await?;

        Ok(())
    }
}
