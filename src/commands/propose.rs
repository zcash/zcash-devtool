use std::{num::NonZeroUsize, str::FromStr};

use anyhow::anyhow;
use gumdrop::Options;

use uuid::Uuid;
use zcash_address::ZcashAddress;
use zcash_client_backend::{
    data_api::wallet::{input_selection::GreedyInputSelector, propose_transfer},
    fees::{zip317::MultiOutputChangeStrategy, DustOutputPolicy, SplitPolicy, StandardFeeRule},
    ShieldedProtocol,
};
use zcash_client_sqlite::{AccountUuid, WalletDb};
use zcash_protocol::value::Zatoshis;
use zip321::{Payment, TransactionRequest};

use crate::{config::get_wallet_network, data::get_db_paths, error, MIN_CONFIRMATIONS};
// Options accepted for the `propose` command
#[derive(Debug, Options)]
pub(crate) struct Command {
    #[options(free, required, help = "the UUID of the account to send funds from")]
    account_id: Uuid,

    #[options(
        required,
        help = "the recipient's Unified, Sapling or transparent address"
    )]
    address: String,

    #[options(required, help = "the amount in zatoshis")]
    value: u64,

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
        let params = get_wallet_network(wallet_dir.as_ref())?;

        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let mut db_data = WalletDb::for_path(db_data, params)?;
        let account_id = AccountUuid::from_uuid(self.account_id);

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
            account_id,
            &input_selector,
            &change_strategy,
            request,
            MIN_CONFIRMATIONS,
        )
        .map_err(error::Error::from)?;

        // Display the proposal
        println!("Proposal: {:#?}", proposal);

        Ok(())
    }
}
