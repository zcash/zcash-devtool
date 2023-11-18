use gumdrop::Options;

use zcash_client_backend::{
    address::RecipientAddress,
    data_api::wallet::{input_selection::GreedyInputSelector, propose_transfer},
    fees::standard::SingleOutputChangeStrategy,
    zip321::{Payment, TransactionRequest},
};
use zcash_client_sqlite::WalletDb;
use zcash_primitives::{
    transaction::{components::amount::NonNegativeAmount, fees::StandardFeeRule},
    zip32::AccountId,
};

use crate::{
    data::{get_db_paths, get_wallet_network},
    error, MIN_CONFIRMATIONS,
};

#[derive(Clone, Copy, Debug)]
pub(crate) enum FeeRule {
    Fixed,
    Zip317,
}

impl Default for FeeRule {
    fn default() -> Self {
        FeeRule::Zip317
    }
}

#[allow(deprecated)]
impl From<FeeRule> for StandardFeeRule {
    fn from(rule: FeeRule) -> Self {
        match rule {
            FeeRule::Fixed => StandardFeeRule::PreZip313,
            FeeRule::Zip317 => StandardFeeRule::Zip317,
        }
    }
}

pub(crate) fn parse_fee_rule(name: &str) -> Result<FeeRule, String> {
    match name {
        "fixed" => Ok(FeeRule::Fixed),
        "zip317" => Ok(FeeRule::Zip317),
        other => Err(format!("Fee rule {} not recognized.", other)),
    }
}

// Options accepted for the `propose` command
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
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let params = get_wallet_network(wallet_dir.as_ref())?;

        let account = AccountId::from(0);
        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let mut db_data = WalletDb::for_path(db_data, params)?;

        let input_selector = GreedyInputSelector::new(
            SingleOutputChangeStrategy::new(self.fee_rule.into(), None),
            Default::default(),
        );

        let request = TransactionRequest::new(vec![Payment {
            recipient_address: RecipientAddress::decode(&params, &self.address)
                .ok_or(error::Error::InvalidRecipient)?,
            amount: NonNegativeAmount::from_u64(self.value)
                .map_err(|_| error::Error::InvalidAmount)?,
            memo: None,
            label: None,
            message: None,
            other_params: vec![],
        }])
        .map_err(error::Error::from)?;

        let proposal = propose_transfer(
            &mut db_data,
            &params,
            account,
            &input_selector,
            request,
            MIN_CONFIRMATIONS,
        )
        .map_err(error::Error::from)?;

        // Display the proposal
        println!("Proposal: {:#?}", proposal);

        Ok(())
    }
}
