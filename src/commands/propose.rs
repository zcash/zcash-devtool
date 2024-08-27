use std::str::FromStr;

use anyhow::anyhow;
use gumdrop::Options;

use zcash_address::ZcashAddress;
use zcash_client_backend::{
    data_api::{
        wallet::{input_selection::GreedyInputSelector, propose_transfer},
        InputSource, WalletRead,
    },
    fees::standard::SingleOutputChangeStrategy,
    ShieldedProtocol,
};
use zcash_primitives::transaction::{components::amount::NonNegativeAmount, fees::StandardFeeRule};
use zip321::{Payment, TransactionRequest};

use crate::{data::get_wallet_network, error, MIN_CONFIRMATIONS};

#[derive(Clone, Copy, Debug, Default)]
pub(crate) enum FeeRule {
    Fixed,
    #[default]
    Zip317,
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
    pub(crate) async fn run<W>(
        self,
        wallet_dir: Option<String>,
        db_data: &mut W,
    ) -> Result<(), anyhow::Error>
    where
        W: WalletRead
            + InputSource<Error = <W as WalletRead>::Error, AccountId = <W as WalletRead>::AccountId>,
        <W as WalletRead>::Error: std::error::Error + Send + Sync + 'static,
        <W as InputSource>::NoteRef: Copy + Eq + Ord,
    {
        let params = get_wallet_network(wallet_dir.as_ref())?;

        let account = *db_data
            .get_account_ids()?
            .first()
            .ok_or_else(|| anyhow!("Wallet has no accounts."))?;

        let input_selector = GreedyInputSelector::new(
            SingleOutputChangeStrategy::new(self.fee_rule.into(), None, ShieldedProtocol::Orchard),
            Default::default(),
        );

        let request = TransactionRequest::new(vec![Payment::without_memo(
            ZcashAddress::from_str(&self.address).map_err(|_| error::Error::InvalidRecipient)?,
            NonNegativeAmount::from_u64(self.value).map_err(|_| error::Error::InvalidAmount)?,
        )])
        .map_err(error::Error::from)?;

        let proposal = propose_transfer::<_, _, _, <W as InputSource>::Error>(
            db_data,
            &params,
            account,
            &input_selector,
            request,
            MIN_CONFIRMATIONS,
        )
        .unwrap();

        // Display the proposal
        println!("Proposal: {:#?}", proposal);

        Ok(())
    }
}
