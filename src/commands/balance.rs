use anyhow::anyhow;
use gumdrop::Options;

use zcash_client_backend::data_api::WalletRead;
use zcash_client_sqlite::WalletDb;
use zcash_primitives::{consensus::Parameters, zip32::AccountId};

use crate::{data::get_db_paths, error, ui::format_zec, MIN_CONFIRMATIONS};

// Options accepted for the `balance` command
#[derive(Debug, Options)]
pub(crate) struct Command {}

impl Command {
    pub(crate) fn run(
        self,
        params: impl Parameters + Copy + 'static,
        wallet_dir: Option<String>,
    ) -> Result<(), anyhow::Error> {
        let account = AccountId::from(0);
        let (_, db_data) = get_db_paths(wallet_dir);
        let db_data = WalletDb::for_path(db_data, params)?;

        let address = db_data
            .get_current_address(account)?
            .ok_or(error::Error::InvalidRecipient)?;

        if let Some(wallet_summary) = db_data.get_wallet_summary(MIN_CONFIRMATIONS.into())? {
            let balance = wallet_summary
                .account_balances()
                .get(&account)
                .ok_or_else(|| anyhow!("Missing account 0"))?;

            println!("{:#?}", wallet_summary);
            println!("{}", address.encode(&params));
            println!("     Height: {}", wallet_summary.chain_tip_height());
            if let Some(progress) = wallet_summary.scan_progress() {
                println!(
                    "     Synced: {:0.3}%",
                    (*progress.numerator() as f64) * 100f64 / (*progress.denominator() as f64)
                );
            }
            println!("    Balance: {}", format_zec(balance.total()));
            println!(
                "  Spendable: {}",
                format_zec(balance.sapling_balance.spendable_value)
            );
        } else {
            println!("Insufficient information to build a wallet summary.");
        }

        Ok(())
    }
}
