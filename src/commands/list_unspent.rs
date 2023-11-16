use anyhow::anyhow;
use gumdrop::Options;

use zcash_client_backend::data_api::{SaplingInputSource, WalletRead};
use zcash_client_sqlite::WalletDb;
use zcash_primitives::{
    consensus::Parameters,
    transaction::components::{
        amount::{Amount, MAX_MONEY},
        sapling::fees::InputView,
    },
    zip32::AccountId,
};

use crate::{data::get_db_paths, error, ui::format_zec};

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

        // Use the height of the maximum scanned block as the anchor height, to emulate a
        // zero-conf transaction in order to select every note in the wallet.
        let anchor_height = db_data
            .block_max_scanned()?
            .ok_or(error::WalletErrorT::ScanRequired)
            .map_err(|e| anyhow!("{:?}", e))?
            .block_height();

        let notes = db_data.select_spendable_sapling_notes(
            account,
            Amount::const_from_i64(MAX_MONEY),
            anchor_height,
            &[],
        )?;

        for note in notes {
            println!("{}: {}", note.note_id(), format_zec(note.value()));
        }

        Ok(())
    }
}
