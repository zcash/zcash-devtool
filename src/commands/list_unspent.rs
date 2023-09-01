use anyhow::anyhow;
use gumdrop::Options;

use zcash_client_backend::data_api::WalletRead;
use zcash_client_sqlite::WalletDb;
use zcash_primitives::{consensus::Parameters, zip32::AccountId};

use crate::{data::get_db_paths, error, MIN_CONFIRMATIONS};

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

        let (target_height, _) = db_data
            .get_target_and_anchor_heights(MIN_CONFIRMATIONS)?
            .ok_or(error::WalletErrorT::ScanRequired)
            .map_err(|e| anyhow!("{:?}", e))?;

        let notes = db_data.get_spendable_sapling_notes(account, target_height, &[])?;

        for note in notes {
            println!("{}: {} zatoshis", note.note_id, u64::from(note.note_value));
        }

        Ok(())
    }
}
