use anyhow::anyhow;
use clap::Args;
use uuid::Uuid;
use zcash_client_backend::{
    data_api::{Account as _, InputSource, WalletRead},
    ShieldedProtocol,
};
use zcash_client_sqlite::WalletDb;
use zcash_protocol::value::{Zatoshis, MAX_MONEY};

use crate::{config::get_wallet_network, data::get_db_paths, error, ui::format_zec};

use super::select_account;

// Options accepted for the `list-unspent` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// The UUID of the account for which to list unspent funds
    account_id: Option<Uuid>,
}

impl Command {
    pub(crate) fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let params = get_wallet_network(wallet_dir.as_ref())?;

        let (_, db_data) = get_db_paths(wallet_dir);
        let db_data = WalletDb::for_path(db_data, params)?;
        let account = select_account(&db_data, self.account_id)?;

        // Use the height of the maximum scanned block as the anchor height, to emulate a
        // zero-conf transaction in order to select every note in the wallet.
        let anchor_height = db_data
            .block_max_scanned()?
            .ok_or(error::WalletErrorT::ScanRequired)
            .map_err(|e| anyhow!("{:?}", e))?
            .block_height();

        let notes = db_data.select_spendable_notes(
            account.id(),
            Zatoshis::const_from_u64(MAX_MONEY),
            &[ShieldedProtocol::Sapling, ShieldedProtocol::Orchard],
            anchor_height,
            &[],
        )?;

        for note in notes.sapling() {
            println!(
                "Sapling {}: {}",
                note.internal_note_id(),
                format_zec(note.note_value()?)
            );
        }

        for note in notes.orchard() {
            println!(
                "Orchard {}: {}",
                note.internal_note_id(),
                format_zec(note.note_value()?)
            );
        }

        Ok(())
    }
}
