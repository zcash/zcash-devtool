use anyhow::anyhow;
use gumdrop::Options;

use zcash_client_backend::{
    data_api::{InputSource, WalletRead},
    ShieldedProtocol,
};
use zcash_protocol::value::{Zatoshis, MAX_MONEY};

use crate::{error, ui::format_zec};

// Options accepted for the `balance` command
#[derive(Debug, Options)]
pub(crate) struct Command {}

impl Command {
    pub(crate) fn run<W>(self, db_data: &W) -> Result<(), anyhow::Error>
    where
        W: WalletRead + InputSource<AccountId = <W as WalletRead>::AccountId>,
        <W as WalletRead>::Error: std::error::Error + Send + Sync + 'static,
        <W as InputSource>::Error: std::error::Error + Send + Sync + 'static,
    {
        let account = *db_data
            .get_account_ids()?
            .first()
            .ok_or(anyhow!("Wallet has no accounts"))?;

        // Use the height of the maximum scanned block as the anchor height, to emulate a
        // zero-conf transaction in order to select every note in the wallet.
        let anchor_height = db_data
            .block_max_scanned()?
            .ok_or(error::WalletErrorT::ScanRequired)
            .map_err(|e| anyhow!("{:?}", e))?
            .block_height();

        let notes = db_data.select_spendable_notes(
            account,
            Zatoshis::const_from_u64(MAX_MONEY),
            &[ShieldedProtocol::Sapling, ShieldedProtocol::Orchard],
            anchor_height,
            &[],
        )?;

        for note in notes.sapling() {
            println!(
                "Sapling {:?}: {}",
                note.internal_note_id(),
                format_zec(note.note_value()?)
            );
        }

        for note in notes.orchard() {
            println!(
                "Orchard {:?}: {}",
                note.internal_note_id(),
                format_zec(note.note_value()?)
            );
        }

        Ok(())
    }
}
