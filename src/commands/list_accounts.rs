use gumdrop::Options;

use zcash_client_backend::data_api::{Account, WalletRead};
use zcash_client_sqlite::WalletDb;

use crate::data::{get_db_paths, get_wallet_network};

// Options accepted for the `list-accounts` command
#[derive(Debug, Options)]
pub(crate) struct Command {}

impl Command {
    pub(crate) fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let params = get_wallet_network(wallet_dir.as_ref())?;
        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let db_data = WalletDb::for_path(db_data, params)?;

        for (i, account_id) in db_data.get_account_ids()?.iter().enumerate() {
            let account = db_data.get_account(*account_id)?.unwrap();

            println!("Account {}", i);
            println!("     UIVK: {}", account.uivk().encode(&params));
            println!(
                "     UFVK: {}",
                account
                    .ufvk()
                    .map_or("None".to_owned(), |k| k.encode(&params))
            );
            println!("     Source: {:?}", account.source());
        }
        Ok(())
    }
}
