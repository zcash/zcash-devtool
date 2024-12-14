use gumdrop::Options;

use uuid::Uuid;
use zcash_client_backend::data_api::Account;
use zcash_client_sqlite::WalletDb;
use zcash_keys::keys::UnifiedAddressRequest;

use crate::{commands::select_account, config::get_wallet_network, data::get_db_paths};

// Options accepted for the `list-accounts` command
#[derive(Debug, Options)]
pub(crate) struct Command {
    #[options(free, help = "the UUID of the account to list addresses for")]
    account_id: Option<Uuid>,
}

impl Command {
    pub(crate) fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let params = get_wallet_network(wallet_dir.as_ref())?;
        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let db_data = WalletDb::for_path(db_data, params)?;

        let account = select_account(&db_data, self.account_id)?;

        println!("Account {:?}", account.id());
        let (ua, _) = account
            .uivk()
            .default_address(UnifiedAddressRequest::all())?;
        println!("     Default Address: {}", ua.encode(&params));
        Ok(())
    }
}
