use anyhow::anyhow;
use gumdrop::Options;

use uuid::Uuid;
use zcash_client_backend::data_api::{Account, WalletRead};
use zcash_client_sqlite::{AccountUuid, WalletDb};
use zcash_keys::keys::UnifiedAddressRequest;

use crate::{config::get_wallet_network, data::get_db_paths};

// Options accepted for the `list-accounts` command
#[derive(Debug, Options)]
pub(crate) struct Command {
    #[options(free, required, help = "the UUID of the account to list addresses for")]
    account_id: Uuid,
}

impl Command {
    pub(crate) fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let params = get_wallet_network(wallet_dir.as_ref())?;
        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let db_data = WalletDb::for_path(db_data, params)?;

        let account = db_data
            .get_account(AccountUuid::from_uuid(self.account_id))?
            .ok_or_else(|| anyhow!("No account exists for account id {}", self.account_id))?;

        println!("Account {}", self.account_id);
        let (ua, _) = account
            .uivk()
            .default_address(UnifiedAddressRequest::all())?;
        println!("     Default Address: {}", ua.encode(&params));
        Ok(())
    }
}
