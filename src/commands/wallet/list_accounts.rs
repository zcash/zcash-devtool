use clap::Args;
use zcash_client_backend::data_api::{
    Account, AccountPurpose, AccountSource, WalletRead, Zip32Derivation,
};
use zcash_client_sqlite::WalletDb;

use crate::{config::get_wallet_network, data::get_db_paths};

// Options accepted for the `list-accounts` command
#[derive(Debug, Args)]
pub(crate) struct Command {}

impl Command {
    pub(crate) fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let params = get_wallet_network(wallet_dir.as_ref())?;
        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let db_data = WalletDb::for_path(db_data, params, (), ())?;

        for account_id in db_data.get_account_ids()?.iter() {
            let account = db_data.get_account(*account_id)?.unwrap();

            println!(
                "Account {} (birthday height {})",
                account_id.expose_uuid(),
                u32::from(account.birthday_height())
            );
            if let Some(name) = account.name() {
                println!("     Name: {name}");
            }
            println!("     UIVK: {}", account.uivk().encode(&params));
            println!(
                "     UFVK: {}",
                account
                    .ufvk()
                    .map_or("None".to_owned(), |k| k.encode(&params))
            );
            print_source(account.source());
        }
        Ok(())
    }
}

fn print_source(source: &AccountSource) {
    match source {
        AccountSource::Derived {
            derivation,
            key_source,
        } => {
            println!("     Source: derived");
            print_derivation(derivation);
            if let Some(key_source) = key_source {
                println!("       Key source: {key_source}");
            }
        }
        AccountSource::Imported {
            purpose,
            key_source,
        } => {
            println!("     Source: imported");
            match purpose {
                AccountPurpose::Spending { derivation } => {
                    println!("       Purpose: spending");
                    if let Some(derivation) = derivation {
                        print_derivation(derivation);
                    }
                }
                AccountPurpose::ViewOnly => {
                    println!("       Purpose: view-only");
                }
            }
            if let Some(key_source) = key_source {
                println!("       Key source: {key_source}");
            }
        }
    }
}

fn print_derivation(derivation: &Zip32Derivation) {
    println!(
        "       Seed fingerprint: {}",
        hex::encode(derivation.seed_fingerprint().to_bytes()),
    );
    println!(
        "       Account index: {}",
        u32::from(derivation.account_index()),
    );
}
