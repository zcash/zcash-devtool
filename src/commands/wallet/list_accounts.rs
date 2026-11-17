use clap::Args;
use zcash_client_backend::data_api::{
    Account, AccountPurpose, AccountSource, WalletRead, Zip32Derivation,
};
use zcash_client_sqlite::{AccountUuid, WalletDb};
use zcash_protocol::consensus;

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
            print_account(&params, &account)?;
        }
        Ok(())
    }
}

/// Prints the details of an account.
///
/// - Preconditions: `params` describes the network of the account.
/// - Inputs: the parameters of the network, and the account.
/// - Outputs: an error if a viewing key of the account cannot be encoded.
/// - Side effects: writes the identifier, birthday height, name, viewing keys and source
///   of the account to standard output.
pub(crate) fn print_account<P: consensus::Parameters>(
    params: &P,
    account: &impl Account<AccountId = AccountUuid>,
) -> anyhow::Result<()> {
    println!(
        "Account {} (birthday height {})",
        account.id().expose_uuid(),
        u32::from(account.birthday_height())
    );
    if let Some(name) = account.name() {
        println!("     Name: {name}");
    }
    println!("     UIVK: {}", account.uivk().encode(params)?);
    println!(
        "     UFVK: {}",
        account
            .ufvk()
            .map(|k| k.encode(params))
            .transpose()?
            .unwrap_or_else(|| "None".to_owned())
    );
    print_source(account.source());
    Ok(())
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
