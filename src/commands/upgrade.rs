use gumdrop::Options;

use zcash_client_sqlite::{
    chain::init::init_blockmeta_db,
    wallet::init::{init_wallet_db, WalletMigrationError},
    FsBlockDb, WalletDb,
};

use crate::{
    config::{get_wallet_network, get_wallet_seed},
    data::get_db_paths,
    error,
};

// Options accepted for the `upgrade` command
#[derive(Debug, Options)]
pub(crate) struct Command {}

impl Command {
    pub(crate) fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let params = get_wallet_network(wallet_dir.as_ref())?;

        let (fsblockdb_root, db_data) = get_db_paths(wallet_dir.as_ref());
        let mut db_cache = FsBlockDb::for_path(fsblockdb_root).map_err(error::Error::from)?;
        let mut db_data = WalletDb::for_path(db_data, params)?;

        init_blockmeta_db(&mut db_cache)?;

        if let Err(e) = init_wallet_db(&mut db_data, None) {
            if matches!(&e, schemerz::MigratorError::Migration {
                error, ..
            } if matches!(error, WalletMigrationError::SeedRequired))
            {
                init_wallet_db(&mut db_data, get_wallet_seed(wallet_dir)?)?;
            } else {
                return Err(e.into());
            }
        }

        println!("Wallet successfully upgraded!");
        Ok(())
    }
}
