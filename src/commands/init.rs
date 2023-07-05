use gumdrop::Options;
use secrecy::{SecretVec, Zeroize};

use zcash_client_backend::{
    data_api::{AccountBirthday, WalletWrite},
    proto::service,
};
use zcash_client_sqlite::{
    chain::init::init_blockmeta_db, wallet::init::init_wallet_db, FsBlockDb, WalletDb,
};
use zcash_primitives::{
    consensus::Parameters,
    zip32::AccountId,
    zip339::{Count, Mnemonic},
};

use crate::{
    data::{get_db_paths, init_wallet_keys},
    error,
    remote::connect_to_lightwalletd,
};

// Options accepted for the `init` command
#[derive(Debug, Options)]
pub(crate) struct Command {
    #[options(help = "mnemonic phrase to initialise the wallet with (default is new phrase)")]
    phrase: Option<String>,

    #[options(help = "the wallet's birthday (default is current chain height)")]
    birthday: Option<u64>,
}

impl Command {
    pub(crate) async fn run(
        self,
        params: impl Parameters + 'static,
        wallet_dir: Option<String>,
    ) -> Result<(), anyhow::Error> {
        let opts = self;

        // Get the current chain height (for the wallet's birthday).
        let mut client = connect_to_lightwalletd().await?;
        let birthday = if let Some(birthday) = opts.birthday {
            birthday
        } else {
            client
                .get_latest_block(service::ChainSpec::default())
                .await?
                .into_inner()
                .height
                - 100
        };

        // Parse or create the wallet's mnemonic phrase.
        let mnemonic = if let Some(phrase) = opts.phrase {
            Mnemonic::from_phrase(&phrase)?
        } else {
            Mnemonic::generate(Count::Words24)
        };

        // Save the wallet keys to disk.
        init_wallet_keys(wallet_dir.as_ref(), &mnemonic, birthday)?;

        // Initialise the block and wallet DBs.
        let (db_cache, db_data) = get_db_paths(wallet_dir);
        let mut db_cache = FsBlockDb::for_path(db_cache).map_err(error::Error::from)?;
        let mut db_data = WalletDb::for_path(db_data, params)?;
        init_blockmeta_db(&mut db_cache)?;
        init_wallet_db(&mut db_data, None)?;

        // Construct an `AccountBirthday` for the account's birthday.
        let birthday = {
            // Fetch the tree state corresponding to the last block prior to the wallet's
            // birthday height. NOTE: THIS APPROACH LEAKS THE BIRTHDAY TO THE SERVER!
            let mut request = service::BlockId::default();
            request.height = birthday - 1;
            let treestate = client.get_tree_state(request).await?.into_inner();
            AccountBirthday::from_treestate(treestate, None).map_err(error::Error::from)?
        };

        // Add one account.
        let seed = {
            let mut seed = mnemonic.to_seed("");
            let secret = seed.to_vec();
            seed.zeroize();
            SecretVec::new(secret)
        };
        let (account, _) = db_data.create_account(&seed, birthday)?;
        assert_eq!(account, AccountId::from(0));

        Ok(())
    }
}
