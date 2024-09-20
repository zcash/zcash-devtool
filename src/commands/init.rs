use bip0039::{Count, English, Mnemonic};
use gumdrop::Options;
use secrecy::{SecretVec, Zeroize};
use tonic::transport::Channel;

use zcash_client_backend::{
    data_api::{AccountBirthday, WalletWrite},
    proto::service::{self, compact_tx_streamer_client::CompactTxStreamerClient},
};
use zcash_client_sqlite::{
    chain::init::init_blockmeta_db, wallet::init::init_wallet_db, FsBlockDb, WalletDb,
};
use zcash_primitives::consensus::{self, Parameters};
use zcash_protocol::consensus::BlockHeight;

use crate::{
    data::{get_db_paths, init_wallet_config, Network},
    error,
    remote::{tor_client, Servers},
};

// Options accepted for the `init` command
#[derive(Debug, Options)]
pub(crate) struct Command {
    #[options(help = "mnemonic phrase to initialise the wallet with (default is new phrase)")]
    phrase: Option<String>,

    #[options(help = "the wallet's birthday (default is current chain height)")]
    birthday: Option<u32>,

    #[options(help = "the number of accounts to initialise the wallet with (default is 1)")]
    accounts: Option<usize>,

    #[options(
        help = "the network the wallet will be used with: \"test\" or \"main\" (default is \"test\")",
        parse(try_from_str = "Network::parse")
    )]
    network: Network,

    #[options(
        help = "the server to initialize with (default is \"ecc\")",
        default = "ecc",
        parse(try_from_str = "Servers::parse")
    )]
    server: Servers,

    #[options(help = "disable connections via TOR")]
    disable_tor: bool,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let opts = self;
        let params = consensus::Network::from(opts.network);

        let server = opts.server.pick(params)?;
        let mut client = if opts.disable_tor {
            server.connect_direct().await?
        } else {
            server.connect(|| tor_client(wallet_dir.as_ref())).await?
        };

        // Get the current chain height (for the wallet's birthday and/or recover-until height).
        let chain_tip: u32 = client
            .get_latest_block(service::ChainSpec::default())
            .await?
            .into_inner()
            .height
            .try_into()
            .expect("block heights must fit into u32");

        let birthday = if let Some(birthday) = opts.birthday {
            birthday
        } else {
            chain_tip - 100
        };

        // Parse or create the wallet's mnemonic phrase.
        let (mnemonic, recover_until) = if let Some(phrase) = opts.phrase {
            (
                <Mnemonic<English>>::from_phrase(phrase)?,
                Some(chain_tip.into()),
            )
        } else {
            (Mnemonic::generate(Count::Words24), None)
        };

        // Save the wallet keys to disk.
        init_wallet_config(wallet_dir.as_ref(), &mnemonic, birthday, opts.network)?;

        let seed = {
            let mut seed = mnemonic.to_seed("");
            let secret = seed.to_vec();
            seed.zeroize();
            SecretVec::new(secret)
        };

        Self::init_dbs(
            client,
            params,
            wallet_dir,
            &seed,
            birthday,
            opts.accounts.unwrap_or(1),
            recover_until,
        )
        .await
    }

    pub(crate) async fn init_dbs(
        mut client: CompactTxStreamerClient<Channel>,
        params: impl Parameters + 'static,
        wallet_dir: Option<String>,
        seed: &SecretVec<u8>,
        birthday: u32,
        accounts: usize,
        recover_until: Option<BlockHeight>,
    ) -> Result<(), anyhow::Error> {
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
            let request = service::BlockId {
                height: (birthday - 1).into(),
                ..Default::default()
            };
            let treestate = client.get_tree_state(request).await?.into_inner();
            AccountBirthday::from_treestate(treestate, recover_until).map_err(error::Error::from)?
        };

        // Add accounts.
        for _ in 0..accounts {
            db_data.create_account(seed, &birthday)?;
        }

        Ok(())
    }
}
