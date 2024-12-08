use bip0039::{Count, English, Mnemonic};
use gumdrop::Options;
use secrecy::{SecretVec, Zeroize};
use tonic::transport::Channel;

use zcash_client_backend::{
    data_api::{AccountBirthday, WalletWrite},
    proto::service::{self, compact_tx_streamer_client::CompactTxStreamerClient},
};
use zcash_primitives::consensus::{self, Parameters};
use zcash_protocol::consensus::BlockHeight;

use crate::{
    config::WalletConfig,
    data::{init_dbs, Network},
    error,
    remote::{tor_client, Servers},
};

// Options accepted for the `init` command
#[derive(Debug, Options)]
pub(crate) struct Command {
    #[options(help = "age identity file to encrypt the mnemonic phrase to")]
    identity: String,

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

        let recipients = age::IdentityFile::from_file(opts.identity)?.to_recipients()?;

        // Parse or create the wallet's mnemonic phrase.
        let (mnemonic, recover_until) = if let Some(phrase) = opts.phrase {
            (
                <Mnemonic<English>>::from_phrase(phrase)?,
                Some(chain_tip.into()),
            )
        } else {
            (Mnemonic::generate(Count::Words24), None)
        };

        let birthday = Self::get_wallet_birthday(
            client,
            opts.birthday
                .unwrap_or(chain_tip.saturating_sub(100))
                .into(),
            recover_until,
        )
        .await?;

        // Save the wallet keys to disk.
        WalletConfig::init_with_mnemonic(
            wallet_dir.as_ref(),
            recipients.iter().map(|r| r.as_ref() as _),
            &mnemonic,
            birthday.height(),
            opts.network.into(),
        )?;

        let seed = {
            let mut seed = mnemonic.to_seed("");
            let secret = seed.to_vec();
            seed.zeroize();
            SecretVec::new(secret)
        };

        Self::init_dbs(
            params,
            wallet_dir.as_ref(),
            &seed,
            birthday,
            opts.accounts.unwrap_or(1),
        )
    }

    pub(crate) async fn get_wallet_birthday(
        mut client: CompactTxStreamerClient<Channel>,
        birthday_height: BlockHeight,
        recover_until: Option<BlockHeight>,
    ) -> Result<AccountBirthday, anyhow::Error> {
        // Fetch the tree state corresponding to the last block prior to the wallet's
        // birthday height. NOTE: THIS APPROACH LEAKS THE BIRTHDAY TO THE SERVER!
        let request = service::BlockId {
            height: u64::from(birthday_height).saturating_sub(1),
            ..Default::default()
        };
        let treestate = client.get_tree_state(request).await?.into_inner();
        let birthday = AccountBirthday::from_treestate(treestate, recover_until)
            .map_err(error::Error::from)?;

        Ok(birthday)
    }

    pub(crate) fn init_dbs(
        params: impl Parameters + 'static,
        wallet_dir: Option<&String>,
        seed: &SecretVec<u8>,
        birthday: AccountBirthday,
        accounts: usize,
    ) -> Result<(), anyhow::Error> {
        // Initialise the block and wallet DBs.
        let mut db_data = init_dbs(params, wallet_dir)?;

        // Add accounts.
        for _ in 0..accounts {
            db_data.create_account(seed, &birthday)?;
        }

        Ok(())
    }
}
