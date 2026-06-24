use age::secrecy::ExposeSecret;
use bip0039::{Count, English, Mnemonic};
use clap::Args;
use secrecy::{ExposeSecret as _, SecretString, SecretVec, Zeroize};
use tokio::io::AsyncWriteExt;
use tonic::transport::Channel;

use zcash_client_backend::{
    data_api::{AccountBirthday, WalletWrite, chain::ChainState},
    proto::service::{self, compact_tx_streamer_client::CompactTxStreamerClient},
};
use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters};

use crate::{
    config::WalletConfig,
    data::{Network, init_dbs},
    error,
    remote::ConnectionArgs,
};

// Options accepted for the `init` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// A name for the account
    #[arg(long)]
    name: String,

    /// age identity file to encrypt the mnemonic phrase to (generated if it doesn't exist)
    #[arg(short, long)]
    identity: String,

    /// The wallet's birthday (default is current chain height)
    #[arg(long)]
    birthday: Option<u32>,

    /// The network the wallet will be used with: \"test\", \"main\", or \"regtest\"
    /// (requires the `regtest_support` feature). Default is \"test\".
    #[arg(short, long)]
    #[arg(value_parser = Network::parse)]
    network: Network,

    /// Required for `-n regtest`: a TOML file giving the validator's
    /// activation height per network upgrade (keys: overwinter, sapling,
    /// blossom, heartwood, canopy, nu5, nu6, nu6_1, nu6_2; a missing key
    /// means the upgrade is inactive). The heights are persisted in the
    /// wallet config so later commands agree. Rejected for main/test.
    #[cfg(feature = "regtest_support")]
    #[arg(long)]
    activation_heights: Option<std::path::PathBuf>,

    #[command(flatten)]
    connection: ConnectionArgs,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let opts = self;

        // Regtest requires explicit activation heights (persisted below so
        // later commands agree); they are rejected for main/test.
        #[cfg(feature = "regtest_support")]
        let params = match opts.network {
            Network::Regtest(_) => {
                let path = opts.activation_heights.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("`-n regtest` requires --activation-heights <file>")
                })?;
                Network::Regtest(crate::data::load_activation_heights(path)?)
            }
            other => {
                if opts.activation_heights.is_some() {
                    return Err(anyhow::anyhow!(
                        "--activation-heights is only valid with `-n regtest`"
                    ));
                }
                other
            }
        };
        #[cfg(not(feature = "regtest_support"))]
        let params = opts.network;

        let mut client = opts.connection.connect(params, wallet_dir.as_ref()).await?;

        // Get the current chain height (for the wallet's birthday and/or recover-until height).
        let chain_tip: u32 = client
            .get_latest_block(service::ChainSpec::default())
            .await?
            .into_inner()
            .height
            .try_into()
            .expect("block heights must fit into u32");

        let recipients = if tokio::fs::try_exists(&opts.identity).await? {
            age::IdentityFile::from_file(opts.identity)?.to_recipients()?
        } else {
            eprintln!("Generating a new age identity to encrypt the mnemonic phrase");
            let identity = age::x25519::Identity::generate();
            let recipient = identity.to_public();

            // Write it to the provided path so we have it for next time.
            let mut f = tokio::fs::File::create_new(opts.identity).await?;
            f.write_all(
                format!(
                    "# created: {}\n",
                    chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
                )
                .as_bytes(),
            )
            .await?;
            f.write_all(format!("# public key: {recipient}\n").as_bytes())
                .await?;
            f.write_all(format!("{}\n", identity.to_string().expose_secret()).as_bytes())
                .await?;
            f.flush().await?;

            vec![Box::new(recipient) as _]
        };

        // Parse or create the wallet's mnemonic phrase. `rpassword`
        // requires a controlling terminal (it prompts and reads via
        // /dev/tty, failing with ENXIO when there is none), so when
        // stdin is not a terminal — automation piping the phrase in,
        // e.g. the `zcash_local_net` test harness — read a line from
        // stdin instead.
        let phrase = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            SecretString::new(rpassword::prompt_password(
                "Enter mnemonic (or just press Enter to generate a new one):",
            )?)
        } else {
            let mut line = String::new();
            std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line)?;
            let phrase = SecretString::new(line.trim().to_string());
            line.zeroize();
            phrase
        };
        let (mnemonic, recover_until) = if !phrase.expose_secret().is_empty() {
            (
                <Mnemonic<English>>::from_phrase(phrase.expose_secret())?,
                Some(chain_tip.into()),
            )
        } else {
            (Mnemonic::generate(Count::Words24), None)
        };

        let birthday = Self::get_wallet_birthday(
            client,
            &params,
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
            params,
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
            &opts.name,
            &seed,
            birthday,
            None,
        )
    }

    pub(crate) async fn get_wallet_birthday<P: Parameters>(
        mut client: CompactTxStreamerClient<Channel>,
        params: &P,
        birthday_height: BlockHeight,
        recover_until: Option<BlockHeight>,
    ) -> Result<AccountBirthday, anyhow::Error> {
        // A shielded wallet's birthday cannot meaningfully precede Sapling
        // activation: there is no note commitment tree before then, and
        // lightwalletd rejects `GetTreeState` for any height below it.
        let sapling_activation = params
            .activation_height(NetworkUpgrade::Sapling)
            .expect("Sapling activation height is known");
        let birthday_height = birthday_height.max(sapling_activation);

        // The birthday is defined by the chain state (note commitment tree
        // frontiers and block hash) as of the block *prior* to the birthday
        // height.
        let birthday = if birthday_height == sapling_activation {
            // Edge case: the block prior to the birthday is the last pre-Sapling
            // block, whose note commitment trees are empty and whose tree state
            // the server cannot serve (`GetTreeState` below Sapling activation
            // is rejected). Construct an empty chain state directly, taking the
            // prior block's hash from the birthday block's `prev_hash` so block
            // scanning can still verify chain continuity.
            let birthday_block = client
                .get_block(service::BlockId {
                    height: u64::from(birthday_height),
                    ..Default::default()
                })
                .await?
                .into_inner();
            AccountBirthday::from_parts(
                ChainState::empty(birthday_height - 1, birthday_block.prev_hash()),
                recover_until,
            )
        } else {
            // Fetch the tree state corresponding to the last block prior to the
            // wallet's birthday height. NOTE: THIS APPROACH LEAKS THE BIRTHDAY
            // TO THE SERVER!
            let request = service::BlockId {
                height: u64::from(birthday_height) - 1,
                ..Default::default()
            };
            let treestate = client.get_tree_state(request).await?.into_inner();
            AccountBirthday::from_treestate(treestate, recover_until).map_err(error::Error::from)?
        };

        Ok(birthday)
    }

    pub(crate) fn init_dbs(
        params: impl Parameters + 'static,
        wallet_dir: Option<&String>,
        account_name: &str,
        seed: &SecretVec<u8>,
        birthday: AccountBirthday,
        key_source: Option<&str>,
    ) -> Result<(), anyhow::Error> {
        // Initialise the block and wallet DBs.
        let mut db_data = init_dbs(params, wallet_dir)?;

        // Add account.
        db_data.create_account(account_name, seed, &birthday, key_source)?;

        Ok(())
    }
}
