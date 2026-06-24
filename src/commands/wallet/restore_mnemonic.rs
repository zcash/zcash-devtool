use age::secrecy::ExposeSecret;
use bip0039::{English, Mnemonic};
use clap::Args;
use secrecy::{ExposeSecret as _, SecretString, SecretVec, Zeroize};
use tokio::io::AsyncWriteExt;

use zcash_client_backend::proto::service;
use zcash_protocol::consensus::{NetworkUpgrade, Parameters};

use crate::{config::WalletConfig, data::Network, remote::ConnectionArgs};

// Options accepted for the `restore-mnemonic` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// A name for the account
    #[arg(long)]
    name: String,

    /// age identity file to encrypt the mnemonic phrase to (generated if it doesn't exist)
    #[arg(short, long)]
    identity: String,

    /// The wallet's birthday. Defaults to the network's Sapling activation height, so the
    /// wallet scans the entire history it could possibly have received funds in.
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

        // Get the current chain height (for the recover-until height).
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

        // Read the mnemonic phrase to restore from. `rpassword` requires a
        // controlling terminal (it prompts and reads via /dev/tty, failing
        // with ENXIO when there is none), so when stdin is not a terminal —
        // automation piping the phrase in — read a line from stdin instead.
        let phrase = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            SecretString::new(rpassword::prompt_password("Enter mnemonic to restore:")?)
        } else {
            let mut line = String::new();
            std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line)?;
            let phrase = SecretString::new(line.trim().to_string());
            line.zeroize();
            phrase
        };
        if phrase.expose_secret().is_empty() {
            return Err(anyhow::anyhow!(
                "A mnemonic phrase is required to restore a wallet"
            ));
        }
        let mnemonic = <Mnemonic<English>>::from_phrase(phrase.expose_secret())?;

        // Default to the network's Sapling activation height, so a restored
        // wallet scans for all funds it could possibly have received, unless
        // the caller knows (and provides) a more recent birthday.
        let birthday_height = opts.birthday.map(Into::into).unwrap_or_else(|| {
            params
                .activation_height(NetworkUpgrade::Sapling)
                .expect("Sapling activation height is known")
        });

        let birthday = super::init::Command::get_wallet_birthday(
            client,
            birthday_height,
            Some(chain_tip.into()),
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

        super::init::Command::init_dbs(
            params,
            wallet_dir.as_ref(),
            &opts.name,
            &seed,
            birthday,
            None,
        )
    }
}
