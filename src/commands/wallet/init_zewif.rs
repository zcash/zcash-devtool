use anyhow::anyhow;
use clap::Args;
use std::path::PathBuf;

use crate::{
    config::WalletConfig,
    data::{self, Network},
    remote::ConnectionArgs,
};

use super::zewif::{
    BirthdayEnrichments, document_network, fetch_birthday_enrichments, import_prepared,
    min_birthday_height, prepare_document, read_zewif_file,
};

// Options accepted for the `init-zewif` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// Path to the ZeWIF interchange file to import
    path: PathBuf,

    /// Import the wallet in view-only mode: no spending key material is
    /// retained, and every account is imported from its viewing key. This
    /// flag is currently required; spending imports are not yet supported.
    #[arg(long, required = true)]
    view_only: bool,

    /// Do not contact a lightwalletd server; import strictly from the
    /// document. Accounts without recorded tree states will be scanned from
    /// their birthday height (or Sapling activation) instead.
    #[arg(long)]
    offline: bool,

    /// Required for a regtest document: a TOML file giving the validator's
    /// activation height per network upgrade (keys: overwinter, sapling,
    /// blossom, heartwood, canopy, nu5, nu6, nu6_1, nu6_2, nu6_3; each a
    /// height or "never"). The heights are persisted verbatim in the wallet
    /// config so later commands agree, and are verified against any schedule
    /// the document records. Rejected for main/test documents.
    #[cfg(feature = "regtest_support")]
    #[arg(long)]
    activation_heights: Option<PathBuf>,

    #[command(flatten)]
    connection: ConnectionArgs,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        // `--view-only` is required while spending imports are unsupported,
        // so this always holds; the flag reserves the CLI shape.
        assert!(self.view_only);

        let document = read_zewif_file(&self.path)?;
        let network = document_network(&document)?;

        #[cfg(feature = "regtest_support")]
        let params = match network {
            ::zewif::Network::Mainnet | ::zewif::Network::Testnet => {
                if self.activation_heights.is_some() {
                    return Err(anyhow!(
                        "--activation-heights is only valid for regtest documents"
                    ));
                }
                if matches!(network, ::zewif::Network::Mainnet) {
                    Network::Main
                } else {
                    Network::Test
                }
            }
            ::zewif::Network::Regtest(_) => {
                let path = self.activation_heights.as_ref().ok_or_else(|| {
                    anyhow!("a regtest ZeWIF document requires --activation-heights <file>")
                })?;
                Network::Regtest(data::load_activation_heights(path)?)
            }
        };
        #[cfg(not(feature = "regtest_support"))]
        let params = match network {
            ::zewif::Network::Mainnet => Network::Main,
            ::zewif::Network::Testnet => Network::Test,
            ::zewif::Network::Regtest(_) => {
                return Err(anyhow!(
                    "regtest documents require the `regtest_support` feature"
                ));
            }
        };

        let enrichments = if self.offline {
            BirthdayEnrichments::new()
        } else {
            let mut client = self.connection.connect(params, wallet_dir.as_ref()).await?;
            fetch_birthday_enrichments(&mut client, &params, &document).await?
        };
        let prepared = prepare_document(&document, &enrichments);

        // Save the wallet config to disk (errors if a wallet already exists
        // in this directory), then initialise the databases and import.
        let birthday = min_birthday_height(&params, &prepared);
        WalletConfig::init_without_mnemonic(wallet_dir.as_ref(), birthday, params)?;
        let mut db_data = data::init_dbs(params, wallet_dir.as_ref())?;
        import_prepared(&mut db_data, &prepared)?;

        Ok(())
    }
}
