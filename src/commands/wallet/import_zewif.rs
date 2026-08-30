use clap::Args;
use std::path::PathBuf;

use rand::rngs::OsRng;
use zcash_client_sqlite::{WalletDb, util::SystemClock};

use crate::{config::WalletConfig, data::get_db_paths, remote::ConnectionArgs};

use super::zewif::{
    BirthdayEnrichments, fetch_birthday_enrichments, import_prepared, prepare_document,
    read_zewif_file,
};

// Options accepted for the `import-zewif` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// Path to the ZeWIF interchange file to import
    path: PathBuf,

    /// Import in view-only mode: no spending key material is retained, and
    /// every account is imported from its viewing key. This flag is
    /// currently required; spending imports are not yet supported.
    #[arg(long, required = true)]
    view_only: bool,

    /// Do not contact a lightwalletd server; import strictly from the
    /// document. Accounts without recorded tree states will be scanned from
    /// their birthday height (or Sapling activation) instead.
    #[arg(long)]
    offline: bool,

    #[command(flatten)]
    connection: ConnectionArgs,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        // `--view-only` is required while spending imports are unsupported,
        // so this always holds; the flag reserves the CLI shape.
        assert!(self.view_only);

        let params = WalletConfig::read(wallet_dir.as_ref())?.network();
        let document = read_zewif_file(&self.path)?;

        let enrichments = if self.offline {
            BirthdayEnrichments::new()
        } else {
            let mut client = self.connection.connect(params, wallet_dir.as_ref()).await?;
            fetch_birthday_enrichments(&mut client, &params, &document).await?
        };
        let prepared = prepare_document(&document, &enrichments);

        // The importer verifies that the document's network matches the
        // wallet's parameters, and rolls back cleanly on any failure
        // (including account collisions from re-importing a document).
        let (_, db_path) = get_db_paths(wallet_dir.as_ref());
        let mut db_data = WalletDb::for_path(db_path, params, SystemClock, OsRng)?;
        import_prepared(&mut db_data, &prepared)?;

        Ok(())
    }
}
