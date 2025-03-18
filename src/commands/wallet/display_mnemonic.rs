use clap::Args;

use crate::config::WalletConfig;
use secrecy::ExposeSecret;

// Options accepted for the `list-addresses` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// age identity file to decrypt the mnemonic phrase with
    #[arg(short, long)]
    identity: String,
}

impl Command {
    pub(crate) fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let mut config = WalletConfig::read(wallet_dir.as_ref())?;
        let identities = age::IdentityFile::from_file(self.identity)?.into_identities()?;

        if let Some(mnemonic_bytes) =
            config.decrypt_mnemonic(identities.iter().map(|i| i.as_ref() as _))?
        {
            println!("{}", std::str::from_utf8(mnemonic_bytes.expose_secret())?);
        } else {
            println!("No mnemonic recovery phrase is available for this wallet.");
        }
        Ok(())
    }
}
