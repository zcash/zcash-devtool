//! Command for managing multisig addresses in Zcash Devtool.
//!
//! Accepts a threshold number of signatures to be required by the generated multisig address and a list
//! of public keys in hex format, separated by commas, that should be able to participate in signing spends from the multi-sig
//! address produced by this command.
//!
//! Generates a multi-sig P2SH address that can be used to send and receive funds, requiring the specified threshold number of
//! signatures to authorize spending from the generated address.

// TODO:
// - Implement the command logic to create a multisig address.
// - Move logic to a new `commands::wallet::Command::GenerateAddress` subcommand
// - Clean up documentation.

use clap::Subcommand;
use secp256k1::PublicKey;
use transparent::address::TransparentAddress;

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Add a nrequired-to-sign transparent multisignature address to the wallet
    Create {
        /// A threshold `k` value indicating the number of signatures required to spend from the address
        #[clap(short, long, required = true)]
        threshold: u32,

        /// A list of public keys in hex format, separated by commas.
        /// Must contain at least the threshold number of keys.
        #[clap(short, long, required = true, value_delimiter = ',')]
        pub_keys: Vec<PublicKey>,
    },
}

impl Command {
    pub(crate) fn run(self) -> anyhow::Result<()> {
        use Command::*;
        match self {
            Create {
                threshold,
                pub_keys,
            } => {
                let p2sh_multisig_addr = generate_multisig_address(threshold, pub_keys)?;
                println!("Multisig address created: {p2sh_multisig_addr:?}");
            }
        };

        Ok(())
    }
}

fn generate_multisig_address(
    _threshold: u32,
    _pub_keys: Vec<PublicKey>,
) -> anyhow::Result<TransparentAddress> {
    Err(anyhow::anyhow!("unimplemented: generate_multisig_address"))
}
