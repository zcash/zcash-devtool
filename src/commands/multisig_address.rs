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
// - Replace `pub_keys` arg type with an enum that allows for passing in addresses (that are in the wallet)
// - Clean up documentation.

use std::io::Write;

use clap::Subcommand;
use secp256k1::PublicKey;
use sha2::{digest::FixedOutput, Sha256};

use ::transparent::address::Script;
use zcash_address::ZcashAddress;
use zcash_protocol::consensus::{Network, NetworkConstants};

/// Maximum size of a script element in bytes
// TODO: Define this constnat in `zcash_transparent` if it's needed.
const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Add a nrequired-to-sign transparent multisignature address to the wallet
    Create {
        /// A threshold `k` value indicating the number of signatures required to spend from the address
        #[clap(short, long, required = true)]
        threshold: u32,

        /// A list of comma-separated hex-encoded public keys.
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
                let (multisig_script, addr) = multisig_script(threshold, pub_keys)?;
                println!("Multisig address created: {addr:?}, script: {multisig_script:?}");
            }
        };

        Ok(())
    }
}

fn multisig_script(
    threshold: u32,
    pub_keys: Vec<PublicKey>,
) -> anyhow::Result<(Script, ZcashAddress)> {
    // TODO: Move this to a subcommand of `wallet` and get the network from the db.
    let net = Network::MainNetwork;
    validate_args(threshold, &pub_keys)?;

    // TODO: Make `Opcode` public and use the enum variants instead of raw opcodes.
    let multisig_script = Script(
        std::iter::once(0x50 + threshold as u8) // Push the number of required signatures (OP_1 to OP_16)
            .chain(pub_keys.iter().flat_map(|pk| pk.serialize())) // Push each public key
            .chain(std::iter::once(0x50 + pub_keys.len() as u8)) // Push the number of keys (OP_1 to OP_16)
            .collect(),
    );

    if multisig_script.0.len() > MAX_SCRIPT_ELEMENT_SIZE {
        return Err(anyhow::anyhow!(
            "the multisig script is too large, it must be less than {MAX_SCRIPT_ELEMENT_SIZE} bytes",
        ));
    }

    // TODO: De-duplicate this code if it exists elsewhere, check `bip32`, `zcash_transparent`, `zcash_address`
    // Hash160(in.begin(), in.end()), "the Hash160 of its serialization"
    let mut script_id = Sha256::default();
    script_id
        .write(multisig_script.0.as_slice())
        .expect("sha256 write is infallible");

    // KeyIO::EncodeDestination
    let script_id: [u8; 32] = script_id
        .finalize_fixed()
        .as_slice()
        .try_into()
        .expect("sha256 output is always 32 bytes");

    let prefix = net.b58_pubkey_address_prefix();
    let address: Vec<u8> = prefix.into_iter().chain(script_id.into_iter()).collect();
    let address = bs58::encode(address).into_string();

    Ok((multisig_script, address.parse()?))
}

fn validate_args(threshold: u32, pub_keys: &Vec<PublicKey>) -> anyhow::Result<()> {
    if threshold < 1 {
        return Err(anyhow::anyhow!("a multisignature address must require at least one key to redeem, threshold must be at least 1"));
    }

    if pub_keys.len() < threshold as usize {
        return Err(anyhow::anyhow!(
            "not enough keys supplied, (got {} keys, but need at least {threshold} to redeem)",
            pub_keys.len()
        ));
    }

    // TODO: Find out if this is correct (in zcashd, the max script size is 520 bytes, but the max number of public keys is 16, 2 + 16*33 == 530 > 520).
    if pub_keys.len() > 16 {
        return Err(anyhow::anyhow!(
            "number of addresses involved in the multisignature address creation > 16\nreduce the number"
        ));
    }

    Ok(())
}
