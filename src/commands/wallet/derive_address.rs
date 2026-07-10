//! Offline derivation of a wallet's default addresses from a mnemonic.
//!
//! Unlike the other wallet commands this needs no chain and no on-disk wallet — it derives the
//! account's default unified address and its transparent receiver straight from the mnemonic. It
//! exists so automated regtest funding can learn the funding wallet's transparent address *before*
//! a chain exists (zebra needs it as its coinbase `miner_address` at launch), keeping the funder on
//! a single chain so its wallet birthday anchor stays valid.

use anyhow::anyhow;
use bip0039::{English, Mnemonic};
use clap::Args;
use secrecy::Zeroize;
use zcash_keys::{
    encoding::AddressCodec,
    keys::{UnifiedAddressRequest, UnifiedSpendingKey},
};

use crate::data::Network;

// Options accepted for the `derive-address` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// The mnemonic phrase to derive from.
    #[arg(long)]
    mnemonic: String,

    /// The network: "main", "test" or "regtest".
    #[arg(short, long)]
    #[arg(value_parser = Network::parse)]
    network: Network,
}

impl Command {
    pub(crate) fn run(self) -> anyhow::Result<()> {
        // `data::Network` implements `Parameters` directly; address derivation
        // only needs the network *type*, so the regtest activation heights are
        // irrelevant here.
        let params = self.network;

        let mnemonic = <Mnemonic<English>>::from_phrase(self.mnemonic.trim())
            .map_err(|e| anyhow!("invalid mnemonic: {e}"))?;
        let mut seed = mnemonic.to_seed("");
        let usk = UnifiedSpendingKey::from_seed(&params, &seed, zip32::AccountId::ZERO)
            .map_err(|e| anyhow!("failed to derive spending key: {e}"))?;
        seed.zeroize();

        // The default address of the first account — exactly what `create_account` produces and
        // what the wallet scans, so a coinbase mined to this transparent receiver is detected.
        let (ua, _) = usk
            .to_unified_full_viewing_key()
            .default_address(UnifiedAddressRequest::AllAvailableKeys)
            .map_err(|e| anyhow!("failed to derive default address: {e}"))?;

        println!("Unified Address: {}", ua.encode(&params));
        if let Some(taddr) = ua.transparent() {
            println!("Transparent Address: {}", taddr.encode(&params));
        }

        Ok(())
    }
}
