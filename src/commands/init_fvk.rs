use anyhow::anyhow;
use gumdrop::Options;

use zcash_address::unified::{Encoding, Ufvk};
use zcash_client_backend::{
    data_api::{AccountPurpose, WalletWrite, Zip32Derivation},
    proto::service,
};
use zcash_keys::{encoding::decode_extfvk_with_network, keys::UnifiedFullViewingKey};
use zcash_primitives::consensus::NetworkType;
use zcash_protocol::consensus;
use zip32::fingerprint::SeedFingerprint;

use crate::{
    config::WalletConfig,
    data::init_dbs,
    remote::{tor_client, Servers},
};

// Options accepted for the `init` command
#[derive(Debug, Options)]
pub(crate) struct Command {
    #[options(help = "a name for the account")]
    name: String,

    #[options(
        help = "serialized full viewing key (Unified or Sapling) to initialize the wallet with"
    )]
    fvk: String,

    #[options(help = "the wallet's birthday (default is current chain height)")]
    birthday: Option<u32>,

    #[options(
        help = "hex encoding of the ZIP 32 fingerprint for the seed from which the UFVK was derived",
        parse(try_from_str = "hex::decode")
    )]
    seed_fingerprint: Option<Vec<u8>>,

    #[options(help = "ZIP 32 account index corresponding to the UFVK")]
    hd_account_index: Option<u32>,

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

        let (network_type, ufvk) = Ufvk::decode(&opts.fvk)
            .map_err(anyhow::Error::new)
            .and_then(
                |(network, ufvk)| -> Result<(NetworkType, UnifiedFullViewingKey), anyhow::Error> {
                    let ufvk = UnifiedFullViewingKey::parse(&ufvk)?;
                    Ok((network, ufvk))
                },
            )
            .or_else(
                |_| -> Result<(NetworkType, UnifiedFullViewingKey), anyhow::Error> {
                    let (network, sfvk) = decode_extfvk_with_network(&opts.fvk)?;
                    let ufvk = UnifiedFullViewingKey::from_sapling_extended_full_viewing_key(sfvk)?;
                    Ok((network, ufvk))
                },
            )?;

        let network = match network_type {
            NetworkType::Main => consensus::Network::MainNetwork,
            NetworkType::Test => consensus::Network::TestNetwork,
            NetworkType::Regtest => {
                return Err(anyhow!("the regtest network is not supported"));
            }
        };

        let server = opts.server.pick(network)?;
        let mut client = if opts.disable_tor {
            server.connect_direct().await?
        } else {
            server.connect(|| tor_client(wallet_dir.as_ref())).await?
        };

        // Get the current chain height (for the wallet's birthday recover-until height).
        let chain_tip: u32 = client
            .get_latest_block(service::ChainSpec::default())
            .await?
            .into_inner()
            .height
            .try_into()
            .expect("block heights must fit into u32");

        let birthday = super::init::Command::get_wallet_birthday(
            client,
            opts.birthday
                .unwrap_or(chain_tip.saturating_sub(100))
                .into(),
            Some(chain_tip.into()),
        )
        .await?;

        let purpose = match (opts.seed_fingerprint, opts.hd_account_index) {
            (Some(seed_fingerprint), Some(hd_account_index)) => Ok(AccountPurpose::Spending {
                derivation: Some(Zip32Derivation::new(
                    SeedFingerprint::from_bytes(
                        seed_fingerprint
                            .as_slice()
                            .try_into()
                            .map_err(|_| anyhow!("Incorrect seed_fingerprint length"))?,
                    ),
                    zip32::AccountId::try_from(hd_account_index)?,
                )),
            }),
            (None, None) => Ok(AccountPurpose::ViewOnly),
            _ => Err(anyhow!("Need either both (for spending) or neither (for view-only) of seed_fingerprint and hd_account_index")),
        }?;

        // Save the wallet config to disk.
        WalletConfig::init_without_mnemonic(wallet_dir.as_ref(), birthday.height(), network)?;

        let mut wallet_db = init_dbs(network, wallet_dir.as_ref())?;
        wallet_db.import_account_ufvk(&opts.name, &ufvk, &birthday, purpose, None)?;

        Ok(())
    }
}
