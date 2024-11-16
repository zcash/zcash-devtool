use anyhow::anyhow;
use gumdrop::Options;

use zcash_address::unified::{Encoding, Ufvk};
use zcash_client_backend::{
    data_api::{AccountPurpose, WalletWrite},
    proto::service,
};
use zcash_keys::{encoding::decode_extfvk_with_network, keys::UnifiedFullViewingKey};
use zcash_primitives::consensus::NetworkType;
use zcash_protocol::consensus;

use crate::{
    data::{init_dbs, init_wallet_config},
    remote::{tor_client, Servers},
};

#[derive(Clone, Copy, Debug, Default)]
pub(crate) enum Purpose {
    #[default]
    Viewing,
    Spending,
}

impl Purpose {
    pub(crate) fn parse(name: &str) -> Result<Purpose, String> {
        match name {
            "viewing" => Ok(Purpose::Viewing),
            "spending" => Ok(Purpose::Spending),
            other => Err(format!("Unsupported purpose: {}", other)),
        }
    }
}

impl From<Purpose> for AccountPurpose {
    fn from(value: Purpose) -> Self {
        match value {
            Purpose::Viewing => AccountPurpose::ViewOnly,
            Purpose::Spending => AccountPurpose::Spending,
        }
    }
}

// Options accepted for the `init` command
#[derive(Debug, Options)]
pub(crate) struct Command {
    #[options(
        help = "serialized full viewing key (Unified or Sapling) to initialize the wallet with"
    )]
    fvk: String,

    #[options(help = "the wallet's birthday (default is current chain height)")]
    birthday: Option<u32>,

    #[options(
        help = "the server to initialize with (default is \"ecc\")",
        default = "ecc",
        parse(try_from_str = "Servers::parse")
    )]
    server: Servers,

    #[options(
        help = "the purpose of the viewing key (default is \"viewing\")",
        parse(try_from_str = "Purpose::parse")
    )]
    purpose: Purpose,

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

        // Save the wallet keys to disk.
        init_wallet_config(wallet_dir.as_ref(), None, birthday.height().into(), network)?;

        let mut wallet_db = init_dbs(network, wallet_dir.as_ref())?;
        wallet_db.import_account_ufvk(&ufvk, &birthday, opts.purpose.into())?;

        Ok(())
    }
}
