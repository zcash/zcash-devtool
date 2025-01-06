/// Initializes a wallet with a Ledger device. This assumes that HW wallet
/// is already containing a Seed Phrase, meaning that the user has gone to the
/// process of generating a new key or restoring it from existing ones using
/// the vendor's proposed workflow. 
/// 
/// A Ledger wallet can only contain a single set of seed bytes (known to the 
/// user as a BIP-0039 mnemonic seed phrase) so this initialization will couple
/// any local data to the device ID for future uses so that users don't mix up
/// devices. On non-ledger workflows this is achieved by using the Seed's
/// Fingerprint but this is not accesible on the ledger code. 
/// 
/// The Ledger device can derive any number of accounts and addresses. This 
/// command will initialize Account index Zero. User will be responsible of 
/// deriving other account indices (this is the same behavior observed in 
/// Ledger Live).
use anyhow::anyhow;
use clap::Args;
use bip32::{secp256k1::{elliptic_curve::PublicKey, Secp256k1}, PublicKeyBytes};
use ledger_zcash::{app::ZcashApp, config::{DK_SIZE, FVK_SIZE}};
use ledger_transport_hid::{hidapi::HidApi, TransportNativeHID};
use sapling::{keys::FullViewingKey, zip32::{DiversifiableFullViewingKey, DiversifierKey}, Diversifier };
use transparent::keys::AccountPubKey;
use zcash_client_backend::{
    data_api::{AccountPurpose, WalletWrite},
    proto::service,
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus;
use zip32::DiversifierIndex;
use zx_bip44::BIP44Path;

use crate::{
    config::WalletConfig,
    data::init_dbs,
    remote::{tor_client, Servers},
};

lazy_static::lazy_static! {
    static ref HIDAPI: HidApi = HidApi::new().expect("Failed to create Hidapi");
}

// Options accepted for the `init_ledger` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// A name for the account
    #[arg(long)]
    name: String,

    /// The wallet's birthday (default is current chain height)
    #[arg(long)]
    birthday: Option<u32>,

    /// The server to initialize with (default is \"ecc\")
    #[arg(short, long)]
    #[arg(default_value = "ecc", value_parser = Servers::parse)]
    server: Servers,

    /// Disable connections via TOR
    #[arg(long)]
    disable_tor: bool,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let opts = self;

        // let (network_type, ufvk) = Ufvk::decode(&opts.fvk)
        //     .map_err(anyhow::Error::new)
        //     .and_then(
        //         |(network, ufvk)| -> Result<(NetworkType, UnifiedFullViewingKey), anyhow::Error> {
        //             let ufvk = UnifiedFullViewingKey::parse(&ufvk)?;
        //             Ok((network, ufvk))
        //         },
        //     )
        //     .or_else(
        //         |_| -> Result<(NetworkType, UnifiedFullViewingKey), anyhow::Error> {
        //             let (network, sfvk) = decode_extfvk_with_network(&opts.fvk)?;
        //             let ufvk = UnifiedFullViewingKey::from_sapling_extended_full_viewing_key(sfvk)?;
        //             Ok((network, ufvk))
        //         },
        //     )?;

        // TODO: get network type from 
        let network = consensus::Network::MainNetwork;
        // match network_type {
        //     NetworkType::Main => consensus::Network::MainNetwork,
        //     NetworkType::Test => consensus::Network::TestNetwork,
        //     NetworkType::Regtest => {
        //         return Err(anyhow!("the regtest network is not supported"));
        //     }
        // };

        // Connect to ledger and retrieve device id or fail
        println!("Create Ledger App Transport");
        let app = ZcashApp::new(TransportNativeHID::new(&HIDAPI).expect("Unable to create transport"));

        println!("Connect to ledger and retrieve device version or fail");
        let version = app.get_version()
            .await
            .map_err(anyhow::Error::new)?;

        println!("version {:?}", version);
        let ledger_id = app.get_device_info()
            .await
            .map_err(anyhow::Error::new)?;
        
        println!("Device ID {:?}", ledger_id);

        println!("get UnifiedFullViewingKey ");
        // get UFVK
        let mut ufvk_raw = app.get_ufvk(0)
            .await
            .map_err(anyhow::Error::new)?;

        
        let dfvk = DiversifiableFullViewingKey::from_bytes(&ufvk_raw.dfvk)
            .expect("Unable to create Sapling Diversifiable Full Viewing Key");

       
        let pub_key_bytes = PublicKeyBytes::from(ufvk_raw.transparent);

        let mut account_pub_key_bytes = [0u8; 65];

        account_pub_key_bytes[32..].copy_from_slice(&pub_key_bytes);
        
        // Create the AccountPubKey for this UFVK
        println!("Create the AccountPubKey for this UFVK");
        let account_pub_key = AccountPubKey::deserialize(&account_pub_key_bytes)
            .map_err(anyhow::Error::new)?;

        let ufvk = UnifiedFullViewingKey::new(
            Some(account_pub_key),
            Some(dfvk), 
            None,
        )
            .map_err(anyhow::Error::new)?;

        println!("Created UFVK: {:?}", ufvk);

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

        let purpose = AccountPurpose::ViewOnly;

        // Save the wallet config to disk.
        WalletConfig::init_without_mnemonic(wallet_dir.as_ref(), birthday.height(), network)?;

        let mut wallet_db = init_dbs(network, wallet_dir.as_ref())?;
        wallet_db.import_account_ufvk(&opts.name, &ufvk, &birthday, purpose, None)?;

        Ok(())
    }

    /// Retrieve the connected ledger's "ID"
    ///
    /// Uses 44'/1'/0/0/0 derivation path
    /// Note: This is TBD
    async fn get_id(app: &ZcashApp<TransportNativeHID>) -> Result<PublicKey<Secp256k1>, anyhow::Error> {
        let addr = app.get_address_unshielded(
            &BIP44Path([44 + 0x8000_0000, 1 + 0x8000_0000, 0, 0, 0]),
            false,
        )
        .await
        .map_err(|_| anyhow!("Failed to get unshielded address for \"ID\""))?;
        
        let pub_key = PublicKey::from_sec1_bytes(&addr.public_key)
                .map_err(|_| anyhow!("Failed to generate \"ID\" from public key"))?;

        Ok(pub_key)
    }

    /// Retrieve the defualt diversifier from a given device and path
    ///
    /// The defualt diversifier is the first valid diversifier starting
    /// from index 0
    async fn get_default_div_from(app: &ZcashApp<TransportNativeHID>, idx: u32) -> Result<Diversifier, anyhow::Error> {
        let mut index = DiversifierIndex::new();

        loop {
            let divs = app.get_div_list(idx, index.as_bytes()).await?;
            let divs: &[[u8; 11]] = bytemuck::cast_slice(&divs);

            //find the first div that is not all 0s
            // all 0s is when it's an invalid diversifier
            for div in divs {
                if div != &[0; 11] {
                    return Ok(Diversifier(*div));
                }

                //increment the index for each diversifier returned
                index.increment().map_err(|_| anyhow!("Diversifier Overflow"))?;
            }
        }
    }
}

