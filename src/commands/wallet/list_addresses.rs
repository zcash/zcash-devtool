use clap::Args;
use uuid::Uuid;
use zcash_client_backend::data_api::Account;
use zcash_client_sqlite::WalletDb;
use zcash_keys::{keys::UnifiedAddressRequest};
use zcash_client_backend::encoding::encode_payment_address;
use zcash_primitives::consensus::MainNetwork;
use zcash_protocol::consensus::NetworkConstants;
use zcash_client_backend::address::UnifiedAddress;
use crate::{commands::select_account, config::get_wallet_network, data::get_db_paths};

#[cfg(feature = "qr")]
use qrcode::{render::unicode, QrCode};

// Options accepted for the `list-addresses` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// The UUID of the account to list addresses for
    account_id: Option<Uuid>,

    /// A flag indicating whether a QR code should be displayed for the address.
    #[cfg(feature = "qr")]
    #[arg(long, default_value = "true")]
    display_qr: bool,
}

impl Command {
    pub(crate) fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let params = get_wallet_network(wallet_dir.as_ref())?;
        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let db_data = WalletDb::for_path(db_data, params, (), ())?;
        let account = select_account(&db_data, self.account_id)?;

        println!("\nAccount        : {:?}\n\n", account.id());
       
        let (ua, _) = account
            .uivk()
            .default_address(UnifiedAddressRequest::AllAvailableKeys)?;
            
        let ua_str = ua.encode(&params);

        let sapling_test = UnifiedAddress::sapling(&ua).unwrap();
        let mysap: String = encode_payment_address(MainNetwork.hrp_sapling_payment_address(), &sapling_test);
  
        let orchard_test = UnifiedAddress::orchard(&ua).unwrap();

        // Build UA Recievers
        let orchard_address = UnifiedAddress::from_receivers(Some(*orchard_test), Some(sapling_test.clone()), None).unwrap();
        let orchard_sapling_address_str = orchard_address.encode(&MainNetwork);

       
        let mysapling: String = ToString::to_string(&mysap);
        let mysap_orch: String = ToString::to_string(&orchard_sapling_address_str);
        let myfull_ua: String = ToString::to_string(&ua_str);


        #[cfg(feature = "qr")]
        if self.display_qr {
            let code = QrCode::new(mysap)?;
            let ua_qr = code
                .render::<unicode::Dense1x2>()
                .dark_color(unicode::Dense1x2::Light)
                .light_color(unicode::Dense1x2::Dark)
                .quiet_zone(true)
                .build();
            println!("{}\n", ua_qr);
            println!("Sapling Address: {}\n", mysapling);


            let code = QrCode::new(orchard_sapling_address_str)?;
            let ua_qr = code
                .render::<unicode::Dense1x2>()
                .dark_color(unicode::Dense1x2::Light)
                .light_color(unicode::Dense1x2::Dark)
                .quiet_zone(true)
                .build();
            println!("{}\n", ua_qr);
            println!("Orchard + Sapling UA: {}\n", mysap_orch);

            let code = QrCode::new(ua_str)?;
            let ua_qr = code
                .render::<unicode::Dense1x2>()
                .dark_color(unicode::Dense1x2::Light)
                .light_color(unicode::Dense1x2::Dark)
                .quiet_zone(true)
                .build();
            println!("{}\n", ua_qr);
            println!("Default Address: {}\n", myfull_ua);
        }
        Ok(())
    }
}
