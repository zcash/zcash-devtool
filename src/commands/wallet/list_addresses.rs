use anyhow::anyhow;
use clap::{Args, ValueEnum};
use uuid::Uuid;
use zcash_client_backend::data_api::Account;
use zcash_client_sqlite::WalletDb;
use zcash_keys::{
    address::{Address, UnifiedAddress},
    keys::UnifiedAddressRequest,
};

use crate::{commands::select_account, config::get_wallet_network, data::get_db_paths};

#[cfg(feature = "qr")]
use qrcode::{QrCode, render::unicode};

/// Which receiver of the account's unified address to emit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Receiver {
    /// The full unified address (all available receivers).
    Unified,
    /// The transparent (P2PKH) receiver, as a bare transparent address.
    Transparent,
    /// The Sapling receiver, as a bare Sapling address.
    Sapling,
    /// The Orchard receiver, as a unified address carrying only Orchard.
    Orchard,
}

// Options accepted for the `list-addresses` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// The UUID of the account to list addresses for
    account_id: Option<Uuid>,

    /// Which receiver(s) to emit. May be repeated to emit several. Defaults to
    /// `unified`, which preserves the full default-address output. Non-unified
    /// receivers are printed one per line as `Receiver(<pool>): <address>`.
    #[arg(long, value_enum)]
    receiver: Vec<Receiver>,

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
        let (ua, _) = account
            .uivk()
            .default_address(UnifiedAddressRequest::AllAvailableKeys)?;

        // An empty `--receiver` list defaults to the unified address, preserving
        // the historical output.
        let receivers = if self.receiver.is_empty() {
            &[Receiver::Unified][..]
        } else {
            &self.receiver[..]
        };

        for receiver in receivers {
            match receiver {
                Receiver::Unified => {
                    println!("Account {:?}", account.id());
                    let ua_str = ua.encode(&params);
                    println!("     Default Address: {ua_str}");

                    #[cfg(feature = "qr")]
                    if self.display_qr {
                        let code = QrCode::new(ua_str)?;
                        let ua_qr = code
                            .render::<unicode::Dense1x2>()
                            .dark_color(unicode::Dense1x2::Light)
                            .light_color(unicode::Dense1x2::Dark)
                            .quiet_zone(true)
                            .build();
                        println!("{}", ua_qr);
                    }
                }
                Receiver::Transparent => {
                    let addr = ua
                        .transparent()
                        .ok_or_else(|| anyhow!("Account address has no transparent receiver"))?;
                    println!(
                        "Receiver(transparent): {}",
                        Address::from(*addr).encode(&params)
                    );
                }
                Receiver::Sapling => {
                    let addr = ua
                        .sapling()
                        .ok_or_else(|| anyhow!("Account address has no sapling receiver"))?;
                    println!(
                        "Receiver(sapling): {}",
                        Address::from(*addr).encode(&params)
                    );
                }
                Receiver::Orchard => {
                    let addr = ua
                        .orchard()
                        .ok_or_else(|| anyhow!("Account address has no orchard receiver"))?;
                    // Orchard receivers have no bare encoding; emit a unified
                    // address carrying only the Orchard receiver.
                    let orchard_only = UnifiedAddress::from_receivers(Some(*addr), None, None)
                        .ok_or_else(|| anyhow!("Failed to encode orchard-only unified address"))?;
                    println!("Receiver(orchard): {}", orchard_only.encode(&params));
                }
            }
        }

        Ok(())
    }
}
