use anyhow::anyhow;
use clap::{Args, ValueEnum};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use uuid::Uuid;
use zcash_client_backend::data_api::{Account, WalletWrite};
use zcash_client_sqlite::{WalletDb, util::SystemClock};
use zcash_keys::{
    address::Address,
    keys::{ReceiverRequirement, UnifiedAddressRequest},
};

use crate::{
    commands::{inspect::address::inspect, select_account},
    config::get_wallet_network,
    data::get_db_paths,
};

#[cfg(feature = "qr")]
use qrcode::{QrCode, render::unicode};

/// A pool for which the generated address carries a receiver.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Pool {
    /// An Orchard receiver.
    Orchard,
    /// A Sapling receiver.
    Sapling,
    /// A transparent P2PKH receiver.
    Transparent,
}

// Options accepted for the `generate-address` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// The UUID of the account to list addresses for
    account_id: Option<Uuid>,

    /// A pool for which the address must carry a receiver. Repeat the flag to name
    /// several pools. The address carries a receiver for each named pool and no others,
    /// and at least one named pool must be shielded.
    ///
    /// If unset, the address carries a receiver for each shielded pool that the account's
    /// viewing key supports at the chosen diversifier index, and no transparent receiver.
    ///
    /// The wallet chooses the diversifier index from the current time unless the address
    /// carries a transparent receiver. An address with a transparent receiver takes the
    /// next index within the wallet's transparent gap limit, so that recovery from seed
    /// finds funds sent to it.
    #[arg(short, long = "pool", value_enum)]
    pools: Vec<Pool>,

    /// A flag indicating whether a QR code should be displayed for the address.
    #[cfg(feature = "qr")]
    #[arg(long, default_value = "true")]
    display_qr: bool,
}

impl Command {
    pub(crate) fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let params = get_wallet_network(wallet_dir.as_ref())?;
        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let mut db_data = WalletDb::for_path(db_data, params, SystemClock, UnwrapErr(SysRng))?;

        let account = select_account(&db_data, self.account_id)?;

        println!("Account {:?}", account.id());
        let (ua, _) = db_data
            .get_next_available_address(account.id(), address_request(&self.pools)?)?
            .ok_or_else(|| anyhow!("Account {:?} was not found", account.id()))?;
        let ua_str = ua.encode(&params);
        println!("     Address: {ua_str}");

        let zaddr = Address::from(ua).to_zcash_address(&params);
        inspect(zaddr);

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

        Ok(())
    }
}

/// Returns the address request for an address that carries a receiver for each of `pools`
/// and no others.
///
/// If `pools` is empty, the request allows each shielded receiver and omits the
/// transparent receiver. Fails if `pools` is not empty and names no shielded pool.
fn address_request(pools: &[Pool]) -> anyhow::Result<UnifiedAddressRequest> {
    if pools.is_empty() {
        return Ok(UnifiedAddressRequest::SHIELDED);
    }
    let requirement = |pool| {
        if pools.contains(&pool) {
            ReceiverRequirement::Require
        } else {
            ReceiverRequirement::Omit
        }
    };
    UnifiedAddressRequest::custom(
        requirement(Pool::Orchard),
        requirement(Pool::Sapling),
        requirement(Pool::Transparent),
    )
    .map_err(|e| anyhow!("Cannot generate an address with the requested receivers: {e}"))
}

#[cfg(test)]
mod tests {
    use zcash_keys::keys::{
        ReceiverRequirement::{self, *},
        UnifiedAddressRequest,
    };

    use super::{Pool, address_request};

    fn requirements(
        pools: &[Pool],
    ) -> (
        ReceiverRequirement,
        ReceiverRequirement,
        ReceiverRequirement,
    ) {
        match address_request(pools).unwrap() {
            UnifiedAddressRequest::Custom(r) => (r.orchard(), r.sapling(), r.p2pkh()),
            UnifiedAddressRequest::AllAvailableKeys => panic!("expected a custom request"),
        }
    }

    #[test]
    fn no_pools_allows_shielded_receivers_only() {
        assert_eq!(requirements(&[]), (Allow, Allow, Omit));
    }

    #[test]
    fn named_pools_are_required_and_others_omitted() {
        assert_eq!(requirements(&[Pool::Orchard]), (Require, Omit, Omit));
        assert_eq!(
            requirements(&[Pool::Sapling, Pool::Transparent]),
            (Omit, Require, Require)
        );
        assert_eq!(
            requirements(&[
                Pool::Orchard,
                Pool::Sapling,
                Pool::Transparent,
                Pool::Orchard
            ]),
            (Require, Require, Require)
        );
    }

    #[test]
    fn transparent_only_is_rejected() {
        assert!(address_request(&[Pool::Transparent]).is_err());
    }
}
