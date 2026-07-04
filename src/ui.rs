use zcash_protocol::consensus::NetworkType;
use zcash_protocol::value::ZatBalance;

pub(crate) mod proposal;

const COIN: u64 = 1_0000_0000;

/// The display ticker for amounts on the given network, matching the
/// zcashd/zebra convention: `ZEC` on mainnet, `TAZ` on testnet, `REG` on
/// regtest.
pub(crate) fn ticker(network: NetworkType) -> &'static str {
    match network {
        NetworkType::Main => "ZEC",
        NetworkType::Test => "TAZ",
        NetworkType::Regtest => "REG",
    }
}

pub(crate) fn format_zec(value: impl TryInto<ZatBalance>, network: NetworkType) -> String {
    let value = i64::from(
        value
            .try_into()
            .map_err(|_| ())
            .expect("Values are formattable"),
    );
    let abs_value = value.unsigned_abs();
    let abs_zec = abs_value / COIN;
    let frac = abs_value % COIN;
    let zec = if value.is_negative() {
        -(abs_zec as i64)
    } else {
        abs_zec as i64
    };
    format!("{zec:3}.{frac:08} {}", ticker(network))
}
