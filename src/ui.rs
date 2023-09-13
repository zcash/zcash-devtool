use zcash_primitives::transaction::components::Amount;

const COIN: u64 = 1_0000_0000;

pub(crate) fn format_zec(value: impl Into<Amount>) -> String {
    let value = u64::from(value.into());
    let zec = value / COIN;
    let frac = value % COIN;
    format!("{:3}.{:08} ZEC", zec, frac)
}
