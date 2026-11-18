use zcash_client_backend::data_api::Ratio;

/// Returns a progress ratio as a percentage, treating nothing left to do (0 of 0) as 100%.
pub(crate) fn percent(ratio: &Ratio<u64>) -> f64 {
    match *ratio.denominator() {
        0 => 100.0,
        denominator => (*ratio.numerator() as f64) * 100.0 / (denominator as f64),
    }
}

#[cfg(test)]
mod tests {
    use super::percent;
    use zcash_client_backend::data_api::Ratio;

    #[test]
    fn empty_range_is_complete() {
        assert_eq!(percent(&Ratio::new(0, 0)), 100.0);
    }

    #[test]
    fn partial_range() {
        assert_eq!(percent(&Ratio::new(1, 4)), 25.0);
    }
}
