use std::fmt;

use clap::ValueEnum;

/// How much data each animated QR code carries. A denser code needs fewer frames to send the
/// same data, but it is larger on screen and harder for a camera to read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub(crate) enum QrDensity {
    /// 100 bytes per QR code. The easiest to scan.
    #[default]
    Low,
    /// 200 bytes per QR code.
    Medium,
    /// 400 bytes per QR code, the Keystone SDK default.
    High,
    /// 800 bytes per QR code. Needs a large terminal and a good camera.
    Max,
}

#[cfg(feature = "pczt-qr")]
impl QrDensity {
    /// Returns the most bytes of the message that each QR code carries.
    pub(crate) fn bytes_per_qr(self) -> usize {
        match self {
            QrDensity::Low => 100,
            QrDensity::Medium => 200,
            QrDensity::High => 400,
            QrDensity::Max => 800,
        }
    }
}

/// Writes the name that `--qr-density` accepts.
impl fmt::Display for QrDensity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            QrDensity::Low => "low",
            QrDensity::Medium => "medium",
            QrDensity::High => "high",
            QrDensity::Max => "max",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_round_trips_through_the_command_line_parser() {
        for density in QrDensity::value_variants() {
            assert_eq!(
                QrDensity::from_str(&density.to_string(), false),
                Ok(*density)
            );
        }
    }

    #[cfg(feature = "pczt-qr")]
    #[test]
    fn denser_tiers_carry_more_bytes() {
        let bytes: Vec<usize> = QrDensity::value_variants()
            .iter()
            .map(|density| density.bytes_per_qr())
            .collect();
        assert!(bytes.windows(2).all(|pair| pair[0] < pair[1]), "{bytes:?}");
    }
}
