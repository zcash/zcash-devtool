use clap::Subcommand;

pub(crate) mod combine;
pub(crate) mod create;
pub(crate) mod create_manual;
pub(crate) mod inspect;
pub(crate) mod prove;
pub(crate) mod redact;
pub(crate) mod send;
pub(crate) mod shield;
pub(crate) mod sign;

#[cfg(feature = "pczt-qr")]
pub(crate) mod qr;

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Create a PCZT
    Create(create::Command),
    /// Create a shielding PCZT
    Shield(shield::Command),
    /// Create a PCZT from manually-provided transparent inputs
    CreateManual(create_manual::Command),
    /// Inspect a PCZT
    Inspect(inspect::Command),
    /// Redact a PCZT
    Redact(redact::Command),
    /// Create proofs for a PCZT
    Prove(prove::Command),
    /// Apply signatures to a PCZT
    Sign(sign::Command),
    /// Combine two PCZTs
    Combine(combine::Command),
    /// Extract a finished transaction and send it
    Send(send::Command),
    #[cfg(feature = "pczt-qr")]
    /// Render a PCZT as an animated QR code
    ToQr(qr::Send),
    #[cfg(feature = "pczt-qr")]
    /// Read a PCZT from an animated QR code via the webcam
    FromQr(qr::Receive),
}
