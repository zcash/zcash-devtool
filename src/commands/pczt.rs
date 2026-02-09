use clap::Subcommand;

pub(crate) mod combine;
pub(crate) mod create;
pub(crate) mod create_manual;
pub(crate) mod create_max;
#[cfg(feature = "frost")]
pub(crate) mod frost_participate;
#[cfg(feature = "frost")]
pub(crate) mod frost_sign;
pub(crate) mod inspect;
pub(crate) mod pay_manual;
pub(crate) mod prove;
pub(crate) mod redact;
pub(crate) mod send;
pub(crate) mod send_without_storing;
pub(crate) mod shield;
pub(crate) mod sign;
pub(crate) mod update_with_derivation;

#[cfg(feature = "pczt-qr")]
pub(crate) mod qr;

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Create a PCZT
    Create(create::Command),
    /// Create a PCZT that sends all funds within the account
    CreateMax(create_max::Command),
    /// Create a shielding PCZT
    Shield(shield::Command),
    /// Create a PCZT from manually-provided transparent inputs
    CreateManual(create_manual::Command),
    /// Create a PCZT to satisfy a payment request by spending manually-provided transparent
    /// inputs.
    PayManual(pay_manual::Command),
    /// Inspect a PCZT
    Inspect(inspect::Command),
    /// Adds BIP 44 or ZIP 32 derivations to a PCZT
    UpdateWithDerivation(update_with_derivation::Command),
    /// Redact a PCZT
    Redact(redact::Command),
    /// Create proofs for a PCZT
    Prove(prove::Command),
    /// Apply signatures to a PCZT
    Sign(sign::Command),
    /// Combine two PCZTs
    Combine(combine::Command),
    /// Coordinate FROST threshold signing for Orchard spends in a PCZT
    #[cfg(feature = "frost")]
    FrostSign(frost_sign::Command),
    /// Participate in a FROST threshold signing ceremony
    #[cfg(feature = "frost")]
    FrostParticipate(frost_participate::Command),
    /// Extract a finished transaction and send it
    Send(send::Command),
    /// Extract a finished transaction and send it, without storing in the wallet.
    ///
    /// This should be used for PCZTs created with `pczt create-manual`.
    SendWithoutStoring(send_without_storing::Command),
    #[cfg(feature = "pczt-qr")]
    /// Render a PCZT as an animated QR code
    ToQr(qr::Send),
    #[cfg(feature = "pczt-qr")]
    /// Read a PCZT from an animated QR code via the webcam
    FromQr(qr::Receive),
}
