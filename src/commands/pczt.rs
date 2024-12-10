use gumdrop::Options;

pub(crate) mod combine;
pub(crate) mod create;
pub(crate) mod prove;
pub(crate) mod send;
pub(crate) mod sign;

#[derive(Debug, Options)]
pub(crate) enum Command {
    #[options(help = "create a PCZT")]
    Create(create::Command),
    #[options(help = "create proofs for a PCZT")]
    Prove(prove::Command),
    #[options(help = "apply signatures to a PCZT")]
    Sign(sign::Command),
    #[options(help = "combine two PCZTs")]
    Combine(combine::Command),
    #[options(help = "extract a finished transaction and send it")]
    Send(send::Command),
}
