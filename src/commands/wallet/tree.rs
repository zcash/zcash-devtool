use clap::Subcommand;

#[cfg(feature = "tui")]
pub(crate) mod explore;

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Explore a tree
    #[cfg(feature = "tui")]
    Explore(explore::Command),
}
