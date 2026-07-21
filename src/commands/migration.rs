use clap::Subcommand;

pub(crate) mod commit;
pub(crate) mod plan;
pub(crate) mod status;
mod store;

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Preview a migration: the note-split denominations, funding notes, and transfer schedule.
    /// Read-only, no wallet changes.
    Plan(plan::Command),

    /// Commit a migration's preparation: build and pre-sign the first layer of preparation
    /// transactions, and persist the migration.
    Commit(commit::Command),

    /// Show the in-progress migration's status and what to do next.
    Status(status::Command),
}
