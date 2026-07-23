use std::path::PathBuf;

use anyhow::anyhow;
use clap::Args;
use pczt::{Pczt, roles::verifier::Verifier};

// Options accepted for the `pczt plan-batches` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// PCZT files to plan into signing rounds, in order (e.g. topological build order, as
    /// written by `migration commit --external`)
    #[arg(long, required = true, num_args = 1..)]
    pczt: Vec<PathBuf>,

    /// Maximum total Orchard + Ironwood actions per round. Keystone's batch-signing firmware
    /// has its own real caps on PCZT count and total payload bytes too (see
    /// `ZCASH_BATCH_MAX_PCZTS`/`ZCASH_BATCH_MAX_TOTAL_BYTES` in the firmware build you're
    /// targeting) -- this only bounds the action count, so still watch for those separately.
    #[arg(long)]
    action_budget: usize,

    /// Include `--redact` in the printed `to-qr-batch` commands (needed for real Keystone
    /// hardware; see `pczt to-qr-batch --help`)
    #[arg(long)]
    redact: bool,
}

impl Command {
    pub(crate) fn run(mut self) -> anyhow::Result<()> {
        if self.action_budget == 0 {
            return Err(anyhow!("--action-budget must be nonzero"));
        }

        // Files are named `<id>.pczt` in the topological (dependency) order `migration commit
        // --external` assigned; that order matters (a later layer/transfer depends on an earlier
        // one's outputs) and must be preserved into each round. A shell glob like `*.pczt` sorts
        // lexicographically (0, 1, 10, 11, ..., 2, 20, ...), not numerically, so trusting the
        // order args arrived in is a real footgun -- sort by the numeric stem instead. Falls back
        // to the given order untouched if any filename doesn't parse as `<number>.pczt`.
        let all_numeric = self.pczt.iter().all(|p| numeric_stem(p).is_some());
        if all_numeric {
            self.pczt.sort_by_key(|p| numeric_stem(p).unwrap());
        } else {
            eprintln!(
                "warning: not every --pczt file is named `<number>.pczt`; using the given order \
                 as-is. If these came from `migration commit --external`, double check they're \
                 in topological (dependency) order, not just alphabetical."
            );
        }

        // Mirrors zcash_pool_migration_backend::engine::batch_unsigned_by_action_budget's greedy,
        // order-preserving packing exactly (a session never splits a file across rounds, and
        // always holds at least one file even if it alone exceeds the budget) -- that function
        // only takes the engine's own `UnsignedMigrationTx` (built fresh at commit time, with its
        // action count already known), so PCZTs already written to disk by an earlier `migration
        // commit --external` are regrouped here by parsing each file's own action count instead.
        let mut rounds: Vec<Vec<(&PathBuf, usize)>> = Vec::new();
        let mut current: Vec<(&PathBuf, usize)> = Vec::new();
        let mut current_actions = 0usize;

        for path in &self.pczt {
            let actions = count_actions(path)?;
            if !current.is_empty() && current_actions.saturating_add(actions) > self.action_budget {
                rounds.push(std::mem::take(&mut current));
                current_actions = 0;
            }
            current_actions = current_actions.saturating_add(actions);
            current.push((path, actions));
        }
        if !current.is_empty() {
            rounds.push(current);
        }

        let total_actions: usize = rounds.iter().flatten().map(|(_, a)| a).sum();
        println!(
            "{} PCZT(s), {total_actions} action(s) total, planned into {} round(s) of <= {} \
             actions each:\n",
            self.pczt.len(),
            rounds.len(),
            self.action_budget,
        );

        let redact_flag = if self.redact { " --redact" } else { "" };
        for (i, round) in rounds.iter().enumerate() {
            let round_actions: usize = round.iter().map(|(_, a)| a).sum();
            println!(
                "# round {i}: {} PCZT(s), {round_actions} action(s)",
                round.len()
            );
            let files = round
                .iter()
                .map(|(path, _)| path.display().to_string())
                .collect::<Vec<_>>()
                .join(" ");
            println!("pczt to-qr-batch{redact_flag} --pczt {files}");
            println!("pczt from-qr-batch --pczt {files}\n");
        }

        Ok(())
    }
}

/// Extracts `N` from a `.../N.pczt` path, if the filename stem is purely numeric.
fn numeric_stem(path: &std::path::Path) -> Option<u64> {
    path.file_stem()?.to_str()?.parse().ok()
}

/// Parses a PCZT file and counts its total Orchard + Ironwood actions (the unit Keystone's
/// batch-signing firmware budgets memory by), the same technique `pczt inspect` uses.
fn count_actions(path: &std::path::Path) -> anyhow::Result<usize> {
    let bytes =
        std::fs::read(path).map_err(|e| anyhow!("Failed to read {}: {e}", path.display()))?;
    let pczt =
        Pczt::parse(&bytes).map_err(|e| anyhow!("Failed to parse {}: {:?}", path.display(), e))?;

    let mut orchard = 0usize;
    let mut ironwood = 0usize;
    Verifier::new(pczt)
        .with_orchard(|bundle| {
            orchard = bundle.actions().len();
            Ok::<_, pczt::roles::verifier::OrchardError<()>>(())
        })
        .map_err(|e| anyhow!("{} failed Orchard verification: {e:?}", path.display()))?
        .with_ironwood(|bundle| {
            ironwood = bundle.actions().len();
            Ok::<_, pczt::roles::verifier::OrchardError<()>>(())
        })
        .map_err(|e| anyhow!("{} failed Ironwood verification: {e:?}", path.display()))?;

    Ok(orchard + ironwood)
}
