# Explicit "never" encoding for inactive network upgrades in activation-heights TOML

Status: accepted

Activation-heights files (and the copy persisted in the wallet config)
originally encoded "upgrade not active" only as key absence. That made a stale
file — one written before the tool learned of a newer upgrade, e.g. NU6.3 —
indistinguishable from a deliberate opt-out, and Height Drift from stale files
surfaces only as validator-rejected transactions. We decided that a key may now
be written as `"never"` (Explicitly Inactive); bare absence (Implicitly
Inactive) remains legal and still means inactive, but is warned about whenever
the file or wallet config is loaded.

## Considered Options

- **Warn on absence, no schema change** — rejected: the warning would be
  unsilenceable for genuine opt-outs, since absence was the only way to say
  "inactive".
- **Require complete files at wallet creation** (every known upgrade stated as
  a height or `"never"`) — rejected in favor of lenient-with-warning: each new
  upgrade the tool learns about would break existing committed heights files
  at `init` until edited.
- **Backfill omitted keys as `"never"` at creation** — rejected: it launders
  "operator never considered this upgrade" into "operator chose never",
  destroying the distinction the encoding exists to preserve.

## Consequences

- The activation-heights schema in operator-committed files is extended;
  reverting `"never"` support after files use it would break those files.
- Wallet-command load paths warn on any known-but-absent upgrade key; the
  warning is silenced by stating the key explicitly (a height or `"never"`).
