# Keep `LocalNetwork` (zcash_protocol `local-consensus`) as the regtest consensus backend

Status: accepted

The devtool-local `ActivationHeights` type owns the TOML schema and verbatim
persistence, but consensus queries for regtest still convert through
`zcash_protocol`'s `LocalNetwork` rather than implementing `Parameters`
directly on `ActivationHeights`. This looks like a prunable indirection — the
`local-consensus` feature could be dropped with ~50 lines of local consensus
logic — and we considered exactly that. We keep it deliberately:
`LocalNetwork` struct literals (the fallback-heights constant and the inspect
encoders) are a compile-time tripwire maintained upstream. When librustzcash
learns a new network upgrade, those literals fail to compile at the next
dependency bump, forcing this tool to confront the upgrade explicitly — the
NU6.3 work was enumerated by precisely these errors. A self-owned
`Parameters` impl would compile silently through a new upgrade, leaving
regtest wallets with a stale consensus view guarded only by a runtime
warning, and would move activation-ordering semantics from upstream's tests
into ours. The feature itself gates one dependency-free module, so pruning
buys nothing measurable.

## Consequences

- Do not replace the `to_local_network()` conversion with a direct
  `Parameters` impl on `ActivationHeights`; the "redundant" conversion is the
  point.
- The `LocalNetwork` literals in the inspect commands must stay exhaustive
  struct literals (no `..Default::default()` shortcuts), or the tripwire is
  disarmed.
