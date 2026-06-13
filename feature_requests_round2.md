# Feature requests (round 2): unblock the rest of the zaino wallet-test port

Audience: the Claude on this `zcash-devtool` clone (branch `add_regtest`).
Round 1 (`feature_requests.md`: regtest network, non-interactive init,
`--min-confirmations`, `--receiver`, `--json`) is done and in use — zaino now
drives this binary via `zcash_local_net` for ~31 wallet tests. These requests
unblock the test families that remain deferred.

zaino consumes this binary as a subprocess through
`zcash_local_net::client::zcash_devtool`; **stdout shapes are an integration
contract** (round-1 rule still applies). Each item below names the zaino tests
it unblocks.

---

## P0 — Accept regtest activation heights at init (don't hardcode them)

**The single biggest blocker.** The `regtest_support` build currently bakes in
one set of activation heights. `zcash_local_net`'s `ZcashDevtoolConfig`
mirrors them in `supported_regtest_activation_heights()` and **rejects** a
launch whose heights differ (`ClientError::UnsupportedActivationHeights`).

Consequence: the wallet only works against a validator launched with exactly
those heights. zaino's **zebrad** sessions match, so they work. zaino's
**zcashd** sessions launch with zcashd's *default* regtest heights, which
differ — so every zcashd-backed test (the entire `json_server` mod, plus the
zcashd column of the send/query matrix) is unportable.

### Request

Let `init` (and any command that constructs the wallet's consensus params for
`-n regtest`) take the activation heights as input rather than compiling them
in. A `LocalNetwork`-shaped set: the activation height per network upgrade
(BeforeOverwinter/Overwinter/Sapling/Blossom/Heartwood/Canopy/NU5/NU6/NU6.1/
NU6.2/NU7). `zcash_protocol`'s `local-consensus` `LocalNetwork` already models
exactly this and is already in the dependency tree — the regtest params just
need to come from config instead of a constant.

Interface (any of these works; coordinate the exact shape with
`zcash_local_net`):
- a `--activation-heights <toml|json file>` flag on `init`, or
- repeatable `--activation-height <upgrade>=<height>` args, or
- a small config file the wallet dir already persists, written at `init`.

Persist the chosen heights in the wallet config so later commands agree.

### What it unblocks

The entire zcashd half of the matrix — `json_server` (its whole mod) and every
zcashd variant of the send/query tests. `zcash_local_net` would then pass the
session's actual heights to the client instead of asserting a constant.

---

## P1 — Confirm (and if needed, enable) detection + shielding of transparent coinbase

Some zaino tests mine to a **transparent** miner address
(`REG_T_ADDR_FROM_ABANDONART`, the abandon-art seed's transparent receiver)
and fund the wallet by maturing that coinbase and **shielding** it
(`send_to_transparent`'s finalization variant, `address_deltas`, the
`test_vectors` chain builder). This requires the faucet wallet to:

1. derive the transparent receiver equal to `REG_T_ADDR_FROM_ABANDONART`
   (round-1 `--receiver transparent` should already give this — please
   confirm it equals that constant for the abandon-art seed), and
2. **detect** the coinbase outputs paid to that address during `sync`, and
3. **shield** them (mature transparent coinbase -> orchard).

`zcash_client_sqlite`'s `transparent-inputs` feature should cover (2)/(3), but
this path has never been exercised here. **First, just confirm it works**: a
`wallet balance` showing the matured transparent coinbase after syncing a
transparent-mined regtest chain, then a successful `shield`. If it already
works, this is a no-op (and zaino unblocks a batch with no devtool change). If
it does **not** (coinbase not credited, or shield refuses transparent coinbase),
that is the gap to close — enable transparent-coinbase scanning/spending for
regtest.

### What it unblocks (only if a gap is found and fixed)

The transparent-mining family: `send_to_transparent` (finalization), the
`state_service` faucet-taddr query tests, `address_deltas`, and the
`test_vectors` builder.

> Note: the faucet-taddr *query* tests that only need the address string (not a
> spend) may already be portable on zaino's side once we confirm item (1); we
> will handle those without a devtool change.

---

## P2 — (Low priority, large) Unconfirmed / mempool balances

`monitor_unverified_mempool` broadcasts transactions without mining and asserts
the recipient wallet reports them as **unconfirmed** per-pool balances.
`wallet sync` is block-based (`zcash_client_backend`) and does not scan the
mempool, so there is nothing to report. Surfacing mempool state is a large
change well beyond regtest plumbing.

Recommendation: **do not attempt.** That one test stays on zingolib or is
re-scoped to assert against zaino's own mempool views. Listed only so the gap
is documented.

---

## Order

1. **P0 activation heights** — unblocks the most (the whole zcashd matrix);
   smallest, most mechanical given `local-consensus` is already a dependency.
2. **P1 transparent coinbase** — start by *confirming*; only implement if a gap
   is found.
3. **P2 mempool** — skip.

Coordinate the P0 config/flag shape with `zcash_local_net`
(`client::zcash_devtool`, infrastructure branch `add_client_support`) so the
contract and its pinning tests move together.
