# Ironwood (NU6.3 / V6) support

`zcash-devtool` tracks the **Zcash Ironwood** upgrade so it can create, inspect,
and exercise **V6 (Ironwood) transactions** end to end — talking to
`lightwalletd` over gRPC as the *funder* in a local harness, and as a general
inspection/PCZT tool.

Ironwood is the **NU6.3** network upgrade. In `librustzcash` the network
upgrade `NetworkUpgrade::Nu6_3` is a *stable* (non-`cfg`-gated) variant whose
consensus branch ID selects `TxVersion::V6`, so V6 transactions build and parse
on an ordinary `cargo build` — **no `--cfg zcash_unstable` flag is required**.
(The separate `zcash_unstable = "nu7"` gate covers a *later* upgrade — ZIP-233
and friends — which this tool does not use.)

## What this tool depends on

Ironwood support comes from `librustzcash` main, pulled in via
`[patch.crates-io]` in `Cargo.toml`: every `librustzcash` crate we use
(directly or transitively) is repointed to
[`zcash/librustzcash`](https://github.com/zcash/librustzcash) at a single
pinned rev. The higher-level crates (`zcash_client_backend 0.23`,
`zcash_client_sqlite 0.21`, `pczt 0.7`, `zip321 0.8`) keep their crates.io
version numbers but depend on `-pre` lower crates, so a git source is required
— the crates.io releases can't be used directly. `orchard` is **not** patched:
it resolves to `orchard 0.15.0-pre.1` from crates.io for us and for the
patched crates alike.

Pre-release crate versions currently in the tree:

| Crate | Version |
|---|---|
| `orchard` | `0.15.0-pre.1` (crates.io) |
| `zcash_primitives` | `0.29.0-pre.0` |
| `zcash_proofs` | `0.29.0-pre.0` |
| `zcash_keys` | `0.15.0-pre.0` |
| `zcash_transparent` | `0.9.0-pre.0` |
| `zcash_protocol` | `0.10.0-pre.0` |
| `zcash_address` | `0.13.0-pre.0` |

To move to a newer rev, bump every `rev = "…"` line in `[patch.crates-io]`
(they must stay in lockstep) and any `-pre` version requirements in
`[dependencies]` that the new rev advances.

## When does Ironwood activate?

V6/Ironwood transactions are produced once the chain tip is **at or above the
NU6.3 activation height** for the network the wallet is configured with. The
network's activation schedule decides this:

| Network | NU6.3 (Ironwood) activation | Notes |
|---|---|---|
| **mainnet** | not yet scheduled (`None`) | V6 is inactive until NU6.3 is assigned a mainnet height in a future `zcash_protocol` release. Nothing to configure here; the tool follows the schedule baked into `zcash_protocol`. |
| **testnet** | height **4,134,000** | Scheduled in `zcash_protocol`. Point the wallet at a testnet `lightwalletd` (`-n test -s zecrocks`) and it produces V6 transactions once the tip passes 4,134,000. |
| **regtest** | **operator-chosen** | Set via the `--activation-heights` file at `init` (see below). This is how you get a chain where Ironwood is active from the start for local testing. |

Because activation is driven entirely by the network parameters, **testnet works
today and mainnet will work automatically** once NU6.3 is assigned a mainnet
height upstream — no code change here is needed for the mainnet cutover beyond
bumping to the `zcash_protocol` release that carries the height.

> **Scope of "support" today.** The tool builds and parses V6 transactions and
> runs against a NU6.3 chain. Post-NU6.3, Orchard outputs use the post-NU6.3
> circuit. The wallet does **not** yet construct the separate Ironwood
> value-pool bundle (upstream `librustzcash` main currently builds V6
> transactions with `ironwood_anchor: None`); when that lands upstream it will
> flow through the normal `wallet send` / `pay` path with no change here. The
> low-level pieces are already wired: the PCZT prover creates an Ironwood proof
> when a bundle is present (`pczt prove`), `inspect` decodes V6, and
> `wallet send --tx-version 6` is accepted.

## Using regtest

Regtest support lives behind the `regtest_support` Cargo feature and is the way
to stand up a local chain where Ironwood is active from an early height.

**1. Build with the feature:**

```bash
cargo build --release --features regtest_support
```

**2. Write an activation-heights file.** A TOML file gives one entry per
network upgrade: a height, or `"never"` for an upgrade that is deliberately
inactive on this chain. A missing key also means "not active", but is warned
about on every load, since absence may just mean the file predates the tool's
knowledge of that upgrade. `nu6_3` is the Ironwood key:

```toml
# regtest-heights.toml — must match the validator (zebra) and lightwalletd.
overwinter = 1
sapling    = 1
blossom    = 1
heartwood  = 1
canopy     = 1
nu5        = 1
nu6        = 1
nu6_1      = 1
nu6_2      = 1
nu6_3      = 1   # Ironwood / V6 active from height 1; write "never" to disable
```

**3. Initialise the wallet against your local `lightwalletd`.** Regtest has no
hosted server, so an explicit `--server host:port` is required. `-n regtest`
*requires* `--activation-heights`; the heights are persisted verbatim into the
wallet's `keys.toml` (as an `[activation_heights]` table) so every later
command agrees with the chain:

```bash
cargo run --release --features regtest_support -- \
  wallet -w ./regtest-wallet init \
  --name dev -i ./regtest-wallet/dev-key.txt \
  -n regtest --activation-heights ./regtest-heights.toml \
  -s 127.0.0.1:9067
```

`init` reads the mnemonic interactively, but when stdin is not a terminal it
reads one line from stdin instead — so an automated funder can pipe a known
phrase in (`echo "$PHRASE" | cargo run … init …`) without a TTY.

**4. Fund and transact as usual** (`wallet sync`, `wallet shield`,
`wallet send`, …). Once the tip is at/above the `nu6_3` height, the transactions
the wallet builds are V6.

### The cross-component invariant

The `--activation-heights` file **must** be identical to the validator's
schedule (zebra's `configured_activation_heights`) and to what `lightwalletd`
serves. Transaction construction derives the consensus branch ID from these
heights; any drift makes the validator reject transactions built while the tip
is inside the drifted window.

### Offline address derivation for funders

`wallet derive-address` derives an account's default unified and transparent
addresses straight from a mnemonic, with **no wallet directory and no server**:

```bash
cargo run --release --features regtest_support -- \
  wallet derive-address -n regtest --mnemonic "$PHRASE"
# Unified Address: u1...
# Transparent Address: t1...
```

This lets a harness learn the funder's transparent address *before* the chain
exists (e.g. so zebra can mine coinbase to it as `miner_address`). The address
is the first account's default receiver — exactly what `create_account`
produces and what `wallet shield` later scans. (A mnemonic on the command line
is visible in the process list; use this for ephemeral test wallets only.)

## Companion node / indexer

The funder is a `lightwalletd` client, and `lightwalletd` follows a Zebra node;
both must understand Ironwood/V6 for the end-to-end flow. Use the official
Ironwood release candidates:

| Component | Ironwood RC |
|---|---|
| Zebra | [`v6.0.0-rc.0`](https://github.com/ZcashFoundation/zebra/releases/tag/v6.0.0-rc.0) (replaces the older `zfnd/zebra:5.x`) |
| lightwalletd | a build whose transaction parser understands V6 |
| Zaino | [zingolabs/zaino#1362](https://github.com/zingolabs/zaino/pull/1362) (`feat/ironwood_nu6_3`) — zaino `dev` does not yet parse V6 |

Confirm the exact node/indexer tags against the pinned librustzcash rev before
a run — the crate versions above and the node's supported transaction format
must agree.

## Provenance

The regtest walkthrough, funder workflow, and offline derivation sections were
adapted from the `zecrocks/zcash-devtool` `ironwood-valar` branch, which
pioneered end-to-end Ironwood testing against the librustzcash Ironwood release
candidates. Wallet-level Ironwood balances and spending remain on that branch;
they depend on `zcash_client_backend` APIs (e.g. `ironwood_balance()`) that
have not yet merged to librustzcash main.
