# Feature requests: CLI surface for the zaino wallet-test client

Audience: the Claude working on this `zcash-devtool` clone (branch
`add_regtest`). These requests come from the zaino side. zaino's wallet
integration tests now drive this binary (via `zcash_local_net`'s
`client::zcash_devtool::ZcashDevtool`, which runs each command as a
subprocess and parses stdout) to replace zingolib. The regtest +
non-interactive-init + `--min-confirmations` work already landed and is
proven end to end (a zaino wallet test funds, sends, and shields through a
devtool wallet, green in CI). These requests unblock porting the *rest* of
the suite.

## How this binary is consumed (read first)

`zcash_local_net` shells out to `zcash-devtool wallet <cmd> ...` and **parses
stdout**. Its `client::zcash_devtool` module has parsers (txid line, balance
lines, default-address line) pinned by integration tests against the real
binary. Therefore:

- **Every stdout line this binary prints for a machine-consumed command is an
  integration contract.** Adding a new parseable line is a feature; changing
  an existing one silently breaks the consumer. Put machine-facing output on
  **stdout** in a stable `Label: value` shape (the balance command's existing
  convention). Decorative/human output (`inspect`'s receiver dump) goes to
  stderr — keep it there.
- Each request below names the paired `zcash_local_net` change (a `Client`
  trait method + parser) for context only; that work lives in the
  infrastructure repo, not here. Coordinate the exact output string with it.

---

## P0 — Emit a bare single-receiver address per pool

**The one blocker for most of the suite.** Today `wallet list-addresses` and
`wallet gen-addr` print only the full unified address (all receivers).
`inspect` decodes the receivers but to stderr, in human prose
(`" - Receivers:"`), which is not parseable. zaino's tests need, on stdout,
in a stable shape:

- the wallet's **transparent (P2PKH) receiver**, encoded as a bare
  transparent address (regtest `tm…`);
- the wallet's **sapling receiver**, encoded as a bare sapling address
  (regtest `zregtestsapling…`);
- the **unified** address (already available; keep it).

### Proposed shape

Add `--receiver <unified|transparent|sapling|orchard>` to `wallet
list-addresses` (default `unified`, preserving today's output). For a
requested non-unified receiver, print exactly one line:

```
Receiver(transparent): tmBsTi2xWTjUdEXnuTceL7fecEQKeWaPDJd
Receiver(sapling): zregtestsapling1...
```

(Multiple `--receiver` flags → one line each. Orchard is included for
completeness; zaino routes orchard via the UA, so it is optional.)

### Implementation hint

The default UA already carries the receivers; this is extraction + bare
encoding, no new key material:

- `UnifiedAddress::transparent() -> Option<&TransparentAddress>`, then
  `AddressCodec::encode(&params)` → `tm…` on regtest.
- `UnifiedAddress::sapling() -> Option<&sapling::PaymentAddress>`, then
  `Address::Sapling(pa).to_zcash_address(&params).encode()` →
  `zregtestsapling…`.

Use the wallet's default/last-generated UA (same one `balance` and
`list-addresses` already resolve) so the emitted receivers belong to the
account being mined to and funded.

### Why this is P0

It unblocks, in one change, the entire transparent/sapling half of the
matrix: `send_to_transparent`, `send_to_sapling`, `send_to_all`,
`check_received_mining_reward_and_send` (sends to a sapling address), and
every zaino query test that funds via a transparent or sapling recipient
(the bulk of `fetch_service` / `state_service` / `json_server`). It also
retires a correctness shortcut: the zaino adapter currently hardcodes the
faucet's transparent address to the known miner constant
(`REG_T_ADDR_FROM_ABANDONART`) because it cannot ask the wallet. With this,
the adapter reads the address from the wallet, which *also* verifies (rather
than assumes) that the abandon-art wallet derives the transparent receiver
the miner pays to.

Paired consumer change: a `Client::address(pool)` method + a `Receiver(...)`
line parser.

---

## P1 — Machine-readable output for `balance` (and `list-tx`)

Not blocking — `zcash_local_net` parses the current text today — but
hardening. `wallet balance` prints a `{:#?}` debug dump of the whole
`WalletSummary` followed by `Label: value` lines (`Sapling Spendable:`,
`Orchard Spendable:`, `Unshielded Spendable:`, `Balance:`, `Height:`). The
debug dump in particular is unstable across `zcash_client_*` upgrades and
sits in the middle of the parsed output.

Request: a `--json` flag on `wallet balance` emitting a stable object, e.g.

```json
{ "total": 250000, "sapling_spendable": 0, "orchard_spendable": 250000,
  "transparent_spendable": 0, "chain_tip_height": 4 }
```

(Field names matching the consumer's `WalletBalance` struct would let the
parser switch from line-scraping to `serde_json`.) The same `--json` on
`wallet list-tx` (emitting `[{ "txid": "...", "mined_height": N }, ...]`)
would let zaino reproduce the one remaining wallet-oracle assertion
(`transaction_summaries` in the `get_address_utxos` tests) without text
parsing. Lower priority than the balance `--json`.

Paired consumer change: swap the hand-rolled stdout parsers for `serde_json`
when `--json` is present.

---

## P2 — (Known gap, likely out of scope) Mempool / unconfirmed balances

One zaino test (`monitor_unverified_mempool`) broadcasts two transactions
*without mining*, then asserts the recipient wallet shows them as
**unconfirmed** per-pool balances. `wallet sync` here is block-based
(`zcash_client_backend`) and does not scan the mempool, so there is no
unconfirmed balance to report. Surfacing mempool state would be a large
change well beyond regtest plumbing.

Recommendation: **do not attempt this for the port.** That single test stays
on zingolib, or is re-scoped on the zaino side to assert against zaino's own
mempool gRPC views rather than a wallet. Listed here only so the gap is
documented and not rediscovered.

---

## Suggested order

1. **P0 receiver addresses** — small, mechanical, unblocks the majority of
   the remaining zaino wallet tests. Do this first.
2. **P1 `balance --json`** — removes the most fragile parse surface; do
   alongside or just after P0.
3. **P1 `list-tx --json`** — only if the `get_address_utxos` oracle tests
   are being ported.
4. **P2 mempool** — skip; documented as a non-goal.

Coordinate the exact stdout strings for P0/P1 with the `zcash_local_net`
`client::zcash_devtool` parsers (infrastructure repo, branch
`add_client_support`) so the contract and its pinning tests move together.
