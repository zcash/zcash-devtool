# Ironwood migration + Keystone batch-signing guide (zodl team)

Practical command reference for the Zodl team's use of `zcash-devtool` — mainly
wallet management, note fan-out (building a synthetic "very active wallet"),
and the Orchard→Ironwood pool migration + Keystone batch-signing workflow.
This is the zodl-specific companion to the upstream `README.md`; that one
covers general build/setup, this one covers "what do I actually type."

Every command below assumes you're in `~/zodl/zcash-devtool` and have built
the binary:

```
cargo build --features regtest_support,pczt-qr
```

The binary lands at `./target/debug/zcash-devtool`. All examples below use
that path directly; substitute `--release` / `target/release/...` if you
built a release binary instead.

**Use a release build for anything that builds/proves multiple
transactions** (e.g. `migration commit` on a wallet with many funding
notes). Orchard/Ironwood proof generation is unoptimized-debug-slow —
often 10-20x slower than release — so a migration with dozens of
transactions can take many minutes longer than it needs to in a debug
build:

```
cargo build --release --features regtest_support,pczt-qr
```

Every command that touches a wallet takes `-w <wallet_dir>` **before** the
subcommand name, e.g. `zcash-devtool wallet -w ~/my-wallet sync`. A "wallet
directory" is just a folder devtool creates and manages (sqlite DB + config +
an `identity.txt` age keyfile); pick any empty directory when starting fresh.

---

## 1. Setting up a wallet

### 1a. Generate an age identity (once per wallet)

The mnemonic is stored encrypted to an [age](https://age-encryption.org)
identity. Generate one before restoring/creating a wallet:

```
mkdir -p ~/my-wallet
age-keygen -o ~/my-wallet/identity.txt
```

(`restore-mnemonic`/`init` will also generate one automatically at the path
you pass to `--identity` if it doesn't already exist — but having a fixed
path there makes automation and script-writing easier, so pre-creating it
is the recommended habit.)

### 1b. Restore an existing wallet from a seed phrase

```
echo "your twenty four word seed phrase goes right here in quotes not needed" | \
./target/debug/zcash-devtool wallet -w ~/my-wallet restore-mnemonic \
  --name my-wallet \
  --identity ~/my-wallet/identity.txt \
  --network test \
  --birthday <BIRTHDAY_HEIGHT> \
  --server 127.0.0.1:9067 --connection direct
```

- `--network`: `test`, `main`, or `regtest` (needs `regtest_support` build feature).
- `--birthday`: the block height the wallet's seed first existed at. Get this
  right — too low means a much longer, slower initial sync; too high means
  missed funds. For zodl's 300-wallet testnet fleet, birthday height is a
  column in `testnet-wallets/testnet_wallets.csv`.
- `--server`: point this at whatever lightwalletd/zaino-compatible server
  you're using. Zodl's local stack runs on `127.0.0.1:9067`.
- `--connection direct`: skip Tor (the CLI default). Always use `direct` for
  local testnet work.

### 1c. Create a brand new empty wallet instead

```
./target/debug/zcash-devtool wallet -w ~/my-wallet init \
  --name my-wallet --identity ~/my-wallet/identity.txt --network test
```

### 1d. Sync

```
./target/debug/zcash-devtool wallet -w ~/my-wallet sync \
  --server 127.0.0.1:9067 --connection direct
```

Run this after any action that changes on-chain state (sending funds,
waiting for confirmations) and before any command that reads balance/notes,
since devtool doesn't auto-sync.

### 1e. Check what you've got

```
./target/debug/zcash-devtool wallet -w ~/my-wallet list-accounts
./target/debug/zcash-devtool wallet -w ~/my-wallet balance
./target/debug/zcash-devtool wallet -w ~/my-wallet list-unspent
```

`list-accounts` prints the account's UUID, UIVK, and UFVK — the UFVK is the
right thing to string-compare against a CSV/ground-truth record to confirm
you restored the wallet you think you did.

`balance` breaks totals down by pool (Sapling / Orchard / Ironwood /
Unshielded); useful flags: `--min-confirmations N`, `--json`.

---

## 2. Building a synthetic "very active wallet" (fan-out)

`wallet fan-out` self-sends a trivial payment and asks the change strategy to
split the leftover value into many small notes, instead of one big change
note. This is how we simulate a long-lived, heavily-used wallet without
waiting for real usage history.

```
./target/debug/zcash-devtool wallet -w ~/my-wallet fan-out \
  --identity ~/my-wallet/identity.txt \
  --target-note-count 80 \
  --min-split-output-value 10000000 \
  --value 1000 \
  --server 127.0.0.1:9067 --connection direct
```

- `--target-note-count`: **this is the total number of notes you want the
  wallet to end up with, not "how many new notes to create."** If the wallet
  already has at least this many notes above `--min-split-output-value`, the
  command will just consolidate down to a single change output instead of
  splitting — it thinks you already have enough. Always set this **above**
  your current `list-unspent` count if you want more notes out of this round.
- `--min-split-output-value`: the floor value (zatoshis) for a split output.
  If the available change can't be divided into `target-note-count` pieces
  each at least this big, fewer, larger notes are created instead.
- `--value`: the (otherwise-irrelevant) explicit self-payment amount in
  zatoshis. Only matters in that it's subtracted from the round's input
  value before splitting; 1000 is a sensible default.

**One round = one transaction.** To build up serious fragmentation (hundreds
or thousands of notes), run this repeatedly, syncing and waiting for
confirmation between rounds, bumping the target each time. A basic loop:

```bash
WALLET=~/my-wallet
IDENTITY=$WALLET/identity.txt
INCREMENT=45   # how many more notes to aim for, each round

for i in $(seq 1 30); do
  CURRENT=$(./target/debug/zcash-devtool wallet -w "$WALLET" list-unspent | grep -c "Orchard Note")
  TARGET=$((CURRENT + INCREMENT))
  ./target/debug/zcash-devtool wallet -w "$WALLET" fan-out \
    --identity "$IDENTITY" --target-note-count "$TARGET" \
    --min-split-output-value 50000 --value 1000 \
    --server 127.0.0.1:9067 --connection direct
  sleep 45   # wait for the transaction to be mined before spending its change
  ./target/debug/zcash-devtool wallet -w "$WALLET" sync --server 127.0.0.1:9067 --connection direct
done
```

**Gotcha to know about:** the fee estimator sizes its worst-case fee off
`target-note-count`, before it knows how many splits are actually
achievable. If you set a huge target far above what the round's available
input value can afford (e.g. target +900 when you're only spending a
0.01 TAZ note), the fee estimate for that many hypothetical outputs
exceeds the available value, the change computation underflows to zero,
and you silently get a single un-split output instead of an error. Keep
each round's target increment modest (tens, not hundreds) relative to the
value you expect that round to actually spend.

**Note-value floor for triggering migration consolidation:** the pool
migration engine only lets a note directly fund a "crossing" transaction if
it's individually worth more than roughly 0.011 TAZ (crossing value + prep
fee). Notes below that must first go through a separate consolidation step
(batched 15-in-per-tx). If you want your fan-out to produce a migration with
*many* transactions (to stress-test batch-QR signing), fan out into notes
**below** that floor (e.g. `--min-split-output-value 50000`, i.e. 0.0005
TAZ) — notes above it just get spent directly as funding, one-for-one, and
won't inflate the migration's transaction count no matter how many of them
there are.

---

## 3. Orchard → Ironwood pool migration

This is the multi-command workflow that plans, schedules, and (for external
signers) exports a wallet's Orchard-to-Ironwood migration.

### 3a. Preview a plan (read-only, no wallet changes)

```
./target/debug/zcash-devtool migration -w ~/my-wallet plan
```

Prints the note-split "crossing value" denominations, the funding notes
built from them, and the transfer schedule (broadcast/expiry heights). Safe
to run any time; doesn't touch the wallet.

### 3b. Commit — build the actual migration

In-process signing (spending key stays local, everything gets signed and
persisted directly):

```
./target/debug/zcash-devtool migration -w ~/my-wallet commit \
  --identity ~/my-wallet/identity.txt
```

External signing (Keystone or other airgapped signer — every transaction is
built and left **unsigned**, and additionally written out as individual
`.pczt` files for batch QR export):

```
./target/debug/zcash-devtool migration -w ~/my-wallet commit \
  --identity ~/my-wallet/identity.txt --external
```

This writes `<wallet_dir>/unsigned-pczts/0.pczt`, `1.pczt`, … and prints the
exact `pczt to-qr-batch` command to run next.

### 3c. Check status / next step

```
./target/debug/zcash-devtool migration -w ~/my-wallet status
```

Shows every transaction's state (`awaiting_signature` / `signed` / `proved`
/ `broadcast` / `mined`) and what's blocking it (dependencies, a scheduled
height, or waiting on an external signature), plus what to do next.

### 3d. Advance

```
./target/debug/zcash-devtool migration -w ~/my-wallet advance
```

Drives the migration forward against the live chain tip — broadcasts
whatever's ready. (As of this writing, the final prove-and-broadcast step
for externally-signed transactions isn't wired up yet; `advance` will say so
and stop cleanly rather than erroring.)

---

## 4. PCZT tools (signing, QR export)

`zcash-devtool pczt` has a lot of subcommands (`create`, `sign`, `prove`,
`combine`, `extract`, `send`, …) for general PCZT handling — see
`pczt --help` for the full list. The two most relevant to Keystone
batch-signing:

### 4a. Single PCZT → animated QR

```
./target/debug/zcash-devtool pczt to-qr < path/to/some.pczt
```

Reads a PCZT from stdin, renders it as a looping animated QR in the
terminal for a camera to scan.

### 4b. Multiple PCZTs → one batch QR (Keystone batch signing)

```
./target/debug/zcash-devtool pczt to-qr-batch \
  --pczt ~/my-wallet/unsigned-pczts/*.pczt
```

Bundles every PCZT you pass into a single `zcash-sign-batch` UR payload and
loops it as an animated QR, same as above. **By default this also redacts
each PCZT first** — clears `spend_auth_sig` and the output-side `ock` /
`zip32_derivation` / `user_address` from every Orchard and Ironwood action,
based on `vizor-wallet`'s `redact_pczt_for_batch_signer`. A freshly-built
PCZT's dummy padding actions already carry a self-signed `spend_auth_sig`,
and Keystone firmware categorically rejects a batch member carrying any
pre-existing one, dummy or real. This tripped us up for a while (see
`../keystone-batch-migration-testing-plan.md`'s "RESOLVED" section) before
Adam Tucker pointed at Vizor's existing pattern as the fix.

**One deliberate difference from Vizor's version: `spend_fvk` is NOT
cleared.** Vizor can safely drop it because their own wallet populates each
spend's `zip32_derivation` field, letting the device re-derive the FVK
itself; `zcash_pool_migration_backend`'s PCZTs never populate that field
(confirmed directly), so clearing `fvk` too leaves the device with no way
to attribute *any* input to the account (`Invalid QR Code / None of inputs
belong to the provided account` on real hardware — a second real bug we
hit and fixed, see the plan doc).

**Before batch-QR-ing a migration's unsigned PCZTs, backfill their missing
`zip32_derivation`** with the existing `pczt update-with-derivation`
command (this is the actual fix for the error above — keeping `fvk` on the
wire wasn't sufficient by itself, the device needs the derivation path):

```bash
mkdir -p ~/my-wallet/unsigned-pczts-with-derivation
for f in ~/my-wallet/unsigned-pczts/*.pczt; do
  name=$(basename "$f")
  out=~/my-wallet/unsigned-pczts-with-derivation/"$name"
  tmp=$(mktemp); cp "$f" "$tmp"
  for pool in orchard ironwood; do
    tmp2=$(mktemp)
    if ./target/debug/zcash-devtool pczt -w ~/my-wallet update-with-derivation \
        --identity ~/my-wallet/identity.txt "$pool" "m/32'/1'/0'" \
        < "$tmp" > "$tmp2" 2>/dev/null; then
      mv "$tmp2" "$tmp"
    else
      rm -f "$tmp2"   # "no spends matched" is expected for the pool a file has no real spend in
    fi
  done
  cp "$tmp" "$out"; rm -f "$tmp"
done
```

Adjust the ZIP 32 path (`m/32'/<coin_type>'/<account>'`) to match the
account you're migrating — `1` is the ZIP 32/SLIP 44 testnet coin type,
`133` mainnet; get the account index from `wallet list-accounts`. Do this
once per migration, then always batch-QR from the
`unsigned-pczts-with-derivation/` directory instead of the raw
`unsigned-pczts/` one.

Useful flags:

- `--no-redact`: skip the redaction and send the raw PCZT bytes. Only
  useful for reproducing the original rejection or inspecting the
  unredacted wire payload — real hardware scans should never use this.
- `--max-fragment-len <N>` (default 100): bytes per QR fragment. **Lower
  this if the rendered QR doesn't fit your terminal window** (fewer bytes
  per frame → lower QR version → smaller module count → more frames but
  each one physically smaller/scannable). Don't raise it trying to reduce
  frame count — bigger fragments make each QR *more* dense, which is the
  opposite of what a real camera needs.
- `--interval <ms>` (default 500): time each QR frame is shown before
  advancing. Raise this if your camera/decoder needs longer to focus and
  decode each frame.
- `--out-file <path>`: instead of an animated terminal loop, dump every UR
  fragment to a file, one per line — this is what the Keystone
  **simulator's** file-based QR input (`qrcode_data.txt`) expects, not a
  real camera. Don't use this flag for real-hardware scanning.

It's just an **animated QR loop by design** — for anything beyond a trivial
payload, the data doesn't fit in one QR frame (a single QR code tops out
around ~3KB; a real migration batch is much bigger), so it's split across
many frames shown in sequence, looping forever until you Ctrl+C. Point the
camera at the screen and hold it steady; the receiver reconstructs the full
message from enough frames across one or more loops — you don't need to
"catch" any particular frame.

### 4c. Reading a signed response back

```
./target/debug/zcash-devtool pczt from-qr
```

Opens the camera and scans an animated QR (e.g. a signed PCZT coming back
from a hardware wallet) until it's fully reconstructed, then writes the
finished PCZT to stdout.

Both `from-qr` and `from-qr-batch` render a **live terminal preview** while
scanning by default (ANSI truecolor, redrawn every tick) plus a status
line: whether a QR was detected this frame, how many unique fountain-code
parts have been seen vs. the total the sender announced, frame count, and
the last scan event. Pass `--no-preview` to fall back to plain silent
scanning if your terminal doesn't render truecolor well.

Use `--camera <substring>` to skip the interactive camera picker and lock
to a specific device every run (case-insensitive match against the
camera's name), e.g. `--camera iphone` or `--camera harry` for a
Continuity Camera phone instead of the built-in webcam — useful since a
phone is usually easier to hold steady and position than aiming a laptop
at the device. Continuity Camera over **USB** has been confirmed to work
for this even when the Wi-Fi-based pairing wasn't cooperating; if the
phone isn't showing up as a camera at all, open Photo Booth or FaceTime
once and select it there first to "wake" the pairing (both apps only show
a camera-source picker when more than one camera is actually detected, so
no picker showing up means the phone genuinely isn't registering yet, not
a UI quirk).

For a batch, use `from-qr-batch` instead:

```
./target/debug/zcash-devtool pczt from-qr-batch \
  --pczt unsigned-pczts/0.pczt unsigned-pczts/1.pczt ... \
  --out-suffix .signed \
  --camera harry
```

Pass the **same files, in the same order** given to `to-qr-batch`. Scans a
`zcash-batch-sig-result` UR, decodes it as a
`pczt::roles::signer::batch::BatchSignResponse`, and applies each PCZT's
signatures via `Signer::apply_orchard_spend_auth_signature`. Without
`--out-suffix`, each `--pczt` file is overwritten in place with its signed
PCZT; with it (e.g. `.signed`), writes alongside instead (`0.pczt.signed`).
Errors out if the response's signature-set count doesn't match the number
of `--pczt` files given — that mismatch means the wrong files/order were
passed.

**Confirmed working end-to-end on real Keystone hardware** (see
`../keystone-batch-migration-testing-plan.md`'s "FULL BATCH SIGN CONFIRMED"
section): a 3-PCZT / 34-action batch was redacted, sent via `to-qr-batch`,
reviewed and signed on a physical device, scanned back via
`from-qr-batch`, and every action came back with a valid distinct
`spend_auth_sig` applied to the original unredacted files.

### 4d. One command instead of two: `qr-batch`

Running `to-qr-batch` and `from-qr-batch` separately means manually
Ctrl+C-ing the sender once the device has scanned it, then starting the
receiver as its own command. `qr-batch` folds both into one process:

```
./target/debug/zcash-devtool pczt qr-batch \
  --pczt unsigned-pczts-with-derivation/0.pczt unsigned-pczts-with-derivation/1.pczt ... \
  --out-suffix .signed \
  --camera harry
```

It shows the outgoing batch QR loop exactly like `to-qr-batch` (redacted by
default, same `--no-redact`/`--max-fragment-len`/`--interval` flags), with
**no camera opened at all** during that phase. Scan it on the device,
review, and sign as usual. Once you're about to flip the camera around to
point it at the device, **press Enter** in the terminal — that's the
signal to open the camera and switch straight into `from-qr-batch`'s scan
loop (same live preview, progress line, and `--camera`/`--out-suffix`
behavior).

Why Enter and not fully automatic: there's no side channel from the
Keystone back to this tool except a camera watching its screen, and during
the sending phase the physical setup is the other way around anyway (the
*device's* camera is pointed at *this* screen, not the other way round) —
so there's nothing this tool's camera could usefully watch yet, and
opening it early just holds the camera (and its indicator light) for no
reason. Enter is a deliberate handoff at the point where you're physically
flipping the camera around, not a guess at timing.

If you'd rather keep the two steps fully separate (e.g. running the sender
and receiver on different machines, or from different terminal sessions),
`to-qr-batch` + `from-qr-batch` are still there and unchanged.

---

## 5. Keystone enrollment

```
./target/debug/zcash-devtool keystone -w ~/my-wallet enroll
```

Emits a `zcash-accounts` UR as an animated QR so a companion app/device can
import this wallet's account info. This is the *reverse* direction from
batch signing — it's about the device learning your account, not about it
signing anything. Not a prerequisite for batch-signing to work (the device
derives its own UFVK from its own seed independently).

---

## 6. Common gotchas

- **`target-note-count` is a target total, not an increment.** See §2.
- **Sync before you trust `balance`/`list-unspent`.** They read whatever's
  already scanned into the local sqlite DB; devtool never auto-syncs.
- **A just-broadcast transaction won't show up until it's mined *and*
  synced.** `balance` can show a pending spend before the wallet has synced
  far enough to see the new change note as spendable — don't assume
  `list-unspent`'s count is final until you've synced past the block your
  transaction landed in.
- **QR batch size vs. hardware limits**: Keystone's batch-PCZT signing has a
  real, firmware-enforced cap on both PCZT count and total payload bytes
  (check the specific firmware build's `ZCASH_BATCH_MAX_PCZTS` /
  `..._MAX_TOTAL_BYTES` constants — these get tuned over time as real
  hardware memory constraints are discovered, so don't assume a number from
  memory is still current). If your migration produces more transactions
  than one batch's cap allows, you'll need multiple scan-and-return rounds.
- **The account's default receiver address may prefer Ironwood over
  Orchard** post-NU6.3 activation. If you're testing pool-migration flows,
  check `wallet balance`'s per-pool breakdown, not just total balance — a
  wallet can show funds when in fact none of it is in the pool you need
  (e.g. all-Ironwood, nothing in Orchard, meaning there's nothing left to
  migrate).

---

## 7. Upstream references

Everything in §3 and §4 depends on unmerged/in-progress work in three
separate repos. Keeping this list current matters — a lot of the bugs in
"Common gotchas" and in the Keystone testing plan doc only made sense once
we knew exactly which branch/PR was actually running.

### librustzcash (pinned in `Cargo.toml`, rev `27d50e831bb67dd6e79f61d2fa4efbe02cc22593`)

- Branch `feat/pool-migration-sqlite`,
  [zcash/librustzcash#2669](https://github.com/zcash/librustzcash/pull/2669)
  ("SQLite persistence for pool migrations", stacked on
  [#2663](https://github.com/zcash/librustzcash/pull/2663), the migration
  engine itself). This is what `zcash_pool_migration_backend` and
  `zcash_pool_migration_sqlite` in `Cargo.toml` point at, and what every
  `migration` subcommand in this tool is built against.
- [zcash/librustzcash#2710](https://github.com/zcash/librustzcash/pull/2710)
  ("consult the drawn anchor boundary at proving time") — the actual
  proving step for externally-signed migration transfers. **Not merged,
  and gated on [#2700](https://github.com/zcash/librustzcash/pull/2700)**
  (migration anchor-checkpoint retention). Until this lands, an
  externally-signed migration transaction can be built and signed (as in
  §4) but not proved, extracted, or broadcast — confirmed directly with
  Danny Willems. This is the one real remaining upstream blocker; nothing
  in this tool works around it because nothing can.
- `orchard` is separately patched (`[patch.crates-io]` in `Cargo.toml`) to
  `63f4101e8bb6cd35d5c6aed6208455168362ee9f`, tracking the tip of
  [zcash/orchard#535](https://github.com/zcash/orchard/pull/535) (the
  deferred-anchor `Updater`/`Prover` API, ZIP 374) that #2710 will
  eventually call.

### keystone3-firmware (KeystoneHQ, testnet build via the valargroup fork)

- [KeystoneHQ/keystone3-firmware#2222](https://github.com/KeystoneHQ/keystone3-firmware/pull/2222)
  ("Add request-derived Zcash testnet support") — opened from
  `valargroup:adam/zcash-pczt-testnet-network` against
  `KeystoneHQ:zcash-upstream`. This is the actual testnet build flashed to
  the physical device used for every real-hardware test referenced in
  `../keystone-batch-migration-testing-plan.md`. `valargroup/keystone3-firmware`
  is a fork of `KeystoneHQ/keystone3-firmware`, not a separate project —
  PR numbers only line up with what Adam/Valar can see when referenced
  through the `KeystoneHQ` repo, not the fork's own internal numbering.
- [KeystoneHQ/keystone3-firmware#2225](https://github.com/KeystoneHQ/keystone3-firmware/pull/2225)
  ("Reject existing Zcash batch signatures") — the check that rejects any
  batch member carrying a pre-existing `spend_auth_sig`. This is correct,
  intentional firmware behavior (confirmed with Adam), not a bug — it's
  why `to-qr-batch`/`qr-batch` redact by default (see §4b).

### vizor-wallet

No code from `vizor-wallet` is vendored or imported here — it's a separate
Flutter/Rust app — but its Keystone hardware-send pipeline
(`rust/src/wallet/sync/pczt.rs`, particularly
`redact_pczt_for_batch_signer`) is what pointed at the actual fix for
#2225: PCZTs sent to the device for batch signing need to be *redacted*
first, not sent as built. `redact_for_batch_signer` in
`src/commands/pczt/qr.rs` is based on that function, with one deliberate
difference — it does not clear `spend_fvk` — because Vizor's own wallet
populates each spend's `zip32_derivation` (letting the device safely do
without the wire `fvk`), while `zcash_pool_migration_backend`'s PCZTs
don't populate that field at all. Clearing `fvk` here without it caused a
second real rejection (`None of inputs belong to the provided account`),
fixed instead by backfilling `zip32_derivation` ourselves via the existing
`pczt update-with-derivation` command (see §4b) — since, unlike Vizor's
software wallet, we hold the migrating account's seed directly and can
compute that ourselves rather than needing the wallet to have done it at
construction time.
