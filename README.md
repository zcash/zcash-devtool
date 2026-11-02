# zcash-devtool (Tachyon Fork💫)

The Tachyon fork of [zcash-devtool](https://github.com/zcash/zcash-devtool). See the upstream repo for docs and usage info.

Here you will find utilities for interacting with the Tachyon shielded protocol.

## Build

`RUSTFLAGS='--cfg zcash_unstable="nutachyon"' cargo build --release --locked --features tachyon`

the binary will be available in `./target/release/zcash-devtool`

Instructions for the Tachyon Alpha Testnet.

## Init

```sh
DEVTOOL="$PWD/target/release/zcash-devtool"
WALLET="$HOME/tachyon-wallet"

"$DEVTOOL" tachyon --wallet-dir "$WALLET" init \
  --rpc-url http://tachyscan.cnode.phd:18232 \
  --activation-height 8 --accept-mock-proofs
"$DEVTOOL" tachyon --wallet-dir "$WALLET" address
```

New wallets use the current tip as their birthday and trust the configured node's checkpoint at the start of that epoch. Use `--birthday-height HEIGHT` for an older birthday, or `--sync-from-activation` to replay from height 8. Existing wallets keep their history.

## Shell completions

Completions use clap_complete's dynamic engine (`COMPLETE=<shell>`), so
subcommands are completed recursively at any depth and options are offered on
an empty token.

Install user-scoped registrations for fish, bash, zsh, PowerShell, and Elvish:

```sh
scripts/install-completions.sh             # zdev wrapper
scripts/install-completions.sh --cli       # also the full zcash-devtool CLI
scripts/install-completions.sh --uninstall
```

The registrations call `zdev` at completion time, so it must be on `PATH`
(direnv adds it inside the repo). Fish and bash pick the files up
automatically. The script prints the one-time `fpath` / `$PROFILE` /
`use zdev` lines for zsh, PowerShell, and Elvish. The registrations only call
back into the binary, so they don't need refreshing when the CLI changes.

## Sync

Sync downloads and validates chain data to update your wallet's note status and balances.

```sh
"$DEVTOOL" tachyon --wallet-dir "$WALLET" sync --max-blocks 10000
```

Repeat until `caught_up` is `true`.

Importing an older receipt automatically extends the scan to its creation epoch. For a legacy receipt without a transaction ID, use `sync --from-height HEIGHT --max-blocks 10000` to search from a known height (or 8 if unknown). Pruned history requires an archive node; proof-service recovery is not yet supported.

## Receive (Tachyon)

Get funds from the [faucet](https://tachyscan.cnode.phd/faucet) using your `tachyon_address`, and save the downloaded note JSON as `~/Downloads/faucet-note.json`.

```sh
"$DEVTOOL" tachyon --wallet-dir "$WALLET" receive \
  --receipt "$HOME/Downloads/faucet-note.json"
"$DEVTOOL" tachyon --wallet-dir "$WALLET" sync --max-blocks 10000
"$DEVTOOL" tachyon --wallet-dir "$WALLET" balance
```

The payment must be mined before it becomes available.

New receipts include a transaction locator. For an older receipt, add `--txid PAYMENT_TXID` to `receive`; optionally add `--height HEIGHT`. These are verified lookup hints. `unresolved_receipts` in sync output counts notes not yet found in downloaded history, including pending payments.

## Send (Tachyon)

```sh
"$DEVTOOL" tachyon --wallet-dir "$WALLET" send \
  --to 'tachyon-test:RECIPIENT_PAYMENT_KEY' --amount-zat 1000000
"$DEVTOOL" tachyon --wallet-dir "$WALLET" export-receipt \
  --txid PAYMENT_TXID --out "$HOME/payment.json"
```

Replace `PAYMENT_TXID` with the ID returned by `send`. Share `payment.json` privately with the recipient so they can import it with `receive`.

Exports include the transaction ID, plus its block height and hash when known to the wallet. Add `--legacy` for older receivers that reject location metadata.

## License

All code in this workspace is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
