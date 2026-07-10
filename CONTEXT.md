# zcash-devtool

A CLI for operating Zcash wallets and inspecting chain data, including against
throwaway regtest chains whose consensus parameters the operator defines.

## Language

### Regtest consensus parameters

**Activation Heights File**:
The operator-authored TOML naming an activation height (or `"never"`) per
network upgrade, required when creating a regtest wallet. The operator keeps it
in revision control and in sync with the validator's own configuration by hand.
_Avoid_: regtest config, node config (the validator never reads this file)

**Wallet Config**:
The per-wallet persisted record of a wallet's identity and, for regtest, a copy
of its Activation Heights File taken at creation time, so every later command
sees the same chain the wallet was created against.
_Avoid_: keys file, wallet settings

**Explicitly Inactive**:
An upgrade whose key is written as `"never"` in an Activation Heights File or
Wallet Config — a deliberate operator choice that the upgrade does not exist on
this chain. Loads silently.
_Avoid_: disabled, off

**Implicitly Inactive**:
An upgrade whose key is absent entirely. Treated as inactive, but warned about
on load, because absence may only mean the file predates the tool's knowledge
of that upgrade.
_Avoid_: unset, missing (without qualification)

**Fallback Heights**:
The baked-in regtest heights used only by commands that take no Activation
Heights File; they mirror the `zcash_local_net` wallet-funding validator
fixture. Wallets created with an Activation Heights File never consult them.
_Avoid_: default network, default heights

**Height Drift**:
Disagreement between a wallet's recorded activation heights and those of the
validator it talks to. Drift makes the wallet derive a different consensus
branch ID than the validator expects, so the validator rejects its
transactions.
_Avoid_: mismatch (without saying between what)

### Ironwood (NU6.3)

**Ironwood Pool**:
The shielded value pool introduced by the Ironwood (NU6.3) upgrade — a fourth
pool alongside transparent, Sapling, and Orchard, with its own note-encryption
domain, note commitment tree, and nullifier set. Within one proposal step,
shielded inputs come from a single pool: Ironwood notes are never co-spent
with Sapling or Orchard notes.
_Avoid_: V6 pool (V6 names the transaction format, not the pool), NU6.3 pool,
scan model (upstream's branch name, not a concept of this tool)
