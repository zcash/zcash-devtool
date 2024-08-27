# zec-sqlite-wallet

This repository contains a CLI app for testing the `zcash_client_sqlite` crate.

## Security Warnings

**DO NOT USE THIS IN PRODUCTION!!!**

This app has not been written with security in mind.

## Usage

No binary artifacts are provided for this crate; it is generally used via
`cargo run` as follows:

To obtain the help docs:
```
cargo run --release -- --help
```
To obtain the help for a specific command (in this case, `init`)
```
cargo run --release -- --help init
```

To create a new empty testnet wallet:
```
cargo run --release -- -w <wallet_dir> init
cargo run --release -- -w <wallet_dir> sync
```

See the help docs for `init` for additional information, including for how to
initialize a mainnet wallet. Initializing a mainnet wallet will require
specifying a mainnet lightwallet server, e.g.
```
cargo run --release -- -w <wallet_dir> init -n "main" -s "zecrocks"
cargo run --release -- -w <wallet_dir> sync -s "zecrocks"
```

Whenever you update the `zcash_client_sqlite` dependency, in order to run
necessary migrations:
```
cargo run --release -- -w <wallet_dir> upgrade
```

If you want to run with debug or trace logging:
```
RUST_LOG=debug cargo run --release -- -w <wallet_dir> <command>
```

## License

All code in this workspace is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

Downstream code forks should note that this app depends on the 'orchard' crate,
which is licensed under the
[Bootstrap Open Source License](https://github.com/zcash/orchard/blob/main/LICENSE-BOSL).
A license exception is provided allowing some derived works that are linked or
combined with the 'orchard' crate to be copied or distributed under the original
licenses (in this case MIT / Apache 2.0), provided that the included portions of
the 'orchard' code remain subject to BOSL.
See <https://github.com/zcash/orchard/blob/main/COPYING> for details of which
derived works can make use of this exception, and the `README.md` files in
subdirectories for which crates and components this applies to.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
