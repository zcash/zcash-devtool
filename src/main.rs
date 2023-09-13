//! An example light client wallet based on the `zcash_client_sqlite` crate.
//!
//! This is **NOT IMPLEMENTED SECURELY**, and it is not written to be efficient or usable!
//! It is only intended to show the overall light client workflow using this crate.

use std::env;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicUsize, Ordering};

use gumdrop::Options;

use zcash_primitives::consensus::TEST_NETWORK;

mod commands;
mod data;
mod error;
mod remote;
mod ui;

const MIN_CONFIRMATIONS: NonZeroU32 = unsafe { NonZeroU32::new_unchecked(3) };

#[derive(Debug, Options)]
struct MyOptions {
    #[options(help = "print help message")]
    help: bool,

    #[options(help = "path to the wallet directory")]
    wallet_dir: Option<String>,

    #[options(command)]
    command: Option<Command>,
}

#[derive(Debug, Options)]
enum Command {
    #[options(help = "initialise a new light wallet")]
    Init(commands::init::Command),

    #[options(help = "upgrade an existing light wallet")]
    Upgrade(commands::upgrade::Command),

    #[options(help = "scan the chain and sync the wallet")]
    Sync(commands::sync::Command),

    #[options(help = "get the balance in the wallet")]
    Balance(commands::balance::Command),

    #[options(help = "list the transactions in the wallet")]
    ListTx(commands::list_tx::Command),

    #[options(help = "list the unspent notes in the wallet")]
    ListUnspent(commands::list_unspent::Command),

    #[options(help = "send funds to the given address")]
    Send(commands::send::Command),
}

fn main() -> Result<(), anyhow::Error> {
    let opts = MyOptions::parse_args_default_or_exit();

    let filter = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_owned());
    tracing_subscriber::fmt().with_env_filter(filter).init();

    rayon::ThreadPoolBuilder::new()
        .thread_name(|i| format!("zec-rayon-{}", i))
        .build_global()
        .expect("Only initialized once");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name_fn(|| {
            static ATOMIC_ID: AtomicUsize = AtomicUsize::new(0);
            let id = ATOMIC_ID.fetch_add(1, Ordering::SeqCst);
            format!("zec-tokio-{}", id)
        })
        .build()?;

    let params = TEST_NETWORK;

    runtime.block_on(async {
        match opts.command {
            Some(Command::Init(command)) => command.run(params, opts.wallet_dir).await,
            Some(Command::Upgrade(command)) => command.run(params, opts.wallet_dir),
            Some(Command::Sync(command)) => command.run(params, opts.wallet_dir).await,
            Some(Command::Balance(command)) => command.run(params, opts.wallet_dir),
            Some(Command::ListTx(command)) => command.run(opts.wallet_dir),
            Some(Command::ListUnspent(command)) => command.run(params, opts.wallet_dir),
            Some(Command::Send(command)) => command.run(params, opts.wallet_dir).await,
            _ => Ok(()),
        }
    })
}
