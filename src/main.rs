//! An example light client wallet based on the `zcash_client_sqlite` crate.
//!
//! This is **NOT IMPLEMENTED SECURELY**, and it is not written to be efficient or usable!
//! It is only intended to show the overall light client workflow using this crate.

use std::env;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicUsize, Ordering};

use gumdrop::Options;
use tracing_subscriber::{layer::SubscriberExt, Layer};

mod commands;
mod data;
mod error;
mod remote;
mod ui;

#[cfg(feature = "tui")]
#[allow(dead_code)]
mod tui;

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

    #[options(help = "reset an existing light wallet to its initalised state")]
    Reset(commands::reset::Command),

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

    #[options(help = "propose a transfer of funds to the given address and display the proposal")]
    Propose(commands::propose::Command),

    #[options(help = "send funds to the given address")]
    Send(commands::send::Command),
}

fn main() -> Result<(), anyhow::Error> {
    let opts = MyOptions::parse_args_default_or_exit();

    #[cfg(not(feature = "tui"))]
    let tui_logger: Option<()> = None;
    #[cfg(feature = "tui")]
    let tui_logger =
        if let Some(Command::Sync(commands::sync::Command { defrag: true, .. })) = opts.command {
            Some(tui_logger::tracing_subscriber_layer())
        } else {
            None
        };

    let stdout_logger = if tui_logger.is_none() {
        let filter = tracing_subscriber::EnvFilter::from(
            env::var("RUST_LOG").unwrap_or_else(|_| "info".to_owned()),
        );
        Some(tracing_subscriber::fmt::layer().with_filter(filter))
    } else {
        None
    };

    let subscriber = tracing_subscriber::registry().with(stdout_logger);
    #[cfg(feature = "tui")]
    let subscriber = subscriber.with(tui_logger);
    tracing::subscriber::set_global_default(subscriber).unwrap();

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

    runtime.block_on(async {
        #[cfg(feature = "tui")]
        let tui = tui::Tui::new()?.tick_rate(4.0).frame_rate(30.0);

        match opts.command {
            Some(Command::Init(command)) => command.run(opts.wallet_dir).await,
            Some(Command::Reset(command)) => command.run(opts.wallet_dir).await,
            Some(Command::Upgrade(command)) => command.run(opts.wallet_dir),
            Some(Command::Sync(command)) => {
                command
                    .run(
                        opts.wallet_dir,
                        #[cfg(feature = "tui")]
                        tui,
                    )
                    .await
            }
            Some(Command::Balance(command)) => command.run(opts.wallet_dir),
            Some(Command::ListTx(command)) => command.run(opts.wallet_dir),
            Some(Command::ListUnspent(command)) => command.run(opts.wallet_dir),
            Some(Command::Propose(command)) => command.run(opts.wallet_dir).await,
            Some(Command::Send(command)) => command.run(opts.wallet_dir).await,
            _ => Ok(()),
        }
    })
}
