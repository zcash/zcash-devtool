//! An example light client wallet based on the `zcash_client_sqlite` crate.
//!
//! This is **NOT IMPLEMENTED SECURELY**, and it is not written to be efficient or usable!
//! It is only intended to show the overall light client workflow using this crate.

use std::env;
use std::io::BufRead;
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
    // #[options(command)]
    // command: Option<Command>,
}

#[derive(Debug, Options)]
enum Command {
    #[options(help = "initialise a new light wallet")]
    Init(commands::init::Command),

    #[options(help = "reset an existing light wallet (does not preserve imported UFVKs)")]
    Reset(commands::reset::Command),

    #[options(help = "import a UFVK")]
    ImportUfvk(commands::import_ufvk::Command),

    #[options(help = "upgrade an existing light wallet")]
    Upgrade(commands::upgrade::Command),

    #[options(help = "scan the chain and sync the wallet")]
    Sync(commands::sync::Command),

    #[options(help = "ensure all transactions have full data available")]
    Enhance(commands::enhance::Command),

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

        let shutdown = &mut ShutdownListener::new();

        // repeat reading a command from the command line the execute
        let stdin = std::io::stdin();
        loop {
            if shutdown.requested() {
                tracing::info!("Shutdown requested");
                break;
            }
            let mut line = String::new();
            print!("(cli-wallet) >>\n");
            stdin
                .lock()
                .read_line(&mut line)
                .expect("Could not read line");
            let args: Vec<String> = line.trim().split(' ').map(|s| String::from(s)).collect();
            let command: Command = gumdrop::parse_args_default(&args)?;

            match command {
                Command::Init(command) => command.run(opts.wallet_dir.clone()).await,
                Command::Reset(command) => command.run(opts.wallet_dir.clone()).await,
                Command::ImportUfvk(command) => command.run(opts.wallet_dir.clone()).await,
                Command::Upgrade(command) => command.run(opts.wallet_dir.clone()),
                Command::Sync(command) => {
                    command
                        .run(
                            shutdown,
                            opts.wallet_dir.clone(),
                            #[cfg(feature = "tui")]
                            tui,
                        )
                        .await
                }
                Command::Enhance(command) => command.run(opts.wallet_dir.clone()).await,
                Command::Balance(command) => command.run(opts.wallet_dir.clone()).await,
                Command::ListTx(command) => command.run(opts.wallet_dir.clone()),
                Command::ListUnspent(command) => command.run(opts.wallet_dir.clone()),
                Command::Propose(command) => command.run(opts.wallet_dir.clone()).await,
                Command::Send(command) => command.run(opts.wallet_dir.clone()).await,
            }.ok();
        }
        Ok(())
    })
}

struct ShutdownListener {
    signal_rx: tokio::sync::oneshot::Receiver<()>,
    #[cfg(feature = "tui")]
    tui_tx: Option<tokio::sync::oneshot::Sender<()>>,
    #[cfg(feature = "tui")]
    tui_rx: tokio::sync::oneshot::Receiver<()>,
}

impl ShutdownListener {
    fn new() -> Self {
        let (signal_tx, signal_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            if let Err(e) = tokio::signal::ctrl_c().await {
                tracing::error!("Failed to listen for Ctrl-C event: {}", e);
            }
            let _ = signal_tx.send(());
        });

        #[cfg(feature = "tui")]
        let (tui_tx, tui_rx) = tokio::sync::oneshot::channel();

        Self {
            signal_rx,
            #[cfg(feature = "tui")]
            tui_tx: Some(tui_tx),
            #[cfg(feature = "tui")]
            tui_rx,
        }
    }

    #[cfg(feature = "tui")]
    fn tui_quit_signal(&mut self) -> tokio::sync::oneshot::Sender<()> {
        self.tui_tx.take().expect("should only call this once")
    }

    fn requested(&mut self) -> bool {
        const NOT_TRIGGERED: Result<(), tokio::sync::oneshot::error::TryRecvError> =
            Err(tokio::sync::oneshot::error::TryRecvError::Empty);

        let signal = self.signal_rx.try_recv();

        #[cfg(feature = "tui")]
        let tui = self.tui_rx.try_recv();
        #[cfg(not(feature = "tui"))]
        let tui = NOT_TRIGGERED;

        match (signal, tui) {
            (NOT_TRIGGERED, NOT_TRIGGERED) => false,
            // If either has been triggered, then a shutdown has been requested.
            _ => true,
        }
    }
}
