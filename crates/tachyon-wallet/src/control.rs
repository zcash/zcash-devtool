//! Cooperative cancellation and stderr-only progress for one wallet command.

use std::{
    collections::BTreeMap,
    fmt,
    io::{self, Write},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::Result;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

/// An interrupted command has finished unwinding its wallet transaction.
#[derive(Debug)]
pub struct Interrupted {
    pub exit_code: i32,
}

impl fmt::Display for Interrupted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("interrupted; uncommitted work rolled back, previously saved transactions and reservations retained")
    }
}

impl std::error::Error for Interrupted {}

#[derive(Debug)]
struct Cancelled;

impl fmt::Display for Cancelled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("command cancelled")
    }
}

impl std::error::Error for Cancelled {}

struct Progress {
    message: String,
    started: Instant,
    last_report: Instant,
}

#[derive(Default)]
struct Sample {
    count: u64,
    total_us: u128,
    max_us: u128,
    bytes: u64,
}

#[derive(Default)]
struct CacheSample {
    hits: u64,
    misses: u64,
    bytes: u64,
}

struct Timing {
    started: Instant,
    stages: BTreeMap<String, Sample>,
    rpc: BTreeMap<String, Sample>,
    cache: BTreeMap<String, CacheSample>,
}

impl Timing {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            stages: BTreeMap::new(),
            rpc: BTreeMap::new(),
            cache: BTreeMap::new(),
        }
    }

    fn sample(map: &mut BTreeMap<String, Sample>, key: String, duration: Duration, bytes: u64) {
        let sample = map.entry(key).or_default();
        sample.count += 1;
        sample.total_us += duration.as_micros();
        sample.max_us = sample.max_us.max(duration.as_micros());
        sample.bytes = sample.bytes.saturating_add(bytes);
    }

    fn record_stage(&mut self, message: &str, duration: Duration) {
        Self::sample(&mut self.stages, normalize_stage(message), duration, 0);
    }

    fn value(&self) -> Value {
        let stages: Vec<_> = self
            .stages
            .iter()
            .map(|(name, s)| {
                json!({"name":name,"count":s.count,"total_us":s.total_us,"max_us":s.max_us})
            })
            .collect();
        let rpc: Vec<_> = self
            .rpc
            .iter()
            .map(|(method, s)| {
                json!({"method":method,"count":s.count,"total_us":s.total_us,
                       "max_us":s.max_us,"bytes":s.bytes})
            })
            .collect();
        let cache: Vec<_> = self
            .cache
            .iter()
            .map(|(kind, s)| json!({"kind":kind,"hits":s.hits,"misses":s.misses,"bytes":s.bytes}))
            .collect();
        json!({
            "total_us": self.started.elapsed().as_micros(),
            "stages": stages,
            "rpc": rpc,
            "cache": cache
        })
    }
}

fn normalize_stage(message: &str) -> String {
    let mut normalized = String::with_capacity(message.len());
    let mut digits = false;
    for character in message.chars() {
        if character.is_ascii_digit() {
            if !digits {
                normalized.push('#');
                digits = true;
            }
        } else {
            normalized.push(character);
            digits = false;
        }
    }
    normalized
}

#[derive(Clone)]
pub(crate) struct Control {
    pub(crate) cancellation: CancellationToken,
    quiet: bool,
    progress: Arc<Mutex<Progress>>,
    timing: Option<Arc<Mutex<Timing>>>,
}

impl Control {
    pub(crate) fn new(quiet: bool) -> Self {
        Self::with_timing(quiet, std::env::var_os("TACHYON_TIMING").is_some())
    }

    fn with_timing(quiet: bool, timing: bool) -> Self {
        Self {
            cancellation: CancellationToken::new(),
            quiet,
            progress: Arc::new(Mutex::new(Progress {
                message: "Starting wallet command".into(),
                started: Instant::now(),
                last_report: Instant::now(),
            })),
            timing: timing.then(|| Arc::new(Mutex::new(Timing::new()))),
        }
    }

    pub(crate) fn check(&self) -> Result<()> {
        if self.cancellation.is_cancelled() {
            return Err(Cancelled.into());
        }
        Ok(())
    }

    /// Call before a bounded unit of work. Labels must never contain private inputs.
    pub(crate) fn stage(&self, message: impl Into<String>) -> Result<()> {
        self.check()?;
        let message = message.into();
        self.write_progress(&message);
        let now = Instant::now();
        let mut progress = self.progress.lock().expect("progress lock is not poisoned");
        if let Some(timing) = &self.timing {
            timing
                .lock()
                .expect("timing lock is not poisoned")
                .record_stage(&progress.message, now.duration_since(progress.started));
        }
        *progress = Progress {
            message,
            started: now,
            last_report: now,
        };
        Ok(())
    }

    pub(crate) fn record_rpc(&self, method: &str, duration: Duration, bytes: u64) {
        if let Some(timing) = &self.timing {
            Timing::sample(
                &mut timing.lock().expect("timing lock is not poisoned").rpc,
                method.to_owned(),
                duration,
                bytes,
            );
        }
    }

    pub(crate) fn record_cache(&self, kind: &str, hit: bool, bytes: u64) {
        if let Some(timing) = &self.timing {
            let mut timing = timing.lock().expect("timing lock is not poisoned");
            let sample = timing.cache.entry(kind.to_owned()).or_default();
            if hit {
                sample.hits += 1;
            } else {
                sample.misses += 1;
            }
            sample.bytes = sample.bytes.saturating_add(bytes);
        }
    }

    #[cfg(test)]
    fn timing_value(&self) -> Option<Value> {
        let timing = self.timing.as_ref()?;
        let progress = self.progress.lock().expect("progress lock is not poisoned");
        let mut timing = timing.lock().expect("timing lock is not poisoned");
        timing.record_stage(&progress.message, progress.started.elapsed());
        Some(timing.value())
    }

    fn finish_timing(&self) {
        let Some(timing) = &self.timing else {
            return;
        };
        let progress = self.progress.lock().expect("progress lock is not poisoned");
        let mut timing = timing.lock().expect("timing lock is not poisoned");
        timing.record_stage(&progress.message, progress.started.elapsed());
        diagnostic(&format!(
            "TACHYON_TIMING {}",
            serde_json::to_string(&timing.value()).expect("timing is serializable")
        ));
    }

    fn write_progress(&self, message: &str) {
        if !self.quiet {
            diagnostic(message);
        }
    }

    fn heartbeat(&self) {
        let mut progress = self.progress.lock().expect("progress lock is not poisoned");
        let elapsed = progress.started.elapsed().as_secs();
        if progress.last_report.elapsed() >= Duration::from_secs(10) {
            self.write_progress(&format!(
                "Still working: {} ({elapsed}s elapsed)",
                progress.message
            ));
            progress.last_report = Instant::now();
        }
    }
}

// A closed stderr must not panic while unwinding or prevent cancellation.
fn diagnostic(message: &str) {
    let _ = writeln!(io::stderr().lock(), "{message}");
}

struct Signals {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
}

impl Signals {
    fn new() -> Result<Self> {
        Ok(Self {
            #[cfg(unix)]
            interrupt: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?,
            #[cfg(unix)]
            terminate: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
        })
    }

    async fn next(&mut self) -> Result<i32> {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = self.interrupt.recv() => Ok(130),
                _ = self.terminate.recv() => Ok(143),
            }
        }
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c().await?;
            Ok(130)
        }
    }
}

pub(crate) async fn run(
    quiet: bool,
    work: impl FnOnce(Control) -> Result<()> + Send + 'static,
) -> Result<()> {
    // Register before starting work, and do not install the ordinary wallet's
    // one-shot handler: it consumes SIGINT without cancelling this worker.
    let mut signals = Signals::new()?;
    let control = Control::new(quiet);
    let worker_control = control.clone();
    let mut worker = tokio::task::spawn_blocking(move || work(worker_control));
    let mut heartbeat = tokio::time::interval(Duration::from_secs(1));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut interrupted = None;
    loop {
        tokio::select! {
            result = &mut worker => {
                // Await the worker even after cancellation: dropping/aborting a
                // started spawn_blocking task cannot stop it or release its DB lock.
                let result = result?;
                control.finish_timing();
                return match interrupted {
                    Some(exit_code) => Err(Interrupted { exit_code }.into()),
                    None => result,
                };
            }
            signal = signals.next() => {
                let exit_code = signal?;
                if interrupted.is_some() {
                    diagnostic("Forcing exit; saved transactions may still have been broadcast. Keep wallet data and sync before retrying.");
                    // Emergency exit for an uninterruptible cryptographic call.
                    // SQLite recovers unfinished transactions on the next open.
                    std::process::exit(exit_code);
                }
                interrupted = Some(exit_code);
                control.cancellation.cancel();
                diagnostic("Cancelling… waiting for the current proof step if necessary. Press Ctrl+C again to force exit.");
            }
            _ = heartbeat.tick() => control.heartbeat(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timing_aggregates_normalized_stages_rpc_and_cache() {
        let control = Control::with_timing(true, true);
        control.stage("Proving epoch 0 stamp intake 1/10…").unwrap();
        std::thread::sleep(Duration::from_millis(2));
        control.stage("Proving epoch 0 stamp intake 2/10…").unwrap();
        control.record_rpc("getblockhash", Duration::from_millis(3), 100);
        control.record_cache("bucket", true, 200);
        control.record_cache("bucket", false, 0);
        let timing = control.timing_value().unwrap();
        let stages = timing["stages"].as_array().unwrap();
        let proving = stages
            .iter()
            .find(|stage| stage["name"] == "Proving epoch # stamp intake #/#…")
            .unwrap();
        assert_eq!(proving["count"], 2);
        assert_eq!(timing["rpc"][0]["method"], "getblockhash");
        assert_eq!(timing["rpc"][0]["count"], 1);
        assert_eq!(timing["rpc"][0]["bytes"], 100);
        assert_eq!(timing["cache"][0]["hits"], 1);
        assert_eq!(timing["cache"][0]["misses"], 1);
        assert_eq!(timing["cache"][0]["bytes"], 200);
    }

    #[test]
    fn timing_is_disabled_without_the_environment_flag() {
        let control = Control::with_timing(true, false);
        control.stage("Proving epoch").unwrap();
        assert!(control.timing_value().is_none());
    }

    #[test]
    fn cancellation_reaches_clones_and_prevents_new_stages() {
        let control = Control::new(true);
        let worker = control.clone();
        assert!(worker.stage("Proving epoch").is_ok());
        control.cancellation.cancel();
        assert!(worker.check().is_err());
        assert!(worker.stage("Must not begin another proof").is_err());
    }

    // A subprocess is essential: testing a process-wide signal handler in the
    // ordinary parallel test runner would interrupt unrelated tests.
    #[cfg(unix)]
    #[test]
    #[ignore = "subprocess helper for second_interrupt_stops_uninterruptible_worker"]
    fn uninterruptible_worker() {
        if std::env::var_os("TACHYON_TEST_UNINTERRUPTIBLE").is_none() {
            return;
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime
            .block_on(run(false, |control| {
                let db =
                    rusqlite::Connection::open(std::env::var("TACHYON_TEST_DATABASE").unwrap())?;
                db.execute_batch(
                    "PRAGMA synchronous=FULL;
                    CREATE TABLE recovery (value INTEGER);
                    INSERT INTO recovery VALUES (1);
                    BEGIN IMMEDIATE;
                    INSERT INTO recovery VALUES (2);",
                )?;
                control.stage("Proving uninterruptible test step")?;
                // Model a single proof-system call that does not accept a token.
                std::thread::sleep(Duration::from_secs(60));
                control.check()
            }))
            .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn second_interrupt_stops_uninterruptible_worker() {
        use std::{
            io::{BufRead, BufReader},
            process::{Child, Command, Stdio},
            sync::mpsc,
            thread,
        };

        struct ChildGuard(Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("recovery.sqlite");
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "control::tests::uninterruptible_worker",
                    "--ignored",
                    "--nocapture",
                ])
                .env("TACHYON_TEST_UNINTERRUPTIBLE", "1")
                .env("TACHYON_TEST_DATABASE", &database)
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let stderr = child.0.stderr.take().unwrap();
        let (send, lines) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                if send.send(line.unwrap()).is_err() {
                    break;
                }
            }
        });
        assert!(
            lines
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .contains("Proving uninterruptible")
        );
        assert!(
            lines
                .recv_timeout(Duration::from_secs(15))
                .unwrap()
                .contains("Still working")
        );
        let signal = || {
            assert!(
                Command::new("kill")
                    .args(["-INT", &child.0.id().to_string()])
                    .status()
                    .unwrap()
                    .success()
            );
        };
        signal();
        assert!(
            lines
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .contains("Cancelling")
        );
        signal();
        assert!(
            lines
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .contains("Forcing exit")
        );
        let start = Instant::now();
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert_eq!(status.code(), Some(130));
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "second interrupt failed"
            );
            thread::sleep(Duration::from_millis(10));
        }
        reader.join().unwrap();
        let db = rusqlite::Connection::open(database).unwrap();
        let values = db
            .prepare("SELECT value FROM recovery")
            .unwrap()
            .query_map([], |row| row.get::<_, i64>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            values,
            vec![1],
            "forced exit must retain commits but roll back unfinished work"
        );
    }
}
