//! The in-process backend with the real interpreter: CPython and spaCy from the hash-locked bundle, inside a runtime
//! worker process, supervised by the W2 pool.
//!
//! These tests need two things that CI does not have yet, and each test skips itself with a printed reason when one is
//! missing (a skipped test reports as passed; read the output with `--nocapture`, and treat "SKIPPED" as pending):
//!
//! * a bundle, built with `build_bundle.py --test-hooks` (see `docs/runtime/rust-workspace.md`), named by
//!   `PRIVOKE_SPACY_BUNDLE` (default `rust/target/bundle/windows`, or `linux`), and
//! * the runtime host built with the real interpreter, named by `PRIVOKE_SPACY_HOST`:
//!   `PYO3_PYTHON=<python 3.11> cargo build --release -p privoke-spacy --bin privoke-spacy-host
//!   --features fake-worker,in-process,test-hooks`.
//!
//! The parity test also needs the recorded NER sets that `parity_sets.py` extracts (`PRIVOKE_SPACY_PARITY_SETS`, default
//! `rust/target/parity/sets`). The sets are read from there and never committed.
//!
//! The host is copied into the bundle directory first: CPython finds its `_pth` isolation file next to its library, and
//! the bundle check refuses a process that is not inside the bundle. This test executable itself embeds no Python.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use privoke_spacy::protocol::Request;
use privoke_spacy::{Backoff, PoolConfig, Selection, SpacyError, SpacyPool, StatusKind};
use tokio::sync::Semaphore;

const EXE: &str = if cfg!(windows) { ".exe" } else { "" };

struct Real {
    bundle: PathBuf,
    host: PathBuf,
}

fn skip(test: &str, reason: &str) -> Option<Real> {
    eprintln!("SKIPPED {test}: {reason}");
    None
}

/// The bundle and the host copied into it, or `None` (printed) when either is missing.
fn real(test: &str) -> Option<Real> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let bundle = std::env::var_os("PRIVOKE_SPACY_BUNDLE")
        .map_or_else(|| manifest.join("../../target/bundle").join(if cfg!(windows) { "windows" } else { "linux" }), PathBuf::from);
    if !bundle.join(format!("privoke-spacy-worker{EXE}")).is_file() || !bundle.join("bundle.lock.txt").is_file() {
        return skip(test, &format!("no bundle at {} (build one with build_bundle.py --test-hooks)", bundle.display()));
    }
    let Some(source) = std::env::var_os("PRIVOKE_SPACY_HOST").map(PathBuf::from).filter(|p| p.is_file()) else {
        return skip(test, "PRIVOKE_SPACY_HOST does not name a privoke-spacy-host built with --features in-process,test-hooks");
    };
    let host = bundle.join(format!("privoke-spacy-host-s11b{EXE}"));
    if std::fs::read(&host).ok() != std::fs::read(&source).ok() {
        std::fs::copy(&source, &host).expect("copy the host into the bundle");
    }
    Some(Real { bundle, host })
}

impl Real {
    fn host_config(&self, workers: usize) -> PoolConfig {
        let mut cfg = PoolConfig::new(&self.host);
        cfg.args = vec![OsString::from("--bundle"), self.bundle.clone().into_os_string(), OsString::from("--max-chars"), "1000000".into()];
        cfg.max_text_chars = 1_000_000;
        self.tune(cfg, workers)
    }

    fn worker_config(&self, workers: usize) -> PoolConfig {
        let mut cfg = PoolConfig::new(self.bundle.join(format!("privoke-spacy-worker{EXE}")));
        cfg.max_text_chars = 1_000_000;
        self.tune(cfg, workers)
    }

    fn tune(&self, mut cfg: PoolConfig, workers: usize) -> PoolConfig {
        cfg.workers = workers;
        cfg.queue_capacity = 4096;
        cfg.backoff = Backoff { initial: Duration::from_millis(50), max: Duration::from_millis(500) };
        cfg.request_deadline = Duration::from_secs(29);
        cfg.startup_timeout = Duration::from_secs(180);
        cfg
    }
}

async fn ready(cfg: PoolConfig) -> SpacyPool {
    let pool = SpacyPool::start(cfg).unwrap();
    pool.wait_ready(Duration::from_secs(180)).await.unwrap();
    pool
}

async fn until(what: &str, mut cond: impl FnMut() -> bool) {
    let start = Instant::now();
    while !cond() {
        assert!(start.elapsed() < Duration::from_secs(180), "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The in-process runtime worker announces the locked bundle's identity, and answers real spaCy.
#[tokio::test]
async fn the_in_process_runtime_worker_runs_the_locked_bundle() {
    let Some(real) = real("the_in_process_runtime_worker_runs_the_locked_bundle") else { return };
    let pool = ready(real.host_config(1)).await;
    let info = pool.worker_info().unwrap();
    assert_eq!(info.spacy.as_deref(), Some("3.7.5"));
    assert_eq!(info.model.as_deref(), Some("en_core_web_sm"));
    assert_eq!(info.model_version.as_deref(), Some("3.7.1"));
    let text = "Alice Smith lives in Paris.";
    let full = pool.analyze(text, Selection::Full).await.unwrap();
    assert!(full.entities.iter().any(|e| &text[e.span.bytes()] == "Paris"));
    assert!(pool.analyze(text, Selection::TaggerOnly).await.unwrap().entities.is_empty());
    assert!(!pool.lemma_index().await.unwrap().is_empty());
}

/// No child process is created when NER runs, with the real interpreter: the runtime worker has none before or after
/// loading spaCy and serving requests.
#[tokio::test]
async fn no_child_process_is_created_when_real_ner_runs() {
    let Some(real) = real("no_child_process_is_created_when_real_ner_runs") else { return };
    let pool = ready(real.host_config(1)).await;
    for text in ["Alice Smith lives in Paris.", "emoji \u{1F600} and CJK \u{4F60}\u{597D}", "ALL CAPS TEXT"] {
        for selection in [Selection::Full, Selection::TaggerOnly] {
            pool.analyze(text, selection).await.unwrap();
        }
    }
    pool.lemma_index().await.unwrap();
    let children = pool.submit_request(|id| Request::TestChildren { id }).await.unwrap();
    if children == "null" {
        eprintln!("SKIPPED no_child_process_is_created_when_real_ner_runs (child listing): not available on this platform");
        return;
    }
    assert_eq!(children, "[]", "running NER created a child process");
}

/// A deliberate interpreter crash (`abort()` inside CPython) takes down only that runtime worker. The W2 pool restarts
/// it, and the request that was in flight is `Unavailable` and is not retried.
#[tokio::test]
async fn a_real_interpreter_crash_kills_only_that_worker_and_is_not_retried() {
    let Some(real) = real("a_real_interpreter_crash_kills_only_that_worker_and_is_not_retried") else { return };
    let pool = ready(real.host_config(2)).await;
    until("two ready workers", || pool.ready_workers() == 2).await;
    assert_eq!(pool.starts(), 2);
    let before = pool.worker_pids();
    let err = pool.submit_request(|id| Request::TestCrash { id }).await.unwrap_err();
    assert!(matches!(err, SpacyError::WorkerFailed(_)), "{err}");
    assert_eq!(err.status(), StatusKind::Unavailable);
    assert!(pool.analyze("Alice lives in Paris.", Selection::Full).await.is_ok(), "the other worker kept serving");
    until("the crashed worker to restart", || pool.ready_workers() == 2).await;
    assert_eq!(pool.starts(), 3, "exactly one restart: the request was not retried");
    let after = pool.worker_pids();
    assert_eq!(before.iter().filter(|pid| after.contains(pid)).count(), 1, "only the crashed worker was replaced");
    assert!(pool.analyze("Bob lives in Rome.", Selection::Full).await.is_ok());
}

/// P4, framing: a `print` and a C-level write to fd 1 from inside the in-process interpreter leave the frames intact.
#[tokio::test]
async fn a_print_inside_the_interpreter_leaves_the_framing_intact() {
    let Some(real) = real("a_print_inside_the_interpreter_leaves_the_framing_intact") else { return };
    let pool = ready(real.host_config(1)).await;
    assert_eq!(pool.submit_request(|id| Request::TestPrint { id }).await.unwrap(), "null");
    assert!(pool.analyze("Alice lives in Paris.", Selection::Full).await.is_ok());
    assert_eq!(pool.starts(), 1, "the print corrupted a frame and the worker was replaced");
}

fn parity_sets() -> PathBuf {
    std::env::var_os("PRIVOKE_SPACY_PARITY_SETS")
        .map_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/parity/sets"), PathBuf::from)
}

/// Parity gate: every document of every recorded NER set, in both selections, gives the same result bytes from the
/// in-process runtime worker and from the worker-pool backend. Any difference, and any error on either side, fails.
/// `PRIVOKE_SPACY_PARITY_LIMIT` caps the documents per set (a quick run); without it the whole set is compared.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_process_output_is_byte_identical_to_the_worker_pool_on_every_recorded_set() {
    let test = "in_process_output_is_byte_identical_to_the_worker_pool_on_every_recorded_set";
    let Some(real) = real(test) else { return };
    let sets = parity_sets();
    let Ok(manifest) = std::fs::read(sets.join("sets.json")) else {
        skip(test, &format!("no recorded NER sets at {} (run parity_sets.py; the sets are not committed)", sets.display()));
        return;
    };
    let manifest: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
    let order: Vec<String> = serde_json::from_value(manifest["order"].clone()).unwrap();
    let limit: usize = std::env::var("PRIVOKE_SPACY_PARITY_LIMIT").ok().and_then(|v| v.parse().ok()).unwrap_or(usize::MAX);

    let in_process = Arc::new(ready(real.host_config(2)).await);
    let oracle = Arc::new(ready(real.worker_config(2)).await);
    assert_eq!(in_process.lemma_index().await.unwrap(), oracle.lemma_index().await.unwrap(), "lemma index differs");

    let gate = Arc::new(Semaphore::new(16));
    let (mut documents, mut different) = (0usize, Vec::new());
    for name in order {
        let texts: Vec<Arc<String>> = std::fs::read_to_string(sets.join(format!("{name}.jsonl")))
            .unwrap()
            .lines()
            .take(limit)
            .map(|l| Arc::new(serde_json::from_str::<String>(l).unwrap()))
            .collect();
        for selection in [Selection::Full, Selection::TaggerOnly] {
            let mut tasks = Vec::with_capacity(texts.len());
            for text in &texts {
                let permit = gate.clone().acquire_owned().await.unwrap();
                let (a, b, text) = (in_process.clone(), oracle.clone(), text.clone());
                tasks.push(tokio::spawn(async move {
                    let _permit = permit;
                    let (x, y) = (a.analyze_raw(&text, selection).await, b.analyze_raw(&text, selection).await);
                    match (x, y) {
                        (Ok(x), Ok(y)) if x.as_str() == y.as_str() => None,
                        (Ok(_), Ok(_)) => Some("the result bytes differ".to_string()),
                        (x, y) => Some(format!("in-process {:?}, pool {:?}", x.err(), y.err())),
                    }
                }));
            }
            for (index, task) in tasks.into_iter().enumerate() {
                documents += 1;
                if let Some(message) = task.await.unwrap() {
                    different.push(format!("{name} {selection:?} #{index}: {message}"));
                }
            }
            eprintln!("[parity] {name} {}: {} documents, {} different so far", selection.as_str(), texts.len(), different.len());
        }
    }
    assert!(
        different.is_empty(),
        "{} of {documents} comparisons differ; first: {:?}",
        different.len(),
        &different[..different.len().min(5)]
    );
    assert!(documents > 0, "the sets directory held no documents");
}
