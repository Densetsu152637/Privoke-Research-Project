//! Pool supervision against the Python-free fake worker: readiness, poisoned input, crash-loop backoff, bundle refusal,
//! queue bound, deadlines, worker errors and shutdown. The real worker has its own tests in `privoke-spacy-worker`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::ffi::OsString;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use privoke_spacy::{Backoff, PoolConfig, Selection, SpacyError, SpacyPool, StatusKind};

const FAKE: &str = env!("CARGO_BIN_EXE_privoke-spacy-fake-worker");

fn config(extra: &[&str]) -> PoolConfig {
    let mut cfg = PoolConfig::new(FAKE);
    cfg.args = extra.iter().map(OsString::from).collect();
    cfg.backoff = Backoff { initial: Duration::from_millis(40), max: Duration::from_millis(400) };
    cfg.request_deadline = Duration::from_secs(5);
    cfg.startup_timeout = Duration::from_secs(10);
    cfg
}

async fn until(what: &str, mut cond: impl FnMut() -> bool) {
    let start = Instant::now();
    while !cond() {
        assert!(start.elapsed() < Duration::from_secs(10), "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn spawn_times(log: &Path) -> Vec<u128> {
    std::fs::read_to_string(log).unwrap_or_default().lines().filter_map(|l| l.parse().ok()).collect()
}

#[tokio::test]
async fn analyzes_in_both_selections_and_caches_the_lemma_index() {
    let pool = SpacyPool::start(config(&[])).unwrap();
    pool.wait_ready(Duration::from_secs(10)).await.unwrap();
    let text = "Alice lives in Paris";
    let full = pool.analyze(text, Selection::Full).await.unwrap();
    assert_eq!(full.tokens.len(), 4);
    assert_eq!(full.entities.len(), 1);
    assert_eq!((full.entities[0].label.as_str(), &text[full.entities[0].span.bytes()]), ("GPE", "Paris"));
    assert!(pool.analyze(text, Selection::TaggerOnly).await.unwrap().entities.is_empty());
    let words = pool.lemma_index().await.unwrap();
    assert_eq!(words.as_slice(), ["alpha", "beta"]);
    assert!(Arc::ptr_eq(&words, &pool.lemma_index().await.unwrap()));
    assert_eq!(pool.worker_info().unwrap().spacy.as_deref(), Some("fake"));
}

/// P3, readiness: a request that arrives while the worker is still loading is `Unavailable`, not queued.
#[tokio::test]
async fn p3_request_during_load_is_unavailable() {
    let pool = SpacyPool::start(config(&["--startup-delay-ms", "700"])).unwrap();
    assert!(!pool.is_ready());
    let err = pool.analyze("hello", Selection::Full).await.unwrap_err();
    assert!(matches!(err, SpacyError::NotReady(_)), "{err}");
    assert_eq!(err.status(), StatusKind::Unavailable);
    pool.wait_ready(Duration::from_secs(10)).await.unwrap();
    assert!(pool.analyze("hello", Selection::Full).await.is_ok());
}

/// P3, poisoned input: the document that crashed a worker is answered `Unavailable` and is never tried on another
/// worker. With two workers a retry would crash the second one too; exactly one restart shows it did not happen.
#[tokio::test]
async fn p3_poisoned_input_is_not_retried() {
    let pool = SpacyPool::start({
        let mut cfg = config(&[]);
        cfg.workers = 2;
        cfg
    })
    .unwrap();
    until("two ready workers", || pool.ready_workers() == 2).await;
    assert_eq!(pool.starts(), 2);
    let err = pool.analyze("CRASH", Selection::Full).await.unwrap_err();
    assert!(matches!(err, SpacyError::WorkerFailed(_)), "{err}");
    assert_eq!(err.status(), StatusKind::Unavailable);
    // The other worker kept serving and the crashed slot came back.
    assert!(pool.analyze("still fine", Selection::Full).await.is_ok());
    until("the crashed slot to restart", || pool.ready_workers() == 2).await;
    assert_eq!(pool.starts(), 3, "exactly one restart: the poisoned request was not retried on the other worker");
}

/// P3, crash loop: a worker that dies at once is restarted with growing delays.
#[tokio::test]
async fn p3_crash_loop_backs_off() {
    let dir = tempfile_dir();
    let log = dir.join("spawns.log");
    let pool = SpacyPool::start(config(&["--exit-at-start", "--spawn-log", log.to_str().unwrap()])).unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let times = spawn_times(&log);
    let backoff = Backoff { initial: Duration::from_millis(40), max: Duration::from_millis(400) };
    assert!(times.len() >= 4, "expected several restarts, saw {}", times.len());
    // Cumulative delays 40, 120, 280, 600, 1000, 1400 ms allow at most 7 starts in 1.5 s; no backoff would allow hundreds.
    assert!(times.len() <= 8, "restarts did not back off: {} starts in 1.5 s", times.len());
    for (n, pair) in times.windows(2).enumerate() {
        let gap = Duration::from_millis((pair[1] - pair[0]) as u64);
        let wanted = backoff.delay(n as u32 + 1);
        assert!(gap + Duration::from_millis(15) >= wanted, "restart {} came after {gap:?}, wanted at least {wanted:?}", n + 1);
    }
    assert!(!pool.is_ready());
    assert!(matches!(pool.analyze("x", Selection::Full).await, Err(SpacyError::NotReady(_))));
    std::fs::remove_dir_all(dir).ok();
}

/// A refused bundle is final: the pool is never ready, reports the reason, and does not restart.
#[tokio::test]
async fn refused_bundle_stops_the_slot_and_reports_why() {
    let pool = SpacyPool::start(config(&["--fatal", "numpy 1.26.3 differs from the lock"])).unwrap();
    let err = pool.wait_ready(Duration::from_secs(10)).await.unwrap_err();
    assert!(err.to_string().contains("numpy 1.26.3 differs from the lock"), "{err}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(pool.starts(), 1);
    let err = pool.analyze("hello", Selection::Full).await.unwrap_err();
    assert_eq!(err.status(), StatusKind::Unavailable);
}

#[tokio::test]
async fn full_queue_is_resource_exhausted() {
    let pool = Arc::new(
        SpacyPool::start({
            let mut cfg = config(&[]);
            cfg.queue_capacity = 1;
            cfg
        })
        .unwrap(),
    );
    pool.wait_ready(Duration::from_secs(10)).await.unwrap();
    let busy = tokio::spawn({
        let pool = pool.clone();
        async move { pool.analyze("SLEEP:900", Selection::Full).await }
    });
    tokio::time::sleep(Duration::from_millis(250)).await; // the worker has taken it
    let queued = tokio::spawn({
        let pool = pool.clone();
        async move { pool.analyze("SLEEP:10", Selection::Full).await }
    });
    tokio::time::sleep(Duration::from_millis(150)).await; // it is waiting in the queue
    let err = pool.analyze("overflow", Selection::Full).await.unwrap_err();
    assert!(matches!(err, SpacyError::ResourceExhausted { capacity: 1 }), "{err}");
    assert_eq!(err.status(), StatusKind::ResourceExhausted);
    assert!(busy.await.unwrap().is_ok());
    assert!(queued.await.unwrap().is_ok());
    assert!(pool.analyze("after", Selection::Full).await.is_ok());
}

/// A worker that misses the deadline is killed and restarted; the request is `Unavailable` and the pool recovers.
#[tokio::test]
async fn deadline_kills_the_worker_and_the_pool_recovers() {
    let pool = SpacyPool::start({
        let mut cfg = config(&[]);
        cfg.request_deadline = Duration::from_millis(400);
        cfg
    })
    .unwrap();
    pool.wait_ready(Duration::from_secs(10)).await.unwrap();
    let started = Instant::now();
    let err = pool.analyze("HANG", Selection::Full).await.unwrap_err();
    assert!(matches!(err, SpacyError::DeadlineExceeded(_)), "{err}");
    assert_eq!(err.status(), StatusKind::Unavailable);
    assert!(started.elapsed() < Duration::from_secs(3));
    until("a restarted worker", || pool.starts() == 2 && pool.is_ready()).await;
    assert!(pool.analyze("alive again", Selection::Full).await.is_ok());
}

/// A request queued behind a hung worker is not poisoned: the hung one is killed at its deadline, and the restarted
/// worker serves the queued request within its own, later deadline.
#[tokio::test]
async fn queued_request_survives_a_hung_worker_ahead_of_it() {
    let pool = Arc::new(
        SpacyPool::start({
            let mut cfg = config(&[]);
            cfg.request_deadline = Duration::from_millis(500);
            cfg
        })
        .unwrap(),
    );
    pool.wait_ready(Duration::from_secs(10)).await.unwrap();
    let hung = tokio::spawn({
        let pool = pool.clone();
        async move { pool.analyze("HANG", Selection::Full).await }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let queued = pool.analyze("behind the hang", Selection::Full).await;
    assert!(queued.is_ok(), "{queued:?}");
    assert!(matches!(hung.await.unwrap(), Err(SpacyError::DeadlineExceeded(_))));
    assert_eq!(pool.starts(), 2);
}

#[tokio::test]
async fn worker_reported_error_keeps_the_worker() {
    let pool = SpacyPool::start(config(&[])).unwrap();
    pool.wait_ready(Duration::from_secs(10)).await.unwrap();
    let err = pool.analyze("ERR", Selection::Full).await.unwrap_err();
    assert!(matches!(err, SpacyError::WorkerReported(ref m) if m == "boom"), "{err}");
    assert_eq!(err.status(), StatusKind::Unavailable);
    assert_eq!(pool.starts(), 1);
    assert!(pool.analyze("fine", Selection::Full).await.is_ok());
}

#[tokio::test]
async fn out_of_protocol_answer_restarts_the_worker() {
    let pool = SpacyPool::start(config(&[])).unwrap();
    pool.wait_ready(Duration::from_secs(10)).await.unwrap();
    let err = pool.analyze("BADID", Selection::Full).await.unwrap_err();
    assert!(matches!(err, SpacyError::WorkerFailed(_)), "{err}");
    until("a restarted worker", || pool.starts() == 2 && pool.is_ready()).await;
}

#[tokio::test]
async fn invalid_text_is_rejected_before_queueing() {
    let pool = SpacyPool::start({
        let mut cfg = config(&[]);
        cfg.max_text_chars = 10;
        cfg
    })
    .unwrap();
    pool.wait_ready(Duration::from_secs(10)).await.unwrap();
    assert_eq!(pool.analyze("", Selection::Full).await.unwrap_err().status(), StatusKind::InvalidArgument);
    assert_eq!(pool.analyze("12345678901", Selection::Full).await.unwrap_err().status(), StatusKind::InvalidArgument);
    assert!(pool.analyze("1234567890", Selection::Full).await.is_ok());
    // Characters, not bytes: ten emoji are 40 bytes and still fit.
    assert!(pool.analyze(&"\u{1F600}".repeat(10), Selection::Full).await.is_ok());
}

#[tokio::test]
async fn a_missing_executable_is_retried_with_backoff_not_a_panic() {
    let mut cfg = config(&[]);
    cfg.command = "this-worker-does-not-exist".into();
    let pool = SpacyPool::start(cfg).unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!pool.is_ready());
    assert!(pool.starts() >= 2);
    assert!(matches!(pool.wait_ready(Duration::from_millis(100)).await, Err(SpacyError::NotReady(_))));
}

#[tokio::test]
async fn shutdown_stops_the_workers() {
    let pool = SpacyPool::start(config(&[])).unwrap();
    pool.wait_ready(Duration::from_secs(10)).await.unwrap();
    pool.shutdown().await;
}

#[test]
fn starting_outside_a_runtime_is_an_error() {
    assert!(SpacyPool::start(config(&[])).is_err());
}

fn tempfile_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("privoke-spacy-test-{}-{:?}", std::process::id(), std::thread::current().id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
