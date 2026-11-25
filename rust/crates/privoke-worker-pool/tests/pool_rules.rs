//! Pool rules against the test worker: readiness, poisoned input, backoff, refusal, queue bound, deadlines, worker
//! errors, a stray print, and shutdown. They run on every platform.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{call, config, ready_pool, until};
use privoke_worker_pool::testing::JsonProtocol;
use privoke_worker_pool::{Backoff, PoolError, WorkerPool};
use serde_json::json;

fn spawn_times(log: &std::path::Path) -> Vec<u128> {
    std::fs::read_to_string(log).unwrap_or_default().lines().filter_map(|l| l.parse().ok()).collect()
}

#[tokio::test]
async fn serves_requests_and_reports_the_announcement() {
    let pool = ready_pool(config(&[])).await;
    assert_eq!(call(&pool, "echo", json!({"text": "hello"})).await.unwrap(), json!("hello"));
    assert!(pool.info().unwrap()["pid"].as_u64().is_some());
}

/// Readiness: a request that arrives while the worker is still loading fails at once, and is not queued.
#[tokio::test]
async fn request_during_load_is_not_ready() {
    let pool = WorkerPool::start(JsonProtocol, config(&["--startup-delay-ms", "700"])).unwrap();
    assert!(!pool.is_ready());
    let err = call(&pool, "echo", json!({"text": "x"})).await.unwrap_err();
    assert!(matches!(err, PoolError::NotReady(_)), "{err}");
    pool.wait_ready(Duration::from_secs(60)).await.unwrap();
    assert!(call(&pool, "echo", json!({"text": "x"})).await.is_ok());
}

/// Poisoned input: the request that crashed a worker fails and is never tried on another worker. With two workers a
/// retry would crash the second one too; exactly one restart shows it did not happen.
#[tokio::test]
async fn poisoned_input_is_not_retried() {
    let mut cfg = config(&[]);
    cfg.workers = 2;
    let pool = WorkerPool::start(JsonProtocol, cfg).unwrap();
    until("two ready workers", || pool.ready_workers() == 2).await;
    assert_eq!(pool.starts(), 2);
    let err = call(&pool, "crash", json!({})).await.unwrap_err();
    assert!(matches!(err, PoolError::WorkerFailed(_)), "{err}");
    assert!(call(&pool, "echo", json!({"text": "still fine"})).await.is_ok());
    until("the crashed slot to restart", || pool.ready_workers() == 2).await;
    assert_eq!(pool.starts(), 3, "exactly one restart: the poisoned request was not retried on the other worker");
}

/// Backoff: a worker that dies at once is restarted with growing delays. Process start-up time varies by host, so the
/// test checks the lower bound the backoff guarantees: each gap is at least the configured delay, which a pool without
/// backoff would break on any host that starts a process in under 100 ms.
#[tokio::test]
async fn crash_loop_backs_off() {
    let dir = std::env::temp_dir().join(format!("privoke-pool-backoff-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("spawns.log");
    let mut cfg = config(&["--exit-at-start", "--spawn-log", log.to_str().unwrap()]);
    cfg.backoff = Backoff { initial: Duration::from_millis(100), max: Duration::from_millis(800) };
    let pool = WorkerPool::start(JsonProtocol, cfg.clone()).unwrap();
    until("six worker starts", || spawn_times(&log).len() >= 6).await;
    let times = spawn_times(&log);
    for (n, pair) in times.windows(2).enumerate() {
        let gap = Duration::from_millis((pair[1] - pair[0]) as u64);
        let wanted = cfg.backoff.delay(n as u32 + 1);
        assert!(gap + Duration::from_millis(15) >= wanted, "restart {} came after {gap:?}, wanted at least {wanted:?}", n + 1);
    }
    assert!(!pool.is_ready());
    drop(pool);
    std::fs::remove_dir_all(dir).ok();
}

/// A completed request resets the failure count, so a crash after a healthy spell restarts at the initial delay. Without
/// the reset the fourth restart would wait 6.4 s; with it every restart waits 0.8 s plus the host's start-up time.
#[tokio::test]
async fn a_completed_request_resets_the_backoff() {
    let dir = std::env::temp_dir().join(format!("privoke-pool-reset-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("spawns.log");
    let mut cfg = config(&["--spawn-log", log.to_str().unwrap()]);
    cfg.backoff = Backoff { initial: Duration::from_millis(800), max: Duration::from_secs(30) };
    let pool = ready_pool(cfg).await;
    for _ in 0..4 {
        assert!(call(&pool, "echo", json!({"text": "healthy"})).await.is_ok());
        assert!(call(&pool, "crash", json!({})).await.is_err());
        until("a restarted worker", || pool.is_ready()).await;
    }
    let times = spawn_times(&log);
    assert_eq!(times.len(), 5);
    let last = Duration::from_millis((times[4] - times[3]) as u64);
    assert!(last >= Duration::from_millis(800 - 15), "{last:?}");
    assert!(last < Duration::from_millis(5500), "the fourth restart waited {last:?}: the failure count was not reset");
    drop(pool);
    std::fs::remove_dir_all(dir).ok();
}

/// A refused worker is final: the pool is never ready, reports the reason, and does not restart.
#[tokio::test]
async fn refused_worker_stops_the_slot_and_reports_why() {
    let pool = WorkerPool::start(JsonProtocol, config(&["--fatal", "the bundle differs from the lock"])).unwrap();
    let err = pool.wait_ready(Duration::from_secs(60)).await.unwrap_err();
    assert!(err.to_string().contains("the bundle differs from the lock"), "{err}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(pool.starts(), 1);
    assert!(matches!(call(&pool, "echo", json!({})).await, Err(PoolError::NotReady(_))));
}

#[tokio::test]
async fn full_queue_is_resource_exhausted() {
    let mut cfg = config(&[]);
    cfg.queue_capacity = 1;
    let pool = Arc::new(ready_pool(cfg).await);
    let busy = tokio::spawn({
        let pool = pool.clone();
        async move { call(&pool, "sleep", json!({"ms": 900})).await }
    });
    tokio::time::sleep(Duration::from_millis(250)).await; // the worker has taken it
    let queued = tokio::spawn({
        let pool = pool.clone();
        async move { call(&pool, "sleep", json!({"ms": 10})).await }
    });
    tokio::time::sleep(Duration::from_millis(150)).await; // it is waiting in the queue
    let err = call(&pool, "echo", json!({})).await.unwrap_err();
    assert!(matches!(err, PoolError::ResourceExhausted { capacity: 1 }), "{err}");
    assert!(busy.await.unwrap().is_ok());
    assert!(queued.await.unwrap().is_ok());
    assert!(call(&pool, "echo", json!({})).await.is_ok());
}

/// A worker that misses the deadline is killed and restarted; the request fails and the pool recovers.
#[tokio::test]
async fn deadline_kills_the_worker_and_the_pool_recovers() {
    let mut cfg = config(&[]);
    cfg.request_deadline = Duration::from_millis(400);
    let pool = ready_pool(cfg).await;
    let started = Instant::now();
    let err = call(&pool, "hang", json!({})).await.unwrap_err();
    assert!(matches!(err, PoolError::DeadlineExceeded(_)), "{err}");
    assert!(started.elapsed() < Duration::from_secs(3));
    until("a restarted worker", || pool.starts() == 2 && pool.is_ready()).await;
    assert!(call(&pool, "echo", json!({})).await.is_ok());
}

/// A request queued behind a hung worker is not poisoned: the hung one is killed at its deadline, and the restarted
/// worker serves the queued request within its own, later deadline.
#[tokio::test]
async fn queued_request_survives_a_hung_worker_ahead_of_it() {
    let mut cfg = config(&[]);
    cfg.request_deadline = Duration::from_secs(4);
    let pool = Arc::new(ready_pool(cfg).await);
    let hung = tokio::spawn({
        let pool = pool.clone();
        async move { call(&pool, "hang", json!({})).await }
    });
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(call(&pool, "echo", json!({})).await.is_ok());
    assert!(matches!(hung.await.unwrap(), Err(PoolError::DeadlineExceeded(_))));
    assert_eq!(pool.starts(), 2);
}

#[tokio::test]
async fn worker_reported_error_keeps_the_worker() {
    let pool = ready_pool(config(&[])).await;
    let err = call(&pool, "err", json!({})).await.unwrap_err();
    assert!(matches!(err, PoolError::WorkerReported(ref m) if m == "boom"), "{err}");
    assert_eq!(pool.starts(), 1);
    assert!(call(&pool, "echo", json!({})).await.is_ok());
}

#[tokio::test]
async fn out_of_protocol_answer_restarts_the_worker() {
    let pool = ready_pool(config(&[])).await;
    let err = call(&pool, "badid", json!({})).await.unwrap_err();
    assert!(matches!(err, PoolError::WorkerFailed(_)), "{err}");
    until("a restarted worker", || pool.starts() == 2 && pool.is_ready()).await;
}

/// The frame pipe: a stray print in the worker goes to stderr and the frames stay intact.
#[tokio::test]
async fn stray_output_does_not_corrupt_the_frames() {
    let pool = ready_pool(config(&[])).await;
    for _ in 0..3 {
        assert_eq!(call(&pool, "print", json!({})).await.unwrap(), json!("printed"));
        assert_eq!(call(&pool, "echo", json!({"text": "after"})).await.unwrap(), json!("after"));
    }
    assert_eq!(pool.starts(), 1, "no restart: the framing was never corrupted");
}

#[tokio::test]
async fn a_missing_executable_is_retried_with_backoff_not_a_panic() {
    let mut cfg = config(&[]);
    cfg.command = "this-worker-does-not-exist".into();
    let pool = WorkerPool::start(JsonProtocol, cfg).unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!pool.is_ready());
    assert!(pool.starts() >= 2);
}

#[tokio::test]
async fn shutdown_stops_the_workers() {
    let pool = ready_pool(config(&[])).await;
    let pids = pool.worker_pids();
    assert_eq!(pids.len(), 1);
    pool.shutdown().await;
}

#[test]
fn starting_outside_a_runtime_is_an_error() {
    assert!(WorkerPool::start(JsonProtocol, config(&[])).is_err());
}
