//! The in-process backend inside a runtime worker process, supervised by the W2 pool. `privoke-spacy-host` stands in
//! for the stage 17 runtime worker: it hosts `InProcess` and speaks the worker frame protocol, so the pool sees one
//! process per worker, exactly as it will see the runtime worker.
//!
//! These tests use the host's Python-free engine, so they run in CI. The same assertions against the real interpreter
//! are in `real_interpreter.rs`, which needs the bundle.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::ffi::OsString;
use std::time::{Duration, Instant};

use privoke_spacy::protocol::Request;
use privoke_spacy::{Backoff, PoolConfig, Selection, SpacyError, SpacyPool, StatusKind};

const HOST: &str = env!("CARGO_BIN_EXE_privoke-spacy-host");

fn config(workers: usize) -> PoolConfig {
    let mut cfg = PoolConfig::new(HOST);
    cfg.args = vec![OsString::from("--engine"), OsString::from("fake")];
    cfg.workers = workers;
    cfg.backoff = Backoff { initial: Duration::from_millis(40), max: Duration::from_millis(400) };
    cfg.request_deadline = Duration::from_secs(10);
    cfg.startup_timeout = Duration::from_secs(60);
    cfg
}

async fn until(what: &str, mut cond: impl FnMut() -> bool) {
    let start = Instant::now();
    while !cond() {
        assert!(start.elapsed() < Duration::from_secs(60), "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn the_runtime_worker_serves_spacy_in_process() {
    let pool = SpacyPool::start(config(1)).unwrap();
    pool.wait_ready(Duration::from_secs(60)).await.unwrap();
    let text = "Alice lives in Paris";
    let full = pool.analyze(text, Selection::Full).await.unwrap();
    assert_eq!(full.entities.len(), 1);
    assert!(pool.analyze(text, Selection::TaggerOnly).await.unwrap().entities.is_empty());
    assert_eq!(pool.lemma_index().await.unwrap().as_slice(), ["alpha", "beta"]);
}

/// No child process is created when NER runs: the worker process the pool started is the only process, and it has no
/// child of its own, before and after the requests.
#[tokio::test]
async fn no_child_process_is_created_when_ner_runs() {
    let pool = SpacyPool::start(config(1)).unwrap();
    pool.wait_ready(Duration::from_secs(60)).await.unwrap();
    let before = pool.submit_request(|id| Request::TestChildren { id }).await.unwrap();
    if before == "null" {
        eprintln!("SKIPPED no_child_process_is_created_when_ner_runs: the host cannot list its child processes on this platform");
        return;
    }
    assert_eq!(before, "[]", "a fresh runtime worker already has child processes");
    for text in ["Alice lives in Paris", "a\u{1F600} Paris", "second request"] {
        for selection in [Selection::Full, Selection::TaggerOnly] {
            pool.analyze(text, selection).await.unwrap();
        }
    }
    pool.lemma_index().await.unwrap();
    let after = pool.submit_request(|id| Request::TestChildren { id }).await.unwrap();
    assert_eq!(after, "[]", "running NER created a child process");
    assert_eq!(pool.worker_pids().len(), 1);
    assert_eq!(pool.starts(), 1, "the pool had to restart the worker");
}

/// A crash of the interpreter inside a runtime worker takes down only that worker. The W2 pool restarts it, and the
/// request that was in flight is answered `Unavailable` and is not retried: with two workers, a retry would crash the
/// second one too, and exactly one restart shows it did not happen.
#[tokio::test]
async fn an_interpreter_crash_kills_only_that_worker_and_the_request_is_not_retried() {
    let pool = SpacyPool::start(config(2)).unwrap();
    until("two ready workers", || pool.ready_workers() == 2).await;
    assert_eq!(pool.starts(), 2);
    let before = pool.worker_pids();
    assert_eq!(before.len(), 2);

    // The deliberate crash happens on the interpreter thread, inside the worker process.
    let err = pool.submit_request(|id| Request::TestCrash { id }).await.unwrap_err();
    assert!(matches!(err, SpacyError::WorkerFailed(_)), "{err}");
    assert_eq!(err.status(), StatusKind::Unavailable);

    // The other worker kept serving, and the crashed slot came back.
    assert!(pool.analyze("still fine", Selection::Full).await.is_ok());
    until("the crashed slot to restart", || pool.ready_workers() == 2).await;
    assert_eq!(pool.starts(), 3, "exactly one restart: the crashed request was not retried on another worker");
    let after = pool.worker_pids();
    assert_eq!(after.len(), 2);
    assert_eq!(before.iter().filter(|pid| after.contains(pid)).count(), 1, "exactly one worker process was replaced: {before:?} {after:?}");
    assert!(pool.analyze("recovered", Selection::Full).await.is_ok());
}

/// The same through a poisoned document: the text itself crashes the interpreter.
#[tokio::test]
async fn a_poisoned_document_crashes_one_worker_and_is_not_retried() {
    let pool = SpacyPool::start(config(2)).unwrap();
    until("two ready workers", || pool.ready_workers() == 2).await;
    let err = pool.analyze("CRASH", Selection::Full).await.unwrap_err();
    assert!(matches!(err, SpacyError::WorkerFailed(_)), "{err}");
    assert!(pool.analyze("still fine", Selection::Full).await.is_ok());
    until("the crashed slot to restart", || pool.ready_workers() == 2).await;
    assert_eq!(pool.starts(), 3);
}

/// The deadline replaces the whole runtime worker, which is how a stuck interpreter thread is handled.
#[tokio::test]
async fn a_stuck_interpreter_is_replaced_with_its_worker_at_the_pool_deadline() {
    let mut cfg = config(1);
    cfg.request_deadline = Duration::from_millis(500);
    let pool = SpacyPool::start(cfg).unwrap();
    pool.wait_ready(Duration::from_secs(60)).await.unwrap();
    let err = pool.analyze("HANG", Selection::Full).await.unwrap_err();
    assert_eq!(err.status(), StatusKind::Unavailable);
    until("a restarted worker", || pool.starts() == 2 && pool.is_ready()).await;
    assert!(pool.analyze("alive again", Selection::Full).await.is_ok());
}
