//! The in-process backend's thread, channel, readiness, queue and deadline logic, against the Python-free engine, plus
//! its byte parity with the worker pool over the fake worker. The real interpreter has its own tests in
//! `real_interpreter.rs` (they need the bundle).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use privoke_spacy::fake::{FakeEngine, fake_info};
use privoke_spacy::{
    ConfigError, Engine, InProcess, InProcessConfig, PoolConfig, Selection, Spacy, SpacyConfig, SpacyError, SpacyPool, StartFailure,
    StatusKind,
};

const FAKE_WORKER: &str = env!("CARGO_BIN_EXE_privoke-spacy-fake-worker");

fn config() -> InProcessConfig {
    let mut cfg = InProcessConfig::new(".");
    cfg.request_deadline = Duration::from_secs(5);
    cfg
}

fn fake(cfg: &InProcessConfig) -> InProcess {
    InProcess::start_with(cfg, || Ok((Box::new(FakeEngine) as Box<dyn Engine>, fake_info()))).unwrap()
}

async fn ready(cfg: &InProcessConfig) -> InProcess {
    let backend = fake(cfg);
    backend.wait_ready(Duration::from_secs(10)).await.unwrap();
    backend
}

#[tokio::test]
async fn analyzes_in_both_selections_and_caches_the_lemma_index() {
    let backend = ready(&config()).await;
    let text = "Alice lives in Paris";
    let full = backend.analyze(text, Selection::Full).await.unwrap();
    assert_eq!(full.tokens.len(), 4);
    assert_eq!((full.entities[0].label.as_str(), &text[full.entities[0].span.bytes()]), ("GPE", "Paris"));
    assert!(backend.analyze(text, Selection::TaggerOnly).await.unwrap().entities.is_empty());
    let words = backend.lemma_index().await.unwrap();
    assert_eq!(words.as_slice(), ["alpha", "beta"]);
    assert!(Arc::ptr_eq(&words, &backend.lemma_index().await.unwrap()));
    assert_eq!(backend.worker_info().unwrap().spacy.as_deref(), Some("fake"));
}

/// The default configuration selects the in-process backend, not the worker pool.
#[test]
fn the_default_backend_is_in_process() {
    assert!(matches!(SpacyConfig::default(), SpacyConfig::InProcess(_)));
    assert!(matches!(SpacyConfig::in_process("bundle"), SpacyConfig::InProcess(_)));
}

/// Without the `in-process` feature, starting the real backend is a clear configuration error, never a silent fall
/// back to a worker process.
#[cfg(not(feature = "in-process"))]
#[test]
fn the_real_backend_needs_the_in_process_feature() {
    let err = Spacy::start(&SpacyConfig::default()).unwrap_err();
    assert!(matches!(err, ConfigError::Invalid(ref m) if m.contains("in-process")), "{err}");
}

#[test]
fn invalid_settings_are_rejected() {
    let mutations: [fn(&mut InProcessConfig); 4] = [
        |c| c.queue_capacity = 0,
        |c| c.request_deadline = Duration::from_secs(30),
        |c| c.request_deadline = Duration::ZERO,
        |c| c.max_text_chars = 0,
    ];
    for mutate in mutations {
        let mut cfg = config();
        mutate(&mut cfg);
        assert!(matches!(InProcess::start_with(&cfg, || Err(StartFailure::Failed(String::new()))), Err(ConfigError::Invalid(_))));
    }
}

#[tokio::test]
async fn invalid_text_is_rejected_before_queueing() {
    let mut cfg = config();
    cfg.max_text_chars = 5;
    let backend = ready(&cfg).await;
    for text in ["", "abcdef"] {
        let err = backend.analyze_raw(text, Selection::Full).await.unwrap_err();
        assert!(matches!(err, SpacyError::InvalidArgument(_)), "{err}");
        assert_eq!(err.status(), StatusKind::InvalidArgument);
    }
    assert!(backend.analyze_raw("abcde", Selection::Full).await.is_ok());
}

/// Byte parity of the two backends over the same engine logic: the bytes a caller gets do not depend on the backend.
/// (The same comparison over spaCy and every recorded NER set is `real_interpreter.rs`.)
#[tokio::test]
async fn results_are_byte_identical_to_the_worker_pool_backend() {
    let in_process = ready(&config()).await;
    let mut pool_cfg = PoolConfig::new(FAKE_WORKER);
    pool_cfg.request_deadline = Duration::from_secs(5);
    let pool = SpacyPool::start(pool_cfg).unwrap();
    pool.wait_ready(Duration::from_secs(60)).await.unwrap();
    for text in ["Alice lives in Paris", "a\u{1F600} Paris b", "  leading and  double  spaces ", "CJK \u{4F60}\u{597D} Paris", "x"] {
        for selection in [Selection::Full, Selection::TaggerOnly] {
            let a = in_process.analyze_raw(text, selection).await.unwrap();
            let b = pool.analyze_raw(text, selection).await.unwrap();
            assert_eq!(a.as_str(), b.as_str(), "{text:?} {selection:?}");
            assert_eq!(a.decode(text).unwrap(), b.decode(text).unwrap());
        }
    }
    assert_eq!(in_process.lemma_index().await.unwrap(), pool.lemma_index().await.unwrap());
}

/// The enum the runtime holds answers the same as the backend inside it.
#[tokio::test]
async fn the_spacy_enum_delegates_to_its_backend() {
    let spacy = Spacy::InProcess(ready(&config()).await);
    assert!(spacy.is_ready());
    assert_eq!(spacy.worker_info().unwrap().model.as_deref(), Some("fake"));
    assert_eq!(spacy.analyze("a Paris", Selection::Full).await.unwrap().entities.len(), 1);
    assert_eq!(spacy.lemma_index().await.unwrap().len(), 2);
}

/// P3, readiness: a request that arrives while the model loads is `Unavailable`, not queued.
#[tokio::test]
async fn p3_request_during_load_is_unavailable() {
    let backend = InProcess::start_with(&config(), || {
        std::thread::sleep(Duration::from_millis(700));
        Ok((Box::new(FakeEngine) as Box<dyn Engine>, fake_info()))
    })
    .unwrap();
    assert!(!backend.is_ready());
    let err = backend.analyze("hello", Selection::Full).await.unwrap_err();
    assert!(matches!(err, SpacyError::NotReady(_)), "{err}");
    assert_eq!(err.status(), StatusKind::Unavailable);
    backend.wait_ready(Duration::from_secs(10)).await.unwrap();
    assert!(backend.analyze("hello", Selection::Full).await.is_ok());
}

/// A refused bundle is final: never ready, the reason is reported, and requests are `Unavailable`.
#[tokio::test]
async fn a_refused_bundle_is_final_and_reports_why() {
    let backend = InProcess::start_with(&config(), || Err(StartFailure::Refused("numpy 1.26.3 differs from the lock".into()))).unwrap();
    let err = backend.wait_ready(Duration::from_secs(10)).await.unwrap_err();
    assert!(err.to_string().contains("numpy 1.26.3 differs from the lock"), "{err}");
    assert!(err.to_string().contains("refused"), "{err}");
    assert!(!backend.is_ready());
    let err = backend.analyze("hello", Selection::Full).await.unwrap_err();
    assert_eq!(err.status(), StatusKind::Unavailable);
}

#[tokio::test]
async fn a_failed_start_and_a_panicking_factory_are_unavailable() {
    let failed = InProcess::start_with(&config(), || Err(StartFailure::Failed("no model".into()))).unwrap();
    assert!(failed.wait_ready(Duration::from_secs(10)).await.unwrap_err().to_string().contains("no model"));
    let panicked = InProcess::start_with(&config(), || panic!("factory exploded")).unwrap();
    assert!(panicked.wait_ready(Duration::from_secs(10)).await.unwrap_err().to_string().contains("factory exploded"));
    assert_eq!(panicked.analyze("x", Selection::Full).await.unwrap_err().status(), StatusKind::Unavailable);
}

#[tokio::test]
async fn an_engine_error_is_reported_and_the_interpreter_keeps_serving() {
    let backend = ready(&config()).await;
    let err = backend.analyze("ERR", Selection::Full).await.unwrap_err();
    assert!(matches!(err, SpacyError::WorkerReported(ref m) if m == "boom"), "{err}");
    assert!(backend.analyze("fine", Selection::Full).await.is_ok());
}

/// A panic on the interpreter thread ends it: the request and every later one are `Unavailable`. (A real interpreter
/// crash ends the process instead; that is covered with the runtime host in `runtime_worker.rs`.)
#[tokio::test]
async fn a_panic_on_the_interpreter_thread_makes_the_backend_unavailable() {
    let backend = ready(&config()).await;
    let err = backend.analyze("PANIC", Selection::Full).await.unwrap_err();
    assert!(matches!(err, SpacyError::WorkerFailed(_)), "{err}");
    assert_eq!(err.status(), StatusKind::Unavailable);
    let start = Instant::now();
    while backend.is_ready() {
        assert!(start.elapsed() < Duration::from_secs(5), "the backend still reports ready");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let err = backend.analyze("fine", Selection::Full).await.unwrap_err();
    assert_eq!(err.status(), StatusKind::Unavailable);
}

#[tokio::test]
async fn full_queue_is_resource_exhausted() {
    let mut cfg = config();
    cfg.queue_capacity = 1;
    let backend = Arc::new(ready(&cfg).await);
    let busy = tokio::spawn({
        let backend = backend.clone();
        async move { backend.analyze("SLEEP:900", Selection::Full).await }
    });
    tokio::time::sleep(Duration::from_millis(250)).await; // the interpreter has taken it
    let queued = tokio::spawn({
        let backend = backend.clone();
        async move { backend.analyze("SLEEP:10", Selection::Full).await }
    });
    tokio::time::sleep(Duration::from_millis(150)).await; // it is waiting in the queue
    let err = backend.analyze("overflow", Selection::Full).await.unwrap_err();
    assert!(matches!(err, SpacyError::ResourceExhausted { capacity: 1 }), "{err}");
    assert_eq!(err.status(), StatusKind::ResourceExhausted);
    assert!(busy.await.unwrap().is_ok());
    assert!(queued.await.unwrap().is_ok());
    assert!(backend.analyze("after", Selection::Full).await.is_ok());
}

/// One deadline covers the queue and the interpreter. A thread cannot be killed, so the backend stays busy until the
/// request ends; the W2 pool's deadline replaces the whole runtime worker in that case.
#[tokio::test]
async fn deadline_is_unavailable_and_the_caller_is_not_held() {
    let mut cfg = config();
    cfg.request_deadline = Duration::from_millis(300);
    let backend = ready(&cfg).await;
    let started = Instant::now();
    let err = backend.analyze("SLEEP:1500", Selection::Full).await.unwrap_err();
    assert!(matches!(err, SpacyError::DeadlineExceeded(_)), "{err}");
    assert_eq!(err.status(), StatusKind::Unavailable);
    assert!(started.elapsed() < Duration::from_millis(1200), "the caller was held until the interpreter finished");
}

/// A request abandoned while it waits in the queue is skipped, so a stuck request does not leave a backlog of dead work.
#[tokio::test]
async fn an_abandoned_queued_request_is_not_run() {
    let mut cfg = config();
    cfg.request_deadline = Duration::from_millis(300);
    let backend = Arc::new(ready(&cfg).await);
    let first = tokio::spawn({
        let backend = backend.clone();
        async move { backend.analyze("SLEEP:600", Selection::Full).await } // the interpreter is busy until 600 ms
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Queued behind the first and abandoned at 400 ms. If it ran it would hold the interpreter until about 1.2 s.
    let queued = backend.analyze("SLEEP:600", Selection::Full).await;
    assert!(matches!(queued, Err(SpacyError::DeadlineExceeded(_))));
    assert!(matches!(first.await.unwrap(), Err(SpacyError::DeadlineExceeded(_))));
    tokio::time::sleep(Duration::from_millis(300)).await; // now 700 ms: the first request has ended
    assert!(backend.analyze("quick", Selection::Full).await.is_ok(), "the abandoned request ran");
}
