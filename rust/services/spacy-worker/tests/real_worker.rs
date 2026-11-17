//! The real worker: CPython embedded through PyO3, spaCy loaded from the bundle, driven through the pool and directly.
//!
//! Needs a bundle built with the test hooks (`build_bundle.py --test-hooks`), named by `PRIVOKE_SPACY_BUNDLE`
//! (default: `rust/target/bundle/windows`). The tests run the worker with no Python on PATH where they spawn it
//! directly; the pool tests use the pool's own spawn. Run with:
//!
//! ```text
//! PYO3_PYTHON=<python 3.11 with libs> cargo test -p privoke-spacy-worker --features embed,test-hooks --locked
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{BufRead, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use privoke_spacy::protocol::Request;
use privoke_spacy::{Backoff, PoolConfig, Selection, SpacyError, SpacyPool, StatusKind};

fn bundle() -> PathBuf {
    let dir = std::env::var_os("PRIVOKE_SPACY_BUNDLE")
        .map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/bundle/windows"), PathBuf::from);
    assert!(
        dir.join(if cfg!(windows) { "privoke-spacy-worker.exe" } else { "privoke-spacy-worker" }).is_file(),
        "no bundle at {}; build one with build_bundle.py --test-hooks and set PRIVOKE_SPACY_BUNDLE",
        dir.display()
    );
    dir
}

fn worker() -> PathBuf {
    bundle().join(if cfg!(windows) { "privoke-spacy-worker.exe" } else { "privoke-spacy-worker" })
}

fn config(workers: usize) -> PoolConfig {
    let mut cfg = PoolConfig::new(worker());
    cfg.workers = workers;
    cfg.backoff = Backoff { initial: Duration::from_millis(50), max: Duration::from_millis(500) };
    cfg.request_deadline = Duration::from_secs(20);
    cfg.startup_timeout = Duration::from_secs(120);
    cfg
}

async fn ready_pool(workers: usize) -> SpacyPool {
    let pool = SpacyPool::start(config(workers)).unwrap();
    pool.wait_ready(Duration::from_secs(120)).await.unwrap();
    pool
}

async fn until(what: &str, mut cond: impl FnMut() -> bool) {
    let start = Instant::now();
    while !cond() {
        assert!(start.elapsed() < Duration::from_secs(120), "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn frame(payload: &str) -> Vec<u8> {
    let mut out = (payload.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(payload.as_bytes());
    out
}

fn read_frame(input: &mut impl Read) -> String {
    let mut len = [0u8; 4];
    input.read_exact(&mut len).expect("a frame length");
    let mut payload = vec![0u8; u32::from_le_bytes(len) as usize];
    input.read_exact(&mut payload).expect("a frame payload");
    String::from_utf8(payload).expect("UTF-8 frame")
}

/// The worker starts from the bundle with no system Python on PATH, announces spaCy 3.7.5 and the model, and then
/// answers over the pipe.
#[test]
fn starts_with_no_python_on_path_and_reports_its_identity() {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "/".into());
    let mut child = Command::new(worker())
        .env_clear()
        .env("SystemRoot", &root)
        .env("PATH", PathBuf::from(&root).join("System32"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let (mut stdin, mut stdout) = (child.stdin.take().unwrap(), child.stdout.take().unwrap());
    let ready: serde_json::Value = serde_json::from_str(&read_frame(&mut stdout)).unwrap();
    assert_eq!(ready["type"], "ready");
    assert_eq!(ready["spacy"], "3.7.5");
    assert_eq!(ready["model_version"], "3.7.1");
    assert_eq!(ready["python"], "3.11.9");
    assert_eq!(ready["lock_sha256"].as_str().unwrap().len(), 64);
    stdin.write_all(&frame(r#"{"id":1,"op":"analyze","selection":"full","text":"Alice lives in Paris."}"#)).unwrap();
    let answer: serde_json::Value = serde_json::from_str(&read_frame(&mut stdout)).unwrap();
    assert_eq!((answer["id"].as_u64(), answer["ok"].as_bool()), (Some(1), Some(true)));
    assert!(answer["result"]["ents"].as_array().unwrap().iter().any(|e| e[2] == "GPE"));
    drop(stdin);
    assert!(child.wait().unwrap().success());
}

/// P4, framing: a `print`, a write to `sys.__stdout__` and a raw write to fd 1 inside the worker reach stderr, and the
/// frames on the framing descriptor stay intact before, between and after them.
#[test]
fn p4_print_inside_the_worker_leaves_the_framing_intact() {
    let mut child = Command::new(worker()).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let (mut stdin, mut stdout, stderr) = (child.stdin.take().unwrap(), child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let collected = std::thread::spawn(move || std::io::BufReader::new(stderr).lines().map_while(Result::ok).collect::<Vec<_>>());
    assert!(read_frame(&mut stdout).contains(r#""type":"ready""#));
    for (id, op) in [
        (1, r#""op":"analyze","selection":"full","text":"before""#),
        (2, r#""op":"test_print""#),
        (3, r#""op":"analyze","selection":"tagger","text":"after""#),
    ] {
        stdin.write_all(&frame(&format!(r#"{{"id":{id},{op}}}"#))).unwrap();
        let answer: serde_json::Value = serde_json::from_str(&read_frame(&mut stdout)).unwrap();
        assert_eq!((answer["id"].as_u64(), answer["ok"].as_bool()), (Some(id), Some(true)), "{answer}");
    }
    drop(stdin);
    assert!(child.wait().unwrap().success());
    let stderr = collected.join().unwrap().join("\n");
    for marker in ["python print", "sys.__stdout__", "raw fd 1 write"] {
        assert!(stderr.contains(&format!("PRIVOKE-TEST-PRINT {marker}")), "{marker} is missing from stderr: {stderr}");
    }
    let mut rest = Vec::new();
    stdout.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty(), "stray bytes on the framing descriptor: {rest:?}");
}

/// P4, offsets: emoji, combining marks and CJK map to the right UTF-8 and UTF-16 offsets for every token and entity.
#[tokio::test]
async fn p4_offsets_are_correct_for_emoji_combining_marks_and_cjk() {
    let pool = ready_pool(1).await;
    let texts = [
        "Alice \u{1F600}\u{1F1EB}\u{1F1F7} met Bob in Paris \u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467} on Monday.",
        "Cafe\u{0301} Mu\u{0308}nchen: Jose\u{0301} A\u{0301}lvarez lives in Zu\u{0308}rich, e\u{0301}\u{0301}x.",
        "\u{6211}\u{53eb}\u{5f20}\u{4f1f}\u{ff0c}\u{4f4f}\u{5728}\u{5317}\u{4eac}\u{5e02}\u{3002} Tom visited \u{6771}\u{4eac}.",
        "Zero\u{200B}width \u{200D}joiners\u{FEFF} in Lon\u{200B}don and \u{20000}\u{20001} astral Berlin.",
    ];
    let mut saw_entity = false;
    for text in texts {
        let units: Vec<u16> = text.encode_utf16().collect();
        let chars: Vec<char> = text.chars().collect();
        let analysis = pool.analyze(text, Selection::Full).await.unwrap();
        assert!(!analysis.tokens.is_empty());
        let check = |what: &str, span: privoke_spacy::Span, expected: Option<&str>| {
            let by_chars: String = chars[span.start_char..span.end_char].iter().collect();
            assert_eq!(&text[span.bytes()], by_chars, "{what}: UTF-8 bytes disagree with code points in {text:?}");
            assert_eq!(
                String::from_utf16(&units[span.start_utf16..span.end_utf16]).unwrap(),
                by_chars,
                "{what}: UTF-16 disagrees in {text:?}"
            );
            if let Some(expected) = expected {
                assert_eq!(by_chars, expected, "{what}");
            }
        };
        for token in &analysis.tokens {
            check("token", token.span, Some(&token.text));
        }
        for entity in &analysis.entities {
            saw_entity = true;
            check(&format!("entity {}", entity.label), entity.span, None);
        }
    }
    assert!(saw_entity, "no entity found in any text, so the entity offsets were not exercised");
    // A concrete check: an astral emoji is one code point, four bytes and two UTF-16 units.
    let analysis = pool.analyze("Alice \u{1F600} Bob", Selection::Full).await.unwrap();
    let bob = analysis.tokens.iter().find(|t| t.text == "Bob").unwrap();
    assert_eq!((bob.idx, bob.span.start_byte, bob.span.start_utf16), (8, 11, 9));
}

/// P3, readiness: a request that arrives while spaCy is loading is `Unavailable`, and the pool serves once it is ready.
#[tokio::test]
async fn p3_request_during_spacy_load_is_unavailable() {
    let pool = SpacyPool::start(config(1)).unwrap();
    let err = pool.analyze("hello", Selection::Full).await.unwrap_err();
    assert!(matches!(err, SpacyError::NotReady(_)), "{err}");
    assert_eq!(err.status(), StatusKind::Unavailable);
    pool.wait_ready(Duration::from_secs(120)).await.unwrap();
    assert!(pool.analyze("hello", Selection::Full).await.is_ok());
    let info = pool.worker_info().unwrap();
    assert_eq!((info.spacy.as_deref(), info.model_version.as_deref()), (Some("3.7.5"), Some("3.7.1")));
}

/// P3, poisoned input: the document that crashes a worker is `Unavailable` and is not retried on the other worker.
#[tokio::test]
async fn p3_crash_input_is_unavailable_and_not_retried() {
    let pool = ready_pool(2).await;
    until("both workers to load spaCy", || pool.ready_workers() == 2).await;
    assert_eq!(pool.starts(), 2);
    let err = pool.submit_request(|id| Request::TestCrash { id }).await.unwrap_err();
    assert!(matches!(err, SpacyError::WorkerFailed(_)), "{err}");
    assert_eq!(err.status(), StatusKind::Unavailable);
    assert!(pool.analyze("the other worker still answers", Selection::Full).await.is_ok());
    until("the crashed slot to reload spaCy", || pool.ready_workers() == 2).await;
    assert_eq!(pool.starts(), 3, "one restart only: the request was not retried on the second worker");
}

/// Killing the worker process in the middle of a request gives `Unavailable` for that request; the pool recovers.
#[tokio::test]
async fn killing_a_worker_mid_request_is_unavailable_and_the_pool_recovers() {
    let pool = Arc::new(ready_pool(1).await);
    let busy = tokio::spawn({
        let pool = pool.clone();
        async move { pool.submit_request(|id| Request::TestSleep { id, ms: 30_000 }).await }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    // Kill this pool's worker by process id: other workers on the machine (the parity gate, other tests) are untouched.
    let pid = pool.worker_pids()[0].to_string();
    let status = if cfg!(windows) {
        Command::new("taskkill").args(["/F", "/PID", &pid]).stdout(Stdio::null()).status()
    } else {
        Command::new("kill").args(["-9", &pid]).status()
    }
    .unwrap();
    assert!(status.success());
    let err = busy.await.unwrap().unwrap_err();
    assert_eq!(err.status(), StatusKind::Unavailable, "{err}");
    until("a replacement worker", || pool.starts() == 2 && pool.is_ready()).await;
    assert!(pool.analyze("recovered", Selection::Full).await.is_ok());
}

/// The deadline path with the real worker: a stuck worker is killed at the deadline and replaced.
#[tokio::test]
async fn deadline_kills_a_stuck_real_worker() {
    let mut cfg = config(1);
    cfg.request_deadline = Duration::from_millis(800);
    let pool = SpacyPool::start(cfg).unwrap();
    pool.wait_ready(Duration::from_secs(120)).await.unwrap();
    let err = pool.submit_request(|id| Request::TestSleep { id, ms: 60_000 }).await.unwrap_err();
    assert!(matches!(err, SpacyError::DeadlineExceeded(_)), "{err}");
    until("a replacement worker", || pool.starts() == 2 && pool.is_ready()).await;
    assert!(pool.analyze("alive", Selection::Full).await.is_ok());
}

/// The bundle check refuses any difference: a lock that names another numpy, CPython version, BLIS target or an extra
/// package stops the worker before it is ever ready, and the pool reports why instead of restarting it.
#[tokio::test]
async fn a_lock_that_differs_from_the_environment_is_refused() {
    let dir = std::env::temp_dir().join(format!("privoke-spacy-lock-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let genuine = std::fs::read_to_string(bundle().join("bundle.lock.txt")).unwrap();
    let tampered = [
        ("numpy==1.26.4", "numpy==1.26.3", "numpy"),
        ("# privoke-lock: cpython-version = 3.11.9", "# privoke-lock: cpython-version = 3.11.8", "CPython 3.11.9"),
        ("blis-target.windows-x86_64 = haswell", "blis-target.windows-x86_64 = skx", "BLIS dispatch target"),
        ("\nwrapt==2.5.0", "\nwrapt==2.5.0\nextra-package==1.0.0", "extra-package"),
    ];
    for (n, (from, to, expect)) in tampered.iter().enumerate() {
        assert!(genuine.contains(from), "the lock no longer contains {from:?}");
        let lock = dir.join(format!("lock-{n}.txt"));
        std::fs::write(&lock, genuine.replacen(from, to, 1)).unwrap();
        let mut cfg = config(1);
        cfg.args = vec!["--lock".into(), lock.clone().into_os_string()];
        let pool = SpacyPool::start(cfg).unwrap();
        let err = pool.wait_ready(Duration::from_secs(120)).await.unwrap_err();
        assert!(err.to_string().contains(expect), "expected {expect:?} in: {err}");
        assert_eq!(pool.starts(), 1, "a refused bundle must not be restarted");
        assert_eq!(pool.analyze("x", Selection::Full).await.unwrap_err().status(), StatusKind::Unavailable);
    }
    std::fs::remove_dir_all(dir).ok();
}

/// The lemma index is the model's lexicon and is cached by the pool.
#[tokio::test]
async fn lemma_index_is_the_models_word_list() {
    let pool = ready_pool(1).await;
    let words = pool.lemma_index().await.unwrap();
    assert!(words.len() > 10_000, "only {} words", words.len());
    assert!(words.iter().any(|w| w == "house") && words.windows(2).all(|p| p[0] <= p[1]));
}
