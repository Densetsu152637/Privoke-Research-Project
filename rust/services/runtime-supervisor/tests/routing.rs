//! Routing between the Rust analysis worker and the Python worker, through the real controller process, the real pool
//! and stand-in workers: the stand-in started as the Rust worker answers with the reason `stand-in-rust`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::session::{Host, HostOptions, LAYER_NER, LAYER_REGEX, LAYER_SEMANTIC, TEST_WORKER, analysis};

fn host(rust: bool) -> Host {
    let env = if rust {
        vec![("PRIVOKE_RUNTIME_ANALYSIS_ENGINE", "rust".to_string()), ("PRIVOKE_RUNTIME_RUST_WORKER", TEST_WORKER.to_string())]
    } else {
        Vec::new()
    };
    Host::start(HostOptions { env, ..HostOptions::default() })
}

fn reason(host: &mut Host, id: u64, layers: &[i32]) -> String {
    analysis(&host.analyze(id, "hello there", layers)).reason
}

#[test]
fn with_the_rust_worker_selected_each_call_goes_to_the_worker_that_serves_it() {
    let mut host = host(true);
    let started = host.set_enabled(1, true);
    assert!(started.enabled, "{}", started.message);
    assert_eq!(reason(&mut host, 2, &[LAYER_REGEX]), "stand-in-rust");
    assert_eq!(reason(&mut host, 3, &[LAYER_NER, LAYER_REGEX]), "stand-in-rust");
    assert_eq!(reason(&mut host, 4, &[LAYER_SEMANTIC]), "stand-in");
    assert_eq!(reason(&mut host, 5, &[LAYER_REGEX, LAYER_NER, LAYER_SEMANTIC]), "stand-in");
    // An empty selection is never sent to the Rust worker: the Python worker refuses it.
    let empty = host.analyze(6, "hello there", &[]);
    assert_eq!((empty["ok"].clone(), empty["code"].clone()), (serde_json::json!(false), serde_json::json!("INVALID_ARGUMENT")), "{empty}");
    assert!(host.set_enabled(7, false).status == "STOPPED");
}

#[test]
fn without_the_rust_worker_everything_stays_on_the_python_worker() {
    let mut host = host(false);
    assert!(host.set_enabled(1, true).enabled);
    assert_eq!(reason(&mut host, 2, &[LAYER_REGEX]), "stand-in");
    assert_eq!(reason(&mut host, 3, &[LAYER_SEMANTIC]), "stand-in");
}

#[test]
fn with_model_roots_the_rust_worker_also_serves_the_plain_semantic_layer() {
    let cache = tempfile::tempdir().unwrap();
    let env = vec![
        ("PRIVOKE_RUNTIME_ANALYSIS_ENGINE", "rust".to_string()),
        ("PRIVOKE_RUNTIME_RUST_WORKER", TEST_WORKER.to_string()),
        ("MODEL_PACKAGE_CACHE_DIR", cache.path().to_string_lossy().into_owned()),
    ];
    let mut host = Host::start(HostOptions { env, ..HostOptions::default() });
    assert!(host.set_enabled(1, true).enabled);
    assert_eq!(reason(&mut host, 2, &[LAYER_SEMANTIC]), "stand-in-rust");
    assert_eq!(reason(&mut host, 3, &[LAYER_REGEX, LAYER_NER, LAYER_SEMANTIC]), "stand-in-rust");
    assert_eq!(reason(&mut host, 4, &[LAYER_REGEX]), "stand-in-rust");
}
