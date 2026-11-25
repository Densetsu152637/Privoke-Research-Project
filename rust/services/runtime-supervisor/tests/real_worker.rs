//! The controller against the real W1 Python worker through the pool shim, under the pool's sandbox. It needs the
//! client runtime's virtual environment with its dependencies (the main checkout's, found the way the model-release
//! tests find theirs) and skips with a note when there is none. Host Python only; no container.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::session::{Host, HostOptions, LAYER_NER, LAYER_REGEX, analysis, listening_sockets, repository_root, runtime_python};
use common::{process_alive, wait_until};

#[test]
fn the_python_worker_analyses_behind_the_controller_and_dies_with_it() {
    let Some(python) = runtime_python() else {
        eprintln!("skipped: no client runtime virtual environment found (set PRIVOKE_TEST_RUNTIME_PYTHON)");
        return;
    };
    let root = repository_root();
    if !root.join("extension/client-runtime/generated").is_dir() {
        eprintln!("skipped: the generated protobuf clients are missing (run evaluation/setup-host.py)");
        return;
    }
    let mut host = Host::start_in(
        HostOptions {
            mode: None,
            python: Some(python),
            env: vec![("PRIVOKE_RUNTIME_START_TIMEOUT_SECONDS", "300".into()), ("PRIVOKE_USE_LOCAL_STACK", "true".into())],
        },
        Some(&root),
    );
    let started = host.set_enabled(1, true);
    assert!(started.enabled, "{}", started.message);
    let worker = started.process_id;
    assert!(process_alive(worker));
    assert!(listening_sockets(host.child.id()).is_empty() && listening_sockets(worker).is_empty(), "no listening port");

    let blocked = analysis(&host.analyze(2, "Contact alex@example.com about the draft.", &[LAYER_REGEX, LAYER_NER]));
    assert_eq!((blocked.action.as_str(), blocked.allowed), ("BLOCK", false), "{blocked:?}");
    let executed: Vec<i32> = blocked.layers.iter().map(|layer| layer.layer).collect();
    assert!(executed.iter().all(|layer| [LAYER_REGEX, LAYER_NER].contains(layer)) && !executed.is_empty(), "{executed:?}");

    let allowed = analysis(&host.analyze(3, "Please explain the steps in this process.", &[LAYER_REGEX, LAYER_NER]));
    assert_eq!(allowed.action, "ALLOW", "{allowed:?}");

    // The worker refuses an implicit full pipeline: an empty layer list is an error, never an analysis.
    let empty = host.analyze(4, "Contact alex@example.com about the draft.", &[]);
    assert_eq!((empty["ok"].clone(), empty["code"].clone()), (serde_json::json!(false), serde_json::json!("INVALID_ARGUMENT")), "{empty}");

    host.kill();
    assert!(wait_until(Duration::from_secs(20), || !process_alive(worker)), "the Python worker died with the controller");
}
