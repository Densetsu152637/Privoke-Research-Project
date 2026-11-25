//! The synthetic fixture through the real stage 11 worker pool (the bundled CPython and spaCy), instead of a replay.
//!
//! Needs the bundle built by `rust/services/spacy-worker/tools/build_bundle.py`. Set `PRIVOKE_SPACY_BUNDLE` to its
//! directory; without it the test reports that it skipped and passes, so `cargo test --workspace` needs no Python.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use privoke_spacy::{PoolConfig, SpacyPool};
use serde_json::Value;

fn worker_path() -> Option<PathBuf> {
    let bundle = PathBuf::from(std::env::var_os("PRIVOKE_SPACY_BUNDLE")?);
    let name = if cfg!(windows) { "privoke-spacy-worker.exe" } else { "privoke-spacy-worker" };
    Some(bundle.join(name))
}

#[tokio::test(flavor = "multi_thread")]
async fn the_real_worker_reproduces_every_recorded_result() {
    let Some(worker) = worker_path() else {
        eprintln!("PRIVOKE_SPACY_BUNDLE is not set: the real-worker parity test is skipped");
        return;
    };
    let encoded = include_str!("fixtures/synthetic_golden.b64");
    let bytes = base64::engine::general_purpose::STANDARD.decode(encoded.trim()).expect("fixture is base64");
    let fixture: Value = serde_json::from_slice(&bytes).expect("fixture is JSON");

    let mut config = PoolConfig::new(worker);
    config.workers = 2;
    let pool = SpacyPool::start(config).expect("pool starts");
    pool.wait_ready(Duration::from_secs(120)).await.expect("worker is ready");
    let lexicon: Arc<HashSet<String>> = Arc::new(pool.lemma_index().await.expect("lemma index").iter().cloned().collect());
    assert!(lexicon.len() > 10_000, "the model's lemma index is a general English word list");

    let mut failures = Vec::new();
    let mut runs = 0;
    for row in fixture["rows"].as_array().expect("rows") {
        let report = common::check_row(&pool, lexicon.clone(), "en_core_web_sm", row, false).await;
        runs += report.layer.len() + report.pattern.len();
        for (name, same) in report.layer.iter().chain(report.pattern.iter()) {
            if !same {
                failures.push(format!("row {} {name}", row["id"]));
            }
        }
        failures.extend(report.diffs);
    }
    assert!(
        failures.is_empty(),
        "{} differences, first:\n{}",
        failures.len(),
        failures.iter().take(6).cloned().collect::<Vec<_>>().join("\n")
    );
    assert!(runs > 1_000);
    pool.shutdown().await;
}
