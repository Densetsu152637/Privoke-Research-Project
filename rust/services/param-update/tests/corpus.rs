//! Parity with the Python service on the stage 0 update sequence (`tests/conformance/update_sequence.json`).
//!
//! The replay runs the bootstrap and the 19 recorded update requests (as protobuf bytes) through the Rust engine with the
//! recorded one-tick-per-call clock, and compares every artifact byte (CRLF folded to LF, which is how the corpus hashes
//! the Python text-mode writer), acknowledgement, error text, receipt and audit line. Receipts and audit lines carry no
//! timestamp or generated id, so the G5 normalisation of `tests/conformance/normalization.toml` replaces nothing here:
//! they are compared exactly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use base64::Engine as _;
use common::{config_for, copy_model, repo_root};
use privoke_contracts::digest::sha256_hex;
use privoke_contracts::fingerprint::parameter_fingerprint;
use privoke_contracts::proto::v1::{ParameterUpdateRequest, ParameterUpdateStatusRequest};
use privoke_param_update::artifact_io;
use privoke_param_update::bootstrap::{PREPARATION_CODE_REVISION, bootstrap_model};
use privoke_param_update::engine::{Clock, Engine, no_hook};
use privoke_param_update::error::Failure;
use privoke_param_update::policy::DriftPolicy;
use privoke_param_update::receipts::ReceiptStore;
use prost::Message;
use serde_json::Value;

fn corpus() -> Value {
    let text = std::fs::read_to_string(repo_root().join("tests/conformance/update_sequence.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn sha256_lf(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap();
    let text = String::from_utf8(bytes).unwrap().replace("\r\n", "\n");
    sha256_hex(text.as_bytes())
}

fn code_name(failure: &Failure) -> &'static str {
    match failure {
        Failure::Invalid(_) => "INVALID_ARGUMENT",
        Failure::Precondition(_) => "FAILED_PRECONDITION",
        Failure::AlreadyExists(_) => "ALREADY_EXISTS",
        Failure::Internal { .. } => "INTERNAL",
    }
}

fn decode<M: Message + Default>(step: &Value) -> M {
    let bytes = base64::engine::general_purpose::STANDARD.decode(step["request_b64"].as_str().unwrap()).unwrap();
    M::decode(bytes.as_slice()).unwrap()
}

/// A model after the recorded bootstrap, an engine on the recorded clock, and the paths they use.
struct Replay {
    _directory: tempfile::TempDir,
    model: PathBuf,
    audit: PathBuf,
    engine: Engine,
}

fn start(corpus: &Value, drift: DriftPolicy) -> Replay {
    let directory = tempfile::tempdir().unwrap();
    let model = copy_model(directory.path(), "privoke-balanced");
    let audit = directory.path().join("updates.jsonl");
    let ticks = Arc::new(AtomicI64::new(corpus["clock_start"].as_i64().unwrap()));
    let clock: Clock = {
        let ticks = ticks.clone();
        Arc::new(move || ticks.fetch_add(1, Ordering::SeqCst) + 1)
    };
    let bootstrap = &corpus["base_artifact"]["bootstrap"];
    assert_eq!(bootstrap["source_revision"].as_str().unwrap(), PREPARATION_CODE_REVISION);
    bootstrap_model(&model, &audit, "privoke-balanced", bootstrap["max_tokens"].as_i64().unwrap(), &clock, &no_hook()).unwrap();
    let mut config = config_for(directory.path(), &model, corpus["expected_model_id"].as_str().unwrap(), drift);
    config.max_abs_gradient = corpus["max_abs_gradient"].as_f64().unwrap();
    let engine = Engine::new(config, clock, no_hook()).unwrap();
    Replay { _directory: directory, model, audit, engine }
}

#[test]
fn the_bootstrap_reproduces_the_python_artifact_byte_for_byte() {
    let corpus = corpus();
    let replay = start(&corpus, DriftPolicy::Off);
    let initial = &corpus["initial_after_bootstrap"];
    let loaded = artifact_io::load(&replay.model).unwrap();
    assert_eq!(loaded.typed.version, initial["version"].as_str().unwrap());
    assert_eq!(loaded.typed.checksum, initial["checksum"].as_str().unwrap());
    assert_eq!(loaded.typed.generated_at_unix, initial["generated_at_unix"].as_i64().unwrap());
    assert_eq!(sha256_lf(&replay.model), initial["sha256_lf"].as_str().unwrap());
    let trainable: Vec<&str> =
        loaded.typed.parameters.iter().filter(|(_, tensor)| tensor.trainable).map(|(name, _)| name.as_str()).collect();
    let recorded: Vec<&str> = initial["trainable"].as_array().unwrap().iter().map(|name| name.as_str().unwrap()).collect();
    assert_eq!(trainable, recorded);
}

#[test]
fn the_update_sequence_reproduces_every_artifact_acknowledgement_and_error() {
    let corpus = corpus();
    let replay = start(&corpus, DriftPolicy::Off);
    let steps = corpus["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 19);
    for step in steps {
        let label = step["label"].as_str().unwrap();
        let before = sha256_lf(&replay.model);
        let request: ParameterUpdateRequest = decode(step);
        let outcome = replay.engine.submit(&request);
        match (&outcome, step["status"].as_str().unwrap()) {
            (Ok(ack), "OK") => {
                let recorded = &step["ack"];
                assert_eq!(ack.accepted, recorded["accepted"].as_bool().unwrap(), "{label}");
                assert_eq!(ack.model_id, recorded["model_id"].as_str().unwrap(), "{label}");
                assert_eq!(ack.applied_version, recorded["applied_version"].as_str().unwrap(), "{label}");
                assert_eq!(ack.message, recorded["message"].as_str().unwrap(), "{label}");
            }
            (Err(failure), status) => {
                assert_eq!(code_name(failure), status, "{label}: {failure}");
                assert_eq!(failure.message(), step["details"].as_str().unwrap(), "{label}");
            }
            (Ok(_), status) => panic!("{label}: accepted, recorded {status}"),
        }
        let after = &step["artifact_after"];
        let loaded = artifact_io::load(&replay.model).unwrap();
        assert_eq!(loaded.typed.version, after["version"].as_str().unwrap(), "{label}");
        assert_eq!(loaded.typed.checksum, after["checksum"].as_str().unwrap(), "{label}");
        assert_eq!(loaded.typed.generated_at_unix, after["generated_at_unix"].as_i64().unwrap(), "{label}");
        let now = sha256_lf(&replay.model);
        assert_eq!(now, after["sha256_lf"].as_str().unwrap(), "{label}: published bytes");
        assert_eq!(now != before, after["changed"].as_bool().unwrap(), "{label}: changed");
    }

    // The final artifact, its metadata and its tensor fingerprint.
    let recorded = &corpus["final"];
    let loaded = artifact_io::load(&replay.model).unwrap();
    assert_eq!(sha256_lf(&replay.model), recorded["sha256_lf"].as_str().unwrap());
    let metadata: serde_json::Map<String, Value> =
        loaded.typed.metadata().iter().map(|(key, value)| (key.clone(), Value::String(value.clone()))).collect();
    assert_eq!(Value::Object(metadata), recorded["metadata"]);
    let values: BTreeMap<String, Vec<f64>> =
        loaded.typed.parameters.iter().map(|(name, tensor)| (name.clone(), tensor.values.clone())).collect();
    let shapes: BTreeMap<String, Vec<u64>> = loaded
        .typed
        .parameters
        .iter()
        .map(|(name, tensor)| (name.clone(), tensor.shape.iter().map(|size| u64::from(*size)).collect()))
        .collect();
    assert_eq!(parameter_fingerprint(&values, Some(&shapes)).unwrap(), recorded["parameters_fingerprint"].as_str().unwrap());

    // The receipts, key for key.
    let store = ReceiptStore::begin(&replay.audit).unwrap();
    let stored = store.all().unwrap();
    let expected = corpus["receipts"].as_array().unwrap();
    assert_eq!(stored.len(), expected.len());
    for ((key, text), recorded) in stored.iter().zip(expected) {
        assert_eq!(key, recorded["key"].as_str().unwrap());
        let parsed: Value = serde_json::from_str(text).unwrap();
        assert_eq!(parsed, recorded["receipt"]);
    }
    drop(store);

    // The audit file: one line per accepted update.
    let audit: Vec<Value> =
        std::fs::read_to_string(&replay.audit).unwrap().lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    assert_eq!(Value::Array(audit), corpus["audit_lines"]);

    // Receipt lookups, including the three refusals.
    for lookup in corpus["status_lookups"].as_array().unwrap() {
        let label = lookup["label"].as_str().unwrap();
        let request: ParameterUpdateStatusRequest = decode(lookup);
        match (replay.engine.status(&request), lookup["status"].as_str().unwrap()) {
            (Ok(status), "OK") => {
                let recorded = &lookup["response"];
                let ack = status.ack.clone().unwrap_or_default();
                assert_eq!(status.found, recorded["found"].as_bool().unwrap(), "{label}");
                assert_eq!(ack.accepted, recorded["ack_accepted"].as_bool().unwrap(), "{label}");
                assert_eq!(ack.model_id, recorded["ack_model_id"].as_str().unwrap(), "{label}");
                assert_eq!(ack.applied_version, recorded["ack_applied_version"].as_str().unwrap(), "{label}");
                assert_eq!(ack.message, recorded["ack_message"].as_str().unwrap(), "{label}");
                assert_eq!(status.base_version, recorded["base_version"].as_str().unwrap(), "{label}");
                assert_eq!(i64::from(status.prompts_generated), recorded["prompts_generated"].as_i64().unwrap(), "{label}");
            }
            (Err(failure), status) => {
                assert_eq!(code_name(&failure), status, "{label}");
                assert_eq!(failure.message(), lookup["details"].as_str().unwrap(), "{label}");
            }
            (Ok(_), status) => panic!("{label}: answered, recorded {status}"),
        }
    }

    let health = replay.engine.health();
    assert_eq!(health.service, corpus["health"]["service"].as_str().unwrap());
    assert_eq!(health.status, corpus["health"]["status"].as_str().unwrap());
}

/// The default drift policy changes no outcome of the recorded sequence: every accepted update stays accepted at the
/// recorded version, every rejection keeps its status and text. (Artifact bytes differ by the one drift record.)
#[test]
fn the_default_drift_bounds_reject_no_update_of_the_recorded_sequence() {
    let corpus = corpus();
    let replay = start(&corpus, DriftPolicy::default());
    for step in corpus["steps"].as_array().unwrap() {
        let label = step["label"].as_str().unwrap();
        let request: ParameterUpdateRequest = decode(step);
        match (replay.engine.submit(&request), step["status"].as_str().unwrap()) {
            (Ok(ack), "OK") => assert_eq!(ack.applied_version, step["ack"]["applied_version"].as_str().unwrap(), "{label}"),
            (Err(failure), status) => {
                assert_eq!(code_name(&failure), status, "{label}: {failure}");
                assert_eq!(failure.message(), step["details"].as_str().unwrap(), "{label}");
            }
            (Ok(_), status) => panic!("{label}: accepted, recorded {status}"),
        }
    }
    let loaded = artifact_io::load(&replay.model).unwrap();
    assert!(loaded.typed.metadata().contains_key(privoke_param_update::receipts::DRIFT_METADATA_KEY));
}
