//! The FULL Adam policy cycle against the Python oracle (RUST-S21F item 1).
//!
//! `tests/fixtures/full_adam_cycles_golden.json` is written by `evaluation/generate_full_adam_cycle_golden.py`: the maintained
//! Python `FuzzerTrainingService` ran policy-admitted FULL projected Adam cycles with the runtime replaced by the response bytes
//! of retained cycles of the iterative fuzzer study and the parameter-update service replaced by a fake. Here the Rust engine runs
//! the same requests against scripted backends and everything observable must be identical:
//!
//! * every wire message (the receipt lookup, the gradient request, the publication), byte for byte and in order;
//! * the admission header and the deadline class of every runtime call;
//! * the cycle's response, or its abort code and message;
//! * every file of the durable dump (the physical attempt reservation, the attempt record, its admission verdict, a reservation
//!   rejection, the complete cycle records) and the reservation rows, byte for byte after the normalisation of timestamps and
//!   of the dump path (timestamp file names become ordinals, the dump directory becomes `<DUMP>`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::{FULL_PATH, HEADS_PATH, STATUS_PATH, SUBMIT_PATH, ScriptedRuntime, ScriptedUpdates, Wire, b64, repo_root};
use privoke_contracts::proto::v1::{
    ComputeSemanticGradientsRequest, FuzzerTrainingRequest, FuzzerTrainingResponse, ParameterUpdateRequest, ParameterUpdateStatusRequest,
};
use privoke_fuzzer::config::{FuzzerConfig, Scope};
use privoke_fuzzer::cycle::Engine;
use prost::Message;
use serde_json::Value;

fn code_name(code: tonic::Code) -> String {
    match code {
        tonic::Code::FailedPrecondition => "FAILED_PRECONDITION".to_string(),
        tonic::Code::InvalidArgument => "INVALID_ARGUMENT".to_string(),
        tonic::Code::Unavailable => "UNAVAILABLE".to_string(),
        tonic::Code::Unknown => "UNKNOWN".to_string(),
        tonic::Code::AlreadyExists => "ALREADY_EXISTS".to_string(),
        other => format!("{other:?}"),
    }
}

fn is_timestamp(name: &str) -> bool {
    name.len() >= 15 && name.ends_with(".json") && name[..name.len() - 5].bytes().all(|byte| byte.is_ascii_digit())
}

fn walk(directory: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else { return };
    for entry in entries.map(Result::unwrap) {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, files);
        } else if !path.file_name().unwrap().to_string_lossy().starts_with("training-reservations.sqlite3") {
            files.push(path);
        }
    }
}

/// Every file of the dump, keyed by its path relative to the dump with timestamp names as ordinals, with the dump path replaced.
fn normalised_dump(dump: &Path) -> BTreeMap<String, String> {
    let mut files = Vec::new();
    walk(dump, &mut files);
    files.sort();
    let mut keys: BTreeMap<PathBuf, String> = BTreeMap::new();
    let mut folders: Vec<PathBuf> = files.iter().map(|path| path.parent().unwrap().to_path_buf()).collect();
    folders.sort();
    folders.dedup();
    for folder in folders {
        let mut stamped: Vec<&PathBuf> =
            files.iter().filter(|path| path.parent() == Some(folder.as_path()) && is_timestamp(&path.file_name().unwrap().to_string_lossy())).collect();
        stamped.sort();
        for (ordinal, path) in stamped.into_iter().enumerate() {
            keys.insert(path.clone(), format!("{ordinal:04}.json"));
        }
    }
    let relative = |path: &PathBuf| -> String {
        let parent = path.parent().unwrap().strip_prefix(dump).unwrap().to_string_lossy().replace('\\', "/");
        let name = keys.get(path).cloned().unwrap_or_else(|| path.file_name().unwrap().to_string_lossy().to_string());
        if parent.is_empty() { name } else { format!("{parent}/{name}") }
    };
    let texts: Vec<(PathBuf, String, String)> =
        files.iter().map(|path| (path.clone(), relative(path), std::fs::read_to_string(path).unwrap())).collect();
    let mut result = BTreeMap::new();
    for (_, key, text) in &texts {
        let mut text = text.clone();
        for (other, other_key, _) in &texts {
            text = text.replace(&other.to_string_lossy().to_string(), &format!("<DUMP>/{other_key}"));
        }
        result.insert(key.clone(), text);
    }
    result
}

fn reservations(directory: &Path) -> Vec<(String, String)> {
    let path = directory.join("training-reservations.sqlite3");
    if !path.exists() {
        return Vec::new();
    }
    let connection = rusqlite::Connection::open(path).unwrap();
    let mut statement = connection.prepare("SELECT identity, fingerprint FROM requests ORDER BY identity").unwrap();
    statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?))).unwrap().map(Result::unwrap).collect()
}

#[tokio::test]
async fn the_full_adam_cycles_replay_identically_to_the_python_oracle() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/full_adam_cycles_golden.json");
    let golden: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(golden["schema"], 1);
    let (mut cycles, mut accepted, mut refused, mut wire_messages, mut calls_checked, mut files_checked) = (0, 0, 0, 0, 0, 0);
    for sequence in golden["sequences"].as_array().unwrap() {
        let label = sequence["label"].as_str().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let dump = directory.path().join("dump");
        let taxonomy = repo_root().join("rust/crates/privoke-curriculum/tests/fixtures/bc01/taxonomy-coverage-v1.json");
        let env: BTreeMap<String, String> =
            sequence["env"].as_object().unwrap().iter().map(|(key, value)| (key.clone(), value.as_str().unwrap().to_string())).collect();
        let config = FuzzerConfig::from_lookup(|name| match name {
            "PRIVOKE_FUZZER_DUMP_DIR" => Some(dump.to_string_lossy().to_string()),
            "FUZZ_PROMPT_DATASET_PATH" => Some(taxonomy.to_string_lossy().to_string()),
            other => env.get(other).cloned(),
        })
        .unwrap();
        let wire = Arc::new(Wire::default());
        let runtime = Arc::new(ScriptedRuntime::new(wire.clone(), |_, _| Err(tonic::Status::internal("no cycle is running"))));
        let updates = Arc::new(ScriptedUpdates::new(wire.clone(), |_| Default::default()));
        let engine = Engine::new(config, runtime.clone(), updates.clone());
        for (index, cycle) in sequence["cycles"].as_array().unwrap().iter().enumerate() {
            let context = format!("{label} cycle {index}");
            let recorded = b64(cycle["runtime_response"].as_str().unwrap());
            let ack = b64(cycle["ack"].as_str().unwrap());
            *runtime.answer.lock().unwrap() =
                Box::new(move |_, _| Ok(privoke_contracts::proto::v1::ComputeSemanticGradientsResponse::decode(recorded.as_slice()).unwrap()));
            *updates.ack.lock().unwrap() =
                Box::new(move |_| privoke_contracts::proto::v1::ParameterUpdateAck::decode(ack.as_slice()).unwrap());
            wire.take();
            wire.take_options();
            let scope = if cycle["scope"] == "full_encoder" { Scope::FullEncoder } else { Scope::Heads };
            let request = FuzzerTrainingRequest::decode(b64(cycle["request"].as_str().unwrap()).as_slice()).unwrap();
            let outcome = engine.run_training_cycle(request, scope).await;

            let observed = wire.take();
            let expected: Vec<(&str, Vec<u8>)> = cycle["calls"]
                .as_array()
                .unwrap()
                .iter()
                .map(|path| {
                    let path = path.as_str().unwrap();
                    let key = match path {
                        STATUS_PATH => "status_request",
                        SUBMIT_PATH => "submit_request",
                        _ => "runtime_request",
                    };
                    (path, b64(cycle[key].as_str().unwrap()))
                })
                .collect();
            let observed_paths: Vec<&str> = observed.iter().map(|(path, _)| path.as_str()).collect();
            assert_eq!(observed_paths, expected.iter().map(|(path, _)| *path).collect::<Vec<_>>(), "{context}: call order");
            assert!(observed_paths.iter().all(|path| [STATUS_PATH, SUBMIT_PATH, HEADS_PATH, FULL_PATH].contains(path)));
            for ((path, bytes), (_, want)) in observed.iter().zip(&expected) {
                let normalised = match path.as_str() {
                    STATUS_PATH => ParameterUpdateStatusRequest::decode(want.as_slice()).unwrap().encode_to_vec(),
                    SUBMIT_PATH => ParameterUpdateRequest::decode(want.as_slice()).unwrap().encode_to_vec(),
                    _ => ComputeSemanticGradientsRequest::decode(want.as_slice()).unwrap().encode_to_vec(),
                };
                assert!(bytes == &normalised, "{context}: {path} request bytes differ ({} against {})", bytes.len(), normalised.len());
                wire_messages += 1;
            }

            // The admission header and the deadline class of each runtime call.
            let options = wire.take_options();
            let runtime_calls = cycle["runtime_calls"].as_array().unwrap();
            assert_eq!(options.len(), runtime_calls.len(), "{context}: runtime calls");
            for (option, call) in options.iter().zip(runtime_calls) {
                let header = call["metadata"].as_array().unwrap();
                assert!(header.len() <= 1, "{context}: one admission header at most");
                assert_eq!(
                    option.header.as_deref(),
                    header.first().map(|pair| pair[1].as_str().unwrap()),
                    "{context}: the admission header"
                );
                if let Some(pair) = header.first() {
                    assert_eq!(pair[0], "x-privoke-training-admission-v1");
                }
                assert_eq!(option.long_deadline, call["timeout"].as_f64() == Some(180.0), "{context}: the deadline class");
                calls_checked += 1;
            }

            match (&cycle["outcome"]["ok"], &cycle["outcome"]["abort"]) {
                (Value::String(response_text), _) => {
                    let response = outcome.unwrap_or_else(|status| panic!("{context}: aborted {status}"));
                    assert_eq!(response, FuzzerTrainingResponse::decode(b64(response_text).as_slice()).unwrap(), "{context}: response");
                    accepted += 1;
                }
                (_, Value::Array(abort)) => {
                    let status = outcome.expect_err(&context);
                    assert_eq!(
                        (code_name(status.code()), status.message().to_string()),
                        (abort[0].as_str().unwrap().to_string(), abort[1].as_str().unwrap().to_string()),
                        "{context}"
                    );
                    refused += 1;
                }
                other => panic!("{context}: unreadable golden outcome {other:?}"),
            }
            cycles += 1;
        }

        let files = normalised_dump(&dump);
        let golden_files: BTreeMap<String, String> =
            sequence["files"].as_object().unwrap().iter().map(|(path, text)| (path.clone(), text.as_str().unwrap().to_string())).collect();
        assert_eq!(files.keys().collect::<Vec<_>>(), golden_files.keys().collect::<Vec<_>>(), "{label}: dump file names");
        for (path, text) in &golden_files {
            assert!(&files[path] == text, "{label}: {path} differs\nrust:   {}\npython: {text}", files[path]);
        }
        files_checked += files.len();
        let golden_reservations: Vec<(String, String)> = sequence["reservations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| (row[0].as_str().unwrap().to_string(), row[1].as_str().unwrap().to_string()))
            .collect();
        assert_eq!(reservations(&dump), golden_reservations, "{label}: reservations");
    }
    assert!(accepted >= 1 && refused >= 5, "accepted and refused cycles are both replayed");
    eprintln!(
        "fuzzer FULL Adam cycle replay: {cycles} cycles ({accepted} accepted, {refused} refused), {wire_messages} wire messages, {calls_checked} runtime calls (header and deadline), {files_checked} dump files: all identical to the Python oracle"
    );
}
