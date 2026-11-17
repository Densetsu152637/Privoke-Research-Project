//! Cycle replay against the Python oracle (acceptance check 1 of stage 21).
//!
//! `tests/fixtures/fuzzer_cycles_golden.json` is written by `evaluation/generate_fuzzer_golden.py`: the maintained Python
//! `FuzzerTrainingService` ran each cycle with the runtime replaced by the response bytes of a real recorded cycle and the
//! parameter-update service replaced by a fake. Here the Rust engine runs the same requests against scripted backends
//! that serve the same bytes, and everything observable must be identical:
//!
//! * every wire message the cycle sends (the gradient request, the receipt lookup, the publication), byte for byte and in
//!   the same order;
//! * the cycle's response, or its abort code and message;
//! * the retained evidence files and the reservation rows, byte for byte; the curriculum database, row for row.
//!
//! The G5 normalisation (`tests/conformance/normalization.toml`) lists timestamps and server-generated identifiers; none
//! occurs in these records, so the comparison is exact.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use common::{FULL_PATH, HEADS_PATH, STATUS_PATH, SUBMIT_PATH, ScriptedRuntime, ScriptedUpdates, Wire, b64, read_golden, repo_root};
use privoke_contracts::proto::v1::{FuzzerTrainingRequest, FuzzerTrainingResponse};
use privoke_fuzzer::config::{FuzzerConfig, Scope};
use privoke_fuzzer::cycle::Engine;
use prost::Message;
use serde_json::Value;

fn code_name(code: tonic::Code) -> String {
    let name = match code {
        tonic::Code::FailedPrecondition => "FAILED_PRECONDITION",
        tonic::Code::InvalidArgument => "INVALID_ARGUMENT",
        tonic::Code::Unavailable => "UNAVAILABLE",
        tonic::Code::AlreadyExists => "ALREADY_EXISTS",
        tonic::Code::ResourceExhausted => "RESOURCE_EXHAUSTED",
        other => return format!("{other:?}"),
    };
    name.to_string()
}

fn collect_evidence(directory: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let root = directory.join("training-cycles");
    let mut pending = vec![root.clone()];
    while let Some(folder) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&folder) else { continue };
        for entry in entries.map(Result::unwrap) {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "json") {
                let relative = path.strip_prefix(directory).unwrap().to_string_lossy().replace('\\', "/");
                out.insert(relative, std::fs::read_to_string(&path).unwrap());
            }
        }
    }
    out
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

fn curriculum_rows(path: &Path) -> (Vec<(String, String, Value)>, Vec<(String, i64)>) {
    let connection = rusqlite::Connection::open(path).unwrap();
    let mut batches = connection.prepare("SELECT identity, fingerprint, allocation FROM batches ORDER BY identity").unwrap();
    let batches: Vec<(String, String, Value)> = batches
        .query_map([], |row| {
            let text: String = row.get(2)?;
            Ok((row.get(0)?, row.get(1)?, serde_json::from_str(&text).unwrap()))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let mut cursors = connection.prepare("SELECT identity, position FROM cursors ORDER BY identity").unwrap();
    let cursors = cursors.query_map([], |row| Ok((row.get(0)?, row.get(1)?))).unwrap().map(Result::unwrap).collect();
    (batches, cursors)
}

struct Counts {
    cycles: usize,
    ok: usize,
    aborted: usize,
    files: usize,
    reservations: usize,
    curriculum_rows: usize,
}

async fn replay(sequence: &Value, counts: &mut Counts) {
    let label = sequence["label"].as_str().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let dump = directory.path().join("dump");
    let state = directory.path().join("curriculum.sqlite3");
    let env: BTreeMap<String, String> =
        sequence["env"].as_object().unwrap().iter().map(|(key, value)| (key.clone(), value.as_str().unwrap().to_string())).collect();
    let curriculum = label.contains("curriculum");
    let manifest = repo_root().join("rust/crates/privoke-curriculum/tests/fixtures/curriculum/manifest.json");
    let config = FuzzerConfig::from_lookup(|name| match name {
        "PRIVOKE_FUZZER_DUMP_DIR" => Some(dump.to_string_lossy().to_string()),
        "FUZZ_CURRICULUM_MANIFEST_PATH" if curriculum => Some(manifest.to_string_lossy().to_string()),
        "FUZZ_CURRICULUM_STATE_PATH" if curriculum => Some(state.to_string_lossy().to_string()),
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
        *updates.ack.lock().unwrap() = Box::new(move |_| privoke_contracts::proto::v1::ParameterUpdateAck::decode(ack.as_slice()).unwrap());
        wire.take();
        let scope = if cycle["scope"] == "full_encoder" { Scope::FullEncoder } else { Scope::Heads };
        let request = FuzzerTrainingRequest::decode(b64(cycle["request"].as_str().unwrap()).as_slice()).unwrap();
        let outcome = engine.run_training_cycle(request, scope).await;

        // The wire: same requests, same bytes, same order.
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
        for ((path, bytes), (_, want)) in observed.iter().zip(&expected) {
            assert!(bytes == want, "{context}: {path} request bytes differ ({} against {})", bytes.len(), want.len());
        }
        assert!(matches!(observed_paths.first(), Some(&STATUS_PATH)), "{context}: the receipt lookup comes first");
        assert!(observed_paths.iter().all(|path| [STATUS_PATH, SUBMIT_PATH, HEADS_PATH, FULL_PATH].contains(path)));

        // The outcome.
        match (&cycle["outcome"]["ok"], &cycle["outcome"]["abort"]) {
            (Value::String(response), _) => {
                let response_bytes = outcome.unwrap_or_else(|status| panic!("{context}: aborted {status}")).encode_to_vec();
                assert!(response_bytes == b64(response), "{context}: response bytes differ");
                let _ = FuzzerTrainingResponse::decode(response_bytes.as_slice()).unwrap();
                counts.ok += 1;
            }
            (_, Value::Array(abort)) => {
                let status = outcome.expect_err(&context);
                assert_eq!(
                    (code_name(status.code()), status.message().to_string()),
                    (abort[0].as_str().unwrap().to_string(), abort[1].as_str().unwrap().to_string()),
                    "{context}"
                );
                counts.aborted += 1;
            }
            other => panic!("{context}: unreadable golden outcome {other:?}"),
        }
        counts.cycles += 1;
    }

    // The durable state: evidence files byte for byte, reservation rows, curriculum rows.
    let evidence = collect_evidence(&dump);
    let golden_evidence: BTreeMap<String, String> =
        sequence["evidence"].as_object().unwrap().iter().map(|(path, text)| (path.clone(), text.as_str().unwrap().to_string())).collect();
    assert_eq!(evidence.keys().collect::<Vec<_>>(), golden_evidence.keys().collect::<Vec<_>>(), "{label}: evidence file names");
    for (path, text) in &golden_evidence {
        assert!(&evidence[path] == text, "{label}: {path} differs\nrust:   {}\npython: {text}", evidence[path]);
    }
    counts.files += evidence.len();
    let golden_reservations: Vec<(String, String)> = sequence["reservations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| (row[0].as_str().unwrap().to_string(), row[1].as_str().unwrap().to_string()))
        .collect();
    assert_eq!(reservations(&dump), golden_reservations, "{label}: reservations");
    counts.reservations += golden_reservations.len();
    if curriculum {
        let (batches, cursors) = curriculum_rows(&state);
        let golden = &sequence["curriculum"];
        let golden_batches: Vec<(String, String, Value)> = golden["batches"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| (row[0].as_str().unwrap().to_string(), row[1].as_str().unwrap().to_string(), row[2].clone()))
            .collect();
        let golden_cursors: Vec<(String, i64)> = golden["cursors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| (row[0].as_str().unwrap().to_string(), row[1].as_i64().unwrap()))
            .collect();
        assert_eq!(batches, golden_batches, "{label}: curriculum batches");
        assert_eq!(cursors, golden_cursors, "{label}: curriculum cursors");
        counts.curriculum_rows += batches.len() + cursors.len();
    }
}

#[tokio::test]
async fn cycles_replay_identically_to_the_python_oracle() {
    let golden = read_golden();
    assert_eq!(golden["schema"], 1);
    let sequences = golden["sequences"].as_array().unwrap();
    assert!(sequences.len() >= 3, "the golden holds the recorded and the curriculum sequences");
    let mut counts = Counts { cycles: 0, ok: 0, aborted: 0, files: 0, reservations: 0, curriculum_rows: 0 };
    for sequence in sequences {
        replay(sequence, &mut counts).await;
    }
    assert!(counts.ok >= 3 && counts.aborted >= 1, "accepted and rejected cycles are both replayed");
    println!(
        "fuzzer cycle replay: {} sequences, {} cycles ({} accepted or replayed, {} refused), {} evidence files, {} reservation rows, {} curriculum rows: all identical",
        sequences.len(),
        counts.cycles,
        counts.ok,
        counts.aborted,
        counts.files,
        counts.reservations,
        counts.curriculum_rows
    );
}
