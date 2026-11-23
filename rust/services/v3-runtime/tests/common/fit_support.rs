//! The replay of a `FitCandidate` golden (`evaluation/generate_v3_runtime_golden.py fit-synthetic` or `fit-real`) through the Rust
//! runtime, shared by the committed synthetic test and the gated real-package test.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use privoke_contracts::proto::experimental_v3 as v3;
use privoke_curriculum::v3::INPUTS;
use privoke_semantic::safetensors::{Tensor, parse};
use privoke_v3_fuzzer::contract::digest;
use privoke_v3_fuzzer::source::Closure;
use privoke_v3_runtime::assets::Admission;
use privoke_v3_runtime::evidence::EVIDENCE_SOURCES;
use privoke_v3_runtime::fit::ScheduleSources;
use privoke_v3_runtime::service::{Runtime, RuntimeParts};
use prost::Message;
use serde_json::Value;

use super::{Scripted, b64, say, serve_package};

/// A checkout in miniature: the four Python files of the evidence and the pinned BC01 inputs at their repository paths.
pub fn checkout(root: &Path) {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    for relative in EVIDENCE_SOURCES {
        let target = root.join(relative);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::copy(repo.join(relative), target).unwrap();
    }
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/privoke-curriculum/tests/fixtures/bc01");
    for (_, relative, _) in INPUTS {
        let target = root.join(relative);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::copy(fixtures.join(Path::new(relative).file_name().unwrap()), target).unwrap();
    }
}

fn relative(a: f64, b: f64) -> f64 {
    (a - b).abs() / b.abs().max(1.0)
}

fn reassemble(chunks: &[v3::Chunk]) -> (Vec<u8>, Vec<u8>) {
    (
        chunks.iter().flat_map(|chunk| chunk.data.clone()).collect(),
        chunks.first().map(|chunk| chunk.manifest_json.clone()).unwrap_or_default(),
    )
}

#[derive(Debug, Default)]
pub struct Counts {
    pub fits: usize,
    pub values: usize,
    pub within: usize,
    pub bitwise: usize,
    pub tensors: usize,
    pub identical_tensors: usize,
    pub candidates_byte_identical: usize,
}

/// The evidence of the two runs: identical where it is a count, a decision or an identity; within tolerance where it is a float.
fn compare_evidence(label: &str, python: &Value, rust: &Value) {
    for key in [
        "schema",
        "model_id",
        "tier",
        "request_id",
        "base",
        "scope",
        "layers",
        "source_commitment",
        "policy",
        "train_wire_sha256",
        "guard_wire_sha256",
        "phases",
        "counts",
        "block_counts",
        "parameter_count",
        "trainable_count",
        "source",
        "serialized_guard_parity",
        "action_harms",
    ] {
        assert_eq!(rust[key], python[key], "{label}: {key}");
    }
    // Torch's float32 backward leaves rounding noise on the key biases (their true gradient is zero) that AdamW turns into a step;
    // the float64 backward leaves none. Those tensors may differ; nothing else may.
    let names = |value: &Value| -> Vec<String> {
        value["changed_tensors"].as_array().unwrap().iter().map(|name| name.as_str().unwrap().to_string()).collect()
    };
    let (rust_changed, python_changed) = (names(rust), names(python));
    let missing: Vec<&String> = python_changed.iter().filter(|name| !rust_changed.contains(name)).collect();
    assert!(rust_changed.iter().all(|name| python_changed.contains(name)), "{label}: Rust changed a tensor Torch did not");
    assert!(missing.iter().all(|name| name.ends_with("attention.self.key.bias")), "{label}: tensors only Torch changed: {missing:?}");
    for group in ["heads", "embeddings", "pooler"] {
        assert_eq!(rust["changes"][group], python["changes"][group], "{label}: {group}");
    }
    assert_eq!(
        rust["changes"]["encoder"].as_u64().unwrap() + missing.len() as u64,
        python["changes"]["encoder"].as_u64().unwrap(),
        "{label}"
    );
    for (a, b) in rust["losses"].as_array().unwrap().iter().zip(python["losses"].as_array().unwrap()) {
        assert!(relative(a.as_f64().unwrap(), b.as_f64().unwrap()) < 1e-4, "{label}: loss {a} against {b}");
    }
    for (a, b) in rust["gradient_trace"].as_array().unwrap().iter().zip(python["gradient_trace"].as_array().unwrap()) {
        assert_eq!(a["step"], b["step"]);
        assert!(
            relative(a["norm_before_clip"].as_f64().unwrap(), b["norm_before_clip"].as_f64().unwrap()) < 1e-4,
            "{label}: {a} against {b}"
        );
        let (x, y) = (a["encoder_nonzero_gradients"].as_f64().unwrap(), b["encoder_nonzero_gradients"].as_f64().unwrap());
        assert!((x - y).abs() <= 0.01 * y.max(1.0), "{label}: encoder nonzero gradients {x} against {y}");
    }
    for guard in ["base_guard", "candidate_guard"] {
        for key in ["joint_correct", "action_correct", "examples"] {
            assert_eq!(rust[guard][key], python[guard][key], "{label}: {guard} {key}");
        }
        for (a, b) in rust[guard]["rows"].as_array().unwrap().iter().zip(python[guard]["rows"].as_array().unwrap()) {
            for key in ["target", "prediction", "action", "target_action", "action_value", "target_action_value", "joint_correct"] {
                assert_eq!(a[key], b[key], "{label}: {guard} {key}: {a} against {b}");
            }
            assert!(
                (a["confidence"].as_f64().unwrap() - b["confidence"].as_f64().unwrap()).abs() <= 1.1e-3,
                "{label}: {guard}: {a} against {b}"
            );
        }
    }
}

fn compare_candidate(label: &str, python: &[u8], rust: &[u8], full: bool, counts: &mut Counts) {
    let (python_tensors, rust_tensors): (BTreeMap<String, Tensor>, BTreeMap<String, Tensor>) =
        (parse(python).unwrap(), parse(rust).unwrap());
    assert_eq!(python_tensors.keys().collect::<Vec<_>>(), rust_tensors.keys().collect::<Vec<_>>(), "{label}: tensor inventory");
    let _ = full;
    let (mut values, mut within, mut worst, mut bitwise, mut identical) = (0usize, 0usize, 0f64, 0usize, 0usize);
    for (name, tensor) in &rust_tensors {
        let reference = &python_tensors[name];
        assert_eq!(tensor.shape, reference.shape, "{label}: {name}");
        let bound = 2.0 * if name.starts_with("heads.") { 1e-3 } else { 2e-5 } * 1.01 + 1e-6;
        for (a, b) in tensor.data.iter().zip(&reference.data) {
            let error = f64::from((a - b).abs());
            assert!(error <= bound, "{label}: {name}: {a} against {b}");
            values += 1;
            within += usize::from(error <= 1e-6);
            bitwise += usize::from(a.to_bits() == b.to_bits());
            worst = worst.max(error);
        }
        identical += usize::from(tensor.sha256 == reference.sha256);
    }
    say(&format!(
        "FitCandidate {label}: candidate {values} values, {within} within 1e-6, {bitwise} bitwise, {identical} of {} tensors byte-identical, max abs error {worst:.3e}",
        rust_tensors.len()
    ));
    assert!(within as f64 >= 0.9 * values as f64, "{label}: only {within} of {values} candidate values within 1e-6");
    counts.values += values;
    counts.within += within;
    counts.bitwise += bitwise;
    counts.tensors += rust_tensors.len();
    counts.identical_tensors += identical;
    if bitwise == values {
        assert_eq!(rust, python, "{label}: bitwise-equal coordinates must publish byte-identical candidates");
        counts.candidates_byte_identical += 1;
    }
}

/// Replay every case of `golden` in order through one runtime over `package` (the base snapshot the oracle fitted from).
pub async fn replay_golden(golden: &Value, package: &Path, model_id: &str, admission: Admission, root: &Path, threads: usize) -> Counts {
    let manifest = b64(golden["base_manifest"].as_str().unwrap());
    let scripted = Scripted::ready();
    let base = serve_package(&scripted, package, model_id, &manifest);
    assert_eq!(base, golden["meta"]["base"].as_str().unwrap());
    let state = tempfile::tempdir().unwrap();
    let parts = RuntimeParts {
        directory: state.path().join("state"),
        threads,
        closure: Closure::Fixed("replay".to_string()),
        admission,
        schedules: ScheduleSources { root: root.to_path_buf(), audience: None },
    };
    let runtime = Arc::new(Runtime::new(parts, scripted.clone()).await.unwrap());
    let mut counts = Counts::default();
    for case in golden["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let request = v3::FitRequest::decode(b64(case["request"].as_str().unwrap()).as_slice()).unwrap();
        assert_eq!(request.layers, vec![4], "every golden request is semantic-only");
        scripted.staged.lock().unwrap().clear();
        let mine = runtime.fit_candidate(request.clone(), Arc::new(AtomicBool::new(true))).await;
        let outcome = &case["outcome"];
        if let Some(abort) = outcome.get("abort") {
            let status = mine.unwrap_err();
            let got = [privoke_v3_runtime::pyerr::code_name(status.code()).to_string(), status.message().to_string()];
            assert_eq!(abort.as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect::<Vec<_>>(), got, "{id}");
            continue;
        }
        if let Some(raised) = outcome.get("raise") {
            let status = mine.unwrap_err();
            assert_eq!(status.code(), tonic::Code::Unknown, "{id}");
            assert_eq!(status.message(), raised.as_str().unwrap(), "{id}");
            continue;
        }
        let response = mine.unwrap_or_else(|status| panic!("{id}: {status:?}"));
        let python_response = v3::FitResponse::decode(b64(outcome["ok"].as_str().unwrap()).as_slice()).unwrap();
        let staged = scripted.staged.lock().unwrap().clone();
        assert_eq!(staged.len(), 2, "{id}: the evidence is staged, then the candidate");
        let (evidence_payload, _) = reassemble(&staged[0]);
        let (candidate_payload, manifest_bytes) = reassemble(&staged[1]);
        assert_eq!(response.evidence_json, evidence_payload, "{id}");
        assert_eq!(response.evidence, digest(&evidence_payload), "{id}");
        assert_eq!(response.candidate, digest(&candidate_payload), "{id}");
        assert_eq!(staged[1][0].sha256, response.candidate);
        let python_staged = case["staged"].as_array().unwrap();
        let (python_evidence, python_candidate) =
            (b64(python_staged[0]["payload"].as_str().unwrap()), b64(python_staged[1]["payload"].as_str().unwrap()));
        assert_eq!(python_response.evidence_json, python_evidence);
        let (python_evidence_json, rust_evidence_json): (Value, Value) =
            (serde_json::from_slice(&python_evidence).unwrap(), serde_json::from_slice(&evidence_payload).unwrap());
        compare_evidence(id, &python_evidence_json, &rust_evidence_json);
        // The candidate manifest: the same canonical metadata, the inventory of its own tensors, the evidence it names.
        let (python_manifest, rust_manifest): (Value, Value) = (
            serde_json::from_slice(&b64(python_staged[1]["manifest"].as_str().unwrap())).unwrap(),
            serde_json::from_slice(&manifest_bytes).unwrap(),
        );
        for key in
            ["schema", "architecture", "model_id", "tier", "parent", "original", "config", "vocab", "source", "parameter_count", "scope"]
        {
            assert_eq!(rust_manifest[key], python_manifest[key], "{id}: manifest {key}");
        }
        assert_eq!(rust_manifest["evidence"], response.evidence.as_str(), "{id}");
        assert_eq!(rust_manifest["blob"], response.candidate.as_str(), "{id}");
        let shapes = |manifest: &Value| -> Vec<(String, Value)> {
            manifest["tensors"].as_object().unwrap().iter().map(|(name, tensor)| (name.clone(), tensor["shape"].clone())).collect()
        };
        assert_eq!(shapes(&rust_manifest), shapes(&python_manifest), "{id}: tensor inventory and shapes");
        compare_candidate(id, &python_candidate, &candidate_payload, id.starts_with("full"), &mut counts);
        // The work directory keeps every wire message of the attempt.
        let work = state.path().join("state/attempts").join(digest(request.request_id.as_bytes()));
        assert_eq!(std::fs::read(work.join("request.pb")).unwrap(), request.encode_to_vec(), "{id}");
        assert_eq!(std::fs::read(work.join("candidate.safetensors")).unwrap(), candidate_payload, "{id}");
        assert_eq!(std::fs::read(work.join("evidence.json")).unwrap(), evidence_payload, "{id}");
        assert_eq!(std::fs::read(work.join("manifest.json")).unwrap(), manifest_bytes, "{id}");
        counts.fits += 1;
    }
    // The `fits` table: the same identities, statuses, failures and request fingerprints (the Python-identical request bytes).
    let rows: Vec<Vec<String>> =
        runtime.store().rows().unwrap().into_iter().map(|row| vec![row.id, row.fingerprint, row.status, row.reason]).collect();
    let expected: Vec<Vec<String>> = golden["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| [0, 1, 2, 4].iter().map(|index| row[*index].as_str().unwrap().to_string()).collect())
        .collect();
    assert_eq!(rows, expected, "the fits table");
    for row in runtime.store().rows().unwrap() {
        assert_eq!(runtime.fit_status(&row.id).unwrap().status, row.status);
    }
    say(&format!(
        "FitCandidate synthetic golden: {} fits replayed, {} cases, {} coordinates ({} within 1e-6, {} bitwise), {} of {} tensors byte-identical, {} candidates byte-identical",
        counts.fits,
        golden["cases"].as_array().unwrap().len(),
        counts.values,
        counts.within,
        counts.bitwise,
        counts.identical_tensors,
        counts.tensors,
        counts.candidates_byte_identical
    ));
    counts
}
