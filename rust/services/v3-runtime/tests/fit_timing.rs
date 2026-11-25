//! Wall time of a real-weight `FitCandidate` (stage V3-P of `docs/plans/v3-routine-training.md`), plus the L2 norm of the candidate's
//! change from the base. Timing only: it needs no Python golden. Gated: without `PRIVOKE_V3_TIMING_PACKAGE` it prints why it skipped
//! and passes (CI has none).
//!
//! ```text
//! PRIVOKE_V3_TIMING_PACKAGE   a V3 package directory (manifest.json, config.json, vocab.txt, model.safetensors)
//! PRIVOKE_V3_TIMING_SCOPES    comma list of `heads`, `full` (default both)
//! PRIVOKE_V3_TIMING_STEPS     the frozen budget, 64 (default), 256 or 512
//! PRIVOKE_V3_TIMING_THREADS   the runtime's CPU threads (default 8)
//! PRIVOKE_V3_TIMING_ADMISSION `pinned` (default) or `structural`
//! PRIVOKE_V3_TIMING_OUT       when set, a directory that keeps each candidate (`<scope>.safetensors`) and `timing.json`
//! ```
//!
//! The request is the one the V3 fuzzer builds: the frozen BC01 schedule (seed 20261123) over the committed pinned inputs, the frozen
//! policy, and `[SEMANTIC]` as the only layer. The test asserts the layer list of the request and the layers recorded in the evidence.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use common::fit_support::checkout;
use common::{Scripted, say, serve_package};
use privoke_contracts::proto::experimental_v3 as v3;
use privoke_contracts::proto::v1::DetectionLayer;
use privoke_curriculum::v3::Policy;
use privoke_curriculum::value;
use privoke_semantic::safetensors::parse;
use privoke_v3_fuzzer::contract::{canonical, digest};
use privoke_v3_fuzzer::source::{Closure, Sampler, Schedules, bc01_input_paths, python_source_hashes};
use privoke_v3_runtime::assets::Admission;
use privoke_v3_runtime::fit::ScheduleSources;
use privoke_v3_runtime::service::{Runtime, RuntimeParts};

fn l2(base: &std::collections::BTreeMap<String, privoke_semantic::safetensors::Tensor>, candidate: &[u8]) -> serde_json::Value {
    let candidate = parse(candidate).unwrap();
    let (mut heads, mut encoder, mut changed_heads, mut changed_encoder) = (0f64, 0f64, 0usize, 0usize);
    for (name, tensor) in &candidate {
        let reference = &base[name];
        let squares: f64 = tensor.data.iter().zip(&reference.data).map(|(a, b)| f64::from(a - b).powi(2)).sum();
        if name.starts_with("heads.") {
            heads += squares;
            changed_heads += usize::from(tensor.sha256 != reference.sha256);
        } else {
            encoder += squares;
            changed_encoder += usize::from(tensor.sha256 != reference.sha256);
        }
    }
    serde_json::json!({
        "l2_total": (heads + encoder).sqrt(), "l2_heads_tensors": heads.sqrt(), "l2_non_heads_tensors": encoder.sqrt(),
        "changed_heads_tensors": changed_heads, "changed_non_heads_tensors": changed_encoder
    })
}

#[tokio::test]
async fn a_real_package_fit_is_timed_and_its_change_measured() {
    let Some(package) = std::env::var_os("PRIVOKE_V3_TIMING_PACKAGE").map(PathBuf::from) else {
        say("PENDING: set PRIVOKE_V3_TIMING_PACKAGE to time real-weight fits (not run in CI)");
        return;
    };
    let env = |name: &str, default: &str| std::env::var(name).unwrap_or_else(|_| default.to_string());
    let steps: u32 = env("PRIVOKE_V3_TIMING_STEPS", "64").parse().unwrap();
    let threads: usize = env("PRIVOKE_V3_TIMING_THREADS", "8").parse().unwrap();
    let admission = if env("PRIVOKE_V3_TIMING_ADMISSION", "pinned") == "pinned" { Admission::Pinned } else { Admission::Structural };
    let out = std::env::var_os("PRIVOKE_V3_TIMING_OUT").map(PathBuf::from);
    let manifest = std::fs::read(package.join("manifest.json")).unwrap();
    let model_id = serde_json::from_slice::<serde_json::Value>(&manifest).unwrap()["model_id"].as_str().unwrap().to_string();
    let base_tensors = parse(&std::fs::read(package.join("model.safetensors")).unwrap()).unwrap();

    let root = tempfile::tempdir().unwrap();
    checkout(root.path());
    // The four Python files that the BC01 source record pins (their digests are part of the record).
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    for relative in privoke_curriculum::v3::BC01_SOURCE_FILES {
        let target = root.path().join(relative);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::copy(repo.join(relative), target).unwrap();
    }
    let policy = Policy { steps };
    let hashes = python_source_hashes(root.path(), Sampler::Bc01).unwrap();
    let sources = privoke_curriculum::v3::load_sources_from(&bc01_input_paths(root.path())).unwrap();
    let schedule = Schedules::bc01(sources, hashes).schedule(20261123, policy).unwrap();
    let source_bytes = value::canonical_bytes(&schedule.source).unwrap();
    let policy_bytes = canonical(&policy.to_value()).unwrap();
    let (train_rows, guard_rows) = (schedule.training.len(), schedule.guard.len());

    let mut records = Vec::new();
    for name in env("PRIVOKE_V3_TIMING_SCOPES", "heads,full").split(',') {
        let scope = match name {
            "heads" => v3::Scope::Heads,
            "full" => v3::Scope::FullEncoder,
            other => panic!("unknown scope {other}"),
        };
        let scripted = Scripted::ready();
        let base = serve_package(&scripted, &package, &model_id, &manifest);
        let state = tempfile::tempdir().unwrap();
        let parts = RuntimeParts {
            directory: state.path().join("state"),
            threads,
            closure: Closure::Fixed("timing".to_string()),
            admission,
            schedules: ScheduleSources { root: root.path().to_path_buf(), audience: None },
        };
        let runtime = Arc::new(Runtime::new(parts, scripted.clone()).await.unwrap());
        let request = v3::FitRequest {
            request_id: format!("v3p-{model_id}-{name}-{steps}"),
            model_id: model_id.clone(),
            base: base.clone(),
            scope: scope as i32,
            layers: vec![DetectionLayer::Semantic as i32],
            train: schedule.training.clone(),
            guard: schedule.guard.clone(),
            policy_json: policy_bytes.clone(),
            source_commitment: digest(&source_bytes),
            source_json: source_bytes.clone(),
        };
        assert_eq!(request.layers, vec![4], "semantic-only request, never an empty layer list");
        let started = std::time::Instant::now();
        let response = runtime.fit_candidate(request, Arc::new(AtomicBool::new(true))).await.unwrap_or_else(|status| panic!("{status:?}"));
        let seconds = started.elapsed().as_secs_f64();
        let evidence: serde_json::Value = serde_json::from_slice(&response.evidence_json).unwrap();
        let layers = evidence["layers"].clone();
        assert_eq!(layers, serde_json::json!([4]), "the executed layer");
        let staged = scripted.staged.lock().unwrap().clone();
        let candidate: Vec<u8> = staged[1].iter().flat_map(|chunk| chunk.data.clone()).collect();
        let mut record = l2(&base_tensors, &candidate);
        let guard = |key: &str| (evidence[key]["joint_correct"].clone(), evidence[key]["examples"].clone());
        record["model_id"] = model_id.clone().into();
        record["scope"] = name.into();
        record["steps"] = steps.into();
        record["threads"] = threads.into();
        record["seconds"] = seconds.into();
        record["train_rows"] = train_rows.into();
        record["guard_rows"] = guard_rows.into();
        record["layers"] = layers;
        record["base_guard_joint_correct_of_examples"] = serde_json::json!(guard("base_guard"));
        record["candidate_guard_joint_correct_of_examples"] = serde_json::json!(guard("candidate_guard"));
        record["candidate_sha256"] = response.candidate.clone().into();
        record["evidence_sha256"] = response.evidence.clone().into();
        record["base_sha256"] = base.into();
        say(&format!("V3P TIMING {record}"));
        if let Some(out) = &out {
            std::fs::create_dir_all(out).unwrap();
            std::fs::write(out.join(format!("{model_id}-{name}-{steps}.safetensors")), &candidate).unwrap();
        }
        records.push(record);
    }
    if let Some(out) = &out {
        std::fs::write(out.join(format!("{model_id}-timing-{steps}.json")), serde_json::to_vec_pretty(&records).unwrap()).unwrap();
    }
}
