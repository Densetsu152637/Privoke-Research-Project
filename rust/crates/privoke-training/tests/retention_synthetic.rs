//! The retention loops on synthetic inputs (no study data): the hinge direction against finite differences and the whole fit
//! on the seeded Tiny golden model for both policies (determinism, the replay of recorded directions, the shape of the trace,
//! the audit and the metadata). The comparison with the unchanged Python loops on the real balanced release is
//! `retention_release_parity.rs`, which needs the local golden and is skipped when `PRIVOKE_RETENTION_GOLDEN` is unset.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use privoke_training::net::TinyNet;
use privoke_training::objective::{Example, Target};
use privoke_training::retention::{
    Directions, GATE_OBJECTIVE, GATE_POLICY, HINGE_OBJECTIVE, HINGE_POLICY, Reference, Release, compute_directions, hinge_deltas, run,
};
use serde_json::Value;

fn golden() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tiny_training_golden.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn examples(values: &Value, count: usize) -> Vec<Example> {
    let items = values.as_array().unwrap();
    (0..count)
        .map(|i| {
            let row = &items[i % items.len()];
            Example {
                text: row["text"].as_str().unwrap().to_string(),
                target: Target {
                    sensitivity: row["sensitivity"].as_str().unwrap().to_string(),
                    visibility: row["visibility"].as_str().unwrap().to_string(),
                    categories: row["categories"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect(),
                },
                weight: row["weight"].as_f64().unwrap(),
            }
        })
        .collect()
}

fn pack(target: &Target) -> u16 {
    let visibilities = ["P0", "P1", "P2", "P3", "P4", "PU"];
    let categories = ["HEALTH", "POLITICS", "RELIGION", "CRIMINAL", "FINANCIAL", "SEXUAL", "CHILD", "LOCATION", "IDENTITY", "THIRD_PARTY"];
    let sensitivity = u16::from(target.sensitivity.as_bytes()[1] - b'0');
    let visibility =
        [0b00100u16, 0b01000, 0b01100, 0b10000, 0b10100, 0b11100][visibilities.iter().position(|v| *v == target.visibility).unwrap()];
    let bits: u16 = target.categories.iter().map(|c| 1u16 << (5 + categories.iter().position(|name| name == c).unwrap())).sum();
    sensitivity | visibility | bits
}

fn references(margin: f64) -> Vec<Reference> {
    examples(&golden()["examples"], 12)
        .into_iter()
        .filter(|e| e.target.is_sensitive())
        .enumerate()
        .map(|(i, e)| {
            let packed = pack(&e.target);
            Reference { id: format!("r{i}"), text: e.text, gold: packed, original: packed, confidence: 0.9, margin }
        })
        .collect()
}

fn artifact() -> Value {
    golden()["models"]["legacy"].clone()
}

fn release(artifact: &Value, margin: f64) -> Release {
    Release {
        sha256: "c".repeat(64),
        teacher_fingerprint: "d".repeat(64),
        teacher_config: artifact["config"].clone(),
        references: references(margin),
    }
}

#[test]
fn the_hinge_gradient_matches_finite_differences() {
    let artifact = artifact();
    let net = TinyNet::from_artifact(&artifact).unwrap();
    // A margin far above the model's own makes every row active, away from the kink.
    let refs = references(60.0);
    let (deltas, loss, diagnostics) = hinge_deltas(&net, &refs).unwrap();
    assert!(loss > 0.0 && diagnostics.active_rows == refs.len(), "{diagnostics:?}");
    let mut checked = 0;
    for name in [
        "head.sensitivity.weight",
        "head.sensitivity.bias",
        "head.category.weight",
        "head.category.bias",
        "layers.0.ffn.input.bias",
        "token_embedding",
    ] {
        let values = &deltas[name];
        let (index, delta) = values.iter().copied().enumerate().max_by(|a, b| a.1.abs().partial_cmp(&b.1.abs()).unwrap()).unwrap();
        if delta == 0.0 {
            // The winning margin of every row is a category (or a severity): the other head has no gradient.
            continue;
        }
        checked += 1;
        let probe = |shift: f64| {
            let mut params = net.params.clone();
            params.get_mut(name).unwrap().data[index] += shift;
            hinge_deltas(&net.with_params(params).unwrap(), &refs).unwrap().1
        };
        let h = 1e-6;
        let numeric = (probe(h) - probe(-h)) / (2.0 * h);
        assert!((numeric + delta).abs() <= 1e-5 * delta.abs().max(1.0), "{name}[{index}]: finite difference {numeric}, direction {delta}");
    }
    assert!(checked >= 3, "only {checked} tensors had a gradient to check");
    // A reference margin the model already exceeds contributes nothing.
    let (zero, zero_loss, inactive) = hinge_deltas(&net, &references(-60.0)).unwrap();
    assert_eq!((zero_loss, inactive.active_rows), (0.0, 0));
    assert!(zero.values().flatten().all(|v| *v == 0.0));
}

#[test]
fn both_policies_fit_deterministically_and_replay_recorded_directions() {
    let artifact = artifact();
    let golden = golden();
    let (main, guard) = (examples(&golden["examples"], 64), examples(&golden["heldout"], 16));
    for (policy, objective) in [(GATE_POLICY, GATE_OBJECTIVE), (HINGE_POLICY, HINGE_OBJECTIVE)] {
        let release = release(&artifact, 0.5);
        let mut recorded: Vec<Directions> = Vec::new();
        let first = run(&artifact, &release, policy, &main, &guard, &mut |step| {
            let directions = compute_directions(step)?;
            recorded.push(directions.clone());
            Ok(directions)
        })
        .unwrap();
        assert_eq!(recorded.len(), 64);
        assert_eq!(recorded.iter().all(|d| d.auxiliary.is_some()), policy == HINGE_POLICY);
        let mut next = 0;
        let replayed = run(&artifact, &release, policy, &main, &guard, &mut |_| {
            next += 1;
            Ok(recorded[next - 1].clone())
        })
        .unwrap();
        assert_eq!(first.trace, replayed.trace, "{policy}: replaying the recorded directions reproduces the trace");
        let trace: Value = serde_json::from_str(&first.trace).unwrap();
        assert_eq!(trace["policy"], policy);
        assert_eq!(trace["adam"]["steps"].as_array().unwrap().len(), 64);
        assert_eq!(trace["safety"].as_array().unwrap().len(), release.references.len());
        assert_eq!(trace["base_safety"].as_array().unwrap().len(), release.references.len());
        let steps = trace["auxiliary"]["steps"].as_array().unwrap().len();
        assert_eq!(steps, if policy == HINGE_POLICY { 64 } else { 0 });
        assert_eq!(first.metadata["contextual_training_objective"], objective);
        assert_eq!(first.metadata["contextual_training_optimizer"], policy);
        assert_eq!(first.metadata["original_train_retention_manifest_sha256"], release.sha256);
        assert_eq!(first.metadata.len(), 22, "the keys the loop writes: {:?}", first.metadata.keys().collect::<Vec<_>>());
        assert_eq!(first.metrics["examples"], 64.0);
        assert!(first.metrics.contains_key("candidate_heldout_safety_regression_rate"));
        let phases: Vec<&str> = first.executions.iter().map(|(name, _)| name.as_str()).collect();
        let expected: Vec<&str> = if policy == HINGE_POLICY {
            vec![
                "training",
                "base_heldout",
                "candidate_heldout",
                "original_train_hinge",
                "base_original_train_safety",
                "original_train_safety",
            ]
        } else {
            vec!["training", "base_heldout", "candidate_heldout", "base_original_train_safety", "original_train_safety"]
        };
        assert_eq!(phases, expected);
        assert_eq!(first.gradients.len(), first.candidate.len());
        let summary: Value = serde_json::from_str(&first.metadata["original_train_retention_summary_v1"]).unwrap();
        assert_eq!(summary["eligible"].as_u64().unwrap() as usize, release.references.len());
        eprintln!(
            "retention synthetic {policy}: {} violations of {} eligible rows, base loss {:.4}, candidate loss {:.4}",
            summary["violations"],
            summary["eligible"],
            first.metrics["base_train_objective_loss"],
            first.metrics["candidate_train_objective_loss"]
        );
    }
    assert!(run(&artifact, &release(&artifact, 0.5), "other_v1", &main, &guard, &mut compute_directions).is_err());
    assert!(run(&artifact, &release(&artifact, 0.5), GATE_POLICY, &main[..63], &guard, &mut compute_directions).is_err());
}
