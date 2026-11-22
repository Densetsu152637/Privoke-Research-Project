//! The window loop on synthetic inputs (no study data): the schedule and identities against Python's values, the component
//! hinge against finite differences, the checkpoint rules, and the whole loop on the seeded Tiny golden model (determinism
//! and the replay of recorded directions). The comparison with the unchanged Python loop on a real release is
//! `window_release_parity.rs`, which needs the local golden and is skipped when `PRIVOKE_WINDOW_GOLDEN` is unset.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use privoke_training::net::TinyNet;
use privoke_training::window::{
    Checkpoint, Directions, Entry, Reference, Release, Row, Window, action_value, array_identity, checkpoint_counts, component_deltas,
    component_predicates, compute_directions, derived_seed, run, schedule, select,
};
use serde_json::Value;

const CATEGORIES: [&str; 10] =
    ["HEALTH", "POLITICS", "RELIGION", "CRIMINAL", "FINANCIAL", "SEXUAL", "CHILD", "LOCATION", "IDENTITY", "THIRD_PARTY"];
const VISIBILITIES: [&str; 6] = ["P0", "P1", "P2", "P3", "P4", "PU"];

fn golden() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tiny_training_golden.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn pack(row: &Value) -> u16 {
    let sensitivity = u16::from(row["sensitivity"].as_str().unwrap().as_bytes()[1] - b'0');
    let visibility = [0b00100, 0b01000, 0b01100, 0b10000, 0b10100, 0b11100]
        [VISIBILITIES.iter().position(|v| *v == row["visibility"].as_str().unwrap()).unwrap()];
    let categories: u16 = row["categories"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| 1u16 << (5 + CATEGORIES.iter().position(|name| *name == c.as_str().unwrap()).unwrap()))
        .sum();
    sensitivity | visibility | categories
}

fn rows_of(values: &Value, count: usize, prefix: &str) -> Vec<Row> {
    let items = values.as_array().unwrap();
    (0..count)
        .map(|i| {
            let item = &items[i % items.len()];
            Row {
                text: item["text"].as_str().unwrap().to_string(),
                packed: pack(item),
                weight: item["weight"].as_f64().unwrap(),
                id: format!("{prefix}{i}"),
                group: format!("g{}", i % 20),
                taxonomy: true,
            }
        })
        .collect()
}

fn window() -> Window {
    let golden = golden();
    let train = rows_of(&golden["examples"], 512, "t");
    Window {
        seed: "12345".to_string(),
        blocks: train.chunks(64).map(<[Row]>::to_vec).collect(),
        guard: rows_of(&golden["heldout"], 16, "h"),
        sha256: "a".repeat(64),
    }
}

fn references(artifact: &Value) -> Vec<Reference> {
    let golden = golden();
    let offset = (0.42f64).ln() - (-0.42f64).ln_1p();
    let sensitive: Vec<Row> = rows_of(&golden["examples"], 12, "r").into_iter().filter(|row| row.packed & 0b11 != 0).collect();
    let _ = artifact;
    sensitive
        .iter()
        .map(|row| Reference {
            text: row.text.clone(),
            gold: row.packed,
            original: row.packed,
            confidence: 0.9,
            components: vec![
                vec![Entry { slot: 0, target: 1.0, index: 0, sign: 0.0, offset: 0.0, positive: vec![1, 2, 3], negative: vec![0] }],
                vec![
                    Entry { slot: 2, target: 0.7, index: 0, sign: -1.0, offset, positive: vec![], negative: vec![] },
                    Entry { slot: 2, target: 1.0, index: 8, sign: 1.0, offset, positive: vec![], negative: vec![] },
                ],
                vec![Entry { slot: 1, target: 0.5, index: 0, sign: 0.0, offset: 0.0, positive: vec![2], negative: vec![0, 1, 3, 4, 5] }],
            ],
        })
        .collect()
}

#[test]
fn the_schedule_and_the_identities_are_pythons() {
    assert_eq!(derived_seed("12345", "epoch", 3), 3_585_173_001_958_878_258);
    assert_eq!(derived_seed("-7", "epoch", 63), 15_798_667_979_456_118_759);
    let expected = [
        2, 7, 4, 5, 3, 6, 1, 0, 0, 5, 4, 1, 6, 2, 3, 7, 6, 7, 4, 3, 1, 0, 2, 5, 3, 0, 4, 1, 2, 6, 7, 5, 4, 0, 6, 5, 7, 1, 2, 3, 6, 4, 5, 2,
        7, 3, 1, 0, 6, 5, 2, 3, 7, 0, 4, 1, 5, 0, 3, 7, 2, 1, 6, 4,
    ];
    assert_eq!(schedule("12345"), expected);
    let arrays = BTreeMap::from([("a".to_string(), vec![1.0, 2.0]), ("b".to_string(), vec![0.5]), ("a:m".to_string(), vec![3.25])]);
    assert_eq!(array_identity(&arrays), "1379f75fce4f1d459912af31897947daf5d9083bb42c33a95a8869b48495218b");
    // Python: S2 with IDENTITY at P0 warns, S2 with IDENTITY at PU warns, S3 below 0.5 confidence warns, S2 + identity at 0.4 warns.
    assert_eq!(action_value(0b10 | 0b00100 | (1 << 13), None), 1);
    assert_eq!(action_value(0b10 | (1 << 13) | 0b11100, None), 1);
    assert_eq!(action_value(3, Some(0.4)), 1);
    assert_eq!(action_value(2 | (1 << 13), Some(0.4)), 1);
    assert_eq!(action_value(3, None), 2);
    assert_eq!(action_value(0b01 | (1 << 13) | 0b01100, None), 1);
    assert_eq!(action_value(0b01 | (1 << 13) | 0b00100, None), 0);
}

fn counts(pairs: &[(&str, i64)]) -> BTreeMap<String, i64> {
    let mut all = checkpoint_counts(&[], &[]).unwrap();
    for (key, value) in pairs {
        all.insert((*key).to_string(), *value);
    }
    all
}

fn checkpoint(step: usize, violations: usize, loss: f64, pairs: &[(&str, i64)]) -> Checkpoint {
    Checkpoint {
        step,
        fingerprint: format!("{step}"),
        counts: counts(pairs),
        loss,
        predictions: Vec::new(),
        original_predictions: Vec::new(),
        violations,
        component_violations: [0; 5],
    }
}

#[test]
fn selection_needs_no_violation_no_regression_and_sensitive_progress() {
    let base = checkpoint(0, 0, 5.0, &[("all_joint", 10), ("sensitive_joint", 3)]);
    // Progress but a violation: not eligible.
    let violated = checkpoint(8, 1, 1.0, &[("all_joint", 20), ("sensitive_joint", 9)]);
    // Progress, no violation, but a lower count somewhere: not eligible.
    let regressed = checkpoint(16, 0, 1.0, &[("all_joint", 20), ("sensitive_joint", 9), ("clean_joint", -1)]);
    // Eligible, no progress: not selected.
    let flat = checkpoint(24, 0, 0.1, &[("all_joint", 10), ("sensitive_joint", 3)]);
    let good = checkpoint(32, 0, 2.0, &[("all_joint", 12), ("sensitive_joint", 5)]);
    let better = checkpoint(40, 0, 2.5, &[("all_joint", 12), ("sensitive_joint", 6)]);
    let tied_later = checkpoint(48, 0, 2.5, &[("all_joint", 12), ("sensitive_joint", 6)]);
    let all = vec![base, violated, regressed, flat, good, better, tied_later];
    assert_eq!(select(&all[..4]).step, 0);
    assert_eq!(select(&all[..5]).step, 32);
    assert_eq!(select(&all[..6]).step, 40, "the higher sensitive joint wins");
    assert_eq!(select(&all).step, 40, "a tie goes to the earlier step");
}

#[test]
fn predicates_and_counts_follow_the_contract() {
    // Gold S2 IDENTITY P0; the original kept the identity category; a candidate that drops it violates the category only.
    let gold = 0b10 | 0b00100 | (1 << 13);
    let kept = component_predicates(gold, gold, 0.9, gold, 0.9);
    assert!(kept.iter().all(|ok| *ok));
    let dropped = component_predicates(gold, gold, 0.9, 0b10 | 0b00100, 0.9);
    assert_eq!(dropped, [true, true, false, true, true]);
    let clean_candidate = component_predicates(gold, gold, 0.9, 0, 0.9);
    assert!(!clean_candidate[0]);
    let totals = checkpoint_counts(&[gold, 0b00100], &[(gold, 0.9), (0b00100, 0.9)]).unwrap();
    assert_eq!(
        (totals["all_joint"], totals["sensitive_joint"], totals["clean_joint"], totals["sensitive_recall"], totals["clean_specificity"]),
        (2, 1, 1, 1, 1)
    );
    assert!(checkpoint_counts(&[gold], &[]).is_err());
}

fn artifact() -> Value {
    golden()["models"]["legacy"].clone()
}

#[test]
fn the_component_hinge_gradient_matches_finite_differences() {
    let artifact = artifact();
    let net = TinyNet::from_artifact(&artifact).unwrap();
    let refs = references(&artifact);
    let (deltas, loss) = component_deltas(&net, &refs).unwrap();
    assert!(loss > 0.0);
    for name in ["head.sensitivity.bias", "head.category.weight", "layers.0.ffn.input.bias", "token_embedding"] {
        let values = &deltas[name];
        let (index, delta) = values.iter().copied().enumerate().max_by(|a, b| a.1.abs().partial_cmp(&b.1.abs()).unwrap()).unwrap();
        assert!(delta != 0.0, "{name} has no gradient");
        let probe = |shift: f64| {
            let mut params = net.params.clone();
            params.get_mut(name).unwrap().data[index] += shift;
            component_deltas(&net.with_params(params).unwrap(), &refs).unwrap().1
        };
        let h = 1e-6;
        let numeric = (probe(h) - probe(-h)) / (2.0 * h);
        assert!((numeric + delta).abs() <= 1e-5 * delta.abs().max(1.0), "{name}[{index}]: finite difference {numeric}, direction {delta}");
    }
}

#[test]
fn the_loop_is_deterministic_and_replays_recorded_directions() {
    let artifact = artifact();
    let window = window();
    let release = Release { sha256: "b".repeat(64), teacher_config: artifact["config"].clone(), references: references(&artifact) };
    let mut recorded: Vec<Directions> = Vec::new();
    let first = run(&artifact, &window, &release, &mut |step| {
        let directions = compute_directions(step)?;
        recorded.push(directions.clone());
        Ok(directions)
    })
    .unwrap();
    assert_eq!(recorded.len(), 64);
    let mut next = 0;
    let replayed = run(&artifact, &window, &release, &mut |_| {
        next += 1;
        Ok(recorded[next - 1].clone())
    })
    .unwrap();
    assert_eq!(first.trace, replayed.trace, "replaying the recorded directions reproduces the trace");
    assert_eq!(first.summary, replayed.summary);
    let trace: Value = serde_json::from_str(&first.trace).unwrap();
    assert_eq!(trace["steps"].as_array().unwrap().len(), 64);
    assert_eq!(trace["checkpoints"].as_array().unwrap().len(), 9);
    assert_eq!(trace["policy"], "full_projected_adam64_window_checkpoint_v1");
    assert_eq!(trace["selected_step"].as_u64().unwrap() as usize, first.selected_step);
    assert!(["selected", "no_update"].contains(&first.status));
    assert_eq!(first.status == "selected", !first.gradients.is_empty());
    assert_eq!(first.identities.len(), 64);
    // The blocks follow the schedule.
    let blocks: Vec<usize> = trace["steps"].as_array().unwrap().iter().map(|s| s["block"].as_u64().unwrap() as usize).collect();
    assert_eq!(blocks, schedule("12345"));
    let summary: Value = serde_json::from_str(&first.summary).unwrap();
    assert_eq!(summary["status"], first.status);
    eprintln!(
        "window synthetic: status {}/{} at step {}; checkpoint violations {:?}; base loss {:.4}",
        first.status,
        first.reason,
        first.selected_step,
        first.checkpoints.iter().map(|c| c.violations).collect::<Vec<_>>(),
        first.checkpoints[0].loss
    );
}
