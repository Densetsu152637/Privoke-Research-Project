//! The V3 fit against the product's own `fit` (`generate_v3_fit_golden.py synthetic`): the committed synthetic V3 package of the
//! semantic crate, 64 TRAIN rows and a guard of 16, the pilot policy (two AdamW steps), once per scope. Torch runs float32 and
//! this port float64 over float32 weights, so the comparison is the tolerance category: the work counts, block counts, phases and
//! tensor-change groups are exact; the losses and gradient norms agree within 1e-4 relative; the candidate tensors agree with the
//! product's exported candidate to within the optimizer's own step bound (AdamW moves a coordinate by at most about the learning
//! rate per step, so a sign flip of a near-zero gradient is the only possible difference), with the fraction within 1e-6 reported.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use privoke_semantic::V3Model;
use privoke_semantic::safetensors::{Tensor, parse};
use privoke_training::v3_fit::{fit_unchecked, validate_execution, validate_policy};
use serde_json::{Value, json};

mod v3_fit_support;
use v3_fit_support::{compare, golden, input};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn package() -> (V3Model, BTreeMap<String, Tensor>) {
    let dir = fixtures().join("../../../privoke-semantic/tests/fixtures/v3_synthetic");
    let model = V3Model::from_files(&dir.join("config.json"), &dir.join("model.safetensors"), &dir.join("vocab.txt")).unwrap();
    (model, parse(&std::fs::read(dir.join("model.safetensors")).unwrap()).unwrap())
}

#[test]
fn the_fit_matches_the_product_in_both_scopes() {
    let golden = golden();
    let (model, base) = package();
    for scope in ["heads", "full_encoder"] {
        let result = fit_unchecked(&model, &base, &input(&golden, scope), &|| true).unwrap();
        let exported = parse(&std::fs::read(fixtures().join(format!("v3_fit/{scope}.safetensors"))).unwrap()).unwrap();
        compare(scope, &golden["scopes"][scope], &result, &exported, 0.9);
    }
}

#[test]
fn a_cancelled_fit_stops_with_the_python_text() {
    let golden = golden();
    let (model, base) = package();
    let error = fit_unchecked(&model, &base, &input(&golden, "heads"), &|| false).unwrap_err();
    assert_eq!(error.to_string(), "Fit cancelled; no publication attempted.");
}

#[test]
fn a_fit_refuses_a_window_or_guard_that_breaks_the_contract() {
    let golden = golden();
    let (model, base) = package();
    let mut short = input(&golden, "heads");
    short.train.pop();
    assert_eq!(fit_unchecked(&model, &base, &short, &|| true).unwrap_err().to_string(), "Frozen TRAIN window/guard counts differ.");
    let mut overlap = input(&golden, "heads");
    overlap.guard[0].text = overlap.train[0].text.clone();
    assert_eq!(fit_unchecked(&model, &base, &overlap, &|| true).unwrap_err().to_string(), "TRAIN/guard normalized texts overlap.");
    let mut policy = input(&golden, "heads");
    policy.policy["eps"] = json!(1e-7);
    assert_eq!(fit_unchecked(&model, &base, &policy, &|| true).unwrap_err().to_string(), "Policy differs from the frozen v3 contract.");
}

#[test]
fn the_policy_contract_is_exact() {
    let golden = golden();
    let pilot = &golden["policy"];
    validate_policy(pilot, true).unwrap();
    assert!(validate_policy(pilot, false).is_err(), "the pilot policy is not a 64/256/512-step policy");
    let mut full = pilot.clone();
    full["steps"] = json!(64);
    full["window_batches"] = json!(8);
    full["epochs"] = json!(8);
    validate_policy(&full, false).unwrap();
    full["steps"] = json!(65);
    assert_eq!(validate_policy(&full, false).unwrap_err().to_string(), "Predeclared v3 work budget must be 64, 256 or 512 steps.");
    let mut forged = pilot.clone();
    forged["weight_decay"] = json!(0.01);
    assert_eq!(validate_policy(&forged, true).unwrap_err().to_string(), "Policy differs from the frozen v3 contract.");
}

/// The synthetic package has three layers and its own parameter count, so its evidence is re-labelled as the two-layer
/// `balanced` tier to exercise the acceptance path of `validate_execution`; every check below then breaks one reconciled fact.
fn as_balanced(evidence: &Value, full: bool) -> Value {
    let mut value = evidence.clone();
    let microbatches = 32u64;
    value["model_id"] = json!("privoke-v3-balanced");
    value["tier"] = json!("balanced");
    value["parameter_count"] = json!(9_596_180);
    value["trainable_count"] = json!(if full { 9_596_180 } else { 20 * 257 });
    value["counts"]["encoder_block_forward"] = json!(microbatches * 2);
    value["counts"]["encoder_block_backward"] = json!(if full { microbatches * 2 } else { 0 });
    value["block_counts"] = json!({"forward": [microbatches, microbatches], "backward": [if full { microbatches } else { 0 }; 2]});
    value["changes"]["blocks"] = json!(if full { [16, 16] } else { [0, 0] });
    value
}

#[test]
fn validate_execution_reconciles_the_evidence() {
    let golden = golden();
    for (scope, full) in [("heads", false), ("full_encoder", true)] {
        let good = as_balanced(&golden["scopes"][scope], full);
        validate_execution(&good, false).unwrap();
        // The guard, the work counts and the identities are each reconciled; one broken fact each is refused.
        let broken: [(&str, Box<dyn Fn(&mut Value)>, &str); 6] = [
            ("parameters", Box::new(|v| v["parameter_count"] = json!(1)), "Execution complete parameter count mismatch."),
            ("counts", Box::new(|v| v["counts"]["train_rows"] = json!(1)), "Actual work counters differ from frozen policy."),
            (
                "blocks",
                Box::new(|v| v["block_counts"]["forward"] = json!([1, 1])),
                "Every encoder block must attest actual forward/backward work.",
            ),
            ("loss", Box::new(|v| v["losses"] = json!([1.0])), "Finite per-step loss trace required."),
            ("harms", Box::new(|v| v["action_harms"] = json!(5)), "Action harm count differs from guard rows."),
            ("guard", Box::new(|v| v["candidate_guard"]["joint_correct"] = json!(9)), "Guard joint count differs from rows."),
        ];
        for (label, mutate, message) in broken {
            let mut value = good.clone();
            mutate(&mut value);
            assert_eq!(validate_execution(&value, false).unwrap_err().to_string(), message, "{scope}: {label}");
        }
        assert_eq!(validate_execution(&good, true).unwrap_err().to_string(), "Expected a lowercase SHA-256 identity.");
    }
    let mut heads = as_balanced(&golden["scopes"]["heads"], false);
    heads["changes"]["encoder"] = json!(3);
    assert_eq!(validate_execution(&heads, false).unwrap_err().to_string(), "HEADS changed pretrained encoder.");
}
