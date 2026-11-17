//! Ports of `contextual_training_test.go`, `full_adam_policy_test.go`, `sensitive_retention_test.go`,
//! `train_window_test.go` and `task_query_test.go`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;

use common::{contextual_fixture, int, make_unadapted, model_artifact, rewrite_config, task_query_fixture, tensor, text};
use privoke_contracts::canonical::{self, Variant};
use privoke_contracts::json::Value;
use privoke_model_streaming::artifact::{self, LoadedArtifact, ModelArtifact, TASK_QUERY_ARCHITECTURE, validate_model_artifact};
use privoke_model_streaming::contextual::*;
use privoke_model_streaming::response::{parameter_messages, response_metadata};

fn loaded(artifact: &ModelArtifact) -> LoadedArtifact {
    LoadedArtifact { artifact: artifact.clone(), file_checksum: String::new() }
}

fn metadata_of(artifact: &ModelArtifact, names: &[String]) -> BTreeMap<String, String> {
    response_metadata(&loaded(artifact), "test", names)
}

// TestContextualSharedFixtureTrainabilityAndMetadata
#[test]
fn contextual_shared_fixture_trainability_and_metadata() {
    let artifact = contextual_fixture();
    let (parameters, names) = parameter_messages(&artifact.parameters);
    assert!(names.len() == 15 && parameters.len() == 26, "incorrect adapted manifest");
    let metadata = metadata_of(&artifact, &names);
    assert_eq!(metadata[STRATEGY_KEY], LAST_BLOCK_STRATEGY, "training strategy not streamed");
    assert!(!artifact.parameters["token_embedding"].trainable && !artifact.parameters["layers.0.ffn.input.weight"].trainable);
}

// TestFullEncoderProfilesAdmitEmbeddingsAndRejectFrozenOrWrongScope
#[test]
fn full_encoder_profiles_admit_embeddings_and_reject_frozen_or_wrong_scope() {
    for profile in ["baseline", "efficient", "balanced", "quality"] {
        let mut artifact = model_artifact(profile);
        artifact.metadata_mut().insert(STRATEGY_KEY.into(), FULL_ENCODER_STRATEGY.into());
        for tensor in artifact.parameters.values_mut() {
            tensor.trainable = true;
        }
        validate_model_artifact(&artifact, "").unwrap_or_else(|error| panic!("full profile {profile} rejected: {error}"));
        let (parameters, names) = parameter_messages(&artifact.parameters);
        assert_eq!(parameters.len(), names.len(), "full tensor trainability lost during transport");
        artifact.metadata_mut().insert(STRATEGY_KEY.into(), LAST_BLOCK_STRATEGY.into());
        assert!(validate_model_artifact(&artifact, "").is_err(), "legacy strategy accepted full trainability");
        artifact.metadata_mut().insert(STRATEGY_KEY.into(), FULL_ENCODER_STRATEGY.into());
        let original_shape = artifact.parameters["token_embedding"].shape.clone();
        let count = artifact.parameters["token_embedding"].values.len() as u32;
        artifact.parameters.get_mut("token_embedding").unwrap().shape = vec![1, count];
        assert!(validate_model_artifact(&artifact, "").is_err(), "full strategy accepted incorrect embedding dimensions");
        let embedding = artifact.parameters.get_mut("token_embedding").unwrap();
        embedding.shape = original_shape;
        embedding.trainable = false;
        assert!(validate_model_artifact(&artifact, "").is_err(), "full strategy accepted frozen embedding");
    }
}

// TestContextualStrategyAndManifestRejectInvalid
#[test]
fn contextual_strategy_and_manifest_reject_invalid() {
    type Mutation = Box<dyn Fn(&mut ModelArtifact)>;
    let mutations: Vec<(&str, Mutation)> = vec![
        ("unknown strategy", Box::new(|a| drop(a.metadata_mut().insert(STRATEGY_KEY.into(), "unknown".into())))),
        ("empty strategy", Box::new(|a| drop(a.metadata_mut().insert(STRATEGY_KEY.into(), String::new())))),
        ("missing strategy", Box::new(|a| drop(a.metadata_mut().remove(STRATEGY_KEY)))),
        ("missing block", Box::new(|a| drop(a.parameters.remove("layers.1.ffn.input.weight")))),
        ("trainable embedding", Box::new(|a| a.parameters.get_mut("token_embedding").unwrap().trainable = true)),
        ("trainable earlier block", Box::new(|a| a.parameters.get_mut("layers.0.ffn.input.weight").unwrap().trainable = true)),
        ("frozen unsupported", Box::new(|a| drop(a.parameters.insert("unsupported".into(), tensor(&[1], vec![0.0], false))))),
        (
            "oversized update",
            Box::new(|a| drop(a.parameters.insert("layers.1.ffn.input.weight".into(), tensor(&[4097], vec![0.0; 4097], true)))),
        ),
        ("null layers", Box::new(|a| a.config = r#"{"num_layers":null}"#.into())),
    ];
    for (name, mutation) in mutations {
        let mut artifact = contextual_fixture();
        mutation(&mut artifact);
        assert!(validate_model_artifact(&artifact, "").is_err(), "invalid contextual contract accepted: {name}");
    }
}

fn serialise(artifact: &ModelArtifact) -> Value {
    artifact::to_value(artifact).unwrap()
}

fn raw_tensor_flags(raw: &Value) -> Result<(), privoke_model_streaming::Error> {
    artifact::validate_raw_tensor_flags(raw)
}

// TestContextualRawFlagsRequireBoolean
#[test]
fn contextual_raw_flags_require_boolean() {
    for value in [Value::Null, text("true"), int(1)] {
        let mut payload = serialise(&contextual_fixture());
        let Value::Object(root) = &mut payload else { unreachable!() };
        let Some(Value::Object(parameters)) = root.get_mut("parameters") else { unreachable!() };
        let Some(Value::Object(tensor)) = parameters.get_mut("head.category.bias") else { unreachable!() };
        tensor.insert("trainable".into(), value);
        assert!(raw_tensor_flags(&payload).is_err(), "invalid flag accepted");
        let Value::Object(root) = &mut payload else { unreachable!() };
        let Some(Value::Object(parameters)) = root.get_mut("parameters") else { unreachable!() };
        let Some(Value::Object(tensor)) = parameters.get_mut("head.category.bias") else { unreachable!() };
        tensor.remove("trainable");
        assert!(raw_tensor_flags(&payload).is_err(), "missing flag accepted");
    }
}

// TestContextualObjectiveIndependentOfTrainingStrategy
#[test]
fn contextual_objective_independent_of_training_strategy() {
    for adapted in [false, true] {
        let mut artifact = contextual_fixture();
        if !adapted {
            make_unadapted(&mut artifact);
        }
        artifact.metadata_mut().insert(OBJECTIVE_KEY.into(), CLASS_BALANCED_OBJECTIVE.into());
        validate_model_artifact(&artifact, "").unwrap();
        let (_, names) = parameter_messages(&artifact.parameters);
        assert_eq!(metadata_of(&artifact, &names)[OBJECTIVE_KEY], CLASS_BALANCED_OBJECTIVE, "objective not streamed");
        for invalid in ["", "unknown"] {
            artifact.metadata_mut().insert(OBJECTIVE_KEY.into(), invalid.into());
            assert!(validate_model_artifact(&artifact, "").is_err(), "unsupported objective accepted");
        }
        artifact.metadata_mut().remove(OBJECTIVE_KEY);
        validate_model_artifact(&artifact, "").expect("legacy objective rejected");
    }
}

fn raw_metadata_variants() -> Vec<Value> {
    vec![Value::Null, Value::Bool(true), int(1), Value::Array(vec![]), Value::Object(BTreeMap::new())]
}

fn decode_with_metadata(key: &str, value: Value) -> Option<ModelArtifact> {
    let mut payload = serialise(&contextual_fixture());
    let Value::Object(root) = &mut payload else { unreachable!() };
    let Some(Value::Object(metadata)) = root.get_mut("metadata") else { unreachable!() };
    metadata.insert(key.into(), value);
    let raw = canonical::to_bytes(&payload, Variant::Utf8Go).unwrap();
    artifact::decode_artifact_bytes(&raw).ok()
}

// TestContextualRawObjectiveTypesRejected
#[test]
fn contextual_raw_objective_types_rejected() {
    for value in raw_metadata_variants() {
        // JSON null becomes an empty string in a string map, which must fail validation; other types fail decoding.
        if let Some(typed) = decode_with_metadata(OBJECTIVE_KEY, value) {
            assert!(validate_model_artifact(&typed, "").is_err(), "invalid objective type accepted");
        }
    }
}

// TestContextualMeanCategoryObjectivePreservesManifestAndStreams
#[test]
fn contextual_mean_category_objective_preserves_manifest_and_streams() {
    for adapted in [false, true] {
        let mut artifact = contextual_fixture();
        if !adapted {
            make_unadapted(&mut artifact);
        }
        let (_, before) = parameter_messages(&artifact.parameters);
        artifact.metadata_mut().insert(OBJECTIVE_KEY.into(), CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE.into());
        validate_model_artifact(&artifact, "").unwrap();
        let (_, names) = parameter_messages(&artifact.parameters);
        assert_eq!(before.len(), names.len(), "objective changed trainability");
        assert_eq!(metadata_of(&artifact, &names)[OBJECTIVE_KEY], CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE);
    }
}

// TestContextualOptimizerIndependentAndStreamed
#[test]
fn contextual_optimizer_independent_and_streamed() {
    for adapted in [false, true] {
        for objective in ["", CLASS_BALANCED_OBJECTIVE, CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE] {
            for optimizer in [LOCAL_SGD_1, LOCAL_SGD_4] {
                let mut artifact = contextual_fixture();
                if !adapted {
                    make_unadapted(&mut artifact);
                }
                if !objective.is_empty() {
                    artifact.metadata_mut().insert(OBJECTIVE_KEY.into(), objective.into());
                }
                artifact.metadata_mut().insert(OPTIMIZER_KEY.into(), optimizer.into());
                validate_model_artifact(&artifact, "").unwrap();
                let (_, names) = parameter_messages(&artifact.parameters);
                assert_eq!(metadata_of(&artifact, &names)[OPTIMIZER_KEY], optimizer, "optimizer not streamed");
                for invalid in ["", "unknown", "local_sgd_2_v1"] {
                    artifact.metadata_mut().insert(OPTIMIZER_KEY.into(), invalid.into());
                    assert!(validate_model_artifact(&artifact, "").is_err(), "unsupported optimizer accepted");
                }
                artifact.metadata_mut().remove(OPTIMIZER_KEY);
                validate_model_artifact(&artifact, "").expect("legacy optimizer rejected");
            }
        }
    }
}

// TestContextualRawOptimizerTypesRejected
#[test]
fn contextual_raw_optimizer_types_rejected() {
    for value in raw_metadata_variants() {
        if let Some(typed) = decode_with_metadata(OPTIMIZER_KEY, value) {
            assert!(validate_model_artifact(&typed, "").is_err(), "invalid optimizer type accepted");
        }
    }
}

// TestContextualDecisionMarginObjectivePreservesManifestAndStreams
#[test]
fn contextual_decision_margin_objective_preserves_manifest_and_streams() {
    for adapted in [false, true] {
        let mut artifact = contextual_fixture();
        if !adapted {
            make_unadapted(&mut artifact);
        }
        let (_, before) = parameter_messages(&artifact.parameters);
        artifact.metadata_mut().insert(OBJECTIVE_KEY.into(), CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE.into());
        for optimizer in ["", LOCAL_SGD_1, LOCAL_SGD_4] {
            if !optimizer.is_empty() {
                artifact.metadata_mut().insert(OPTIMIZER_KEY.into(), optimizer.into());
            }
            validate_model_artifact(&artifact, "").unwrap();
            let (_, names) = parameter_messages(&artifact.parameters);
            assert_eq!(before.len(), names.len(), "objective changed manifest");
            assert_eq!(metadata_of(&artifact, &names)[OBJECTIVE_KEY], CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE);
        }
    }
}

// TestContextualDecisionMarginConfigurationFailsClosed
#[test]
fn contextual_decision_margin_configuration_fails_closed() {
    let label_cases: Vec<Value> =
        vec![common::list(&["S1", "S2"]), common::list(&["S0"]), common::list(&["S0", "S0"]), Value::Null, Value::Bool(true)];
    for labels in label_cases {
        let mut artifact = contextual_fixture();
        artifact.metadata_mut().insert(OBJECTIVE_KEY.into(), CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE.into());
        rewrite_config(&mut artifact, |config| drop(config.insert("sensitivity_labels".into(), labels)));
        assert!(validate_contextual_training_artifact(&artifact).is_err(), "invalid reference labels accepted");
    }
    let threshold_cases: Vec<Value> = vec![Value::Null, Value::Bool(true), Value::Float(0.0), Value::Float(1.0), text("0.38")];
    for threshold in threshold_cases {
        let mut artifact = contextual_fixture();
        artifact.metadata_mut().insert(OBJECTIVE_KEY.into(), CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE.into());
        rewrite_config(&mut artifact, |config| drop(config.insert("category_threshold".into(), threshold)));
        assert!(validate_contextual_training_artifact(&artifact).is_err(), "invalid threshold accepted");
    }
    for threshold in [0.38, 0.5, 0.9] {
        let mut artifact = contextual_fixture();
        artifact.metadata_mut().insert(OBJECTIVE_KEY.into(), CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE.into());
        rewrite_config(&mut artifact, |config| drop(config.insert("category_threshold".into(), Value::Float(threshold))));
        validate_contextual_training_artifact(&artifact).unwrap();
    }
}

// ---- full_adam_policy_test.go ----

fn full_adam_artifact(profile: &str) -> ModelArtifact {
    let mut artifact = model_artifact(profile);
    let metadata = artifact.metadata_mut();
    metadata.insert(STRATEGY_KEY.into(), FULL_ENCODER_STRATEGY.into());
    metadata.insert(OBJECTIVE_KEY.into(), CLASS_BALANCED_SUM_DECISION_MARGIN_OBJECTIVE.into());
    metadata.insert(OPTIMIZER_KEY.into(), FULL_ADAM.into());
    metadata.insert(CANDIDATE_ELIGIBILITY_KEY.into(), CANDIDATE_ELIGIBILITY.into());
    metadata.insert(FULL_ADAM_CONFIG_KEY.into(), FULL_ADAM_CONFIG.into());
    for tensor in artifact.parameters.values_mut() {
        tensor.trainable = true;
    }
    artifact
}

// TestFullAdamThreeProfilesAndExactMetadata
#[test]
fn full_adam_three_profiles_and_exact_metadata() {
    for profile in ["efficient", "balanced", "quality"] {
        let artifact = full_adam_artifact(profile);
        validate_model_artifact(&artifact, "").unwrap_or_else(|error| panic!("{profile}: {error}"));
        let (_, names) = parameter_messages(&artifact.parameters);
        let metadata = metadata_of(&artifact, &names);
        for key in [STRATEGY_KEY, OBJECTIVE_KEY, OPTIMIZER_KEY, CANDIDATE_ELIGIBILITY_KEY, FULL_ADAM_CONFIG_KEY] {
            assert_eq!(metadata[key], artifact.metadata()[key], "metadata changed: {key}");
        }
    }
}

// TestFullAdamPolicyRejectsMissingMalformedMixedAndUnsupported
#[test]
fn full_adam_policy_rejects_missing_malformed_mixed_and_unsupported() {
    type Mutation = Box<dyn Fn(&mut ModelArtifact)>;
    let set =
        |key: &'static str, value: String| -> Mutation { Box::new(move |a| drop(a.metadata_mut().insert(key.into(), value.clone()))) };
    let remove = |key: &'static str| -> Mutation { Box::new(move |a| drop(a.metadata_mut().remove(key))) };
    let mutations: Vec<(&str, Mutation)> = vec![
        ("missing strategy", remove(STRATEGY_KEY)),
        ("head strategy", set(STRATEGY_KEY, LAST_BLOCK_STRATEGY.into())),
        ("missing objective", remove(OBJECTIVE_KEY)),
        ("other objective", set(OBJECTIVE_KEY, CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE.into())),
        ("missing optimizer", remove(OPTIMIZER_KEY)),
        ("unknown optimizer", set(OPTIMIZER_KEY, "adam".into())),
        ("local optimizer", set(OPTIMIZER_KEY, LOCAL_SGD_4.into())),
        ("missing eligibility", remove(CANDIDATE_ELIGIBILITY_KEY)),
        ("unknown eligibility", set(CANDIDATE_ELIGIBILITY_KEY, "base_train_exact_v1".into())),
        ("missing config", remove(FULL_ADAM_CONFIG_KEY)),
        ("noncanonical config", set(FULL_ADAM_CONFIG_KEY, format!(" {FULL_ADAM_CONFIG}"))),
        ("invalid json config", set(FULL_ADAM_CONFIG_KEY, "{".into())),
        ("unsupported steps", set(FULL_ADAM_CONFIG_KEY, r#"{"steps":63}"#.into())),
        ("diagnostics", set("contextual_training_diagnostics_policy", String::new())),
        ("backtracking", set("contextual_training_backtracking_policy", "full_train_backtracking_v1".into())),
        ("backtracking preparation", set("contextual_training_backtracking_preparation", "{}".into())),
        ("frozen embedding", Box::new(|a| a.parameters.get_mut("token_embedding").unwrap().trainable = false)),
        (
            "wrong shape",
            Box::new(|a| {
                let embedding = a.parameters.get_mut("token_embedding").unwrap();
                embedding.shape = vec![1, embedding.values.len() as u32];
            }),
        ),
    ];
    for (name, mutate) in mutations {
        let mut artifact = full_adam_artifact("balanced");
        mutate(&mut artifact);
        assert!(validate_model_artifact(&artifact, "").is_err(), "invalid FULL Adam accepted: {name}");
    }
}

// TestSumDecisionMarginConfigAndOptimizerParity
#[test]
fn sum_decision_margin_config_and_optimizer_parity() {
    for key in ["category_threshold", "sensitivity_labels"] {
        let values: Vec<Value> = if key == "sensitivity_labels" {
            vec![
                Value::Null,
                Value::Bool(true),
                common::list(&["S1"]),
                common::list(&["S0"]),
                common::list(&["S0", "S0"]),
                Value::Array(vec![text("S0"), Value::Null]),
            ]
        } else {
            vec![Value::Null, Value::Bool(true), text("invalid"), Value::Float(0.0), Value::Float(1.0)]
        };
        for value in values {
            let mut artifact = full_adam_artifact("balanced");
            rewrite_config(&mut artifact, |config| drop(config.insert(key.into(), value)));
            assert!(validate_contextual_training_artifact(&artifact).is_err(), "invalid SUM {key} accepted");
        }
    }
    // The earlier SUM objective with absent optimizer remains its distinct route.
    let mut artifact = full_adam_artifact("balanced");
    for key in [OPTIMIZER_KEY, CANDIDATE_ELIGIBILITY_KEY, FULL_ADAM_CONFIG_KEY] {
        artifact.metadata_mut().remove(key);
    }
    validate_model_artifact(&artifact, "").unwrap();
    artifact.metadata_mut().insert(OPTIMIZER_KEY.into(), LOCAL_SGD_1.into());
    assert!(validate_model_artifact(&artifact, "").is_err(), "SUM allowed local SGD");
}

// ---- sensitive_retention_test.go ----

fn hex_pin(character: &str) -> String {
    character.repeat(64)
}

// TestSensitiveRetentionPoliciesCoexistAndFailClosed
#[test]
fn sensitive_retention_policies_coexist_and_fail_closed() {
    for policy in [RETENTION_GATE, RETENTION_HINGE] {
        let objective = if policy == RETENTION_HINGE { RETENTION_HINGE_OBJECTIVE } else { RETENTION_GATE_OBJECTIVE };
        let meta: BTreeMap<String, String> = [
            (OPTIMIZER_KEY, policy),
            (STRATEGY_KEY, FULL_ENCODER_STRATEGY),
            (OBJECTIVE_KEY, objective),
            (CANDIDATE_ELIGIBILITY_KEY, RETENTION_ELIGIBILITY),
            (FULL_ADAM_CONFIG_KEY, FULL_ADAM_CONFIG),
            (RETENTION_MANIFEST_KEY, &hex_pin("a")),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();
        validate_contextual_full_adam_policy(&meta).unwrap();
        for key in [OBJECTIVE_KEY, CANDIDATE_ELIGIBILITY_KEY, FULL_ADAM_CONFIG_KEY, RETENTION_MANIFEST_KEY] {
            let mut copy = meta.clone();
            copy.insert(key.into(), "wrong".into());
            assert!(validate_contextual_full_adam_policy(&copy).is_err(), "accepted wrong {key}");
        }
    }
    let orphan = BTreeMap::from([(RETENTION_MANIFEST_KEY.to_string(), hex_pin("a"))]);
    assert!(validate_contextual_full_adam_policy(&orphan).is_err(), "accepted orphan retention pin");
    let old_full: BTreeMap<String, String> = [
        (OPTIMIZER_KEY, FULL_ADAM),
        (STRATEGY_KEY, FULL_ENCODER_STRATEGY),
        (OBJECTIVE_KEY, CLASS_BALANCED_SUM_DECISION_MARGIN_OBJECTIVE),
        (CANDIDATE_ELIGIBILITY_KEY, CANDIDATE_ELIGIBILITY),
        (FULL_ADAM_CONFIG_KEY, FULL_ADAM_CONFIG),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value.to_string()))
    .collect();
    validate_contextual_full_adam_policy(&old_full).expect("old FULL policy changed");
}

// ---- train_window_test.go ----

// TestWindowPolicyRequiresExactConfigurationAndIndependentPins
#[test]
fn window_policy_requires_exact_configuration_and_independent_pins() {
    let mut metadata: BTreeMap<String, String> = [
        (OPTIMIZER_KEY, WINDOW_ADAM),
        (STRATEGY_KEY, FULL_ENCODER_STRATEGY),
        (OBJECTIVE_KEY, CLASS_BALANCED_SUM_DECISION_MARGIN_OBJECTIVE),
        (CANDIDATE_ELIGIBILITY_KEY, WINDOW_ELIGIBILITY),
        (WINDOW_CONFIG_KEY, WINDOW_CONFIG),
        (WINDOW_MANIFEST_KEY, &hex_pin("a")),
        (COMPONENT_MANIFEST_KEY, &hex_pin("b")),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value.to_string()))
    .collect();
    validate_contextual_full_adam_policy(&metadata).unwrap();
    for key in [WINDOW_CONFIG_KEY, WINDOW_MANIFEST_KEY, COMPONENT_MANIFEST_KEY, CANDIDATE_ELIGIBILITY_KEY] {
        let mut altered = metadata.clone();
        altered.remove(key);
        assert!(validate_contextual_full_adam_policy(&altered).is_err(), "accepted missing {key}");
    }
    metadata.insert(FULL_ADAM_CONFIG_KEY.into(), FULL_ADAM_CONFIG.into());
    assert!(validate_contextual_full_adam_policy(&metadata).is_err(), "accepted legacy/new mixture");
    let orphan = BTreeMap::from([(WINDOW_MANIFEST_KEY.to_string(), hex_pin("a"))]);
    assert!(validate_contextual_full_adam_policy(&orphan).is_err(), "accepted orphan window pin");
}

// ---- task_query_test.go ----

// TestTaskQuerySharedFixtureTransportAndScopes
#[test]
fn task_query_shared_fixture_transport_and_scopes() {
    let mut artifact = task_query_fixture();
    for strategy in ["", LAST_BLOCK_STRATEGY, FULL_ENCODER_STRATEGY] {
        if strategy.is_empty() {
            artifact.metadata_mut().remove(STRATEGY_KEY);
        } else {
            artifact.metadata_mut().insert(STRATEGY_KEY.into(), strategy.into());
        }
        let (names, _) = contextual_trainable_names(&artifact.config, strategy).unwrap();
        for (name, tensor) in &mut artifact.parameters {
            tensor.trainable = names.contains(name);
        }
        validate_model_artifact(&artifact, "").unwrap();
        let (_, trainables) = parameter_messages(&artifact.parameters);
        assert_eq!(trainables.len(), names.len(), "query trainability lost in transport");
        for task in ["sensitivity", "visibility", "category"] {
            assert!(names.contains(&format!("readout.{task}.query")), "query is silently frozen");
        }
        let metadata = response_metadata(&loaded(&artifact), "synthetic", &trainables);
        assert_eq!(metadata["architecture"], TASK_QUERY_ARCHITECTURE, "query architecture lost in stream");
    }
}

// TestTaskQueryFailClosed
#[test]
fn task_query_fail_closed() {
    type Mutation = Box<dyn Fn(&mut ModelArtifact)>;
    let cases: Vec<(&str, Mutation)> = vec![
        ("legacy identity", Box::new(|a| a.architecture = artifact::EXPECTED_ARCHITECTURE.into())),
        ("missing query", Box::new(|a| drop(a.parameters.remove("readout.category.query")))),
        ("wrong query shape", Box::new(|a| a.parameters.get_mut("readout.category.query").unwrap().shape = vec![1, 2])),
        ("frozen query", Box::new(|a| a.parameters.get_mut("readout.category.query").unwrap().trainable = false)),
        ("extra tensor", Box::new(|a| drop(a.parameters.insert("extra".into(), tensor(&[1], vec![0.0], false))))),
        ("unsupported readout", Box::new(|a| rewrite_config(a, |c| drop(c.insert("readout".into(), text("unknown")))))),
        ("missing readout", Box::new(|a| rewrite_config(a, |c| drop(c.remove("readout"))))),
        ("bad attention", Box::new(|a| rewrite_config(a, |c| drop(c.insert("num_attention_heads".into(), int(3)))))),
    ];
    for (name, mutate) in cases {
        let mut artifact = task_query_fixture();
        mutate(&mut artifact);
        assert!(validate_model_artifact(&artifact, "").is_err(), "malformed query artifact accepted: {name}");
    }
}
