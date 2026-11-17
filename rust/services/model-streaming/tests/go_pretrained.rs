//! Ports of `pretrained_context_test.go`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;

use common::{fixture_bytes, fixture_path, fixture_text, int, list, pretrained_fixture, rewrite_config, tensor, text};
use privoke_contracts::json::Value;
use privoke_model_streaming::artifact::{self, ModelArtifact, validate_model_artifact};
use privoke_model_streaming::catalog::Catalog;
use privoke_model_streaming::config::ServiceConfig;
use privoke_model_streaming::jsonx;
use privoke_model_streaming::pretrained::{ARCHITECTURE, MODEL_ID};
use privoke_model_streaming::response::parameter_response;

// TestPretrainedSharedPythonFixtureLoadsAndStreamsSixFrozenHeads
#[test]
fn pretrained_shared_python_fixture_loads_and_streams_six_frozen_heads() {
    let artifact = pretrained_fixture();
    let response = parameter_response(&artifact, "test");
    assert!(
        response.parameters.len() == 6
            && response.metadata["architecture"] == ARCHITECTURE
            && response.metadata["trainable_parameters"].is_empty(),
        "pretrained stream does not preserve six frozen head contract"
    );
    let count: usize = response.parameters.iter().map(|tensor| tensor.values.len()).sum();
    assert_eq!(count, 7700, "expected 7700 head values");
}

// TestPretrainedArtifactRejectsConfigHeadAndIdentityDrift
#[test]
fn pretrained_artifact_rejects_config_head_and_identity_drift() {
    type Mutation = Box<dyn Fn(&mut ModelArtifact)>;
    let artifact_cases: Vec<(&str, Mutation)> = vec![
        ("invalid version", Box::new(|a| a.version = "x".repeat(129))),
        ("wrong ID", Box::new(|a| a.model_id = "privoke-balanced".into())),
        ("wrong architecture", Box::new(|a| a.architecture = artifact::EXPECTED_ARCHITECTURE.into())),
        ("missing head", Box::new(|a| drop(a.parameters.remove("head.category.bias")))),
        ("extra head", Box::new(|a| drop(a.parameters.insert("extra".into(), tensor(&[1], vec![0.0], false))))),
        ("trainable", Box::new(|a| a.parameters.get_mut("head.category.bias").unwrap().trainable = true)),
        ("wrong shape", Box::new(|a| a.parameters.get_mut("head.visibility.bias").unwrap().shape = vec![2, 3])),
        ("float32 overflow", Box::new(|a| a.parameters.get_mut("head.category.bias").unwrap().values[0] = 1e100)),
    ];
    for (name, mutate) in artifact_cases {
        let mut model = pretrained_fixture().artifact;
        mutate(&mut model);
        assert!(validate_model_artifact(&model, "").is_err(), "invalid pretrained artifact accepted: {name}");
    }
    type ConfigMutation = Box<dyn Fn(&mut jsonx::Object)>;
    let config_cases: Vec<(&str, ConfigMutation)> = vec![
        ("semantics", Box::new(|c| drop(c.insert("category_semantics".into(), text("topic_tags_v1"))))),
        ("unknown", Box::new(|c| drop(c.insert("extra".into(), Value::Bool(true))))),
        ("tokenizer", Box::new(|c| drop(c.insert("tokenizer_sha256".into(), text(&"f".repeat(64)))))),
        ("backbone", Box::new(|c| drop(c.insert("backbone_revision".into(), text(&"f".repeat(40)))))),
        ("context", Box::new(|c| drop(c.insert("max_tokens".into(), int(513))))),
        ("threshold", Box::new(|c| drop(c.insert("category_threshold".into(), int(0))))),
        ("label order", Box::new(|c| drop(c.insert("sensitivity_labels".into(), list(&["S3", "S2", "S1", "S0"]))))),
    ];
    for (name, mutate) in config_cases {
        let mut model = pretrained_fixture().artifact;
        rewrite_config(&mut model, |config| mutate(config));
        assert!(validate_model_artifact(&model, "").is_err(), "invalid pretrained config accepted: {name}");
    }
}

// TestPretrainedOnlyAdmittedContextProfilesPreserveStreamConfig
#[test]
fn pretrained_only_admitted_context_profiles_preserve_stream_config() {
    let limits: Vec<(Value, Option<i64>)> = vec![
        (int(256), Some(256)),
        (int(512), Some(512)),
        (int(0), None),
        (int(255), None),
        (int(257), None),
        (int(511), None),
        (int(513), None),
        (Value::Bool(true), None),
        (text("512"), None),
        (Value::Float(512.5), None),
        (Value::Null, None),
    ];
    for (limit, admitted) in limits {
        let mut model = pretrained_fixture().artifact;
        rewrite_config(&mut model, |config| drop(config.insert("max_tokens".into(), limit.clone())));
        let result = validate_model_artifact(&model, "");
        assert_eq!(result.is_ok(), admitted.is_some(), "context limit {limit:?} admission mismatch: {result:?}");
        if let Some(expected) = admitted {
            let loaded = artifact::LoadedArtifact { artifact: model, file_checksum: String::new() };
            let response = parameter_response(&loaded, "test");
            let config = jsonx::object_of(&response.metadata["model_config"]).unwrap();
            assert_eq!(jsonx::int64(config.get("max_tokens")).unwrap(), expected, "stream lost admitted context limit {limit:?}");
        }
    }
}

// TestPretrainedRawDuplicateFlagsAndUnknownFieldsRejected
#[test]
fn pretrained_raw_duplicate_flags_and_unknown_fields_rejected() {
    let text = fixture_text("pretrained-context-minilm.json");
    let replace = |from: &str, to: &str| {
        assert!(text.contains(from), "fixture no longer contains {from}");
        text.replacen(from, to, 1)
    };
    let invalid = [
        replace(r#""schema_version":1"#, r#""schema_version":1,"schema_version":1"#),
        replace(
            r#""architecture":"privoke_pretrained_context_v1""#,
            r#""architecture":"privoke_pretrained_context_v1","architecture":"privoke_tiny_transformer_v1""#,
        ),
        replace(r#""category_threshold":0.5"#, r#""category_threshold":0.5,"category_threshold":0.6"#),
        replace(r#","trainable":false"#, ""),
        format!("{},\"extra\":1}}", text.trim().strip_suffix('}').unwrap()),
    ];
    for raw in invalid {
        assert!(artifact::load_model_artifact_bytes(raw.as_bytes(), "").is_err(), "invalid raw pretrained artifact accepted");
    }
}

// TestPretrainedCannotBeLatestAndExplicitCatalogLoadPreservesIdentity
#[test]
fn pretrained_cannot_be_latest_and_explicit_catalog_load_preserves_identity() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(format!("{MODEL_ID}.json"));
    std::fs::write(&path, fixture_bytes("pretrained-context-minilm.json")).unwrap();
    assert!(Catalog::load(directory.path(), MODEL_ID).is_err(), "experimental latest admitted");
    let mut catalog = Catalog::from_paths("privoke-balanced", BTreeMap::from([(MODEL_ID.to_string(), path)]));
    let loaded = catalog.load_model(MODEL_ID).expect("explicit load failed");
    assert_eq!(loaded.artifact.model_id, MODEL_ID);
    catalog.set_latest_model_id(MODEL_ID);
    assert!(catalog.load_model("latest").is_err(), "hand-built experimental latest admitted");
    let lookup = |key: &str| (key == "MODEL_LATEST_ID").then(|| MODEL_ID.to_string());
    assert!(ServiceConfig::from_lookup(lookup).is_err(), "experimental latest configuration admitted");
    let _ = fixture_path("pretrained-context-minilm.json");
}

// TestPretrainedClosedASCIIReleaseVersionsMatchPython
#[test]
fn pretrained_closed_ascii_release_versions_match_python() {
    for version in ["", "has space", "café", ".leading", &"x".repeat(129)] {
        let mut model = pretrained_fixture().artifact;
        model.version = version.to_string();
        assert!(validate_model_artifact(&model, "").is_err(), "invalid pretrained version accepted: {version:?}");
    }
}
