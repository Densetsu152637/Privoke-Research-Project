//! Ports of `artifact_test.go` (sparse presence artifacts and raw-flag guards).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{fixture_path, list, nested, presence_fixture, rewrite_config, tensor, text};
use privoke_contracts::json::Value;
use privoke_model_streaming::artifact::{self, validate_model_artifact, validate_raw_tensor_flags};
use privoke_model_streaming::jsonx::{self, valid_json_unicode};
use privoke_model_streaming::response::{parameter_chunk, parameter_response};

// TestPresenceSharedPythonFixtureLoadsAndStreamsMetadata
#[test]
fn presence_shared_python_fixture_loads_and_streams_metadata() {
    let model = presence_fixture();
    validate_model_artifact(&model, "privoke-presence-efficient").unwrap();
    let loaded = artifact::load_model_artifact(&fixture_path("presence-efficient.json"), &model.model_id).unwrap();
    let response = parameter_response(&loaded, "test");
    assert_eq!(response.metadata["task"], "annotation_presence");
    assert_eq!(response.metadata["profile"], "efficient");
    assert_eq!(response.metadata["arithmetic"], "float32_parameters_float64_features_fsum_v1");
    assert!(
        !parameter_chunk(&response, &response.parameters[0], 0, 0, 1).metadata["model_config"].is_empty(),
        "first stream chunk missing config"
    );
    assert!(parameter_chunk(&response, &response.parameters[0], 0, 1, 2).metadata.is_empty(), "config should only be transmitted once");
}

// TestPresenceConfigRejectsInvalidContracts
#[test]
fn presence_config_rejects_invalid_contracts() {
    type Mutation = Box<dyn Fn(&mut jsonx::Object)>;
    let cases: Vec<(&str, Mutation)> = vec![
        ("unknown field", Box::new(|c| drop(c.insert("extra".into(), common::int(1))))),
        ("null threshold", Box::new(|c| drop(c.insert("threshold".into(), Value::Null)))),
        ("boolean threshold", Box::new(|c| drop(c.insert("threshold".into(), Value::Bool(true))))),
        ("threshold range", Box::new(|c| drop(c.insert("threshold".into(), common::int(2))))),
        ("wrong task", Box::new(|c| drop(c.insert("task".into(), text("privacy_severity"))))),
        ("wrong profile", Box::new(|c| drop(c.insert("profile".into(), text("other"))))),
        ("wrong column order", Box::new(|c| drop(c.insert("column_order".into(), list(&["char", "word"]))))),
        ("wrong block", Box::new(|c| drop(c.insert("coefficient_block_size".into(), common::int(4095))))),
        ("wrong vocabulary", Box::new(|c| drop(nested(c, &["branches", "word"]).insert("features".into(), list(&["a"]))))),
        ("duplicate vocabulary", Box::new(|c| drop(nested(c, &["branches", "word"]).insert("features".into(), list(&["mail", "mail"]))))),
        ("bad char ngram", Box::new(|c| drop(nested(c, &["branches", "char"]).insert("features".into(), list(&["xx"]))))),
        ("null lowercase", Box::new(|c| drop(nested(c, &["branches", "word"]).insert("lowercase".into(), Value::Null)))),
        ("wrong TF setting", Box::new(|c| drop(nested(c, &["branches", "char"]).insert("sublinear_tf".into(), Value::Bool(false))))),
    ];
    for (name, mutate) in cases {
        let mut model = presence_fixture();
        rewrite_config(&mut model, |config| mutate(config));
        assert!(validate_model_artifact(&model, "").is_err(), "invalid presence config accepted: {name}");
    }
}

// TestPresenceParametersRejectInvalidManifest
#[test]
fn presence_parameters_reject_invalid_manifest() {
    for name in ["frozen flag", "missing tensor", "wrong shape", "zero idf", "float32 overflow", "extra tensor", "wrong model"] {
        let mut model = presence_fixture();
        match name {
            "frozen flag" => model.parameters.get_mut("features.word.idf").unwrap().trainable = true,
            "missing tensor" => drop(model.parameters.remove("head.presence.bias")),
            "wrong shape" => model.parameters.get_mut("head.presence.bias").unwrap().shape = vec![1, 1],
            "zero idf" => model.parameters.get_mut("features.word.idf").unwrap().values[0] = 0.0,
            "float32 overflow" => model.parameters.get_mut("head.presence.bias").unwrap().values[0] = f64::MAX,
            "extra tensor" => drop(model.parameters.insert("head.extra".into(), tensor(&[1], vec![0.0], false))),
            "wrong model" => model.model_id = "privoke-presence-balanced".into(),
            _ => unreachable!(),
        }
        assert!(validate_model_artifact(&model, "").is_err(), "invalid presence tensor contract accepted: {name}");
    }
}

fn flags(raw: &str) -> Result<(), privoke_model_streaming::Error> {
    validate_raw_tensor_flags(&jsonx::parse(raw).unwrap())
}

// TestPresenceRawTrainableFlagsAndUnicode
#[test]
fn presence_raw_trainable_flags_and_unicode() {
    for raw in [
        r#"{"parameters":{"features.word.idf":{"trainable":null}}}"#,
        r#"{"parameters":{"features.word.idf":{}}}"#,
        r#"{"parameters":{"features.word.idf":{"trainable":1}}}"#,
    ] {
        assert!(flags(raw).is_err(), "non-boolean/missing trainable accepted");
    }
    flags(r#"{"parameters":{"features.word.idf":{"trainable":false}}}"#).unwrap();
    for raw in [r#""\ud800ab""#, r#""\udc00ab""#, r#""\ud800\u0041""#] {
        assert!(!valid_json_unicode(raw.as_bytes()), "invalid surrogate accepted: {raw}");
    }
    for raw in [r#""\ud83e\uddea""#, r#""\\ud800""#, "\"café\""] {
        assert!(valid_json_unicode(raw.as_bytes()), "valid Unicode rejected: {raw}");
    }
}

// TestLoadPresenceArtifactRejectsMissingAndNullTrainableFlags
#[test]
fn load_presence_artifact_rejects_missing_and_null_trainable_flags() {
    for test in ["missing", "null"] {
        let model = presence_fixture();
        let mut payload = artifact::to_value(&model).unwrap();
        let Value::Object(root) = &mut payload else { unreachable!() };
        let Some(Value::Object(parameters)) = root.get_mut("parameters") else { unreachable!() };
        let Some(Value::Object(tensor)) = parameters.get_mut("features.word.idf") else { unreachable!() };
        if test == "missing" {
            tensor.remove("trainable");
        } else {
            tensor.insert("trainable".into(), Value::Null);
        }
        let checksum = artifact::calculate_artifact_checksum(&payload).unwrap();
        let Value::Object(root) = &mut payload else { unreachable!() };
        root.insert("checksum".into(), Value::String(checksum));
        let raw = privoke_contracts::canonical::to_bytes(&payload, privoke_contracts::canonical::Variant::Utf8Go).unwrap();
        let error = artifact::load_model_artifact_bytes(&raw, "privoke-presence-efficient").unwrap_err();
        assert!(error.0.contains("explicit boolean trainable"), "expected raw flag rejection, got {error}");
    }
}
