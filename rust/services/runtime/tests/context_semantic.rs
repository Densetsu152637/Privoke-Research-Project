//! The worker's semantic layer on the pretrained contextual model, against the Python findings, metadata and identity.
//!
//! The fixture is the one of `privoke-semantic` (`tests/fixtures/context_golden.json`, written by
//! `evaluation/generate_pretrained_context_golden.py`): a synthetic backbone with the structure of the pinned export, and
//! the unchanged Python `StreamedPretrainedContextModel.classify` on it. The backbone reference is numpy float32, not
//! onnxruntime (see the generator's docstring), so this is parity of the Rust layer with the Python model, not a
//! measurement of the real MiniLM export. It is a semantic-only (LLM-only) check: no regex or NER layer runs.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use privoke_rules::preprocessing::normalize_with_offsets;
use privoke_runtime::pipeline::{LayerExecution, Status};
use privoke_runtime::semantic::{CONTEXT_IDENTITY_PREFIX, PRETRAINED_CONTEXT_MODEL_ID, SemanticLayer};
use privoke_semantic::bert::BertConfig;
use serde_json::Value;

/// A named way to break the artifact.
type Breaker = (&'static str, fn(&mut Value));

fn fixture() -> Value {
    serde_json::from_str(include_str!("../../../crates/privoke-semantic/tests/fixtures/context_golden.json")).expect("the fixture is JSON")
}

fn backbone(document: &Value) -> BertConfig {
    let number = |name: &str| document["backbone"][name].as_u64().unwrap() as usize;
    BertConfig {
        hidden_size: number("hidden_size"),
        num_hidden_layers: number("num_hidden_layers"),
        num_attention_heads: number("num_attention_heads"),
        intermediate_size: number("intermediate_size"),
        max_position_embeddings: number("max_position_embeddings"),
        vocab_size: number("vocab_size"),
        type_vocab_size: number("type_vocab_size"),
        layer_norm_eps: document["backbone"]["layer_norm_eps"].as_f64().unwrap(),
    }
}

/// A model root holding the artifact, and an asset directory holding the backbone and the tokenizer.
struct Rig {
    _roots: tempfile::TempDir,
    assets: tempfile::TempDir,
    layer: SemanticLayer,
    document: Value,
}

fn rig(artifact_key: &[&str]) -> Rig {
    let document = fixture();
    let roots = tempfile::tempdir().unwrap();
    let artifact = artifact_key.iter().fold(&document, |value, key| &value[*key]).as_str().unwrap().to_string();
    std::fs::write(roots.path().join(format!("{PRETRAINED_CONTEXT_MODEL_ID}.json")), artifact).unwrap();
    let assets = tempfile::tempdir().unwrap();
    std::fs::write(assets.path().join("model.onnx"), STANDARD.decode(document["onnx_b64"].as_str().unwrap()).unwrap()).unwrap();
    std::fs::write(assets.path().join("tokenizer.json"), document["tokenizer_json"].as_str().unwrap()).unwrap();
    let layer = SemanticLayer::new(vec![roots.path().to_path_buf()], None).unwrap().with_pretrained_context_assets(
        assets.path(),
        document["onnx_sha256"].as_str().unwrap(),
        document["tokenizer_sha256"].as_str().unwrap(),
        backbone(&document),
    );
    Rig { _roots: roots, assets, layer, document }
}

fn run(layer: &SemanticLayer, text: &str) -> LayerExecution {
    layer.run(text, Some(PRETRAINED_CONTEXT_MODEL_ID))
}

fn map(value: &Value) -> BTreeMap<String, String> {
    value.as_object().unwrap().iter().map(|(key, item)| (key.clone(), item.as_str().unwrap().to_string())).collect()
}

fn expected_identity(document: &Value) -> BTreeMap<String, String> {
    let mut identity = map(&document["semantic_identity"]);
    identity.extend(map(&document["context_identity"]));
    identity
}

#[test]
fn findings_metadata_and_identity_equal_the_python_model() {
    let rig = rig(&["artifact"]);
    let mut compared = 0;
    for case in rig.document["model_cases"].as_array().unwrap() {
        let text = case["text"].as_str().unwrap();
        // The pipeline normalises before it classifies; the golden is of text for which that changes nothing.
        if normalize_with_offsets(text, true, None).unwrap().text() != text {
            continue;
        }
        let execution = run(&rig.layer, text);
        assert_eq!((execution.status, execution.error.clone()), (Status::Ok, None), "{text:?}");
        assert_eq!(execution.identity.as_ref(), Some(&expected_identity(&rig.document)), "{text:?}: identity");
        let findings = case["findings"].as_array().unwrap();
        assert_eq!(execution.results.len(), findings.len(), "{text:?}: number of findings");
        for (ours, theirs) in execution.results.iter().zip(findings) {
            assert_eq!(u64::from(ours.classification.pack()), theirs["packed"].as_u64().unwrap(), "{text:?}: classification");
            assert_eq!(ours.reasoning, theirs["reasoning"].as_str().unwrap(), "{text:?}: reasoning");
            assert_eq!(ours.section, theirs["section_of_text"].as_str().unwrap(), "{text:?}: section");
            let span = theirs["span"].as_array().map(|pair| (pair[0].as_u64().unwrap() as usize, pair[1].as_u64().unwrap() as usize));
            assert_eq!(ours.span, span, "{text:?}: span");
            assert_eq!(ours.confidence, theirs["confidence"].as_f64(), "{text:?}: confidence");
            let expected = map(&theirs["metadata"]);
            assert_eq!(ours.metadata.keys().collect::<Vec<_>>(), expected.keys().collect::<Vec<_>>(), "{text:?}: metadata keys");
            for (key, value) in &expected {
                if key == "category_probabilities" {
                    let (ours, theirs): (Value, Value) =
                        (serde_json::from_str(&ours.metadata[key]).unwrap(), serde_json::from_str(value).unwrap());
                    assert_eq!(
                        ours.as_object().unwrap().keys().collect::<Vec<_>>(),
                        theirs.as_object().unwrap().keys().collect::<Vec<_>>()
                    );
                    for (label, probability) in theirs.as_object().unwrap() {
                        let difference = (ours[label].as_f64().unwrap() - probability.as_f64().unwrap()).abs();
                        assert!(difference <= 1.0001e-4, "{text:?}: {label} differs by {difference}");
                    }
                } else {
                    assert_eq!(&ours.metadata[key], value, "{text:?}: metadata {key}");
                }
            }
        }
        compared += 1;
    }
    assert!(compared >= 8, "the golden lost cases ({compared})");
    eprintln!("context semantic golden (LLM-only, semantic layer only): {compared} prompts, findings, metadata and identity equal Python");
}

#[test]
fn heads_that_decide_the_empty_classification_produce_no_finding() {
    let rig = rig(&["clean", "artifact"]);
    let execution = run(&rig.layer, "my name is john smith");
    assert_eq!((execution.status, execution.results.len()), (Status::Ok, 0), "{execution:?}");
    assert!(execution.identity.as_ref().is_some_and(|identity| identity.contains_key("model_id")));
}

#[test]
fn an_overlength_prompt_is_the_layers_error_and_still_names_the_model() {
    let rig = rig(&["artifact"]);
    let execution = run(&rig.layer, &"the ".repeat(300));
    assert_eq!(execution.status, Status::Error);
    assert_eq!(execution.error.as_deref(), Some("Pretrained contextual input exceeds its 256-token context including special tokens."));
    // `pretrained_context_identity` is captured before inference, so a failed layer still carries it.
    let identity = execution.identity.unwrap();
    assert_eq!(identity, map(&rig.document["context_identity"]));
    assert!(identity.keys().all(|key| key.starts_with(CONTEXT_IDENTITY_PREFIX)));
}

#[test]
fn without_verified_assets_the_model_is_the_layers_error() {
    let rig = rig(&["artifact"]);
    // No asset directory configured.
    let roots = tempfile::tempdir().unwrap();
    std::fs::write(roots.path().join(format!("{PRETRAINED_CONTEXT_MODEL_ID}.json")), rig.document["artifact"].as_str().unwrap()).unwrap();
    let bare = SemanticLayer::new(vec![roots.path().to_path_buf()], None).unwrap();
    let execution = run(&bare, "my name is john smith");
    assert_eq!(execution.error.as_deref(), Some("PRIVOKE_PRETRAINED_CONTEXT_DIR must name verified local encoder assets."));
    assert!(execution.identity.is_none() && execution.results.is_empty());
    // The pinned digests do not admit the synthetic files.
    let pinned = SemanticLayer::new(vec![roots.path().to_path_buf()], None).unwrap().with_pretrained_context_dir(rig.assets.path());
    assert_eq!(run(&pinned, "hello").error.as_deref(), Some("Pretrained encoder asset size or SHA-256 does not match."));
    // A directory that does not exist.
    let missing =
        SemanticLayer::new(vec![roots.path().to_path_buf()], None).unwrap().with_pretrained_context_dir(Path::new("no-such-directory"));
    assert_eq!(run(&missing, "hello").status, Status::Error);
}

#[test]
fn an_artifact_that_breaks_the_contract_is_refused() {
    let rig = rig(&["artifact"]);
    let original: Value = serde_json::from_str(rig.document["artifact"].as_str().unwrap()).unwrap();
    let breakers: [Breaker; 7] = [
        ("an unknown key", |artifact| artifact["extra"] = Value::from(1)),
        ("a wrong constant", |artifact| artifact["config"]["pooling"] = Value::from("cls")),
        ("a label order", |artifact| artifact["config"]["category_labels"].as_array_mut().unwrap().swap(0, 1)),
        ("an unsupported context length", |artifact| artifact["config"]["max_tokens"] = Value::from(128)),
        ("a threshold outside (0, 1)", |artifact| artifact["config"]["category_threshold"] = Value::from(1.0)),
        ("a trainable head", |artifact| artifact["parameters"]["head.category.bias"]["trainable"] = Value::Bool(true)),
        ("a missing head", |artifact| {
            artifact["parameters"].as_object_mut().unwrap().remove("head.category.bias");
        }),
    ];
    for (name, break_it) in breakers {
        let mut artifact = original.clone();
        break_it(&mut artifact);
        let roots = tempfile::tempdir().unwrap();
        std::fs::write(roots.path().join(format!("{PRETRAINED_CONTEXT_MODEL_ID}.json")), artifact.to_string()).unwrap();
        let layer = SemanticLayer::new(vec![roots.path().to_path_buf()], None).unwrap().with_pretrained_context_assets(
            rig.assets.path(),
            rig.document["onnx_sha256"].as_str().unwrap(),
            rig.document["tokenizer_sha256"].as_str().unwrap(),
            backbone(&rig.document),
        );
        let execution = run(&layer, "hello");
        assert_eq!(execution.status, Status::Error, "{name}: {execution:?}");
        assert!(execution.results.is_empty(), "{name}");
    }
}
