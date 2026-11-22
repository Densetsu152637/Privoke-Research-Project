//! The pretrained contextual encoder against the Python heads and decision rules, on a synthetic backbone.
//!
//! `tests/fixtures/context_golden.json` is written by `evaluation/generate_pretrained_context_golden.py` (see its
//! docstring). The backbone is a small synthetic export with the structure of the pinned one, written as a real ONNX
//! file; the reference of its computation is a numpy float32 implementation of the exported graph, because the host that
//! made the golden has no onnxruntime. The heads, the decision rules and the findings are the unchanged Python classes.
//! This is therefore a parity test of the Rust port with the Python model over a synthetic backbone, and says nothing
//! about agreement with onnxruntime on the real `model.onnx`.
//!
//! Tolerances (the stage 14 rule): features within 1e-6 (the Rust activations are float64, the reference float32; the
//! largest difference between a float64 and the float32 reference was 4.5e-8 when the golden was made), probabilities
//! within 1e-5, and every decision (labels, categories, whether a finding exists) exactly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use privoke_semantic::SemanticError;
use privoke_semantic::bert::BertConfig;
use privoke_semantic::context::{self, ContextEncoder, ContextModel};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/context_golden.json")).expect("the fixture is JSON")
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

fn onnx(document: &Value) -> Vec<u8> {
    STANDARD.decode(document["onnx_b64"].as_str().unwrap()).unwrap()
}

fn encoder(document: &Value, max_tokens: usize) -> ContextEncoder {
    ContextEncoder::from_bytes(&onnx(document), document["tokenizer_json"].as_str().unwrap().as_bytes(), max_tokens, backbone(document))
        .unwrap()
}

fn floats(value: &Value) -> Vec<f64> {
    value.as_array().unwrap().iter().map(|item| item.as_f64().unwrap()).collect()
}

fn max_difference(ours: &[f32], theirs: &[f64]) -> f64 {
    assert_eq!(ours.len(), theirs.len());
    ours.iter().zip(theirs).map(|(a, b)| (f64::from(*a) - b).abs()).fold(0.0, f64::max)
}

#[test]
fn the_synthetic_backbone_is_read_from_its_onnx_bytes_and_encodes_like_the_reference() {
    let document = fixture();
    assert_eq!(privoke_contracts::digest::sha256_hex(&onnx(&document)), document["onnx_sha256"].as_str().unwrap());
    let encoder = encoder(&document, document["encoder_max_tokens"].as_u64().unwrap() as usize);
    let (mut worst, mut compared, mut refused) = (0f64, 0, 0);
    for case in document["encoder_cases"].as_array().unwrap() {
        let text = case["text"].as_str().unwrap();
        match (encoder.encode_normalized(text), case.get("error")) {
            (Ok(features), None) => {
                worst = worst.max(max_difference(&features, &floats(&case["features"])));
                compared += 1;
            }
            (Err(error), Some(expected)) => {
                assert!(matches!(error, SemanticError::Input(_)), "{text:?}: {error:?}");
                assert_eq!(error.to_string(), expected.as_str().unwrap(), "{text:?}");
                refused += 1;
            }
            (ours, theirs) => panic!("{text:?}: Rust {ours:?}, Python error {theirs:?}"),
        }
    }
    assert!(compared >= 10 && refused >= 2, "the golden lost cases");
    assert!(worst <= 1e-6, "features differ by {worst}");
    eprintln!(
        "context golden: {compared} feature vectors within 1e-6 (largest difference {worst:.2e}), {refused} context-length errors identical"
    );
}

/// The six head tensors of an artifact as the model takes them: three weights, three biases, and the threshold.
fn heads(artifact: &Value) -> ([Vec<f32>; 3], [Vec<f32>; 3], f64) {
    let tensor = |name: &str| -> Vec<f32> {
        artifact["parameters"][name]["values"].as_array().unwrap().iter().map(|v| v.as_f64().unwrap() as f32).collect()
    };
    let weights = ["sensitivity", "visibility", "category"].map(|task| tensor(&format!("head.{task}.weight")));
    let biases = ["sensitivity", "visibility", "category"].map(|task| tensor(&format!("head.{task}.bias")));
    (weights, biases, artifact["config"]["category_threshold"].as_f64().unwrap())
}

fn model(document: &Value, artifact: &Value) -> ContextModel {
    let (weights, biases, threshold) = heads(artifact);
    let max_tokens = document["model_max_tokens"].as_u64().unwrap() as usize;
    ContextModel::new(
        encoder(document, max_tokens),
        [weights[0].as_slice(), weights[1].as_slice(), weights[2].as_slice()],
        [biases[0].as_slice(), biases[1].as_slice(), biases[2].as_slice()],
        threshold,
    )
    .unwrap()
}

#[test]
fn heads_and_decisions_equal_the_python_model() {
    let document = fixture();
    let artifact: Value = serde_json::from_str(document["artifact"].as_str().unwrap()).unwrap();
    let model = model(&document, &artifact);
    let (mut worst_probability, mut worst_feature) = (0f64, 0f64);
    for case in document["model_cases"].as_array().unwrap() {
        let text = case["text"].as_str().unwrap();
        let expected = &case["prediction"];
        let ours = model.predict(text).unwrap();
        worst_feature = worst_feature.max(max_difference(&ours.pooled, &floats(&case["pooled"])));
        // The decisions, exactly.
        assert_eq!(ours.prediction.sensitivity, expected["sensitivity"].as_str().unwrap(), "{text:?}");
        assert_eq!(ours.prediction.visibility, expected["visibility"].as_str().unwrap(), "{text:?}");
        let categories: Vec<&str> = expected["categories"].as_array().unwrap().iter().map(|c| c.as_str().unwrap()).collect();
        assert_eq!(ours.prediction.categories, categories, "{text:?}");
        // The probabilities, within the tolerance.
        for (name, ours, theirs) in [
            ("sensitivity", &ours.sensitivity_probabilities, &expected["sensitivity_probabilities"]),
            ("visibility", &ours.visibility_probabilities, &expected["visibility_probabilities"]),
            ("category", &ours.category_probabilities, &expected["category_probabilities"]),
        ] {
            let difference = max_difference(ours, &floats(theirs));
            worst_probability = worst_probability.max(difference);
            assert!(difference <= 1e-5, "{text:?}: {name} probabilities differ by {difference}");
        }
        assert!((ours.prediction.confidence_raw - expected["confidence"].as_f64().unwrap()).abs() <= 1e-5, "{text:?}: confidence");
        // A finding exists exactly when Python reported one.
        let findings = case["findings"].as_array().unwrap();
        let empty =
            ours.prediction.classification.categories() == 0 && ours.prediction.sensitivity == "S0" && ours.prediction.visibility == "PU";
        assert_eq!(!empty, !findings.is_empty(), "{text:?}");
        if let Some(finding) = findings.first() {
            assert_eq!(
                u64::from(ours.prediction.classification.pack()),
                finding["packed"].as_u64().unwrap(),
                "{text:?}: packed classification"
            );
        }
    }
    assert!(worst_feature <= 1e-6, "features differ by {worst_feature}");
    eprintln!("context golden: 14 predictions, labels exact, probabilities within {worst_probability:.2e} (limit 1e-5)");
}

#[test]
fn heads_that_decide_the_empty_classification_report_no_finding() {
    let document = fixture();
    let artifact: Value = serde_json::from_str(document["clean"]["artifact"].as_str().unwrap()).unwrap();
    let model = model(&document, &artifact);
    for case in document["clean"]["cases"].as_array().unwrap() {
        let text = case["text"].as_str().unwrap();
        let ours = model.predict(text).unwrap();
        assert_eq!((ours.prediction.sensitivity.as_str(), ours.prediction.visibility.as_str()), ("S0", "PU"), "{text:?}");
        assert!(ours.prediction.categories.is_empty(), "{text:?}");
        assert!(case["findings"].as_array().unwrap().is_empty(), "{text:?}: Python reported a finding");
    }
}

#[test]
fn the_assets_are_admitted_by_their_digests_before_they_are_parsed() {
    let document = fixture();
    let (model_bytes, tokenizer) = (onnx(&document), document["tokenizer_json"].as_str().unwrap().to_string());
    let (model_sha, tokenizer_sha) = (document["onnx_sha256"].as_str().unwrap(), document["tokenizer_sha256"].as_str().unwrap());
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("model.onnx"), &model_bytes).unwrap();
    std::fs::write(directory.path().join("tokenizer.json"), &tokenizer).unwrap();
    let config = backbone(&document);

    let loaded = ContextEncoder::load_directory_admitted_by(directory.path(), 12, model_sha, tokenizer_sha, &config).unwrap();
    assert_eq!(loaded.max_tokens(), 12);
    // The synthetic files are not the pinned ones: the product loader refuses them.
    let refused = ContextEncoder::load_directory(directory.path(), 256).unwrap_err();
    assert_eq!(refused.to_string(), "Pretrained encoder asset size or SHA-256 does not match.");
    assert!(ContextEncoder::load_directory_admitted_by(directory.path(), 12, &"0".repeat(64), tokenizer_sha, &config).is_err());
    assert!(ContextEncoder::load_directory_admitted_by(directory.path(), 12, model_sha, &"0".repeat(64), &config).is_err());
    // A missing file, and a tampered one, are refused too.
    std::fs::write(directory.path().join("tokenizer.json"), format!("{tokenizer} ")).unwrap();
    assert!(ContextEncoder::load_directory_admitted_by(directory.path(), 12, model_sha, tokenizer_sha, &config).is_err());
    std::fs::remove_file(directory.path().join("model.onnx")).unwrap();
    assert!(ContextEncoder::load_directory_admitted_by(directory.path(), 12, model_sha, tokenizer_sha, &config).is_err());
}

#[test]
fn the_pinned_constants_are_the_python_ones() {
    assert_eq!(context::MODEL_ID, "privoke-pretrained-context-minilm");
    assert_eq!(context::ARCHITECTURE, "privoke_pretrained_context_v1");
    assert_eq!(context::BACKBONE_SHA256, "6fd5d72fe4589f189f8ebc006442dbb529bb7ce38f8082112682524616046452");
    assert_eq!(context::TOKENIZER_SHA256, "be50c3628f2bf5bb5e3a7f17b1f74611b2561a3a27eeab05e5aa30f411572037");
    let config = context::minilm_config();
    assert_eq!((config.hidden_size, config.num_hidden_layers, config.num_attention_heads, config.intermediate_size), (384, 6, 12, 1536));
}

#[test]
fn a_backbone_that_does_not_match_its_configuration_is_refused() {
    let document = fixture();
    let mut config = backbone(&document);
    config.num_hidden_layers = 2;
    let error = ContextEncoder::from_bytes(&onnx(&document), document["tokenizer_json"].as_str().unwrap().as_bytes(), 12, config.clone());
    assert!(error.is_err(), "two layers were asked for and the export has one");
    config.num_hidden_layers = 1;
    config.hidden_size += 12;
    assert!(ContextEncoder::from_bytes(&onnx(&document), document["tokenizer_json"].as_str().unwrap().as_bytes(), 12, config).is_err());
}
