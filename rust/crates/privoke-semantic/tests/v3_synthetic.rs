//! V3 inference against torch, on the committed synthetic release: a seeded 3-layer BERT (hidden 32) with random heads,
//! saved and run by the product's own Python classes (`evaluation/generate_semantic_golden.py synthetic`).
//!
//! The release is built with the same file layout and tensor names as the pinned standard releases, so this runs the whole
//! path (safetensors, config, WordPiece vocabulary, encoder, heads, layer) in CI without the local release store.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{Report, check_v3_row, fixtures, read_json};
use privoke_semantic::{SemanticError, V3Model};

fn model() -> V3Model {
    let dir = fixtures().join("v3_synthetic");
    V3Model::from_files(&dir.join("config.json"), &dir.join("model.safetensors"), &dir.join("vocab.txt")).unwrap()
}

#[test]
fn synthetic_release_matches_torch_on_every_row() {
    let golden = read_json(&fixtures().join("v3_synthetic").join("golden.json"));
    assert_eq!(golden["meta"]["layers"], serde_json::json!(["semantic"]), "golden is semantic-only");
    let model = model();
    let mut report = Report::default();
    for row in golden["rows"].as_array().unwrap() {
        check_v3_row(&model, row, &mut report);
    }
    println!("torch {} with {} threads, Python {}", golden["meta"]["torch"], golden["meta"]["threads"], golden["meta"]["python"]);
    assert!(report.rows > 150);
    assert_eq!(report.error_rows, 2, "the two over-length prompts are layer errors");
    assert!(report.finding_rows > 100);
    report.assert_clean("v3 synthetic");
}

#[test]
fn the_thread_count_does_not_change_a_single_bit() {
    let golden = read_json(&fixtures().join("v3_synthetic").join("golden.json"));
    let one = model().with_threads(1);
    let many = model().with_threads(7);
    for row in golden["rows"].as_array().unwrap().iter().take(40) {
        let text = row["text"].as_str().unwrap();
        match (one.logits(text), many.logits(text)) {
            (Ok(a), Ok(b)) => assert_eq!(a, b, "{text:?}"),
            (Err(_), Err(_)) => {}
            other => panic!("threads disagree on {text:?}: {other:?}"),
        }
    }
}

#[test]
fn an_input_over_512_tokens_is_the_python_error() {
    let message = model().tokenize(&"the ".repeat(600)).unwrap_err();
    assert!(matches!(message, SemanticError::Input(_)));
    assert_eq!(message.to_string(), "V3 input exceeds 512 native WordPiece tokens including special tokens.");
}

#[test]
fn a_release_directory_without_a_pinned_manifest_is_refused() {
    let dir = std::env::temp_dir().join(format!("privoke-semantic-unpinned-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for name in ["config.json", "model.safetensors", "vocab.txt"] {
        std::fs::copy(fixtures().join("v3_synthetic").join(name), dir.join(name)).unwrap();
    }
    std::fs::write(dir.join("manifest.json"), b"{}\n").unwrap();
    let error = V3Model::load_release(&dir, "privoke-v3-balanced").unwrap_err();
    assert!(matches!(error, SemanticError::Artifact(_)), "{error}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_checkpoint_with_a_missing_head_is_refused() {
    // Drop the whole file's contents after the header: the header names tensors whose bytes are missing.
    let dir = fixtures().join("v3_synthetic");
    let bytes = std::fs::read(dir.join("model.safetensors")).unwrap();
    let truncated = std::env::temp_dir().join(format!("privoke-semantic-truncated-{}.safetensors", std::process::id()));
    std::fs::write(&truncated, &bytes[..bytes.len() - 64]).unwrap();
    let result = V3Model::from_files(&dir.join("config.json"), &truncated, &dir.join("vocab.txt"));
    std::fs::remove_file(&truncated).unwrap();
    assert!(matches!(result, Err(SemanticError::Artifact(_))));
}
