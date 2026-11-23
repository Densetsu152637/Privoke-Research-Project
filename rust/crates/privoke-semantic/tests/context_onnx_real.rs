//! The Rust pretrained contextual encoder against onnxruntime on the real pinned `model.onnx`.
//!
//! Env-gated, local evidence: the model file is not committed. It runs only when both of these are set (otherwise it says
//! so and passes, like the other optional-asset tests):
//!
//! * `PRIVOKE_PRETRAINED_CONTEXT_DIR`: the directory with the pinned `model.onnx` and `tokenizer.json` (both are verified
//!   against their pins by the loader);
//! * `PRIVOKE_CONTEXT_ONNX_GOLDEN`: the file written by `evaluation/generate_context_encoder_onnx_golden.py`
//!   (onnxruntime 1.23.2, one CPU thread, float32 features of the committed fixture texts; git-ignored under
//!   `tests/local/`).
//!
//! Tolerance: the stage 14 rule that `context.rs` declares for the features, an absolute 1e-6 (the Rust activations are
//! float64, onnxruntime's float32). The maximum difference and the number of bit-identical features are printed.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use privoke_semantic::context::{BACKBONE_SHA256, ContextEncoder, TOKENIZER_SHA256};
use serde_json::Value;

const TOLERANCE: f64 = 1e-6;

fn decode(hex: &str) -> Vec<f32> {
    let bytes: Vec<u8> = (0..hex.len()).step_by(2).map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap()).collect();
    bytes.chunks_exact(4).map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])).collect()
}

#[test]
fn the_encoder_agrees_with_onnxruntime_on_the_real_backbone() {
    let (Some(directory), Some(golden)) =
        (std::env::var_os("PRIVOKE_PRETRAINED_CONTEXT_DIR"), std::env::var_os("PRIVOKE_CONTEXT_ONNX_GOLDEN"))
    else {
        eprintln!(
            "PRIVOKE_PRETRAINED_CONTEXT_DIR and PRIVOKE_CONTEXT_ONNX_GOLDEN are not both set; the real-backbone comparison is skipped"
        );
        return;
    };
    let document: Value = serde_json::from_slice(&std::fs::read(PathBuf::from(golden)).unwrap()).unwrap();
    assert_eq!(document["backbone_sha256"], BACKBONE_SHA256);
    assert_eq!(document["tokenizer_sha256"], TOKENIZER_SHA256);
    let encoder = ContextEncoder::load_directory(&PathBuf::from(directory), 512).expect("the pinned assets load");

    let rows = document["rows"].as_array().unwrap();
    assert!(rows.len() >= 20, "{} rows", rows.len());
    let (mut worst, mut worst_row, mut identical, mut total, mut over) = (0f64, 0usize, 0usize, 0usize, 0usize);
    for (index, row) in rows.iter().enumerate() {
        let expected = decode(row["features_f32_hex"].as_str().unwrap());
        let ours = encoder.encode_normalized(row["text"].as_str().unwrap()).unwrap();
        assert_eq!(ours.len(), expected.len(), "row {index}");
        for (a, b) in ours.iter().zip(&expected) {
            let difference = (f64::from(*a) - f64::from(*b)).abs();
            if difference > worst {
                (worst, worst_row) = (difference, index);
            }
            over += usize::from(difference > TOLERANCE);
            identical += usize::from(a.to_bits() == b.to_bits());
            total += 1;
        }
    }
    let tokens: Vec<u64> = rows.iter().map(|row| row["tokens"].as_u64().unwrap()).collect();
    println!(
        "context encoder vs onnxruntime ({}): {} texts ({} to {} tokens), {total} features, max |difference| {worst:.3e} (row {worst_row}), \
         {identical} bit-identical, {over} above {TOLERANCE:e}",
        document["versions"]["onnxruntime"],
        rows.len(),
        tokens.iter().min().unwrap(),
        tokens.iter().max().unwrap(),
    );
    assert_eq!(over, 0, "features differ from onnxruntime by more than {TOLERANCE:e}; max {worst:e}");
}
