//! The recorded W1 gradient and presence responses, reproduced through the service. The inputs are the frames in
//! `tests/conformance/worker-frames/training.json` and the models are the ones that capture used (the prepared
//! full-encoder Tiny release and a presence release), built with the W1 helper. Needs the same optional Python
//! environment as `service.rs`; the digests are valid for the torch build that recorded them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;
use std::time::Duration;

use common::{Env, raw_call, repo_root, strip_wall_clock, worker_python};
use sha2::{Digest, Sha256};
use tonic::Code;

fn hex_decode(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap()).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn torch_matches_capture(python: &Path) -> bool {
    let output = std::process::Command::new(python).args(["-c", "import torch; print(torch.__version__)"]).output().unwrap();
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(repo_root().join("tests/conformance/worker-frames/manifest.json")).unwrap()).unwrap();
    String::from_utf8_lossy(&output.stdout).trim() == manifest["environment"]["torch"].as_str().unwrap()
}

/// Builds the W1 capture's training models with the helper the W1 tests use.
fn build_training_root(python: &Path, directory: &Path) {
    let runtime = repo_root().join("extension/client-runtime");
    let separator = if cfg!(windows) { ";" } else { ":" };
    let path =
        [runtime.join("test"), runtime.clone(), repo_root().join("shared/python"), runtime.join("generated"), repo_root().join("models")]
            .iter()
            .map(|part| part.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(separator);
    let script = "import sys, pathlib, worker_cases; worker_cases.build_training_root(pathlib.Path(sys.argv[1]))";
    let output = std::process::Command::new(python)
        .args(["-c", script])
        .arg(directory)
        .current_dir(&runtime)
        .env("PYTHONPATH", path)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
}

/// `u16 count`, then per entry `u16 key_len`, key, `u32 value_len`, value; returns the entries and the rest.
fn split_metadata(block: &[u8]) -> (Vec<(String, String)>, &[u8]) {
    let count = u16::from_be_bytes([block[0], block[1]]) as usize;
    let mut offset = 2;
    let mut entries = Vec::new();
    for _ in 0..count {
        let key_len = u16::from_be_bytes([block[offset], block[offset + 1]]) as usize;
        offset += 2;
        let key = String::from_utf8(block[offset..offset + key_len].to_vec()).unwrap();
        offset += key_len;
        let value_len = u32::from_be_bytes(block[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let value = String::from_utf8(block[offset..offset + value_len].to_vec()).unwrap();
        offset += value_len;
        entries.push((key, value));
    }
    (entries, &block[offset..])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gradients_and_presence_equal_the_recorded_w1_responses() {
    let Some(python) = worker_python() else {
        eprintln!("PRIVOKE_ANALYSIS_TEST_PYTHON is not set; the gradient parity scenario is skipped");
        return;
    };
    if !torch_matches_capture(&python) {
        eprintln!("the torch build differs from the capture; the gradient parity scenario is skipped");
        return;
    }
    let env = Env::new();
    let training = tempfile::tempdir().unwrap();
    build_training_root(&python, training.path());
    env.overlay_models(training.path());
    let models = env.start_model_streaming().await;
    let fuzzer = env.service("fuzzer", "publisher");
    let analysis = env.service("analysis", "runtime");
    let mut config = env.analysis_config(models.internal_addr, &analysis, &python);
    // The prepared full-encoder release is not a semantic-layer model, so nothing is warmed; models load on demand.
    config.warm_models = vec![];
    let transport = env.tls_args().into_config().unwrap();
    let server =
        privoke_analysis::server::start(&config, "127.0.0.1:0".parse().unwrap(), transport, Duration::from_millis(50)).await.unwrap();
    let channel = privoke_transport::client::connect(&server.addr.to_string(), &env.client_config(&fuzzer)).await.unwrap();

    let capture: serde_json::Value =
        serde_json::from_slice(&std::fs::read(repo_root().join("tests/conformance/worker-frames/training.json")).unwrap()).unwrap();
    let mut compared = 0;
    for case in capture["cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let frame = hex_decode(case["request_frame_hex"].as_str().unwrap());
        let method = frame[6];
        let body = &frame[20..];
        let (entries, message) = if frame[7] & 1 == 1 { split_metadata(body) } else { (Vec::new(), body) };
        let path = match method {
            4 => "/privoke.v1.PrivokeRuntimeService/ComputeSemanticGradients",
            5 => "/privoke.v1.PrivokeRuntimeService/ComputeUnderlyingModelGradients",
            2 => "/privoke.v1.PrivokeRuntimeService/DetectAnnotationPresence",
            6 => "/privoke.v1.PrivokeRuntimeService/ComputePresenceGradients",
            other => panic!("{label}: method {other}"),
        };
        let outcome = raw_call(channel.clone(), path, message.to_vec(), &entries).await;
        if label.contains("wrong-layers") {
            assert_eq!(outcome.unwrap_err().code(), Code::InvalidArgument, "{label}");
            continue;
        }
        let answer = outcome.unwrap_or_else(|status| panic!("{label}: {status}"));
        let normalised = match method {
            2 => strip_wall_clock(&answer, 9, None),
            _ => strip_wall_clock(&answer, 0, Some(6)),
        };
        assert_eq!(hex(&Sha256::digest(&normalised)), case["response_payload_sha256"].as_str().unwrap(), "{label}");
        assert_eq!(normalised.len() as u64, case["response_payload_bytes"].as_u64().unwrap(), "{label}");
        compared += 1;
    }
    eprintln!("{compared} recorded W1 gradient and presence responses reproduced byte for byte through the service");
    assert_eq!(compared, 9);
    server.shutdown().await.unwrap();
    models.shutdown().await.unwrap();
}
