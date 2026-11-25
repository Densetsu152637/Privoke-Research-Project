//! The whole service with a real W1 worker: access control, the semantic-only rule, parity with the recorded W1 pipe
//! responses, and model refresh. It needs a Python environment that can run the worker; set
//! `PRIVOKE_ANALYSIS_TEST_PYTHON` to its interpreter (the repository's `evaluation/.venv-v1-v3-pipeline` works). Without
//! it the test says so and passes, as the other optional-dependency tests of the workspace do.
//!
//! One test drives every scenario in turn because starting a worker loads torch and the models, which takes much longer
//! than any single check.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use common::{Env, connect, raw_call, repo_root, strip_wall_clock, worker_python};
use privoke_contracts::proto::v1::model_streaming_service_client::ModelStreamingServiceClient;
use privoke_contracts::proto::v1::param_update_service_client::ParamUpdateServiceClient;
use privoke_contracts::proto::v1::{
    AnalyzePromptRequest, ComputePresenceGradientsRequest, ComputeSemanticGradientsRequest, DetectAnnotationPresenceRequest,
    DetectionLayer, ModelParametersRequest, ParameterUpdateRequest, RuntimeHealthRequest,
};
use sha2::{Digest, Sha256};
use tonic::Code;

fn hex_decode(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap()).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn semantic(text: &str) -> AnalyzePromptRequest {
    AnalyzePromptRequest {
        request_id: "t".into(),
        text: text.into(),
        layers: vec![DetectionLayer::Semantic as i32],
        semantic_model_id: "privoke-balanced".into(),
        ..AnalyzePromptRequest::default()
    }
}

/// The torch build that recorded the digests; they are valid only for it.
fn torch_matches_capture(python: &std::path::Path) -> bool {
    let output = std::process::Command::new(python).args(["-c", "import torch; print(torch.__version__)"]).output().unwrap();
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(repo_root().join("tests/conformance/worker-frames/manifest.json")).unwrap()).unwrap();
    String::from_utf8_lossy(&output.stdout).trim() == manifest["environment"]["torch"].as_str().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_service_with_a_real_worker() {
    let Some(python) = worker_python() else {
        eprintln!("PRIVOKE_ANALYSIS_TEST_PYTHON is not set; the real-worker scenarios are skipped");
        return;
    };
    let env = Env::new();
    let models = env.start_model_streaming().await;
    let fuzzer = env.service("fuzzer", "publisher");
    let other = env.service("param-update", "publisher");
    let analysis = env.service("analysis", "runtime");
    let installation = env.installation("alice");
    let config = env.analysis_config(models.internal_addr, &analysis, &python);
    let transport = env.tls_args().into_config().unwrap();
    let bind = "127.0.0.1:0".parse().unwrap();
    let started = std::time::Instant::now();
    let server = privoke_analysis::server::start(&config, bind, transport, Duration::from_millis(50)).await.expect("the service starts");
    eprintln!("analysis service ready in {:?} on {}", started.elapsed(), server.addr);
    let mut fuzzer_client = connect(&env, server.addr, &fuzzer).await;
    let channel = privoke_transport::client::connect(&server.addr.to_string(), &env.client_config(&fuzzer)).await.unwrap();

    // --- the fuzzer is served, and the answer is a semantic-only execution -------------------------------------
    let health = fuzzer_client.health(RuntimeHealthRequest {}).await.unwrap().into_inner();
    assert_eq!((health.service.as_str(), health.status.as_str()), ("privoke-analysis-service", "SERVING"));
    let response = fuzzer_client.analyze_prompt(semantic("My doctor prescribed medication for my diagnosis.")).await.unwrap().into_inner();
    assert!(response.error.is_empty(), "{}", response.error);
    let executed: Vec<i32> = response.layers.iter().map(|layer| layer.layer).collect();
    assert_eq!(executed, [DetectionLayer::Semantic as i32], "only the semantic layer ran");
    assert!(response.layers.iter().all(|layer| layer.status == "ok" && layer.error.is_empty()));

    // --- responses equal the recorded W1 pipe responses ----------------------------------------------------------
    if torch_matches_capture(&python) {
        let capture: serde_json::Value =
            serde_json::from_slice(&std::fs::read(repo_root().join("tests/conformance/worker-frames/analysis.json")).unwrap()).unwrap();
        let mut replayed = 0;
        for case in capture["cases"].as_array().unwrap() {
            let label = case["label"].as_str().unwrap();
            if case["scope"] != "llm_only" || case["method"] != "AnalyzePrompt" || label.contains("v3") {
                continue;
            }
            let frame = hex_decode(case["request_frame_hex"].as_str().unwrap());
            assert_eq!(frame[7], 0, "analysis requests carry no metadata block");
            // The captured request bytes go in untouched and the response bytes come back untouched.
            let answer = raw_call(channel.clone(), "/privoke.v1.PrivokeRuntimeService/AnalyzePrompt", frame[20..].to_vec(), &[])
                .await
                .unwrap_or_else(|status| panic!("{label}: {status}"));
            let digest = hex(&Sha256::digest(strip_wall_clock(&answer, 11, Some(8))));
            assert_eq!(digest, case["response_payload_sha256"].as_str().unwrap(), "{label}");
            replayed += 1;
        }
        eprintln!("replayed {replayed} recorded W1 semantic-only cases through the service: all digests equal");
        assert!(replayed >= 20);
    } else {
        eprintln!("the torch build differs from the capture; the digest replay is skipped");
    }

    // --- the semantic-only rule -------------------------------------------------------------------------------
    for layers in [
        vec![],
        vec![DetectionLayer::Regex as i32],
        vec![DetectionLayer::Ner as i32],
        vec![DetectionLayer::Runtime as i32],
        vec![DetectionLayer::Semantic as i32, DetectionLayer::Ner as i32],
        vec![DetectionLayer::Semantic as i32, DetectionLayer::Semantic as i32],
    ] {
        let mut request = semantic("Email bob@example.com");
        request.layers = layers.clone();
        assert_eq!(fuzzer_client.analyze_prompt(request).await.unwrap_err().code(), Code::InvalidArgument, "{layers:?}");
    }
    // The gradient RPCs are not served at all (stage V3-R8a): `UNIMPLEMENTED`, whatever the layers, with no worker called.
    let mut gradients =
        ComputeSemanticGradientsRequest { request_id: "g".into(), model_id: "privoke-balanced".into(), ..Default::default() };
    assert_eq!(fuzzer_client.compute_semantic_gradients(gradients.clone()).await.unwrap_err().code(), Code::Unimplemented, "empty layers");
    gradients.layers = vec![DetectionLayer::Semantic as i32];
    assert_eq!(fuzzer_client.compute_semantic_gradients(gradients.clone()).await.unwrap_err().code(), Code::Unimplemented);
    assert_eq!(fuzzer_client.compute_underlying_model_gradients(gradients).await.unwrap_err().code(), Code::Unimplemented);
    let presence_gradients =
        ComputePresenceGradientsRequest { request_id: "g".into(), model_id: "privoke-presence-efficient".into(), ..Default::default() };
    assert_eq!(fuzzer_client.compute_presence_gradients(presence_gradients).await.unwrap_err().code(), Code::Unimplemented);
    let presence = DetectAnnotationPresenceRequest { text: "x".into(), layers: vec![DetectionLayer::Regex as i32], ..Default::default() };
    assert_eq!(fuzzer_client.detect_annotation_presence(presence).await.unwrap_err().code(), Code::InvalidArgument);

    // --- access -----------------------------------------------------------------------------------------------
    let mut stranger = connect(&env, server.addr, &other).await;
    assert_eq!(stranger.analyze_prompt(semantic("hello there")).await.unwrap_err().code(), Code::PermissionDenied, "a non-fuzzer service");
    let mut consumer = connect(&env, server.addr, &installation).await;
    assert_eq!(consumer.analyze_prompt(semantic("hello there")).await.unwrap_err().code(), Code::PermissionDenied, "an installation");
    let mut model_identity = connect(&env, server.addr, &analysis).await;
    assert_eq!(
        model_identity.analyze_prompt(semantic("hello there")).await.unwrap_err().code(),
        Code::PermissionDenied,
        "the service's own identity"
    );
    // A publisher RPC and the model RPCs are not served here at all.
    let channel = privoke_transport::client::connect(&server.addr.to_string(), &env.client_config(&fuzzer)).await.unwrap();
    let update = ParameterUpdateRequest {
        source_id: "fuzzer".into(),
        model_id: "privoke-balanced".into(),
        base_version: "v1".into(),
        ..Default::default()
    };
    assert_eq!(
        ParamUpdateServiceClient::new(channel.clone()).submit_parameter_update(update).await.unwrap_err().code(),
        Code::Unimplemented
    );
    let request = ModelParametersRequest { consumer_id: "fuzzer".into(), model_id: "privoke-balanced".into() };
    assert_eq!(ModelStreamingServiceClient::new(channel).get_model_parameters(request).await.unwrap_err().code(), Code::Unimplemented);

    // --- an unknown model is answered as the gRPC path answers it, inside the response --------------------------
    let mut unknown = semantic("My email is bob@example.com");
    unknown.semantic_model_id = "privoke-does-not-exist".into();
    let answer = fuzzer_client.analyze_prompt(unknown).await.unwrap().into_inner();
    assert!(!answer.error.is_empty() || answer.layers.iter().any(|layer| layer.status != "ok"));

    // --- a published update reaches the worker without a restart ---------------------------------------------------
    let artifact_path = env.models.path().join("privoke-balanced.json");
    let mut loaded = privoke_model_streaming::artifact::load_model_artifact(&artifact_path, "privoke-balanced").unwrap().artifact;
    let before = loaded.version.clone();
    loaded.version = format!("{before}-next");
    std::fs::write(&artifact_path, privoke_model_streaming::artifact::to_checked_bytes(&loaded).unwrap()).unwrap();
    let mut seen = BTreeMap::new();
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let answer =
            fuzzer_client.analyze_prompt(semantic("My doctor prescribed medication for my diagnosis.")).await.unwrap().into_inner();
        assert!(answer.error.is_empty(), "{}", answer.error);
        let version = answer.metadata.iter().find(|(key, _)| key.contains("version")).map(|(_, value)| value.clone()).unwrap_or_default();
        seen.insert(version.clone(), ());
        if version.ends_with("-next") {
            break;
        }
    }
    assert!(seen.keys().any(|version| version.ends_with("-next")), "the worker never saw the new version: {:?}", seen.keys());

    server.shutdown().await.unwrap();
    models.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_worker_that_cannot_start_stops_the_service_before_it_binds() {
    let env = Env::new();
    let models = env.start_model_streaming().await;
    let analysis = env.service("analysis", "runtime");
    let mut config = env.analysis_config(models.internal_addr, &analysis, std::path::Path::new("definitely-not-a-python"));
    config.worker.startup_timeout = Duration::from_secs(3);
    let transport = env.tls_args().into_config().unwrap();
    let outcome = privoke_analysis::server::start(&config, "127.0.0.1:0".parse().unwrap(), transport, Duration::from_millis(50)).await;
    assert!(outcome.is_err(), "no worker, no listener");
    models.shutdown().await.unwrap();
}
