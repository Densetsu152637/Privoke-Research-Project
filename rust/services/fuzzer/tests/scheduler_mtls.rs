//! Acceptance check 2 of stage 21: the stage 5 scheduler interoperates with the Rust fuzzer over mutual TLS.
//!
//! The real scheduler (`privoke_param_update::scheduler::run` with its mutual-TLS `GrpcFuzzer` and its journal) calls the
//! real Rust fuzzer service (`privoke_fuzzer::server::start` with the stage 1 transport and the fuzzer's role policy)
//! through one dual cycle: the head stage, then the full-encoder stage on the head stage's published version. The
//! runtime and the parameter-update service behind the fuzzer are scripted (the runtime from a recorded response, with
//! the full-encoder tensors synthesised from its model configuration), so the cycle runs end to end without a stack.
//! Further cases check the access policy: an unregistered certificate, a certificate registered for a role that may only
//! probe health, and a server certificate from an untrusted CA are all refused before any cycle is served.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use common::{Env, FULL_PATH, HEADS_PATH, ScriptedRuntime, ScriptedUpdates, Wire, b64, read_golden};
use privoke_contracts::fingerprint::parameter_fingerprint;
use privoke_contracts::json;
use privoke_contracts::proto::v1::{ComputeSemanticGradientsResponse, ParameterUpdateAck, RuntimeParameterDelta};
use privoke_fuzzer::config::{FuzzerConfig, Scope};
use privoke_fuzzer::cycle::Engine;
use privoke_fuzzer::runtime::{FULL_ENCODER_STRATEGY, full_encoder_tensor_shapes};
use privoke_fuzzer::server;
use privoke_fuzzer::service::FuzzerHandler;
use privoke_param_update::journal::{Journal, Stage};
use privoke_param_update::scheduler::{FuzzerRequestConfig, GrpcFuzzer, run};
use prost::Message;

const MODEL: &str = "privoke-baseline";

fn scheduler_configuration(directory: &std::path::Path, target: String) -> FuzzerRequestConfig {
    FuzzerRequestConfig {
        target,
        prompt_count: 32,
        model_id: MODEL.into(),
        source_id: "updater".into(),
        timeout_seconds: 60.0,
        interval_seconds: 0.0,
        initial_delay_seconds: 0.0,
        retry_seconds: 0.0,
        max_attempts: 1,
        seed: 42,
        curriculum_sampler_policy: "deterministic_v1".into(),
        curriculum_sampler_seed: 0,
        train_underlying: true,
        state_path: directory.join("cycles.sqlite3"),
    }
}

/// The recorded head response of the golden, rewritten per request, and the full-encoder response derived from it.
fn runtime_answer(
    template: ComputeSemanticGradientsResponse,
) -> impl FnMut(Scope, &privoke_contracts::proto::v1::ComputeSemanticGradientsRequest) -> Result<ComputeSemanticGradientsResponse, tonic::Status>
+ Send {
    move |scope, request| {
        let mut response = template.clone();
        response.request_id = request.request_id.clone();
        response.model_id = request.model_id.clone();
        if scope == Scope::FullEncoder {
            let config = json::parse(&template.metadata["model_config"]).unwrap();
            let shapes = full_encoder_tensor_shapes(&config).unwrap();
            response.gradients = shapes
                .iter()
                .map(|(name, shape)| RuntimeParameterDelta {
                    name: name.clone(),
                    values: vec![0.0; usize::try_from(shape.iter().product::<u64>()).unwrap()],
                    shape: shape.iter().map(|size| u32::try_from(*size).unwrap()).collect(),
                })
                .collect();
            let empty: BTreeMap<String, Vec<f64>> = shapes.keys().map(|name| (name.clone(), Vec::new())).collect();
            let names: Vec<String> = shapes.keys().map(|name| format!("\"{name}\"")).collect();
            response.metadata.insert("training_scope".into(), "full_encoder".into());
            response.metadata.insert("strategy".into(), FULL_ENCODER_STRATEGY.into());
            response.metadata.insert("trained_parameter_names".into(), format!("[{}]", names.join(", ")));
            response
                .metadata
                .insert("trained_parameter_inventory_fingerprint".into(), parameter_fingerprint(&empty, Some(&shapes)).unwrap());
            // The full-encoder stage trains on the version the head stage published.
            response.base_version = "S1".into();
        }
        Ok(response)
    }
}

struct Stack {
    env: Env,
    wire: Arc<Wire>,
    handle: server::ServerHandle,
}

async fn start(env: Env) -> Stack {
    let golden = read_golden();
    let recorded = golden["sequences"].as_array().unwrap().iter().find(|sequence| sequence["label"] == "recorded-passed").unwrap();
    let template =
        ComputeSemanticGradientsResponse::decode(b64(recorded["cycles"][0]["runtime_response"].as_str().unwrap()).as_slice()).unwrap();
    let dump = env.path("dump");
    let config = FuzzerConfig::from_lookup(|name| match name {
        "FUZZ_CONTEXTUAL_SAMPLING_STRATEGY" => Some("legacy_random_v1".to_string()),
        "MODEL_ID" => Some(MODEL.to_string()),
        "PRIVOKE_FUZZER_DUMP_DIR" => Some(dump.to_string_lossy().to_string()),
        _ => None,
    })
    .unwrap();
    let wire = Arc::new(Wire::default());
    let runtime = Arc::new(ScriptedRuntime::new(wire.clone(), runtime_answer(template)));
    let updates = Arc::new(ScriptedUpdates::new(wire.clone(), |request| ParameterUpdateAck {
        accepted: true,
        model_id: request.model_id.clone(),
        applied_version: if request.metadata.get("training_scope").map(String::as_str) == Some("full_encoder") { "S2" } else { "S1" }
            .into(),
        message: String::new(),
    }));
    let limits = server::limits_for(&config);
    let transport = env.tls_args().into_config().unwrap();
    let handler = FuzzerHandler::new(Arc::new(Engine::new(config, runtime, updates)));
    let handle = server::start("127.0.0.1:0".parse().unwrap(), handler, transport, limits, Duration::from_millis(50)).await.unwrap();
    Stack { env, wire, handle }
}

#[tokio::test]
async fn the_scheduler_completes_a_dual_cycle_against_the_rust_fuzzer_over_mutual_tls() {
    let stack = start(Env::new()).await;
    let scheduler = stack.env.service("param-update", Some("publisher"));
    let directory = tempfile::tempdir().unwrap();
    let config = scheduler_configuration(directory.path(), stack.handle.addr.to_string());
    let caller = GrpcFuzzer::new(config.target.clone(), stack.env.client_config(Some(&scheduler)));
    run(&config, &caller).await.unwrap();

    let record = Journal::open(&config.state_path).unwrap().latest().unwrap().unwrap();
    assert_eq!(record.state, "complete");
    assert_eq!(record.stage(Stage::Heads).unwrap().applied_version.as_deref(), Some("S1"));
    assert_eq!(record.stage(Stage::FullEncoder).unwrap().applied_version.as_deref(), Some("S2"));

    // Semantic-only selection: both gradient requests named exactly the semantic layer, never an empty list.
    let calls = stack.wire.take();
    let runtime: Vec<_> = calls.iter().filter(|(path, _)| path == HEADS_PATH || path == FULL_PATH).collect();
    assert_eq!(runtime.iter().map(|(path, _)| path.as_str()).collect::<Vec<_>>(), vec![HEADS_PATH, FULL_PATH]);
    for (_, bytes) in &runtime {
        let request = privoke_contracts::proto::v1::ComputeSemanticGradientsRequest::decode(bytes.as_slice()).unwrap();
        assert_eq!(request.layers, vec![4]);
        assert_eq!((request.examples.len(), request.heldout_examples.len()), (64, 16));
    }
    stack.handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_certificate_the_registry_does_not_list_is_refused_before_any_cycle() {
    let stack = start(Env::new()).await;
    let unregistered = stack.env.service("param-update", None);
    let directory = tempfile::tempdir().unwrap();
    let config = scheduler_configuration(directory.path(), stack.handle.addr.to_string());
    let caller = GrpcFuzzer::new(config.target.clone(), stack.env.client_config(Some(&unregistered)));
    run(&config, &caller).await.unwrap();
    assert!(stack.wire.take().is_empty(), "nothing reached the runtime or the updater");
    let record = Journal::open(&config.state_path).unwrap().latest().unwrap().unwrap();
    assert_eq!(record.state, "pending");
    assert!(record.stage(Stage::Heads).unwrap().last_error.as_ref().unwrap().contains("PermissionDenied"));
    stack.handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_service_registered_only_for_health_probes_cannot_train() {
    let stack = start(Env::new()).await;
    let probe = stack.env.service("param-update", Some("runtime"));
    let directory = tempfile::tempdir().unwrap();
    let config = scheduler_configuration(directory.path(), stack.handle.addr.to_string());
    let caller = GrpcFuzzer::new(config.target.clone(), stack.env.client_config(Some(&probe)));
    run(&config, &caller).await.unwrap();
    assert!(stack.wire.take().is_empty());
    let record = Journal::open(&config.state_path).unwrap().latest().unwrap().unwrap();
    assert!(record.stage(Stage::Heads).unwrap().last_error.as_ref().unwrap().contains("PermissionDenied"));
    stack.handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn the_scheduler_refuses_a_fuzzer_certificate_from_an_untrusted_ca() {
    let stack = start(Env::new()).await;
    let scheduler = stack.env.service("param-update", Some("publisher"));
    let directory = tempfile::tempdir().unwrap();
    let config = scheduler_configuration(directory.path(), stack.handle.addr.to_string());
    let mut tls = stack.env.client_config(Some(&scheduler));
    tls.server_ca = stack.env.path("foreign-ca/ca.crt");
    let caller = GrpcFuzzer::new(config.target.clone(), tls);
    run(&config, &caller).await.unwrap();
    assert!(stack.wire.take().is_empty());
    let record = Journal::open(&config.state_path).unwrap().latest().unwrap().unwrap();
    assert_eq!(record.state, "pending");
    stack.handle.shutdown().await.unwrap();
}
