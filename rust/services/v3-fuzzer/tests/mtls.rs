//! Acceptance check 3 of the second half of stage 21: the V3 fuzzer listener is mutual TLS with a role policy, and a caller that
//! the registry does not list, or that is listed for a role that may only probe health, is refused with `PERMISSION_DENIED`
//! before any cycle exists: no request reaches the runtime or the checkpoint service, no `cycles` row is written and no work
//! directory is created. A registered publisher runs one complete cycle through the real listener, and the fit request that the
//! cycle sends selects exactly the semantic layer.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{Creds, Env, Inputs, Scripted, b64, engine_for, synthetic_golden};
use privoke_contracts::proto::experimental_v3::HealthRequest;
use privoke_contracts::proto::experimental_v3::v3_fuzzer_service_client::V3FuzzerServiceClient;
use privoke_contracts::proto::v1::{FuzzerTrainingRequest, FuzzerTrainingResponse};
use privoke_transport::client::connect;
use privoke_v3_fuzzer::cycle::Engine;
use privoke_v3_fuzzer::pywire::fuzzer_response_bytes;
use privoke_v3_fuzzer::server::{self, ServerHandle, limits_for};
use privoke_v3_fuzzer::service::V3Handler;
use prost::Message;
use tonic::{Code, Request, Status};

struct Stack {
    env: Env,
    scripted: Arc<Scripted>,
    engine: Arc<Engine>,
    handle: ServerHandle,
    request: FuzzerTrainingRequest,
    expected: Vec<u8>,
    health: Vec<u8>,
    state: tempfile::TempDir,
}

/// The first cycle of the synthetic golden (a BC01 heads cycle that the checkpoint service applies), behind the real listener.
async fn start() -> Stack {
    let golden = synthetic_golden();
    let sequence = &golden["sequences"][0];
    let cycle = &sequence["cycles"][0];
    let env = Env::new();
    let state = tempfile::tempdir().unwrap();
    let scripted = Arc::new(Scripted::default());
    let engine = Arc::new(engine_for(sequence, &Inputs::load(), &state.path().join("state"), &scripted).await);
    scripted.set(cycle["answers"].clone());
    let transport = env.tls_args().into_config().unwrap();
    let limits = limits_for(Duration::from_secs(600));
    let handler = V3Handler::new(engine.clone());
    let handle = server::start("127.0.0.1:0".parse().unwrap(), handler, transport, limits, Duration::from_millis(50)).await.unwrap();
    Stack {
        env,
        scripted,
        engine,
        handle,
        request: FuzzerTrainingRequest::decode(b64(cycle["request"].as_str().unwrap()).as_slice()).unwrap(),
        expected: b64(cycle["outcome"]["ok"].as_str().unwrap()),
        health: b64(sequence["health"].as_str().unwrap()),
        state,
    }
}

async fn client(stack: &Stack, creds: Option<&Creds>) -> Result<V3FuzzerServiceClient<tonic::transport::Channel>, Status> {
    let channel = connect(&stack.handle.addr.to_string(), &stack.env.client_config(creds))
        .await
        .map_err(|error| Status::unavailable(error.to_string()))?;
    Ok(V3FuzzerServiceClient::new(channel))
}

fn with_timeout<T>(message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.set_timeout(Duration::from_secs(120));
    request
}

/// Nothing happened: no call reached a dependency, no row exists, and the state directory holds only the database.
async fn assert_no_cycle(stack: &Stack) {
    assert!(stack.scripted.take().is_empty(), "no request reached the runtime or the checkpoint service");
    assert!(stack.engine.rows().await.unwrap().is_empty(), "no cycles row was written");
    let entries: Vec<_> = std::fs::read_dir(stack.state.path().join("state")).unwrap().map(|entry| entry.unwrap().file_name()).collect();
    assert_eq!(entries, vec![std::ffi::OsString::from("cycles.sqlite")], "no work directory was created");
}

#[tokio::test]
async fn a_registered_publisher_runs_a_cycle_through_the_listener() {
    let stack = start().await;
    let publisher = stack.env.service("param-update", Some("publisher"));
    let mut caller = client(&stack, Some(&publisher)).await.unwrap();
    let response: FuzzerTrainingResponse = caller.run_training_cycle(with_timeout(stack.request.clone())).await.unwrap().into_inner();
    assert_eq!(fuzzer_response_bytes(&response), stack.expected);
    assert!(response.accepted);
    assert_eq!(stack.scripted.fit_layers.lock().unwrap().clone(), vec![vec![4]], "the fit request selects exactly the semantic layer");
    assert_eq!(stack.scripted.fit_rows.lock().unwrap().clone(), vec![(64, 16)]);
    let rows = stack.engine.rows().await.unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].2.is_some(), "the response is stored in the row");
    let health = caller.health(with_timeout(HealthRequest {})).await.unwrap().into_inner();
    assert_eq!(health.encode_to_vec(), stack.health);
    stack.handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_trainer_may_run_the_full_encoder_cycle_and_the_identity_is_then_refused_in_the_other_scope() {
    let stack = start().await;
    let trainer = stack.env.service("operator", Some("trainer"));
    let mut caller = client(&stack, Some(&trainer)).await.unwrap();
    caller.run_training_cycle(with_timeout(stack.request.clone())).await.unwrap();
    let status = caller.run_underlying_training_cycle(with_timeout(stack.request.clone())).await.unwrap_err();
    assert_eq!(status.code(), Code::AlreadyExists);
    stack.handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_certificate_the_registry_does_not_list_is_refused_before_any_cycle() {
    let stack = start().await;
    let unregistered = stack.env.service("param-update", None);
    let mut caller = client(&stack, Some(&unregistered)).await.unwrap();
    for status in [
        caller.run_training_cycle(with_timeout(stack.request.clone())).await.unwrap_err(),
        caller.run_underlying_training_cycle(with_timeout(stack.request.clone())).await.unwrap_err(),
        caller.health(with_timeout(HealthRequest {})).await.map(|_| ()).unwrap_err(),
    ] {
        assert_eq!(status.code(), Code::PermissionDenied, "{status:?}");
    }
    assert_no_cycle(&stack).await;
    stack.handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_service_registered_only_for_health_probes_cannot_train() {
    let stack = start().await;
    let probe = stack.env.service("probe", Some("runtime"));
    let mut caller = client(&stack, Some(&probe)).await.unwrap();
    assert_eq!(caller.run_training_cycle(with_timeout(stack.request.clone())).await.unwrap_err().code(), Code::PermissionDenied);
    assert_eq!(caller.run_underlying_training_cycle(with_timeout(stack.request.clone())).await.unwrap_err().code(), Code::PermissionDenied);
    assert_no_cycle(&stack).await;
    caller.health(with_timeout(HealthRequest {})).await.expect("a registered runtime may probe health");
    stack.handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_server_certificate_from_an_untrusted_ca_is_refused_before_any_cycle() {
    let stack = start().await;
    let publisher = stack.env.service("param-update", Some("publisher"));
    let mut tls = stack.env.client_config(Some(&publisher));
    tls.server_ca = stack.env.path("foreign-ca/ca.crt");
    let refused = match connect(&stack.handle.addr.to_string(), &tls).await {
        Err(_) => true,
        Ok(channel) => V3FuzzerServiceClient::new(channel).run_training_cycle(with_timeout(stack.request.clone())).await.is_err(),
    };
    assert!(refused, "a client that does not trust the server certificate sends nothing");
    assert_no_cycle(&stack).await;
    stack.handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_peer_without_a_client_certificate_cannot_reach_the_service() {
    let stack = start().await;
    let refused = match client(&stack, None).await {
        Err(_) => true,
        Ok(mut anonymous) => anonymous.run_training_cycle(with_timeout(stack.request.clone())).await.is_err(),
    };
    assert!(refused, "the handshake or the first call fails");
    assert_no_cycle(&stack).await;
    stack.handle.shutdown().await.unwrap();
}
