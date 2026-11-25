//! The V3 runtime listener is mutual TLS with a role policy. A caller that the registry does not list is refused with
//! `PERMISSION_DENIED` before any state exists; a registered `runtime` service may probe health and analyse but not fit; a
//! publisher reads the status of an unknown fit. The four `PrivokeRuntimeService` RPCs that the Python runtime never served
//! answer `UNIMPLEMENTED` with the precise gap.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::{Stack, start};
use privoke_contracts::proto::experimental_v3::training_service_client::TrainingServiceClient;
use privoke_contracts::proto::experimental_v3::{FitRequest, HealthRequest, StatusRequest};
use privoke_contracts::proto::v1::privoke_runtime_service_client::PrivokeRuntimeServiceClient;
use privoke_contracts::proto::v1::{ComputeSemanticGradientsRequest, RuntimeHealthRequest};
use privoke_transport::client::connect;
use tonic::transport::Channel;
use tonic::{Code, Request, Status};

async fn channel(stack: &Stack, creds: Option<&common::Creds>) -> Result<Channel, Status> {
    connect(&stack.handle.addr.to_string(), &stack.env.client_config(creds)).await.map_err(|error| Status::unavailable(error.to_string()))
}

fn with_timeout<T>(message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.set_timeout(Duration::from_secs(120));
    request
}

#[tokio::test]
async fn health_reports_the_runtime_role_and_the_capabilities() {
    let stack = start().await;
    let probe = stack.env.service("probe", Some("runtime"));
    let mut client = TrainingServiceClient::new(channel(&stack, Some(&probe)).await.unwrap());
    let health = client.health(with_timeout(HealthRequest {})).await.unwrap().into_inner();
    assert!(health.ready);
    assert_eq!(health.role, "runtime");
    assert_eq!(health.capabilities["device"], "cpu");
    assert_eq!(health.capabilities["threads"], "2");
    assert_eq!(health.capabilities["source_closure"], "test-closure");
    stack.handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn an_unknown_fit_has_the_status_unknown_and_a_started_one_is_reported() {
    let stack = start().await;
    let trainer = stack.env.service("operator", Some("trainer"));
    let mut client = TrainingServiceClient::new(channel(&stack, Some(&trainer)).await.unwrap());
    let receipt = client.get_fit_status(with_timeout(StatusRequest { request_id: "nope".to_string() })).await.unwrap().into_inner();
    assert_eq!(
        (receipt.status.as_str(), receipt.request_id.as_str(), receipt.candidate.as_str(), receipt.reason.as_str()),
        ("unknown", "nope", "", "")
    );
    stack.runtime.store().start("fit-1", "fp").unwrap();
    let receipt = client.get_fit_status(with_timeout(StatusRequest { request_id: "fit-1".to_string() })).await.unwrap().into_inner();
    assert_eq!(receipt.status, "started");
    stack.handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn the_rpcs_the_python_runtime_never_served_answer_unimplemented_with_the_gap() {
    let stack = start().await;
    let trainer = stack.env.service("operator", Some("trainer"));
    let mut client = PrivokeRuntimeServiceClient::new(channel(&stack, Some(&trainer)).await.unwrap());
    let status = client.compute_semantic_gradients(with_timeout(ComputeSemanticGradientsRequest::default())).await.unwrap_err();
    assert_eq!(status.code(), Code::Unimplemented);
    assert!(status.message().contains("ComputeSemanticGradients is not served by the V3 runtime"), "{status:?}");
    let status = client.health(with_timeout(RuntimeHealthRequest::default())).await.unwrap_err();
    assert_eq!(status.code(), Code::Unimplemented);
    assert!(status.message().contains("TrainingService/Health"), "{status:?}");
    stack.handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_certificate_the_registry_does_not_list_is_refused_before_any_work() {
    let stack = start().await;
    let unregistered = stack.env.service("stranger", None);
    let mut training = TrainingServiceClient::new(channel(&stack, Some(&unregistered)).await.unwrap());
    for status in [
        training.health(with_timeout(HealthRequest {})).await.map(|_| ()).unwrap_err(),
        training.get_fit_status(with_timeout(StatusRequest::default())).await.map(|_| ()).unwrap_err(),
        training.fit_candidate(with_timeout(FitRequest::default())).await.map(|_| ()).unwrap_err(),
    ] {
        assert_eq!(status.code(), Code::PermissionDenied, "{status:?}");
    }
    assert!(stack.runtime.store().rows().unwrap().is_empty());
    stack.handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_service_registered_only_for_the_runtime_role_cannot_fit() {
    let stack = start().await;
    let probe = stack.env.service("probe", Some("runtime"));
    let mut training = TrainingServiceClient::new(channel(&stack, Some(&probe)).await.unwrap());
    assert_eq!(training.fit_candidate(with_timeout(FitRequest::default())).await.unwrap_err().code(), Code::PermissionDenied);
    assert_eq!(training.get_fit_status(with_timeout(StatusRequest::default())).await.unwrap_err().code(), Code::PermissionDenied);
    assert!(stack.runtime.store().rows().unwrap().is_empty());
    stack.handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_server_certificate_from_an_untrusted_ca_is_refused() {
    let stack = start().await;
    let trainer = stack.env.service("operator", Some("trainer"));
    let mut tls = stack.env.client_config(Some(&trainer));
    tls.server_ca = stack.env.path("foreign-ca/ca.crt");
    let refused = match connect(&stack.handle.addr.to_string(), &tls).await {
        Err(_) => true,
        Ok(channel) => TrainingServiceClient::new(channel).health(with_timeout(HealthRequest {})).await.is_err(),
    };
    assert!(refused, "a client that does not trust the server certificate sends nothing");
    stack.handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_peer_without_a_client_certificate_cannot_reach_the_service() {
    let stack = start().await;
    let refused = match channel(&stack, None).await {
        Err(_) => true,
        Ok(anonymous) => TrainingServiceClient::new(anonymous).health(with_timeout(HealthRequest {})).await.is_err(),
    };
    assert!(refused, "the handshake or the first call fails");
    stack.handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_checkpoint_service_that_is_not_ready_stops_the_runtime_at_startup() {
    use std::sync::Arc;

    use privoke_v3_fuzzer::source::Closure;
    use privoke_v3_runtime::assets::Admission;
    use privoke_v3_runtime::fit::ScheduleSources;
    use privoke_v3_runtime::service::{Runtime, RuntimeParts};

    let scripted = Arc::new(common::Scripted::default());
    let directory = tempfile::tempdir().unwrap();
    let parts = RuntimeParts {
        directory: directory.path().join("state"),
        threads: 1,
        closure: Closure::Fixed("x".to_string()),
        admission: Admission::Pinned,
        schedules: ScheduleSources { root: std::path::PathBuf::from("."), audience: None },
    };
    let error = Runtime::new(parts, scripted).await.unwrap_err();
    assert_eq!(error.0, "Checkpoint server not ready.");
}
