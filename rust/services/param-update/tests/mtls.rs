//! Authorisation over real mutual TLS, in process, with certificates issued at test time: the UPDSEC rows T14 and R9 in their
//! in-process form, the removal of `SubmitParameterUpdate` (stage V3-R8b: `UNIMPLEMENTED` for every role, and the model never
//! changes), plus fail-closed startup of the built binary.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::process::Command;
use std::sync::Arc;

use common::{Env, code, copy_model, engine, generous};
use privoke_contracts::proto::v1::ParameterUpdateRequest;
use privoke_contracts::proto::v1::model_streaming_service_client::ModelStreamingServiceClient;
use privoke_contracts::proto::v1::{HealthRequest, ModelParametersRequest, ParameterUpdateStatusRequest};
use tonic::Code;

const BINARY: &str = env!("CARGO_BIN_EXE_param-update-service");

fn status_of(source: &str) -> ParameterUpdateStatusRequest {
    ParameterUpdateStatusRequest {
        source_id: source.into(),
        request_id: "never-issued".into(),
        request_source_id: String::new(),
        model_id: "privoke-baseline".into(),
        request_fingerprint: String::new(),
    }
}

struct Fixture {
    env: Env,
    model: std::path::PathBuf,
    _directory: tempfile::TempDir,
}

fn fixture() -> (Fixture, common::Creds, common::Creds, common::Creds, common::Creds) {
    let env = Env::new();
    let directory = tempfile::tempdir().unwrap();
    let model = copy_model(directory.path(), "privoke-baseline");
    // Everything is registered before the server starts: the registry reloads by polling.
    let fuzzer = env.service("server-fuzzer", Some("publisher"));
    let trainer = env.service("trainer", Some("trainer"));
    let impostor = env.service("test-trainer", Some("publisher"));
    let consumer = env.installation("consumer", true);
    (Fixture { env, model, _directory: directory }, fuzzer, trainer, impostor, consumer)
}

/// `SubmitParameterUpdate` was removed with V1 training (stage V3-R8b): it is not in the policy, so even a registered publisher
/// naming itself gets `UNIMPLEMENTED`, and a peer without a certificate never gets an answer.
#[tokio::test]
async fn submit_parameter_update_is_unimplemented_and_changes_nothing() {
    let (fixture, fuzzer, trainer, _impostor, consumer) = fixture();
    let dir = fixture._directory.path();
    let server = fixture.env.start(Arc::new(engine(dir, &fixture.model, "privoke-baseline")), generous()).await;
    let before = std::fs::read(&fixture.model).unwrap();
    let request = ParameterUpdateRequest {
        source_id: "server-fuzzer".into(),
        model_id: "privoke-baseline".into(),
        base_version: "v1".into(),
        ..Default::default()
    };
    for creds in [&fuzzer, &trainer, &consumer] {
        let mut client = fixture.env.updates(server.addr, Some(creds)).await;
        assert_eq!(code(client.submit_parameter_update(request.clone()).await), Code::Unimplemented);
    }
    let channel = privoke_transport::client::connect(&server.addr.to_string(), &fixture.env.client_config(None)).await;
    if let Ok(channel) = channel {
        let mut client = privoke_contracts::proto::v1::param_update_service_client::ParamUpdateServiceClient::new(channel);
        assert!(client.submit_parameter_update(request).await.is_err(), "a peer without a certificate was answered");
    }
    assert_eq!(std::fs::read(&fixture.model).unwrap(), before);
    server.shutdown().await.unwrap();
}

/// T14: the receipt lookup needs a certificate and a publisher or trainer role, and binds the source id too.
#[tokio::test]
async fn t14_the_receipt_lookup_is_authenticated_and_bound() {
    let (fixture, fuzzer, trainer, _impostor, consumer) = fixture();
    let dir = fixture._directory.path();
    let server = fixture.env.start(Arc::new(engine(dir, &fixture.model, "privoke-baseline")), generous()).await;

    let channel = privoke_transport::client::connect(&server.addr.to_string(), &fixture.env.client_config(None)).await;
    if let Ok(channel) = channel {
        let mut client = privoke_contracts::proto::v1::param_update_service_client::ParamUpdateServiceClient::new(channel);
        assert!(client.get_parameter_update_status(status_of("updsec-unknown")).await.is_err(), "T14");
    }
    let mut as_consumer = fixture.env.updates(server.addr, Some(&consumer)).await;
    assert_eq!(code(as_consumer.get_parameter_update_status(status_of("consumer")).await), Code::PermissionDenied);
    let mut as_trainer = fixture.env.updates(server.addr, Some(&trainer)).await;
    assert!(!as_trainer.get_parameter_update_status(status_of("trainer")).await.unwrap().into_inner().found);
    assert_eq!(code(as_trainer.get_parameter_update_status(status_of("server-fuzzer")).await), Code::PermissionDenied, "claimed source");
    let mut as_fuzzer = fixture.env.updates(server.addr, Some(&fuzzer)).await;
    assert!(!as_fuzzer.get_parameter_update_status(status_of("server-fuzzer")).await.unwrap().into_inner().found);
    // A trainer reads status and health; it never publishes.
    assert_eq!(as_trainer.health(HealthRequest {}).await.unwrap().into_inner().service, "param-update-service");
    server.shutdown().await.unwrap();
}

/// R9 and the surface: nothing but the status, health and checkpoint RPCs is served here, whatever the role.
#[tokio::test]
async fn r9_other_services_methods_are_unimplemented_on_this_listener() {
    let (fixture, fuzzer, _trainer, _impostor, consumer) = fixture();
    let dir = fixture._directory.path();
    let server = fixture.env.start(Arc::new(engine(dir, &fixture.model, "privoke-baseline")), generous()).await;
    for creds in [&fuzzer, &consumer] {
        let channel = privoke_transport::client::connect(&server.addr.to_string(), &fixture.env.client_config(Some(creds))).await.unwrap();
        let mut models = ModelStreamingServiceClient::new(channel);
        let request = ModelParametersRequest { consumer_id: String::new(), model_id: "privoke-baseline".into() };
        assert_eq!(code(models.get_model_parameters(request.clone()).await), Code::Unimplemented);
        assert_eq!(code(models.get_model_package(request).await), Code::Unimplemented);
    }
    server.shutdown().await.unwrap();
}

#[test]
fn startup_fails_closed_without_the_five_tls_inputs_and_has_no_insecure_flag() {
    let directory = tempfile::tempdir().unwrap();
    let silent = |arguments: &[&str]| {
        Command::new(BINARY)
            .args(arguments)
            .env("PARAM_UPDATE_STORAGE_PATH", directory.path().join("updates.jsonl"))
            .env("MODEL_ARTIFACT_PATH", directory.path().join("absent.json"))
            .env("PARAM_UPDATE_BIND", "127.0.0.1")
            .env("FUZZER_PROMPT_COUNT", "0")
            .output()
            .unwrap()
    };
    let bare = silent(&[]);
    assert!(!bare.status.success());
    assert!(String::from_utf8_lossy(&bare.stderr).contains("--cert"), "{}", String::from_utf8_lossy(&bare.stderr));
    for flag in ["--insecure", "--plaintext", "--allow-insecure"] {
        let refused = silent(&[flag]);
        assert!(!refused.status.success(), "{flag}");
        assert!(String::from_utf8_lossy(&refused.stderr).contains("unexpected argument"), "{flag}");
    }
    assert!(!directory.path().join("updates.jsonl").exists(), "nothing was opened before the verifier");
}
