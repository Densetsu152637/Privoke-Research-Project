//! Publisher authorisation and identity binding over real mutual TLS, in process, with certificates issued at test time:
//! the UPDSEC rows A1 to A3, T14, R1, R2, R5 and R9 in their in-process form (the same rows run against the built
//! container through `evaluation/update_security.py --target rust`), plus fail-closed startup of the built binary.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::process::Command;
use std::sync::Arc;

use common::{Env, baseline_update, code, config_for, copy_model, engine, generous, gradient, update, version_of};
use privoke_contracts::proto::v1::model_streaming_service_client::ModelStreamingServiceClient;
use privoke_contracts::proto::v1::{HealthRequest, ModelParametersRequest, ParameterUpdateStatusRequest};
use privoke_param_update::engine::{Engine, no_hook, system_clock};
use privoke_param_update::policy::DriftPolicy;
use tonic::{Code, Request};

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

fn named(base: &str, source: &str) -> privoke_contracts::proto::v1::ParameterUpdateRequest {
    let mut request = baseline_update(base, &[]);
    request.source_id = source.to_string();
    request
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

#[tokio::test]
async fn a_publisher_submits_an_update_that_names_itself() {
    let (fixture, fuzzer, ..) = fixture();
    let dir = fixture._directory.path();
    let server = fixture.env.start(Arc::new(engine(dir, &fixture.model, "privoke-baseline")), generous()).await;
    let mut client = fixture.env.updates(server.addr, Some(&fuzzer)).await;
    let base = version_of(&fixture.model);
    let mut request = baseline_update(&base, &[("request_id", "mtls-1")]);
    request.source_id = "server-fuzzer".into();
    let ack = client.submit_parameter_update(request.clone()).await.unwrap().into_inner();
    assert!(ack.accepted);
    assert_eq!(version_of(&fixture.model), ack.applied_version);
    // The recorded provenance is the certificate's name.
    let stored = privoke_param_update::artifact_io::load(&fixture.model).unwrap();
    assert_eq!(stored.typed.metadata()["last_update_source"], "server-fuzzer");
    // The same publisher can look the outcome up, and the replay is idempotent.
    let lookup = ParameterUpdateStatusRequest {
        source_id: "server-fuzzer".into(),
        request_id: "mtls-1".into(),
        request_source_id: String::new(),
        model_id: "privoke-baseline".into(),
        request_fingerprint: String::new(),
    };
    assert!(client.get_parameter_update_status(lookup).await.unwrap().into_inner().found);
    assert_eq!(client.submit_parameter_update(request).await.unwrap().into_inner().applied_version, ack.applied_version);
    assert_eq!(client.health(HealthRequest {}).await.unwrap().into_inner().status, "SERVING");
    server.shutdown().await.unwrap();
}

/// A1: an update with no credential. A3: the same with a bogus bearer token and API key, which are ignored. The model
/// does not change in either case.
#[tokio::test]
async fn a1_a3_a_peer_without_a_certificate_is_refused_and_a_bogus_token_changes_nothing() {
    let (fixture, fuzzer, ..) = fixture();
    let dir = fixture._directory.path();
    let server = fixture.env.start(Arc::new(engine(dir, &fixture.model, "privoke-baseline")), generous()).await;
    let before = std::fs::read(&fixture.model).unwrap();
    let request = baseline_update(&version_of(&fixture.model), &[]);

    let channel = privoke_transport::client::connect(&server.addr.to_string(), &fixture.env.client_config(None)).await;
    if let Ok(channel) = channel {
        let mut client = privoke_contracts::proto::v1::param_update_service_client::ParamUpdateServiceClient::new(channel);
        assert!(client.submit_parameter_update(request.clone()).await.is_err(), "a peer without a certificate was answered");
        let mut bogus = Request::new(request.clone());
        bogus.metadata_mut().insert("authorization", "Bearer invalid-test-token-not-real".parse().unwrap());
        bogus.metadata_mut().insert("x-api-key", "invalid-test-key-not-real".parse().unwrap());
        assert!(client.submit_parameter_update(bogus).await.is_err(), "a bogus token stood in for a certificate");
    }
    assert_eq!(std::fs::read(&fixture.model).unwrap(), before);

    // With a real certificate the same headers are simply ignored: there is no bearer-token path.
    let mut client = fixture.env.updates(server.addr, Some(&fuzzer)).await;
    let mut with_token = Request::new(named(&version_of(&fixture.model), "server-fuzzer"));
    with_token.metadata_mut().insert("authorization", "Bearer invalid-test-token-not-real".parse().unwrap());
    client.submit_parameter_update(with_token).await.unwrap();
    server.shutdown().await.unwrap();
}

/// R1: a valid consumer installation certificate cannot publish. R2: a publisher cannot publish under another
/// principal's name. A registered certificate of the wrong role is refused too, and so is an unregistered one.
#[tokio::test]
async fn r1_r2_only_a_publisher_naming_itself_can_publish() {
    let (fixture, _fuzzer, trainer, impostor, consumer) = fixture();
    let stranger = fixture.env.service("stranger", None);
    let dir = fixture._directory.path();
    let server = fixture.env.start(Arc::new(engine(dir, &fixture.model, "privoke-baseline")), generous()).await;
    let before = std::fs::read(&fixture.model).unwrap();
    let base = version_of(&fixture.model);
    let request = |source: &str| named(&base, source);

    let mut as_consumer = fixture.env.updates(server.addr, Some(&consumer)).await;
    assert_eq!(code(as_consumer.submit_parameter_update(request("server-fuzzer")).await), Code::PermissionDenied, "R1");
    let mut as_trainer = fixture.env.updates(server.addr, Some(&trainer)).await;
    assert_eq!(code(as_trainer.submit_parameter_update(request("trainer")).await), Code::PermissionDenied, "a trainer cannot publish");
    let mut as_stranger = fixture.env.updates(server.addr, Some(&stranger)).await;
    assert_eq!(code(as_stranger.submit_parameter_update(request("stranger")).await), Code::PermissionDenied, "unregistered service");
    // R2: `test-trainer` is a registered publisher, but the source it claims is `server-fuzzer`.
    let mut as_impostor = fixture.env.updates(server.addr, Some(&impostor)).await;
    assert_eq!(code(as_impostor.submit_parameter_update(request("server-fuzzer")).await), Code::PermissionDenied, "R2");
    assert_eq!(std::fs::read(&fixture.model).unwrap(), before, "no refused update changed the model");
    // The same publisher under its own name is accepted, so the refusal above is the binding and nothing else.
    assert!(as_impostor.submit_parameter_update(request("test-trainer")).await.is_ok());
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

/// R9 and the surface: nothing but the three update RPCs is served here, whatever the role.
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

/// R5 over the wire: drift spread across many small updates, each under the per-update bound, is refused at the budget
/// and the model stops changing there.
#[tokio::test]
async fn r5_drift_spread_over_many_small_updates_is_refused_at_the_budget() {
    let (fixture, fuzzer, ..) = fixture();
    let dir = fixture._directory.path();
    let drift = DriftPolicy::Enforce { max_update_l2: 2.0, max_cumulative_l2: 5.5 };
    let bounded = Engine::new(config_for(dir, &fixture.model, "privoke-baseline", drift), system_clock(), no_hook()).unwrap();
    let server = fixture.env.start(Arc::new(bounded), generous()).await;
    let mut client = fixture.env.updates(server.addr, Some(&fuzzer)).await;
    let mut accepted = 0;
    let mut refusal = None;
    for index in 0..20 {
        let mut request = update(
            "server-fuzzer",
            "privoke-baseline",
            &version_of(&fixture.model),
            vec![gradient("head.sensitivity.bias", &[4], &[0.5, 0.5, 0.5, 0.5])],
            &[],
        );
        request.metadata.insert("request_id".into(), format!("r5-{index}"));
        match client.submit_parameter_update(request).await {
            Ok(_) => accepted += 1,
            Err(status) => {
                refusal = Some(status);
                break;
            }
        }
    }
    assert_eq!(accepted, 5, "norm 1.0 per update against a budget of 5.5");
    let refusal = refusal.expect("the budget was never exhausted");
    assert_eq!(refusal.code(), Code::FailedPrecondition);
    let held = std::fs::read(&fixture.model).unwrap();
    let again = update(
        "server-fuzzer",
        "privoke-baseline",
        &version_of(&fixture.model),
        vec![gradient("head.sensitivity.bias", &[4], &[0.5; 4])],
        &[],
    );
    assert_eq!(client.submit_parameter_update(again).await.unwrap_err().code(), Code::FailedPrecondition);
    assert_eq!(std::fs::read(&fixture.model).unwrap(), held);
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
