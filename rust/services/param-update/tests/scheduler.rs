//! The training-cycle scheduler: the ported cases of `test_fuzzer_requests.py` and `test_dual_training_cycles.py`
//! against a scripted fuzzer, and one cycle over real mutual TLS against an in-process fuzzer that admits only registered
//! publishers (the cycle completes; an unregistered scheduler certificate and an untrusted fuzzer certificate are
//! refused before any training request is served).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::Env;
use privoke_contracts::proto::v1::fuzzer_service_server::{FuzzerService, FuzzerServiceServer};
use privoke_contracts::proto::v1::{FuzzerTrainingRequest, FuzzerTrainingResponse, HealthRequest, HealthResponse};
use privoke_param_update::journal::{Journal, Stage};
use privoke_param_update::scheduler::{
    CallError, FuzzerCaller, FuzzerRequestConfig, GrpcFuzzer, build_training_request, client_tls_from_lookup, run,
};
use privoke_transport::{AuthLayer, LimiterKey, Limits, Policy, Role, SecureListener, secure_server};
use prost::Message;
use tonic::{Code, Request, Response, Status};

type Change = Box<dyn Fn(&mut FuzzerRequestConfig)>;

fn configuration(directory: &Path) -> FuzzerRequestConfig {
    FuzzerRequestConfig {
        target: "unused".into(),
        prompt_count: 32,
        model_id: "privoke-balanced".into(),
        source_id: "updater".into(),
        timeout_seconds: 60.0,
        interval_seconds: 0.0,
        initial_delay_seconds: 0.0,
        retry_seconds: 0.0,
        max_attempts: 2,
        seed: 42,
        curriculum_sampler_policy: "deterministic_v1".into(),
        curriculum_sampler_seed: 0,
        train_underlying: true,
        state_path: directory.join("cycles.sqlite3"),
    }
}

fn response(version: &str, base: &str) -> FuzzerTrainingResponse {
    FuzzerTrainingResponse {
        accepted: true,
        model_id: "privoke-balanced".into(),
        base_version: base.into(),
        applied_version: version.into(),
        prompts_generated: 32,
        ..FuzzerTrainingResponse::default()
    }
}

fn transient(message: &str) -> CallError {
    CallError { code: None, message: message.into() }
}

/// A fuzzer that answers from a script and records what it was asked.
#[derive(Default)]
struct Script {
    replies: Mutex<VecDeque<Result<FuzzerTrainingResponse, CallError>>>,
    calls: Mutex<Vec<(Stage, FuzzerTrainingRequest)>>,
}

impl Script {
    fn with(replies: Vec<Result<FuzzerTrainingResponse, CallError>>) -> Self {
        Self { replies: Mutex::new(replies.into()), calls: Mutex::new(Vec::new()) }
    }

    fn recorded(&self) -> Vec<(Stage, FuzzerTrainingRequest)> {
        self.calls.lock().unwrap().clone()
    }
}

impl FuzzerCaller for Script {
    async fn call(&self, stage: Stage, request: FuzzerTrainingRequest, _timeout: Duration) -> Result<FuzzerTrainingResponse, CallError> {
        self.calls.lock().unwrap().push((stage, request));
        self.replies.lock().unwrap().pop_front().unwrap_or_else(|| Err(transient("script exhausted")))
    }
}

// ---- configuration and request construction (test_fuzzer_requests.py)

#[test]
fn the_default_environment_enables_both_periodic_stages() {
    let config = FuzzerRequestConfig::from_lookup(|_| None).unwrap();
    assert!(config.train_underlying);
    assert_eq!(config.prompt_count, 32);
    assert_eq!(config.interval_seconds, 3600.0);
    assert_eq!(config.target, "privoke-fuzzer:50053");
    assert_eq!(config.state_path, Path::new("/data/training-cycles.sqlite3"));
    assert_eq!(config.target_host(), "privoke-fuzzer");
}

#[tokio::test]
async fn a_zero_prompt_count_disables_the_scheduler_without_opening_the_journal() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = configuration(directory.path());
    config.prompt_count = 0;
    let script = Script::default();
    run(&config, &script).await.unwrap();
    assert!(script.recorded().is_empty());
    assert!(!config.state_path.exists());
}

#[test]
fn the_sampler_seed_and_limits_validate() {
    let directory = tempfile::tempdir().unwrap();
    let base = configuration(directory.path());
    let invalid: Vec<Change> = vec![
        Box::new(|config: &mut FuzzerRequestConfig| config.seed = -1),
        Box::new(|config: &mut FuzzerRequestConfig| config.seed = 1 << 32),
        Box::new(|config: &mut FuzzerRequestConfig| config.prompt_count = -1),
        Box::new(|config: &mut FuzzerRequestConfig| config.max_attempts = 0),
        Box::new(|config: &mut FuzzerRequestConfig| config.curriculum_sampler_policy = "bad".into()),
        Box::new(|config: &mut FuzzerRequestConfig| config.curriculum_sampler_seed = 42),
        Box::new(|config: &mut FuzzerRequestConfig| {
            config.curriculum_sampler_policy = "seeded_family_v1".into();
            config.curriculum_sampler_seed = 1 << 32;
        }),
        Box::new(|config: &mut FuzzerRequestConfig| config.timeout_seconds = 0.0),
        Box::new(|config: &mut FuzzerRequestConfig| config.retry_seconds = f64::NAN),
        Box::new(|config: &mut FuzzerRequestConfig| config.interval_seconds = -1.0),
    ];
    for (index, change) in invalid.iter().enumerate() {
        let mut config = base.clone();
        change(&mut config);
        assert!(config.validate().is_err(), "case {index}");
    }
    let mut seeded = base.clone();
    seeded.curriculum_sampler_policy = "seeded_family_v1".into();
    seeded.curriculum_sampler_seed = 42;
    seeded.validate().unwrap();
}

#[test]
fn requests_carry_the_exact_ids_seed_and_expected_prior_base() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = configuration(directory.path());
    config.seed = 1338;
    let heads = build_training_request(&config, "cycle-2-heads", None);
    assert_eq!((heads.request_id.as_str(), heads.seed, heads.prompt_count), ("cycle-2-heads", 1338, 32));
    assert_eq!(heads.metadata["require_full_capability"], "true");
    assert!(!heads.metadata.contains_key("expected_base_version"));
    let full = build_training_request(&config, "cycle-2-full", Some("S1"));
    assert_eq!(full.metadata["expected_base_version"], "S1");
    assert_eq!(full.source_id, "updater");
    assert_eq!(full.model_id, "privoke-balanced");
}

#[test]
fn the_head_only_opt_out_preserves_the_standalone_request_contract() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = configuration(directory.path());
    config.train_underlying = false;
    let request = build_training_request(&config, "head", None);
    let metadata: Vec<(&str, &str)> = request.metadata.iter().map(|(key, value)| (key.as_str(), value.as_str())).collect();
    assert_eq!(metadata, vec![("initiator", "param-update-service")]);
}

#[test]
fn the_sampler_settings_reach_the_request() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = configuration(directory.path());
    config.curriculum_sampler_policy = "seeded_family_v1".into();
    config.curriculum_sampler_seed = 44;
    let request = build_training_request(&config, "full", Some("S1"));
    assert_eq!(request.metadata["curriculum_sampler_policy"], "seeded_family_v1");
    assert_eq!(request.metadata["curriculum_sampler_seed"], "44");
}

// ---- the journal and the loop (test_dual_training_cycles.py)

#[test]
fn a_terminal_partial_cycle_is_followed_by_new_ids_and_the_next_seed() {
    let directory = tempfile::tempdir().unwrap();
    let config = configuration(directory.path());
    let mut journal = Journal::open(&config.state_path).unwrap();
    let mut first = journal.reserve(&config, 10.0).unwrap().unwrap();
    let mut heads = first.stage(Stage::Heads).unwrap().clone();
    heads.state = "accepted".into();
    heads.applied_version = Some("S1".into());
    first.set_stage(Stage::Heads, heads);
    let mut full = first.stage(Stage::FullEncoder).unwrap().clone();
    full.state = "rejected".into();
    first.set_stage(Stage::FullEncoder, full);
    first.state = "partial".into();
    first.finished_at = Some(100.0);
    journal.save(&first).unwrap();
    let mut periodic = config.clone();
    periodic.interval_seconds = 50.0;
    let second = journal.reserve(&periodic, 200.0).unwrap().unwrap();
    assert_eq!(second.seed, first.seed + 1);
    assert_ne!(second.cycle_id, first.cycle_id);
}

#[test]
fn a_completed_cycle_respects_the_remaining_cadence_and_an_explicit_new_payload() {
    let directory = tempfile::tempdir().unwrap();
    let config = configuration(directory.path());
    let mut journal = Journal::open(&config.state_path).unwrap();
    let mut record = journal.reserve(&config, 10.0).unwrap().unwrap();
    record.state = "complete".into();
    record.finished_at = Some(100.0);
    journal.save(&record).unwrap();
    let mut periodic = config.clone();
    periodic.interval_seconds = 50.0;
    assert_eq!(journal.reserve(&periodic, 110.0).unwrap().unwrap().cycle_id, record.cycle_id);
    let mut different = config.clone();
    different.prompt_count = 64;
    assert_ne!(journal.reserve(&different, 110.0).unwrap().unwrap().cycle_id, record.cycle_id);
}

#[tokio::test]
async fn head_then_full_with_a_fresh_base_persisted_requests_and_no_calls_on_a_completed_restart() {
    let directory = tempfile::tempdir().unwrap();
    let config = configuration(directory.path());
    let script = Script::with(vec![Ok(response("S1", "v0")), Ok(response("S2", "S1"))]);
    run(&config, &script).await.unwrap();
    let calls = script.recorded();
    assert_eq!(calls.iter().map(|(stage, _)| *stage).collect::<Vec<_>>(), vec![Stage::Heads, Stage::FullEncoder]);
    assert_eq!(calls[1].1.metadata["expected_base_version"], "S1");
    let record = Journal::open(&config.state_path).unwrap().latest().unwrap().unwrap();
    assert_eq!(record.state, "complete");
    let (heads, full) = (record.stage(Stage::Heads).unwrap(), record.stage(Stage::FullEncoder).unwrap());
    assert_ne!(heads.request_id, full.request_id);
    let persisted =
        FuzzerTrainingRequest::decode(privoke_param_update::util::unhex(full.request_protobuf_hex.as_ref().unwrap()).unwrap().as_slice())
            .unwrap();
    assert_eq!(persisted.metadata["expected_base_version"], "S1");
    assert_eq!(persisted.seed, 42);
    assert_eq!(persisted, calls[1].1);
    // A completed one-shot cycle is not repeated after a restart.
    let idle = Script::default();
    run(&config, &idle).await.unwrap();
    assert!(idle.recorded().is_empty());
}

#[tokio::test]
async fn a_pending_full_stage_resumes_on_restart_without_recalling_the_head_even_if_transport_changes() {
    let directory = tempfile::tempdir().unwrap();
    let config = configuration(directory.path());
    let first = Script::with(vec![Ok(response("S1", "v0")), Err(transient("lost ack")), Err(transient("offline"))]);
    run(&config, &first).await.unwrap();
    let before = Journal::open(&config.state_path).unwrap().latest().unwrap().unwrap();
    assert_eq!(before.state, "pending");
    assert_eq!(before.stage(Stage::FullEncoder).unwrap().attempt_errors.len(), 2);

    let mut moved = config.clone();
    moved.target = "new-target".into();
    moved.timeout_seconds = 90.0;
    let second = Script::with(vec![Ok(response("S2", "S1"))]);
    run(&moved, &second).await.unwrap();
    let calls = second.recorded();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, Stage::FullEncoder);
    assert_eq!(calls[0].1.request_id, before.stage(Stage::FullEncoder).unwrap().request_id);
}

#[tokio::test]
async fn a_lost_head_acknowledgement_retries_the_identical_identity_and_seed() {
    let directory = tempfile::tempdir().unwrap();
    let config = configuration(directory.path());
    let script = Script::with(vec![Err(transient("lost")), Ok(response("S1", "v0")), Ok(response("S2", "S1"))]);
    run(&config, &script).await.unwrap();
    let calls = script.recorded();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0], calls[1]);
    assert_eq!(calls[0].1.seed, calls[1].1.seed);
}

#[tokio::test]
async fn a_terminal_full_safety_rejection_retains_the_head_and_reports_partial() {
    let directory = tempfile::tempdir().unwrap();
    let config = configuration(directory.path());
    let rejection = CallError { code: Some(Code::FailedPrecondition), message: "candidate is worse".into() };
    let script = Script::with(vec![Ok(response("S1", "v0")), Err(rejection)]);
    run(&config, &script).await.unwrap();
    let record = Journal::open(&config.state_path).unwrap().latest().unwrap().unwrap();
    assert_eq!(record.state, "partial");
    assert_eq!(record.stage(Stage::Heads).unwrap().state, "accepted");
    assert_eq!(record.stage(Stage::FullEncoder).unwrap().state, "rejected");
    assert_eq!(record.stage(Stage::FullEncoder).unwrap().physical_attempts, 1, "a definite rejection is not retried");
    let idle = Script::default();
    run(&config, &idle).await.unwrap();
    assert!(idle.recorded().is_empty());
}

#[tokio::test]
async fn an_unacceptable_response_is_a_terminal_rejection() {
    let directory = tempfile::tempdir().unwrap();
    let config = configuration(directory.path());
    let wrong_base = Script::with(vec![Ok(response("S1", "v0")), Ok(response("S2", "other"))]);
    run(&config, &wrong_base).await.unwrap();
    let record = Journal::open(&config.state_path).unwrap().latest().unwrap().unwrap();
    assert_eq!(record.state, "partial");
    assert!(record.stage(Stage::FullEncoder).unwrap().last_error.as_ref().unwrap().contains("head publication base"));
}

#[tokio::test]
async fn a_pending_cycle_with_changed_training_settings_fails_closed_and_zero_disables_both() {
    let directory = tempfile::tempdir().unwrap();
    let config = configuration(directory.path());
    run(&config, &Script::with(vec![Err(transient("offline")), Err(transient("offline"))])).await.unwrap();
    let mut changed = config.clone();
    changed.prompt_count = 64;
    let failure = run(&changed, &Script::default()).await.unwrap_err();
    assert!(failure.to_string().contains("different training settings"), "{failure}");
    let mut disabled = config.clone();
    disabled.prompt_count = 0;
    let idle = Script::default();
    run(&disabled, &idle).await.unwrap();
    assert!(idle.recorded().is_empty());
}

// ---- one cycle over mutual TLS against an in-process fuzzer

#[derive(Clone)]
struct FakeFuzzer {
    served: Arc<AtomicUsize>,
}

#[tonic::async_trait]
impl FuzzerService for FakeFuzzer {
    async fn run_training_cycle(&self, request: Request<FuzzerTrainingRequest>) -> Result<Response<FuzzerTrainingResponse>, Status> {
        self.served.fetch_add(1, Ordering::SeqCst);
        let message = request.into_inner();
        Ok(Response::new(FuzzerTrainingResponse {
            accepted: true,
            model_id: message.model_id,
            base_version: "v0".into(),
            applied_version: "S1".into(),
            prompts_generated: message.prompt_count,
            ..FuzzerTrainingResponse::default()
        }))
    }

    async fn run_underlying_training_cycle(
        &self,
        request: Request<FuzzerTrainingRequest>,
    ) -> Result<Response<FuzzerTrainingResponse>, Status> {
        self.served.fetch_add(1, Ordering::SeqCst);
        let message = request.into_inner();
        Ok(Response::new(FuzzerTrainingResponse {
            accepted: true,
            model_id: message.model_id,
            base_version: message.metadata.get("expected_base_version").cloned().unwrap_or_default(),
            applied_version: "S2".into(),
            prompts_generated: message.prompt_count,
            ..FuzzerTrainingResponse::default()
        }))
    }

    async fn run_presence_training_cycle(
        &self,
        _request: Request<FuzzerTrainingRequest>,
    ) -> Result<Response<FuzzerTrainingResponse>, Status> {
        Err(Status::unimplemented("not part of the scheduler"))
    }

    async fn health(&self, _request: Request<HealthRequest>) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse { service: "privoke-fuzzer".into(), status: "SERVING".into() }))
    }
}

/// Serve the fake fuzzer behind the transport's mutual TLS and a registry that admits only registered publishers.
async fn serve_fuzzer(env: &Env, served: Arc<AtomicUsize>) -> SocketAddr {
    let transport = env.tls_args().into_config().unwrap();
    let limits = Limits::default();
    let listener = SecureListener::bind("127.0.0.1:0".parse().unwrap(), transport.tls.clone(), limits.clone()).await.unwrap();
    let address = listener.local_addr().unwrap();
    let policy = Policy::new().allow("/privoke.v1.FuzzerService/RunTrainingCycle", &[Role::Publisher], LimiterKey::Identity).allow(
        "/privoke.v1.FuzzerService/RunUnderlyingTrainingCycle",
        &[Role::Publisher],
        LimiterKey::Identity,
    );
    let auth = AuthLayer::new(policy, transport.registry.registry(), limits.rate);
    let server = secure_server(&limits, auth).add_service(FuzzerServiceServer::new(FakeFuzzer { served }));
    tokio::spawn(async move {
        let _keep_alive = transport;
        let _ = server.serve_with_incoming(listener.incoming()).await;
    });
    address
}

#[tokio::test]
async fn one_cycle_completes_against_the_fuzzer_over_mutual_tls() {
    let env = Env::new();
    let scheduler = env.service("param-update", Some("publisher"));
    let served = Arc::new(AtomicUsize::new(0));
    let address = serve_fuzzer(&env, served.clone()).await;
    let directory = tempfile::tempdir().unwrap();
    let mut config = configuration(directory.path());
    config.target = address.to_string();
    let caller = GrpcFuzzer::new(config.target.clone(), env.client_config(Some(&scheduler)));
    run(&config, &caller).await.unwrap();
    assert_eq!(served.load(Ordering::SeqCst), 2);
    let record = Journal::open(&config.state_path).unwrap().latest().unwrap().unwrap();
    assert_eq!(record.state, "complete");
    assert_eq!(record.stage(Stage::Heads).unwrap().applied_version.as_deref(), Some("S1"));
    assert_eq!(record.stage(Stage::FullEncoder).unwrap().applied_version.as_deref(), Some("S2"));
}

#[tokio::test]
async fn the_scheduler_is_refused_when_its_certificate_is_not_registered() {
    let env = Env::new();
    // Signed by the client CA, so the handshake succeeds, but never registered as a publisher.
    let unregistered = env.service("param-update", None);
    let served = Arc::new(AtomicUsize::new(0));
    let address = serve_fuzzer(&env, served.clone()).await;
    let directory = tempfile::tempdir().unwrap();
    let mut config = configuration(directory.path());
    config.target = address.to_string();
    config.max_attempts = 1;
    let caller = GrpcFuzzer::new(config.target.clone(), env.client_config(Some(&unregistered)));
    run(&config, &caller).await.unwrap();
    assert_eq!(served.load(Ordering::SeqCst), 0, "the fuzzer served nothing");
    let record = Journal::open(&config.state_path).unwrap().latest().unwrap().unwrap();
    assert_eq!(record.state, "pending");
    assert!(record.stage(Stage::Heads).unwrap().last_error.as_ref().unwrap().contains("PermissionDenied"));
}

#[tokio::test]
async fn the_scheduler_refuses_a_fuzzer_certificate_from_an_untrusted_ca() {
    let env = Env::new();
    let scheduler = env.service("param-update", Some("publisher"));
    let served = Arc::new(AtomicUsize::new(0));
    let address = serve_fuzzer(&env, served.clone()).await;
    let directory = tempfile::tempdir().unwrap();
    let mut config = configuration(directory.path());
    config.target = address.to_string();
    config.max_attempts = 1;
    let mut tls = env.client_config(Some(&scheduler));
    tls.server_ca = env.path("foreign-ca/ca.crt");
    let caller = GrpcFuzzer::new(config.target.clone(), tls);
    run(&config, &caller).await.unwrap();
    assert_eq!(served.load(Ordering::SeqCst), 0);
    let record = Journal::open(&config.state_path).unwrap().latest().unwrap().unwrap();
    assert_eq!(record.state, "pending");
}

#[test]
fn the_scheduler_credentials_are_required_files() {
    let directory = tempfile::tempdir().unwrap();
    let config = configuration(directory.path());
    assert!(client_tls_from_lookup(&config, |_| None).is_err());
    let file = directory.path().join("credential.pem");
    std::fs::write(&file, b"synthetic").unwrap();
    let path = file.to_string_lossy().to_string();
    let lookup = |key: &str| match key {
        "PRIVOKE_TLS_CA_FILE" | "PRIVOKE_TLS_CERT_FILE" | "PRIVOKE_TLS_KEY_FILE" => Some(path.clone()),
        _ => None,
    };
    let spec = client_tls_from_lookup(&config, lookup).unwrap();
    assert_eq!(spec.server_name, "unused");
    assert!(spec.identity.is_some());
    let empty = directory.path().join("empty.pem");
    std::fs::write(&empty, b"").unwrap();
    let empty_path = empty.to_string_lossy().to_string();
    assert!(client_tls_from_lookup(&config, |key| (key == "PRIVOKE_TLS_CA_FILE").then(|| empty_path.clone())).is_err());
}
