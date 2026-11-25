//! Acceptance check G1 of stage V3-R6: the scheduler runs three tiers x two stages (HEADS, then FULL_ENCODER) through the V3 fuzzer
//! over mutual TLS, journals every allocation before the request, and survives being killed at each boundary.
//!
//! The V3 fuzzer is a fake mutual-TLS `V3FuzzerService`, and the store authority behind it is a table: real weights and the real
//! fit cannot run in CI, and the real gates are exercised on the golden world in `v3_guard.rs`. What the fake does is what the
//! real chain depends on: at the moment it "commits" it looks the request up through [`JournalAllocations`], the table the guard
//! gate reads, and refuses (as the gate would) a request the scheduler did not allocate, on another base, in another scope, at
//! another seed or under another commitment. Killing is `JoinHandle::abort` of the scheduler task at a point the fake chooses.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::Env;
use privoke_contracts::digest::sha256_hex;
use privoke_contracts::proto::experimental_v3::v3_fuzzer_service_server::{V3FuzzerService, V3FuzzerServiceServer};
use privoke_contracts::proto::experimental_v3::{HealthRequest, HealthResponse};
use privoke_contracts::proto::v1::{FuzzerTrainingRequest, FuzzerTrainingResponse};
use privoke_curriculum::v3::BC01_SAMPLER;
use privoke_param_update::error::Result as UpdateResult;
use privoke_param_update::journal::{Journal, JournalAllocations, Stage, TIERS, model_of};
use privoke_param_update::scheduler::{CommitStatus, Commitments, FuzzerRequestConfig, GrpcFuzzer, StoreView, run};
use privoke_param_update::v3_guard::Allocations;
use privoke_transport::startup::CloudTransport;
use privoke_transport::{AuthLayer, LimiterKey, Limits, Policy, Role, SecureListener, secure_server};
use tokio::sync::{Notify, watch};
use tonic::{Request, Response, Status};

const POLICY: &str = "p0licy0licy0licy0licy0licy0licy0licy0licy0licy0licy0licy0licy0licy0lic";

/// The commitment the scheduler allocates and the fake checks.
#[derive(Debug)]
struct Fixed;

impl Commitments for Fixed {
    fn policy_sha256(&self) -> String {
        POLICY.to_string()
    }

    fn commitment(&self, sampler: &str, seed: u32) -> UpdateResult<String> {
        Ok(sha256_hex(format!("{sampler}|{seed}|{POLICY}").as_bytes()))
    }
}

/// How the fake treats a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// Serve it.
    None,
    /// Never answer (the scheduler is killed while it waits): the fit never happened.
    Hang,
    /// Commit, then never answer: the fit and the commit happened, the answer is lost.
    CommitThenHang,
    /// Answer `FAILED_PRECONDITION` without committing: the fit was lost.
    Lost,
}

#[derive(Debug, Default)]
struct World {
    current: BTreeMap<String, String>,
    receipts: BTreeMap<String, CommitStatus>,
    /// `(request_id, model, stage)` of every request the fuzzer received, in order.
    requests: Vec<(String, String, String)>,
    /// The fault to apply to the next request of `(model, stage)`.
    faults: BTreeMap<(String, String), Fault>,
}

#[derive(Debug, Clone)]
struct Shared {
    world: Arc<Mutex<World>>,
    allocations: JournalAllocations,
    entered: Arc<Notify>,
    served: Arc<AtomicUsize>,
}

impl StoreView for Shared {
    fn resolve(&self, model_id: &str) -> UpdateResult<String> {
        Ok(self.world.lock().unwrap().current.get(model_id).cloned().unwrap())
    }

    fn commit_status(&self, request_id: &str) -> UpdateResult<Option<CommitStatus>> {
        Ok(self.world.lock().unwrap().receipts.get(request_id).cloned())
    }
}

struct FakeFuzzer {
    shared: Shared,
}

impl std::fmt::Debug for FakeFuzzer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("FakeFuzzer")
    }
}

impl FakeFuzzer {
    async fn serve(&self, stage: Stage, request: FuzzerTrainingRequest) -> Result<Response<FuzzerTrainingResponse>, Status> {
        let model = request.model_id.clone();
        let fault = {
            let mut world = self.shared.world.lock().unwrap();
            world.requests.push((request.request_id.clone(), model.clone(), stage.name().to_string()));
            world.faults.remove(&(model.clone(), stage.name().to_string())).unwrap_or(Fault::None)
        };
        self.shared.served.fetch_add(1, Ordering::SeqCst);
        // The request is exactly what the scheduler allocates: the metadata of the routine mode and nothing else.
        assert_eq!(request.metadata.keys().map(String::as_str).collect::<Vec<_>>(), ["expected_base", "policy_sha256", "sampler"]);
        assert_eq!(request.metadata["policy_sha256"], POLICY);
        if fault == Fault::Hang {
            self.shared.entered.notify_one();
            std::future::pending::<()>().await;
        }
        if fault == Fault::Lost {
            return Err(Status::failed_precondition("Prior cycle outcome unknown; query runtime/commit status, never replay fit."));
        }
        // A resumed identity whose commit the store already holds is answered from the receipt, never refitted.
        let known = self.shared.world.lock().unwrap().receipts.get(&request.request_id).cloned();
        let base = self.shared.world.lock().unwrap().current.get(&model).cloned().unwrap();
        let candidate = match known {
            Some(status) => status.candidate,
            None => {
                // What the guard gate does at commit time: the journal must hold this request, for this model, scope, seed,
                // base and commitment.
                let allocation = self.shared.allocations.allocation(&request.request_id, &model).expect("the request was allocated");
                assert_eq!(allocation.scope, stage.name());
                assert_eq!(allocation.seed, u64::from(request.seed));
                assert_eq!(allocation.expected_base, request.metadata["expected_base"]);
                assert_eq!(allocation.expected_base, base, "the allocation names the base the store serves");
                assert_eq!(allocation.sampler, request.metadata["sampler"]);
                assert_eq!(allocation.source_commitment, Fixed.commitment(&allocation.sampler, request.seed).unwrap());
                let candidate = sha256_hex(request.request_id.as_bytes());
                let mut world = self.shared.world.lock().unwrap();
                world.current.insert(model.clone(), candidate.clone());
                world.receipts.insert(
                    request.request_id.clone(),
                    CommitStatus { status: "applied".to_string(), candidate: candidate.clone(), reason: String::new() },
                );
                candidate
            }
        };
        if fault == Fault::CommitThenHang {
            self.shared.entered.notify_one();
            std::future::pending::<()>().await;
        }
        let allocation = self.shared.allocations.allocation(&request.request_id, &model).unwrap();
        Ok(Response::new(FuzzerTrainingResponse {
            accepted: true,
            model_id: model,
            base_version: request.metadata["expected_base"].clone(),
            applied_version: candidate,
            prompts_generated: 32,
            message: "applied: ".to_string(),
            metadata: [("routine_commitment".to_string(), allocation.source_commitment)].into_iter().collect(),
        }))
    }
}

#[derive(Debug, Clone)]
struct Handler(Arc<FakeFuzzer>);

#[tonic::async_trait]
impl V3FuzzerService for Handler {
    async fn run_training_cycle(&self, request: Request<FuzzerTrainingRequest>) -> Result<Response<FuzzerTrainingResponse>, Status> {
        self.0.serve(Stage::Heads, request.into_inner()).await
    }

    async fn run_underlying_training_cycle(
        &self,
        request: Request<FuzzerTrainingRequest>,
    ) -> Result<Response<FuzzerTrainingResponse>, Status> {
        self.0.serve(Stage::FullEncoder, request.into_inner()).await
    }

    async fn health(&self, _request: Request<HealthRequest>) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse { ready: true, role: "v3-fuzzer".to_string(), capabilities: BTreeMap::new() }))
    }
}

fn policy() -> Policy {
    let run = [Role::Publisher, Role::Trainer];
    Policy::new()
        .allow("/privoke.experimental.v3.V3FuzzerService/RunTrainingCycle", &run, LimiterKey::Identity)
        .allow("/privoke.experimental.v3.V3FuzzerService/RunUnderlyingTrainingCycle", &run, LimiterKey::Identity)
        .allow("/privoke.experimental.v3.V3FuzzerService/Health", &run, LimiterKey::Identity)
}

/// The fake behind a real mutual-TLS listener with the registry's role policy.
async fn serve_fake(transport: CloudTransport, handler: Handler) -> (std::net::SocketAddr, watch::Sender<bool>) {
    let limits = Limits { request_timeout: Duration::from_secs(120), ..Limits::default() };
    let tls_watcher = transport.tls.spawn_watcher(Duration::from_millis(50));
    let registry_watcher = transport.registry.spawn_watcher(Duration::from_millis(50));
    let registry = transport.registry.registry();
    let listener = SecureListener::bind("127.0.0.1:0".parse().unwrap(), transport.tls.clone(), limits.clone()).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let auth = AuthLayer::new(policy(), registry, limits.rate);
    let (stop, receiver) = watch::channel(false);
    let server = secure_server(&limits, auth).add_service(V3FuzzerServiceServer::new(handler));
    tokio::spawn(async move {
        let _keep = (tls_watcher, registry_watcher, transport);
        let mut receiver = receiver;
        let _ = server
            .serve_with_incoming_shutdown(listener.incoming(), async move {
                let _ = receiver.wait_for(|stop| *stop).await;
            })
            .await;
    });
    (addr, stop)
}

struct Rig {
    env: Env,
    scheduler: common::Creds,
    directory: tempfile::TempDir,
    shared: Shared,
    addr: std::net::SocketAddr,
    stop: watch::Sender<bool>,
}

async fn rig() -> Rig {
    let env = Env::new();
    let directory = tempfile::tempdir().unwrap();
    let journal = directory.path().join("cycles.sqlite3");
    Journal::open(&journal).unwrap();
    let mut world = World::default();
    for tier in TIERS {
        world.current.insert(model_of(tier), sha256_hex(format!("pinned release of {tier}").as_bytes()));
    }
    let shared = Shared {
        world: Arc::new(Mutex::new(world)),
        allocations: JournalAllocations::new(&journal),
        entered: Arc::new(Notify::new()),
        served: Arc::new(AtomicUsize::new(0)),
    };
    let handler = Handler(Arc::new(FakeFuzzer { shared: shared.clone() }));
    // Registered before the listener starts, so that the first request never races the registry reload.
    let scheduler = env.service("param-update", Some("publisher"));
    let transport = env.tls_args().into_config().unwrap();
    let (addr, stop) = serve_fake(transport, handler).await;
    Rig { env, scheduler, directory, shared, addr, stop }
}

impl Rig {
    fn config(&self) -> FuzzerRequestConfig {
        FuzzerRequestConfig {
            target: self.addr.to_string(),
            prompt_count: 32,
            source_id: "param-update".to_string(),
            timeout_seconds: 60.0,
            interval_seconds: 0.0,
            initial_delay_seconds: 0.0,
            retry_seconds: 0.0,
            max_attempts: 2,
            seed: 1337,
            state_path: self.directory.path().join("cycles.sqlite3"),
            policy_file: self.directory.path().join("policy.json"),
            tiers: TIERS.iter().map(|tier| (*tier).to_string()).collect(),
        }
    }

    fn caller(&self, config: &FuzzerRequestConfig) -> GrpcFuzzer {
        GrpcFuzzer::new(config.target.clone(), self.env.client_config(Some(&self.scheduler)))
    }

    fn start(&self) -> tokio::task::JoinHandle<UpdateResult<()>> {
        let config = self.config();
        let caller = self.caller(&config);
        let shared = self.shared.clone();
        tokio::spawn(async move { run(&config, &caller, &shared, &Fixed).await })
    }

    fn journal(&self) -> Journal {
        Journal::open(&self.directory.path().join("cycles.sqlite3")).unwrap()
    }

    fn fault(&self, tier: &str, stage: Stage, fault: Fault) {
        self.shared.world.lock().unwrap().faults.insert((model_of(tier), stage.name().to_string()), fault);
    }

    fn requests(&self) -> Vec<(String, String, String)> {
        self.shared.world.lock().unwrap().requests.clone()
    }
}

fn order() -> Vec<(String, String)> {
    TIERS.iter().flat_map(|tier| [Stage::Heads, Stage::FullEncoder].map(|stage| (model_of(tier), stage.name().to_string()))).collect()
}

#[tokio::test]
async fn a_round_trains_three_tiers_heads_then_full_encoder_each_allocated_before_its_request() {
    let rig = rig().await;
    rig.start().await.unwrap().unwrap();
    let requests = rig.requests();
    assert_eq!(requests.iter().map(|(_, model, stage)| (model.clone(), stage.clone())).collect::<Vec<_>>(), order());
    let journal = rig.journal();
    let rows = journal.allocations(0).unwrap();
    assert_eq!(rows.len(), 6);
    let mut seeds = std::collections::BTreeSet::new();
    let mut previous: BTreeMap<String, String> = BTreeMap::new();
    for row in &rows {
        assert_eq!(row.state, "accepted", "{row:?}");
        assert_eq!(row.sampler, BC01_SAMPLER, "the first round is BC01");
        assert_eq!(row.source_commitment, Fixed.commitment(&row.sampler, row.seed).unwrap());
        assert!(seeds.insert(row.seed), "a fresh seed per allocation");
        // The base is what the store served at the time: the pinned release for HEADS, the HEADS candidate for FULL_ENCODER.
        let expected = previous
            .get(&row.model_id)
            .cloned()
            .unwrap_or_else(|| sha256_hex(format!("pinned release of {}", row.model_id.trim_start_matches("privoke-v3-")).as_bytes()));
        assert_eq!(row.expected_base, expected, "{} {}", row.model_id, row.stage.name());
        previous.insert(row.model_id.clone(), row.candidate.clone().unwrap());
    }
    // The round is complete: a one-shot does not run it again, and the journal says so.
    rig.start().await.unwrap().unwrap();
    assert_eq!(rig.requests().len(), 6);
    let _ = rig.stop.send(true);
}

#[tokio::test]
async fn a_scheduler_killed_before_the_fit_resumes_the_same_identity() {
    let rig = rig().await;
    rig.fault("balanced", Stage::Heads, Fault::Hang);
    let task = rig.start();
    rig.shared.entered.notified().await;
    task.abort();
    let _ = task.await;
    let journal = rig.journal();
    let in_flight: Vec<_> = journal.allocations(0).unwrap().into_iter().filter(|row| row.state == "allocated").collect();
    assert_eq!(in_flight.len(), 1, "the allocation was journalled before the request: {in_flight:?}");
    let row = &in_flight[0];
    assert_eq!((row.model_id.as_str(), row.stage), ("privoke-v3-balanced", Stage::Heads));
    // Restart: the store has no receipt for it, so the same request id is sent again and served; nothing is reallocated.
    rig.start().await.unwrap().unwrap();
    let all = rig.journal().allocations(0).unwrap();
    assert_eq!(all.len(), 6, "no stage was allocated twice");
    assert!(all.iter().all(|settled| settled.state == "accepted"));
    let resent: Vec<_> = rig.requests().into_iter().filter(|(id, ..)| *id == row.request_id).collect();
    assert_eq!(resent.len(), 2, "the same identity was sent before and after the kill");
}

#[tokio::test]
async fn a_scheduler_killed_after_the_commit_asks_the_store_and_does_not_ask_the_fuzzer_again() {
    let rig = rig().await;
    rig.fault("efficient", Stage::FullEncoder, Fault::CommitThenHang);
    let task = rig.start();
    rig.shared.entered.notified().await;
    task.abort();
    let _ = task.await;
    let stuck = rig.journal().allocations(0).unwrap().into_iter().find(|row| row.state == "allocated").unwrap();
    assert_eq!((stuck.model_id.as_str(), stuck.stage), ("privoke-v3-efficient", Stage::FullEncoder));
    let before = rig.requests().len();
    rig.start().await.unwrap().unwrap();
    let after = rig.requests();
    assert!(after.iter().filter(|(id, ..)| *id == stuck.request_id).count() == 1, "the settled request was not sent again");
    assert_eq!(after.len(), before + 4, "only the four stages after it were requested");
    let settled = rig.journal().allocations(0).unwrap().into_iter().find(|row| row.request_id == stuck.request_id).unwrap();
    assert_eq!(settled.state, "accepted");
    assert_eq!(settled.candidate.as_deref(), Some(sha256_hex(stuck.request_id.as_bytes()).as_str()), "settled from the store's receipt");
}

#[tokio::test]
async fn a_lost_fit_is_replaced_by_a_new_request_with_a_new_seed() {
    let rig = rig().await;
    rig.fault("quality", Stage::Heads, Fault::Lost);
    rig.start().await.unwrap().unwrap();
    let rows = rig.journal().allocations(0).unwrap();
    let quality: Vec<_> = rows.iter().filter(|row| row.model_id == "privoke-v3-quality" && row.stage == Stage::Heads).collect();
    assert_eq!(quality.len(), 2, "{quality:?}");
    assert_eq!((quality[0].state.as_str(), quality[0].attempt), ("lost", 0));
    assert_eq!((quality[1].state.as_str(), quality[1].attempt), ("accepted", 1));
    assert_ne!(quality[0].request_id, quality[1].request_id, "a new request id");
    assert_ne!(quality[0].seed, quality[1].seed, "and a new seed");
    assert_eq!(quality[0].expected_base, quality[1].expected_base, "the store did not move");
}

#[tokio::test]
async fn a_request_the_scheduler_did_not_allocate_is_unknown_to_the_guard_table() {
    let rig = rig().await;
    rig.start().await.unwrap().unwrap();
    let table = JournalAllocations::new(rig.directory.path().join("cycles.sqlite3"));
    let row = rig.journal().allocations(0).unwrap().remove(0);
    let found = table.allocation(&row.request_id, &row.model_id).unwrap();
    assert_eq!(
        (found.scope.as_str(), found.seed, found.expected_base.as_str()),
        ("heads", u64::from(row.seed), row.expected_base.as_str())
    );
    assert!(table.allocation("never-allocated", &row.model_id).is_none());
    assert!(table.allocation(&row.request_id, "privoke-v3-quality").is_none(), "the model is part of the key");
    let _ = rig.stop.send(true);
}

#[tokio::test]
async fn the_scheduler_refuses_a_fuzzer_certificate_from_an_untrusted_ca() {
    let rig = rig().await;
    let other = Env::new();
    let scheduler = other.service("param-update", Some("publisher"));
    let config = rig.config();
    let caller = GrpcFuzzer::new(config.target.clone(), other.client_config(Some(&scheduler)));
    let mut config = config;
    config.max_attempts = 1;
    run(&config, &caller, &rig.shared, &Fixed).await.unwrap();
    assert!(rig.requests().is_empty(), "no request reached the fuzzer");
    assert!(rig.journal().allocations(0).unwrap().iter().all(|row| row.state == "allocated"), "the allocations stay in flight");
}
