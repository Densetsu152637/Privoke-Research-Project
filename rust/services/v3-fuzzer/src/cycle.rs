//! `FuzzerServer.run` of `fuzzer_server.py`: one frozen-schedule fit, judged and published, per request identity.
//!
//! The order of the steps is the Python order, because the work directory and the `cycles` row that a failure leaves behind are
//! part of the contract (a retried identity answers from them and never replays a fit):
//!
//! 1. the frozen request is validated and fingerprinted (the scope, the request bytes and, for AU3, the sampler and the release);
//! 2. under one lock, a known identity answers from its row, and a new one is reserved (`response` stays `NULL`) and gets its
//!    work directory with `cycle-request.pb`;
//! 3. the expected base is checked against the private current catalog, the schedule is built, the host's policy and source
//!    commitments are checked, and `source.json` and `fit-request.pb` are written;
//! 4. the fit runs; a failed call is never retried (`fit-status-after-error.pb`), its evidence is validated against the dispatched
//!    source, scope and policy, and the candidate manifest fetched from the checkpoint service must agree with it;
//! 5. `fit-response.pb`, `evidence.json` and `commit-request.pb` are written, the candidate is committed (`unknown-commit.pb` when
//!    the outcome cannot be established), `receipt.pb` is written, and the response is stored in the row.
//!
//! Every fit request lists exactly the semantic layer, `[SEMANTIC]`.
//!
//! # Routine mode (stage V3-R5)
//!
//! [`Mode::Routine`] sits beside the frozen study mode, in the same engine, and changes only how the schedule is chosen. The
//! scheduler is the one allocator of `(request_id, seed, expected_base)`: the fuzzer receives them (`request_id`, `seed`, the
//! `expected_base` metadata) and records them. It builds nothing from a host-supplied commitment:
//!
//! 1. the `sampler` metadata names BC01 or AU3 (both are loaded in routine mode);
//! 2. the fuzzer computes the routine commitment ([`crate::source::routine_commitment`]), which covers the sampler, its pinned
//!    inputs, the Python sources, the policy digest and the scheduler's seed, and none of the schedule's rows;
//! 3. the schedule is built at `routine_guard_seed(seed, commitment)`, so the frozen validators (the runtime's and the checkpoint
//!    store's) hold unchanged, and the guard rows come from `privoke_curriculum::v3::routine_guard_rows`, the one definition,
//!    which must equal the guard of that schedule;
//! 4. `source_commitment` (the digest of the source record, which the runtime requires) and the routine commitment are recorded
//!    in `routine.json` and in the response metadata.
//!
//! A cycle whose process died after the fit is resumed by the same request identity only when the work directory holds its
//! `commit-request.pb`: the recorded commit is looked up with `GetCommitStatus` and, if the store never saw it, re-sent with the
//! same bytes (the store's request-id idempotence makes that safe). Nothing is ever refitted. An identity with no commit on disk
//! stays `FAILED_PRECONDITION`; the scheduler then asks the store for `GetCommitStatus` of the journalled identity and, when the
//! fit was lost, allocates a new request identity (and seed), so a tier never stalls and an identity never carries two contents.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use privoke_contracts::proto::experimental_v3 as v3;
use privoke_contracts::proto::v1::{DetectionLayer, FuzzerTrainingRequest, FuzzerTrainingResponse, RuntimeTrainingExample};
use privoke_curriculum::v3::{self as curriculum, Policy, Schedule, routine_guard_rows, routine_guard_seed};
use privoke_curriculum::value::{self, Value};
use prost::Message;
use serde_json::Value as Serde;
use tokio::sync::Mutex;
use tonic::Status;

use crate::ROLE;
use crate::backend::{CheckpointBackend, FitBackend, assemble_blob};
use crate::contract::{
    MAX_EVIDENCE_BYTES, MAX_MANIFEST_BYTES, canonical, check_sha, digest, parse, publication_passes, to_serde, validate_execution,
    validate_manifest, validate_policy,
};
use crate::error::{Error, Failure, Result, invalid};
use crate::pywire::{fuzzer_request_bytes, fuzzer_response_bytes};
use crate::source::{Closure, Schedules};
use crate::state::{CycleStore, Row};

/// The layer every fit request selects. A request with no layer would select the whole detector pipeline.
const SEMANTIC_LAYER: i32 = DetectionLayer::Semantic as i32;

/// How an engine chooses the schedule of a cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The frozen study mode: one configured sampler, a source the host committed to.
    Frozen,
    /// The routine mode: both samplers, a scheduler-allocated seed per cycle, commitments computed and recorded here.
    Routine,
}

/// What an engine is built from.
#[derive(Debug)]
pub struct EngineParts {
    /// The frozen policy document (`parse(Path(V3_POLICY_FILE).read_bytes())`).
    pub policy: Value,
    /// The sampler and its loaded inputs.
    pub schedules: Schedules,
    /// The state directory: `cycles.sqlite` and one work directory per request.
    pub directory: PathBuf,
    /// How long the runtime may take for one fit.
    pub fit_timeout: Duration,
    /// The source of the `source_closure` of `Health`.
    pub closure: Closure,
}

/// The V3 fuzzer's cycle engine.
pub struct Engine {
    fit: Arc<dyn FitBackend>,
    checkpoint: Arc<dyn CheckpointBackend>,
    schedules: Schedules,
    policy: Policy,
    policy_bytes: Vec<u8>,
    policy_sha256: String,
    policy_serde: Serde,
    directory: PathBuf,
    fit_timeout: Duration,
    closure: Closure,
    routine: Option<Vec<Schedules>>,
    store: Mutex<CycleStore>,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Engine")
            .field("sampler", &self.schedules.sampler())
            .field("policy_sha256", &self.policy_sha256)
            .field("directory", &self.directory)
            .finish_non_exhaustive()
    }
}

fn put(work: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    std::fs::write(work.join(name), bytes)?;
    Ok(())
}

fn abort(status: Status) -> Failure {
    Failure::Abort(status)
}

fn dependency(label: &str, status: &Status) -> Error {
    Error(format!("{label}: {:?}: {}", status.code(), status.message()))
}

impl Engine {
    /// `FuzzerServer.__init__`: validate the policy, open the state, and require both dependencies to report ready.
    pub async fn new(parts: EngineParts, fit: Arc<dyn FitBackend>, checkpoint: Arc<dyn CheckpointBackend>) -> Result<Self> {
        let policy = validate_policy(&parts.policy)?;
        let policy_bytes = canonical(&parts.policy)?;
        let policy_serde = to_serde(&parts.policy)?;
        std::fs::create_dir_all(&parts.directory)?;
        let store = CycleStore::open(&parts.directory)?;
        let runtime = fit.health().await.map_err(|status| dependency("runtime health", &status))?;
        if !runtime.ready {
            return invalid("Dependency not ready.");
        }
        let catalog = checkpoint.health().await.map_err(|status| dependency("checkpoint health", &status))?;
        if !catalog.ready {
            return invalid("Dependency not ready.");
        }
        Ok(Self {
            fit,
            checkpoint,
            schedules: parts.schedules,
            policy,
            policy_sha256: digest(&policy_bytes),
            policy_bytes,
            policy_serde,
            directory: parts.directory,
            fit_timeout: parts.fit_timeout,
            closure: parts.closure,
            routine: None,
            store: Mutex::new(store),
        })
    }

    /// Switch to [`Mode::Routine`] over the given samplers (each at most once). Every request then names its sampler.
    pub fn with_routine(mut self, schedules: Vec<Schedules>) -> Result<Self> {
        let mut names: Vec<&str> = schedules.iter().map(|item| item.sampler().name()).collect();
        names.sort_unstable();
        names.dedup();
        if schedules.is_empty() || names.len() != schedules.len() {
            return invalid("Routine mode needs each sampler once.");
        }
        self.routine = Some(schedules);
        Ok(self)
    }

    /// The mode of this engine.
    pub fn mode(&self) -> Mode {
        if self.routine.is_some() { Mode::Routine } else { Mode::Frozen }
    }

    /// The state directory.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// The work directory of a request identity: `<state>/<sha256(request_id)>`.
    pub fn work_directory(&self, request_id: &str) -> PathBuf {
        self.directory.join(digest(request_id.as_bytes()))
    }

    /// Every row of the `cycles` table, ordered by identity.
    pub async fn rows(&self) -> Result<Vec<Row>> {
        self.store.lock().await.rows()
    }

    /// `Health`: ready, the policy and source identities and the sampler.
    pub fn health(&self) -> std::result::Result<v3::HealthResponse, Status> {
        let closure = self.closure.identity().map_err(|error| Status::unknown(error.0))?;
        let capabilities: BTreeMap<String, String> = [
            ("schema", "1".to_string()),
            ("policy_sha256", self.policy_sha256.clone()),
            ("source_closure", closure),
            ("sampler", self.schedules.sampler().name().to_string()),
        ]
        .into_iter()
        .map(|(key, item)| (key.to_string(), item))
        .collect();
        let mut capabilities = capabilities;
        if let Some(routine) = &self.routine {
            capabilities.insert("mode".to_string(), "routine".to_string());
            capabilities.insert("samplers".to_string(), routine.iter().map(|item| item.sampler().name()).collect::<Vec<_>>().join(","));
        }
        Ok(v3::HealthResponse { ready: true, role: ROLE.to_string(), capabilities })
    }

    /// `RunTrainingCycle` (heads) and `RunUnderlyingTrainingCycle` (full encoder).
    pub async fn run(&self, request: FuzzerTrainingRequest, scope: v3::Scope) -> std::result::Result<FuzzerTrainingResponse, Status> {
        self.cycle(request, scope).await.map_err(Status::from)
    }

    fn fingerprint(&self, schedules: &Schedules, request: &FuzzerTrainingRequest, scope: v3::Scope) -> String {
        let mut payload = (scope as i32).to_string().into_bytes();
        payload.extend_from_slice(&fuzzer_request_bytes(request));
        if self.routine.is_some() {
            payload.extend_from_slice(b"routine");
        }
        if let Some(pin) = schedules.source_pin() {
            payload.extend_from_slice(schedules.sampler().name().as_bytes());
            payload.extend_from_slice(pin.as_bytes());
        } else if self.routine.is_some() {
            payload.extend_from_slice(schedules.sampler().name().as_bytes());
        }
        digest(&payload)
    }

    /// The schedules a request runs over: the configured sampler in the frozen mode, the one the request names in the routine mode.
    fn schedules_for(&self, request: &FuzzerTrainingRequest) -> std::result::Result<&Schedules, Failure> {
        let Some(routine) = &self.routine else { return Ok(&self.schedules) };
        let name = request.metadata.get("sampler").map(String::as_str).unwrap_or_default();
        routine
            .iter()
            .find(|item| item.sampler().name() == name)
            .ok_or_else(|| abort(Status::invalid_argument("Routine request must name a configured sampler.")))
    }

    async fn cycle(&self, request: FuzzerTrainingRequest, scope: v3::Scope) -> std::result::Result<FuzzerTrainingResponse, Failure> {
        let originals = self.policy.window_batches() as u64 * 32;
        if request.request_id.is_empty() || request.request_id.chars().count() > 200 || u64::from(request.prompt_count) != originals {
            return Err(abort(Status::invalid_argument("Frozen request ID/original prompt budget required.")));
        }
        let schedules = self.schedules_for(&request)?;
        let fingerprint = self.fingerprint(schedules, &request, scope);
        let store = self.store.lock().await;
        if let Some(prior) = store.prior(&request.request_id)? {
            if prior.fingerprint != fingerprint {
                return Err(abort(Status::already_exists("Cycle ID reused with different content/scope.")));
            }
            return match prior.response {
                Some(bytes) => FuzzerTrainingResponse::decode(bytes.as_slice()).map_err(|error| Failure::Raised(error.to_string())),
                None if self.routine.is_some() => {
                    let response = self.resume(&request, scope).await?;
                    store.record(&request.request_id, &fuzzer_response_bytes(&response))?;
                    Ok(response)
                }
                None => {
                    Err(abort(Status::failed_precondition("Prior cycle outcome unknown; query runtime/commit status, never replay fit.")))
                }
            };
        }
        store.reserve(&request.request_id, &fingerprint)?;
        let response = self.fit_and_publish(&request, scope, schedules).await?;
        store.record(&request.request_id, &fuzzer_response_bytes(&response))?;
        Ok(response)
    }

    /// The frozen plan: the host already committed to the source record of the seed it sent.
    fn plan_frozen(&self, request: &FuzzerTrainingRequest, schedules: &Schedules) -> std::result::Result<Planned, Failure> {
        let Schedule { training, guard, source } = schedules.schedule(u64::from(request.seed), self.policy)?;
        let source_bytes = value::canonical_bytes(&source).map_err(Error::from)?;
        let source_sha = digest(&source_bytes);
        if request.metadata.get("policy_sha256") != Some(&self.policy_sha256)
            || request.metadata.get("source_commitment") != Some(&source_sha)
        {
            return Err(Failure::Raised("Host frozen policy/source differs from actual dispatched schedule.".to_string()));
        }
        Ok(Planned { training, guard, source, source_bytes, source_sha, routine: None })
    }

    /// The routine plan: the commitment, the schedule seed and the guard rows are computed here from the scheduler's seed.
    fn plan_routine(&self, request: &FuzzerTrainingRequest, schedules: &Schedules) -> std::result::Result<Planned, Failure> {
        if request.metadata.get("policy_sha256") != Some(&self.policy_sha256) {
            return Err(Failure::Raised("Host frozen policy differs from the engine policy.".to_string()));
        }
        let seed = u64::from(request.seed);
        let commitment = schedules.routine_commitment(&self.policy_sha256, seed)?;
        let schedule_seed = routine_guard_seed(seed, &commitment).map_err(Error::from)?;
        let Schedule { training, guard, source } = schedules.schedule(schedule_seed, self.policy)?;
        // The guard rows exist only through the shared selection; the schedule's own guard must be the same rows.
        let selected = routine_guard_rows(schedules.guard_release(), seed, &commitment).map_err(Error::from)?;
        let selected: Vec<_> = selected.iter().map(curriculum::wire).collect::<std::result::Result<_, _>>().map_err(Error::from)?;
        if selected != guard {
            return Err(Failure::Raised("Routine guard rows differ from the frozen source guard.".to_string()));
        }
        let source_bytes = value::canonical_bytes(&source).map_err(Error::from)?;
        let source_sha = digest(&source_bytes);
        if request.metadata.get("source_commitment").is_some_and(|host| *host != source_sha) {
            return Err(Failure::Raised("Host source commitment differs from the routine source.".to_string()));
        }
        let record = value::object(vec![
            ("schema", value::int(1)),
            ("mode", value::string("routine")),
            ("sampler", value::string(schedules.sampler().name())),
            ("request_id", value::string(&request.request_id)),
            ("expected_base", value::string(request.metadata.get("expected_base").map(String::as_str).unwrap_or_default())),
            ("seed", value::uint(seed)),
            ("routine_commitment", value::string(&commitment)),
            ("schedule_seed", value::uint(schedule_seed)),
            ("source_commitment", value::string(&source_sha)),
        ]);
        let routine = RoutinePlan { commitment, schedule_seed, record: value::canonical_bytes(&record).map_err(Error::from)? };
        Ok(Planned { training, guard, source, source_bytes, source_sha, routine: Some(routine) })
    }

    async fn fit_and_publish(
        &self,
        request: &FuzzerTrainingRequest,
        scope: v3::Scope,
        schedules: &Schedules,
    ) -> std::result::Result<FuzzerTrainingResponse, Failure> {
        let id = &request.request_id;
        let work = self.work_directory(id);
        std::fs::create_dir(&work).map_err(Error::from)?;
        put(&work, "cycle-request.pb", &fuzzer_request_bytes(request))?;

        let expected_base = request.metadata.get("expected_base");
        let current = self.checkpoint.resolve_current(&request.model_id).await.map_err(|status| Failure::rpc(&status))?;
        if expected_base != Some(&current.sha256) {
            return Err(Failure::Raised("Cycle expected base differs from private current catalog.".to_string()));
        }
        let base = current.sha256;

        let planned = if self.routine.is_some() { self.plan_routine(request, schedules)? } else { self.plan_frozen(request, schedules)? };
        let Planned { training, guard, source, source_bytes, source_sha, routine } = planned;
        put(&work, "source.json", &source_bytes)?;
        if let Some(routine) = &routine {
            put(&work, "routine.json", &routine.record)?;
        }
        let prompts = training.len();
        let fit_request = v3::FitRequest {
            request_id: id.clone(),
            model_id: request.model_id.clone(),
            base: base.clone(),
            scope: scope as i32,
            layers: vec![SEMANTIC_LAYER],
            train: training,
            guard,
            policy_json: self.policy_bytes.clone(),
            source_commitment: source_sha.clone(),
            source_json: source_bytes,
        };
        put(&work, "fit-request.pb", &fit_request.encode_to_vec())?;

        let fitted = match self.fit.fit_candidate(fit_request, self.fit_timeout).await {
            Ok(fitted) => fitted,
            Err(_) => {
                let status = self.fit.fit_status(id).await.map_err(|status| Failure::rpc(&status))?;
                put(&work, "fit-status-after-error.pb", &status.encode_to_vec())?;
                return Err(Failure::Raised(format!("Physical fit response uncertain; stopped without replay. Status={}", status.status)));
            }
        };

        let evidence = to_serde(&parse(&fitted.evidence_json, MAX_EVIDENCE_BYTES)?)?;
        validate_execution(&evidence)?;
        let train_wire = value::str_at(&source, "train_wire_sha256").map_err(Error::from)?;
        let guard_wire = value::str_at(&source, "guard_wire_sha256").map_err(Error::from)?;
        let scope_name = scope_name(scope);
        let field = |key: &str| evidence[key].as_str();
        let consistent = digest(&fitted.evidence_json) == fitted.evidence
            && field("request_id") == Some(id.as_str())
            && field("base") == Some(base.as_str())
            && field("source_commitment") == Some(source_sha.as_str())
            && field("train_wire_sha256") == Some(train_wire)
            && field("guard_wire_sha256") == Some(guard_wire)
            && evidence["policy"] == self.policy_serde
            && field("scope") == Some(scope_name)
            && evidence["serialized_guard_parity"].as_bool() == Some(true);
        if !consistent {
            return Err(Failure::Raised("Runtime fit evidence does not match dispatched source/scope/policy.".to_string()));
        }

        check_sha(&fitted.candidate)?;
        let chunks = self.checkpoint.fetch_blob(&fitted.candidate).await.map_err(|status| Failure::rpc(&status))?;
        let manifest = validate_manifest(&parse(&assemble_blob(&chunks, &fitted.candidate)?, MAX_MANIFEST_BYTES)?)?;
        if manifest.evidence.as_deref() != Some(fitted.evidence.as_str()) || Some(manifest.blob.as_str()) != field("candidate_blob") {
            return Err(Failure::Raised("Runtime candidate differs from checkpoint service snapshot.".to_string()));
        }
        put(&work, "fit-response.pb", &fitted.encode_to_vec())?;
        put(&work, "evidence.json", &fitted.evidence_json)?;

        let commit = v3::Commit {
            request_id: id.clone(),
            model_id: request.model_id.clone(),
            expected_base: base.clone(),
            candidate: fitted.candidate.clone(),
            evidence: fitted.evidence.clone(),
        };
        put(&work, "commit-request.pb", &commit.encode_to_vec())?;
        let tail = Tail { base, source_sha, scope_name, evidence, prompts, routine };
        self.finish(request, &work, commit, tail, false).await
    }

    /// Step 5 of the cycle: commit (or, when resuming, look the recorded commit up first), check the terminal receipt and answer.
    async fn finish(
        &self,
        request: &FuzzerTrainingRequest,
        work: &Path,
        commit: v3::Commit,
        tail: Tail,
        resume: bool,
    ) -> std::result::Result<FuzzerTrainingResponse, Failure> {
        let id = &request.request_id;
        let known = if resume {
            let status = self.checkpoint.commit_status(id).await.map_err(|status| Failure::rpc(&status))?;
            (status.status != "unknown").then_some(status)
        } else {
            None
        };
        let receipt = match known {
            Some(status) => status,
            None => match self.checkpoint.commit_candidate(commit.clone()).await {
                Ok(receipt) => receipt,
                Err(_) => {
                    let status = self.checkpoint.commit_status(id).await.map_err(|status| Failure::rpc(&status))?;
                    if status.status == "unknown" {
                        put(work, "unknown-commit.pb", &status.encode_to_vec())?;
                        return Err(Failure::Raised("Commit outcome unknown; stop without replay.".to_string()));
                    }
                    status
                }
            },
        };
        if !matches!(receipt.status.as_str(), "applied" | "rejected") || receipt.candidate != commit.candidate || receipt.base != tail.base
        {
            return Err(Failure::Raised("Terminal publication receipt differs from fitted candidate.".to_string()));
        }
        put(work, "receipt.pb", &receipt.encode_to_vec())?;

        let applied = receipt.status == "applied";
        let passed = publication_passes(&tail.evidence)?;
        let mut metadata: BTreeMap<String, String> = [
            ("candidate_manifest", commit.candidate.clone()),
            ("evidence_sha256", commit.evidence.clone()),
            ("publication_status", receipt.status.clone()),
            ("terminal_candidate_retained", "true".to_string()),
            ("source_commitment", tail.source_sha.clone()),
            ("semantic_layers", "4".to_string()),
            ("scope", tail.scope_name.to_string()),
            ("guard_passed", passed.to_string()),
        ]
        .into_iter()
        .map(|(key, item)| (key.to_string(), item))
        .collect();
        if let Some(routine) = &tail.routine {
            for (key, item) in [
                ("mode", "routine".to_string()),
                ("sampler", request.metadata.get("sampler").cloned().unwrap_or_default()),
                ("seed", request.seed.to_string()),
                ("routine_commitment", routine.commitment.clone()),
                ("schedule_seed", routine.schedule_seed.to_string()),
            ] {
                metadata.insert(key.to_string(), item);
            }
        }
        Ok(FuzzerTrainingResponse {
            accepted: applied,
            model_id: request.model_id.clone(),
            base_version: tail.base.clone(),
            applied_version: if applied { commit.candidate.clone() } else { tail.base },
            prompts_generated: u32::try_from(tail.prompts).unwrap_or(u32::MAX),
            message: format!("{}: {}", receipt.status, receipt.reason),
            metadata,
        })
    }

    /// A routine identity whose response was never stored: finish it from its work directory when the fit and the commit request
    /// are on disk, never refit. Anything else is the frozen `FAILED_PRECONDITION`.
    async fn resume(&self, request: &FuzzerTrainingRequest, scope: v3::Scope) -> std::result::Result<FuzzerTrainingResponse, Failure> {
        let unknown = || abort(Status::failed_precondition("Prior cycle outcome unknown; query runtime/commit status, never replay fit."));
        let work = self.work_directory(&request.request_id);
        let read = |name: &str| std::fs::read(work.join(name));
        let (Ok(commit_bytes), Ok(evidence_bytes), Ok(source_bytes), Ok(routine_bytes)) =
            (read("commit-request.pb"), read("evidence.json"), read("source.json"), read("routine.json"))
        else {
            return Err(unknown());
        };
        let commit = v3::Commit::decode(commit_bytes.as_slice()).map_err(|error| Failure::Raised(error.to_string()))?;
        if commit.request_id != request.request_id || commit.model_id != request.model_id || commit.evidence != digest(&evidence_bytes) {
            return Err(Failure::Raised("Recorded commit differs from the cycle on disk.".to_string()));
        }
        let evidence = to_serde(&parse(&evidence_bytes, MAX_EVIDENCE_BYTES)?)?;
        let record = parse(&routine_bytes, MAX_EVIDENCE_BYTES)?;
        let routine = RoutinePlan {
            commitment: value::str_at(&record, "routine_commitment").map_err(Error::from)?.to_string(),
            schedule_seed: value::i64_at(&record, "schedule_seed").map_err(Error::from)? as u64,
            record: routine_bytes.clone(),
        };
        let tail = Tail {
            base: commit.expected_base.clone(),
            source_sha: digest(&source_bytes),
            scope_name: scope_name(scope),
            evidence,
            prompts: self.policy.window_batches() * 64,
            routine: Some(routine),
        };
        self.finish(request, &work, commit, tail, true).await
    }
}

fn scope_name(scope: v3::Scope) -> &'static str {
    if scope == v3::Scope::Heads { "heads" } else { "full_encoder" }
}

/// The schedule of one cycle with the identities the mode computed for it.
struct Planned {
    training: Vec<RuntimeTrainingExample>,
    guard: Vec<RuntimeTrainingExample>,
    source: Value,
    source_bytes: Vec<u8>,
    source_sha: String,
    routine: Option<RoutinePlan>,
}

/// What a routine cycle records besides the frozen source.
struct RoutinePlan {
    commitment: String,
    schedule_seed: u64,
    record: Vec<u8>,
}

/// What the end of a cycle needs, from the fit or (when resuming) from the work directory.
struct Tail {
    base: String,
    source_sha: String,
    scope_name: &'static str,
    evidence: Serde,
    prompts: usize,
    routine: Option<RoutinePlan>,
}
