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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use privoke_contracts::proto::experimental_v3 as v3;
use privoke_contracts::proto::v1::{DetectionLayer, FuzzerTrainingRequest, FuzzerTrainingResponse};
use privoke_curriculum::v3::{Policy, Schedule};
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
            store: Mutex::new(store),
        })
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
        Ok(v3::HealthResponse { ready: true, role: ROLE.to_string(), capabilities })
    }

    /// `RunTrainingCycle` (heads) and `RunUnderlyingTrainingCycle` (full encoder).
    pub async fn run(&self, request: FuzzerTrainingRequest, scope: v3::Scope) -> std::result::Result<FuzzerTrainingResponse, Status> {
        self.cycle(request, scope).await.map_err(Status::from)
    }

    fn fingerprint(&self, request: &FuzzerTrainingRequest, scope: v3::Scope) -> String {
        let mut payload = (scope as i32).to_string().into_bytes();
        payload.extend_from_slice(&fuzzer_request_bytes(request));
        if let Some(pin) = self.schedules.source_pin() {
            payload.extend_from_slice(self.schedules.sampler().name().as_bytes());
            payload.extend_from_slice(pin.as_bytes());
        }
        digest(&payload)
    }

    async fn cycle(&self, request: FuzzerTrainingRequest, scope: v3::Scope) -> std::result::Result<FuzzerTrainingResponse, Failure> {
        let originals = self.policy.window_batches() as u64 * 32;
        if request.request_id.is_empty() || request.request_id.chars().count() > 200 || u64::from(request.prompt_count) != originals {
            return Err(abort(Status::invalid_argument("Frozen request ID/original prompt budget required.")));
        }
        let fingerprint = self.fingerprint(&request, scope);
        let store = self.store.lock().await;
        if let Some(prior) = store.prior(&request.request_id)? {
            if prior.fingerprint != fingerprint {
                return Err(abort(Status::already_exists("Cycle ID reused with different content/scope.")));
            }
            return match prior.response {
                Some(bytes) => FuzzerTrainingResponse::decode(bytes.as_slice()).map_err(|error| Failure::Raised(error.to_string())),
                None => {
                    Err(abort(Status::failed_precondition("Prior cycle outcome unknown; query runtime/commit status, never replay fit.")))
                }
            };
        }
        store.reserve(&request.request_id, &fingerprint)?;
        let response = self.fit_and_publish(&request, scope).await?;
        store.record(&request.request_id, &fuzzer_response_bytes(&response))?;
        Ok(response)
    }

    async fn fit_and_publish(
        &self,
        request: &FuzzerTrainingRequest,
        scope: v3::Scope,
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

        let Schedule { training, guard, source } = self.schedules.schedule(u64::from(request.seed), self.policy)?;
        let source_bytes = value::canonical_bytes(&source).map_err(Error::from)?;
        let source_sha = digest(&source_bytes);
        if request.metadata.get("policy_sha256") != Some(&self.policy_sha256)
            || request.metadata.get("source_commitment") != Some(&source_sha)
        {
            return Err(Failure::Raised("Host frozen policy/source differs from actual dispatched schedule.".to_string()));
        }
        put(&work, "source.json", &source_bytes)?;
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
        let scope_name = if scope == v3::Scope::Heads { "heads" } else { "full_encoder" };
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
        let receipt = match self.checkpoint.commit_candidate(commit).await {
            Ok(receipt) => receipt,
            Err(_) => {
                let status = self.checkpoint.commit_status(id).await.map_err(|status| Failure::rpc(&status))?;
                if status.status == "unknown" {
                    put(&work, "unknown-commit.pb", &status.encode_to_vec())?;
                    return Err(Failure::Raised("Commit outcome unknown; stop without replay.".to_string()));
                }
                status
            }
        };
        if !matches!(receipt.status.as_str(), "applied" | "rejected") || receipt.candidate != fitted.candidate || receipt.base != base {
            return Err(Failure::Raised("Terminal publication receipt differs from fitted candidate.".to_string()));
        }
        put(&work, "receipt.pb", &receipt.encode_to_vec())?;

        let applied = receipt.status == "applied";
        let passed = publication_passes(&evidence)?;
        let metadata: BTreeMap<String, String> = [
            ("candidate_manifest", fitted.candidate.clone()),
            ("evidence_sha256", fitted.evidence.clone()),
            ("publication_status", receipt.status.clone()),
            ("terminal_candidate_retained", "true".to_string()),
            ("source_commitment", source_sha),
            ("semantic_layers", "4".to_string()),
            ("scope", scope_name.to_string()),
            ("guard_passed", passed.to_string()),
        ]
        .into_iter()
        .map(|(key, item)| (key.to_string(), item))
        .collect();
        Ok(FuzzerTrainingResponse {
            accepted: applied,
            model_id: request.model_id.clone(),
            base_version: base.clone(),
            applied_version: if applied { fitted.candidate.clone() } else { base },
            prompts_generated: u32::try_from(prompts).unwrap_or(u32::MAX),
            message: format!("{}: {}", receipt.status, receipt.reason),
            metadata,
        })
    }
}
