//! A fake V3 runtime and checkpoint service for the routine-mode tests, one `World` that is both.
//!
//! The runtime half checks the request exactly as the real `FitCandidate` does before it fits (the layer list is `[SEMANTIC]`, the
//! source commitment is the digest of the canonical source bytes, and the rows are the frozen schedule that `validate_bc01` or
//! `validate_au3` accept), then fabricates the evidence and the candidate manifest of the admitted tier (the real tier
//! constants, so the fuzzer's `validate_execution` and `validate_manifest` run unchanged). No weights exist: a candidate blob is a
//! few bytes. The checkpoint half is the store's contract: compare-and-swap on the current manifest, request-id idempotence with a
//! content conflict, and an admission that runs the param-update store's own `validate_source_evidence` over the evidence and the
//! contract's `publication_passes`, so a routine source record must satisfy the store's pinned-source validator.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use privoke_contracts::proto::experimental_v3 as v3;
use privoke_contracts::v3::{TIERS, VOCAB_SHA256, action_value, harm_count, valid_packed};
use privoke_curriculum::v3::{self as curriculum, Policy, Schedule};
use privoke_curriculum::value::{self, Value};
use privoke_param_update::v3_store::{AudienceSource, PinnedSources, SourceEvidence};
use privoke_v3_fuzzer::backend::{CheckpointBackend, FitBackend, blob_chunks};
use privoke_v3_fuzzer::contract::{self, MAX_EVIDENCE_BYTES, MAX_MANIFEST_BYTES, digest};
use prost::Message;
use serde_json::{Value as Serde, json};
use tonic::Status;

use super::{Inputs, fixtures};

const ACTIONS: [&str; 3] = ["ALLOW", "WARN", "BLOCK"];

#[derive(Debug, Default)]
struct Inner {
    blobs: BTreeMap<String, Vec<u8>>,
    current: BTreeMap<String, String>,
    commits: BTreeMap<String, (Vec<u8>, v3::Receipt)>,
}

/// The fake runtime and the fake checkpoint service.
#[derive(Debug)]
pub struct World {
    inner: Mutex<Inner>,
    inputs: Inputs,
    pinned: PinnedSources,
    /// Every fit request, in order.
    pub fits: Mutex<Vec<v3::FitRequest>>,
    /// Every commit that reached the store (whether or not it was refused), in order.
    pub commits_seen: Mutex<Vec<v3::Commit>>,
    /// While set, `CommitCandidate` fails without recording anything and `GetCommitStatus` answers `unknown` (the process died
    /// after the fit and before the commit).
    pub lose_commits: AtomicBool,
    /// How many fits ran.
    pub fit_count: AtomicUsize,
}

fn tier_name(model_id: &str) -> &str {
    model_id.strip_prefix("privoke-v3-").unwrap_or_default()
}

fn guard_row(packed: u64, prediction: u64, confidence: f64) -> Serde {
    let action_of = |packed: u64, confidence: f64| action_value(u16::try_from(packed).unwrap(), Some(confidence));
    let (action, target_action) = (action_of(prediction, confidence), action_of(packed, 0.999));
    assert!(valid_packed(prediction));
    json!({
        "target": packed, "prediction": prediction, "confidence": confidence,
        "action": ACTIONS[usize::try_from(action).unwrap()], "action_value": action,
        "target_action": ACTIONS[usize::try_from(target_action).unwrap()], "target_action_value": target_action,
        "joint_correct": packed == prediction && action == target_action
    })
}

fn guard_summary(rows: Vec<Serde>) -> Serde {
    let joint = rows.iter().filter(|row| row["joint_correct"] == true).count();
    let action = rows.iter().filter(|row| row["action"] == row["target_action"]).count();
    json!({"examples": rows.len(), "rows": rows, "joint_correct": joint, "action_correct": action})
}

impl World {
    pub fn new() -> Self {
        let inputs = Inputs::load();
        let root = fixtures();
        let bc01 = [
            ("taxonomy", "bc01/taxonomy-coverage-v1.json"),
            ("pool", "bc01/pool-authored.json"),
            ("manifest", "bc01/benign-manifest.json"),
            ("proof", "bc01/exclusion-proof.json"),
        ]
        .into_iter()
        .map(|(key, relative)| (key, root.join(relative)))
        .collect();
        let audience = AudienceSource::Trusted {
            path: root.join("au3/audience-v3-manifest-v1.json"),
            sha256: privoke_curriculum::audience::BUNDLED_MANIFEST_SHA256.to_string(),
        };
        Self {
            inner: Mutex::new(Inner::default()),
            inputs,
            pinned: PinnedSources::new(bc01, audience),
            fits: Mutex::default(),
            commits_seen: Mutex::default(),
            lose_commits: AtomicBool::new(false),
            fit_count: AtomicUsize::new(0),
        }
    }

    pub fn inputs(&self) -> &Inputs {
        &self.inputs
    }

    fn put(&self, payload: &[u8]) -> String {
        let sha = digest(payload);
        self.inner.lock().unwrap().blobs.insert(sha.clone(), payload.to_vec());
        sha
    }

    /// Install the ORIGINAL of a tier as the model's current version; returns the manifest SHA-256.
    pub fn bootstrap(&self, tier: &str) -> String {
        let tier = TIERS.iter().find(|candidate| candidate.name == tier).unwrap();
        let tensor = |name: &str| {
            value::object(vec![
                ("dtype", value::string("F32")),
                ("shape", Value::Array(vec![value::uint(tier.parameters)])),
                ("sha256", value::string(&digest(name.as_bytes()))),
            ])
        };
        let manifest = value::object(vec![
            ("schema", value::int(1)),
            ("architecture", value::string(privoke_contracts::v3::ARCHITECTURE)),
            ("model_id", value::string(&format!("privoke-v3-{}", tier.name))),
            ("tier", value::string(tier.name)),
            ("parent", value::string("")),
            ("original", value::string("")),
            ("blob", value::string(&digest(format!("original-weights-{}", tier.name).as_bytes()))),
            ("config", value::string(tier.config_sha256)),
            ("vocab", value::string(VOCAB_SHA256)),
            ("evidence", value::string("")),
            (
                "source",
                value::object(vec![
                    ("repository", value::string(tier.repository)),
                    ("revision", value::string(tier.revision)),
                    ("weights_sha256", value::string(tier.weights_sha256)),
                    ("config_sha256", value::string(tier.config_sha256)),
                    ("vocab_sha256", value::string(VOCAB_SHA256)),
                ]),
            ),
            ("tensors", value::object(vec![("encoder.weight", tensor(tier.name))])),
            ("parameter_count", value::uint(tier.parameters)),
            ("scope", value::string("original")),
        ]);
        let sha = self.put(&value::canonical_bytes(&manifest).unwrap());
        self.inner.lock().unwrap().current.insert(format!("privoke-v3-{}", tier.name), sha.clone());
        sha
    }

    pub fn current(&self, model_id: &str) -> String {
        self.inner.lock().unwrap().current[model_id].clone()
    }

    pub fn receipt_of(&self, request_id: &str) -> Option<v3::Receipt> {
        self.inner.lock().unwrap().commits.get(request_id).map(|(_, receipt)| receipt.clone())
    }

    fn read(&self, sha: &str) -> Option<Vec<u8>> {
        self.inner.lock().unwrap().blobs.get(sha).cloned()
    }

    /// The checks of `Runtime::prepare` that concern the schedule.
    fn prepare(&self, request: &v3::FitRequest) -> Result<(Value, Policy), Status> {
        let invalid = |message: &str| Status::unknown(message.to_string());
        let policy_document = contract::parse(&request.policy_json, MAX_MANIFEST_BYTES).map_err(|error| invalid(&error.0))?;
        let policy = contract::validate_policy(&policy_document).map_err(|error| invalid(&error.0))?;
        let source = contract::parse(&request.source_json, MAX_EVIDENCE_BYTES).map_err(|error| invalid(&error.0))?;
        if digest(&request.source_json) != request.source_commitment {
            return Err(invalid("Fit source commitment differs from supplied canonical bytes."));
        }
        let schedule = Schedule { training: request.train.clone(), guard: request.guard.clone(), source: source.clone() };
        let sampler = value::get(&source, "sampler").and_then(value::as_str).unwrap_or_default().to_string();
        let checked = if sampler == curriculum::AU3_SAMPLER {
            curriculum::validate_au3(&schedule, policy, &self.inputs.release)
        } else {
            curriculum::validate_bc01(&schedule, policy, &self.inputs.sources)
        };
        checked.map_err(|error| invalid(&error.to_string()))?;
        if request.train.len() != policy.window_batches() * 64 || request.guard.len() != 16 {
            return Err(invalid("Frozen TRAIN window/guard counts differ."));
        }
        Ok((policy_document, policy))
    }
}

#[tonic::async_trait]
impl FitBackend for World {
    async fn fit_candidate(&self, request: v3::FitRequest, _timeout: Duration) -> Result<v3::FitResponse, Status> {
        self.fits.lock().unwrap().push(request.clone());
        if request.layers != [4] {
            return Err(Status::invalid_argument("Explicit bounded fit identity/scope and semantic-only selection required."));
        }
        let (policy_document, policy) = self.prepare(&request)?;
        self.fit_count.fetch_add(1, Ordering::SeqCst);
        let full = request.scope == v3::Scope::FullEncoder as i32;
        let tier = TIERS.iter().find(|candidate| candidate.name == tier_name(&request.model_id)).unwrap();
        let base_bytes = self.read(&request.base).ok_or_else(|| Status::unknown("base is not in the checkpoint service"))?;
        let base = contract::parse(&base_bytes, MAX_MANIFEST_BYTES).map_err(|error| Status::unknown(error.0))?;
        let base_serde = contract::to_serde(&base).map_err(|error| Status::unknown(error.0))?;
        if base_serde["model_id"] != request.model_id.as_str() {
            return Err(Status::unknown("Fit model/base mismatch."));
        }

        // The guard: the base gets half of the rows wrong, the candidate gets all of them right.
        let (mut before, mut after) = (Vec::new(), Vec::new());
        for (index, row) in request.guard.iter().enumerate() {
            let packed = u64::from(row.target.as_ref().unwrap().packed);
            before.push(guard_row(packed, if index < 8 { packed } else { packed ^ 1 }, 0.999));
            after.push(guard_row(packed, packed, 0.999));
        }
        let harms = harm_count(&Serde::Array(before.clone()), &Serde::Array(after.clone()));
        let steps = u64::from(policy.steps);
        let (rows, micro) = (policy_serde(&policy_document, "batch_rows"), policy_serde(&policy_document, "microbatch"));
        let microbatches = steps * rows / micro;
        let layers = tier.num_hidden_layers;
        let layer_count = usize::try_from(layers).unwrap();
        let counts = json!({
            "optimizer_steps": steps, "train_rows": steps * rows, "microbatch_forward": microbatches, "microbatch_backward": microbatches,
            "encoder_block_forward": microbatches * layers, "encoder_block_backward": if full { microbatches * layers } else { 0 }
        });
        let changed = u64::from(full);
        let source_serde = contract::to_serde(&contract::parse(&request.source_json, MAX_EVIDENCE_BYTES).unwrap()).unwrap();
        let candidate_payload = format!("candidate:{}", request.request_id).into_bytes();
        let candidate_blob = digest(&candidate_payload);
        let evidence = json!({
            "schema": 1, "model_id": request.model_id, "tier": tier.name, "request_id": request.request_id, "base": request.base,
            "scope": if full { "full_encoder" } else { "heads" }, "layers": request.layers.iter().map(|_| 4).collect::<Vec<_>>(),
            "source_commitment": request.source_commitment, "policy": contract::to_serde(&policy_document).unwrap(),
            "train_wire_sha256": digest(&curriculum::wire_bytes(&request.train)),
            "guard_wire_sha256": digest(&curriculum::wire_bytes(&request.guard)),
            "phases": {
                "training": {"layer": 4, "status": "ok", "examples": steps * rows},
                "base_heldout": {"layer": 4, "status": "ok", "examples": 16},
                "candidate_heldout": {"layer": 4, "status": "ok", "examples": 16}
            },
            "base_guard": guard_summary(before), "candidate_guard": guard_summary(after), "action_harms": harms,
            "changes": {
                "heads": 6, "encoder": changed * 10, "embeddings": changed, "first_block": changed, "last_block": changed, "pooler": changed,
                "blocks": vec![changed; layer_count]
            },
            "changed_tensors": 6, "counts": counts,
            "block_counts": {"forward": vec![microbatches; layer_count], "backward": vec![if full { microbatches } else { 0 }; layer_count]},
            "losses": (0..steps).map(|step| 1.0 / (step as f64 + 1.0)).collect::<Vec<_>>(),
            "gradient_trace": (0..steps).map(|step| json!({"step": step + 1, "norm_before_clip": 1.0, "encoder_nonzero_gradients": changed})).collect::<Vec<_>>(),
            "parameter_count": tier.parameters, "trainable_count": if full { tier.parameters } else { 20 * (tier.hidden_size + 1) },
            "device": "cpu", "torch": "fake", "seconds": 0.0, "cuda_peak_bytes": 0,
            "candidate_blob": candidate_blob, "serialized_guard_parity": true, "capabilities": {}, "source": source_serde,
        });
        let evidence_bytes = canonical_of(&evidence);
        let evidence_sha = self.put(&evidence_bytes);
        self.put(&candidate_payload);

        let mut manifest = base_serde.clone();
        manifest["parent"] = request.base.clone().into();
        manifest["original"] = if base_serde["original"].as_str().is_some_and(|text| !text.is_empty()) {
            base_serde["original"].clone()
        } else {
            request.base.clone().into()
        };
        manifest["blob"] = candidate_blob.into();
        manifest["scope"] = (if full { "full_encoder" } else { "heads" }).into();
        manifest["evidence"] = evidence_sha.clone().into();
        let manifest_sha = self.put(&canonical_of(&manifest));
        Ok(v3::FitResponse { candidate: manifest_sha, evidence: evidence_sha, evidence_json: evidence_bytes })
    }

    async fn fit_status(&self, request_id: &str) -> Result<v3::Receipt, Status> {
        Ok(v3::Receipt { status: "unknown".to_string(), request_id: request_id.to_string(), ..v3::Receipt::default() })
    }

    async fn health(&self) -> Result<v3::HealthResponse, Status> {
        Ok(v3::HealthResponse { ready: true, role: "runtime".to_string(), capabilities: BTreeMap::new() })
    }
}

fn policy_serde(policy: &privoke_contracts::json::Value, key: &str) -> u64 {
    contract::to_serde(policy).unwrap()[key].as_u64().unwrap()
}

/// The canonical bytes of a document (the strict parser accepts only these).
pub fn canonical_of(document: &Serde) -> Vec<u8> {
    let value = value::parse_bytes(document.to_string().as_bytes()).unwrap();
    value::canonical_bytes(&value).unwrap()
}

#[tonic::async_trait]
impl CheckpointBackend for World {
    async fn resolve_current(&self, model_id: &str) -> Result<v3::Ref, Status> {
        match self.inner.lock().unwrap().current.get(model_id) {
            Some(sha256) => Ok(v3::Ref { sha256: sha256.clone() }),
            None => Err(Status::invalid_argument("Model is not in this private catalog.")),
        }
    }

    async fn fetch_blob(&self, sha256: &str) -> Result<Vec<v3::Chunk>, Status> {
        self.read(sha256).map(|payload| blob_chunks(&payload)).ok_or_else(|| Status::not_found("no such blob"))
    }

    async fn commit_candidate(&self, commit: v3::Commit) -> Result<v3::Receipt, Status> {
        if self.lose_commits.load(Ordering::SeqCst) {
            return Err(Status::unavailable("the commit never reached the store"));
        }
        self.commits_seen.lock().unwrap().push(commit.clone());
        let bytes = commit.encode_to_vec();
        let mut inner = self.inner.lock().unwrap();
        if let Some((recorded, receipt)) = inner.commits.get(&commit.request_id) {
            return if *recorded == bytes {
                Ok(receipt.clone())
            } else {
                Err(Status::already_exists("Commit request ID reused with different content."))
            };
        }
        let mut receipt = v3::Receipt {
            status: "applied".to_string(),
            request_id: commit.request_id.clone(),
            model_id: commit.model_id.clone(),
            base: commit.expected_base.clone(),
            candidate: commit.candidate.clone(),
            reason: "applied".to_string(),
        };
        let refusal = (|| -> Option<&'static str> {
            if inner.current.get(&commit.model_id) != Some(&commit.expected_base) {
                return Some("stale_base");
            }
            let evidence = contract::parse(inner.blobs.get(&commit.evidence)?, MAX_EVIDENCE_BYTES).ok()?;
            let serde = contract::to_serde(&evidence).ok()?;
            if self.pinned.validate(&evidence).is_err() {
                return Some("source_rejected");
            }
            if !contract::publication_passes(&serde).ok()? {
                return Some("guard_rejected");
            }
            None
        })();
        match refusal {
            Some(reason) => {
                receipt.status = "rejected".to_string();
                receipt.reason = reason.to_string();
            }
            None => {
                inner.current.insert(commit.model_id.clone(), commit.candidate.clone());
            }
        }
        inner.commits.insert(commit.request_id.clone(), (bytes, receipt.clone()));
        Ok(receipt)
    }

    async fn commit_status(&self, request_id: &str) -> Result<v3::Receipt, Status> {
        if self.lose_commits.load(Ordering::SeqCst) {
            return Ok(v3::Receipt { status: "unknown".to_string(), request_id: request_id.to_string(), ..v3::Receipt::default() });
        }
        Ok(self.receipt_of(request_id).unwrap_or(v3::Receipt {
            status: "unknown".to_string(),
            request_id: request_id.to_string(),
            ..v3::Receipt::default()
        }))
    }

    async fn health(&self) -> Result<v3::HealthResponse, Status> {
        Ok(v3::HealthResponse { ready: true, role: "checkpoint".to_string(), capabilities: BTreeMap::new() })
    }
}
