//! `RuntimeServer.FitCandidate` of `runtime_server.py`: one physical V3 fit per request identity.
//!
//! The order of the steps is the Python order, because the `fits` row and the work directory that a failure leaves behind are part
//! of the contract (a retried identity answers `ALREADY_EXISTS` and never replays a fit):
//!
//! 1. the request is bounded: exactly the semantic layer, a scope of `HEADS` or `FULL_ENCODER`, an identity of 1 to 200
//!    characters (`INVALID_ARGUMENT`; an empty layer list is refused, never read as the whole detector pipeline);
//! 2. the policy, the base and source commitments, the canonical source bytes and the actual rows against the pinned source
//!    ([`privoke_curriculum::v3::validate_bc01`] or [`validate_au3`](privoke_curriculum::v3::validate_au3), the ports of
//!    `validate_schedule`) are checked; a violation is a raised `ValueError`, which gRPC reports as `UNKNOWN`;
//! 3. under the engine lock, a known identity is `ALREADY_EXISTS`; a new one is reserved (`started`) and gets its work directory
//!    with `request.pb`;
//! 4. the base snapshot is loaded, the fit runs ([`privoke_training::v3_fit`]), the candidate is written to
//!    `candidate.safetensors`, reloaded from its bytes and its guard inference checked against the evidence, `evidence.json` and
//!    `manifest.json` are written, and the evidence and then the candidate are staged at the checkpoint service;
//! 5. the row becomes `completed` with the candidate, or `failed` with `Type: message`, and the failure is raised.
//!
//! The fit is the stage 19 port: arithmetic is float64 over float32 storage, so the candidate agrees with Torch's within the
//! tolerance category of stage 19 (per-coordinate 1e-6, with the bitwise count reported), not bit for bit.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use privoke_contracts::json::Value;
use privoke_contracts::proto::experimental_v3 as v3;
use privoke_contracts::proto::v1::{DetectionLayer, RuntimeTrainingExample};
use privoke_curriculum::audience;
use privoke_curriculum::v3::{self as curriculum, Policy, Schedule};
use privoke_runtime::model::{category_names, visibility_name};
use privoke_semantic::safetensors;
use privoke_training::v3_fit::{self, FitInput, Row};
use privoke_v3_fuzzer::contract::{self, MAX_EVIDENCE_BYTES, MAX_MANIFEST_BYTES, canonical, check_sha, digest};
use privoke_v3_fuzzer::source::bc01_input_paths;
use prost::Message;
use tonic::Status;

use crate::assets::{Admission, check_inventory};
use crate::checkpoint::stage_chunks;
use crate::evidence::{from_serde, inventory_value, safetensors_bytes, source_hashes};
use crate::pyerr::PyError;
use crate::service::Runtime;

const SEMANTIC: i32 = DetectionLayer::Semantic as i32;
const SAMPLER_AU3: &str = "audience_common_frozen_stream_v1";

/// Where the pinned sources of the frozen schedules come from.
#[derive(Debug, Clone)]
pub struct ScheduleSources {
    /// The checkout that holds the BC01 inputs (`evaluation/results/iterative_fuzzer_20261011/...`) and the bundled audience
    /// release (`services/privoke-fuzzer/data/audience-v3-manifest-v1.json`).
    pub root: std::path::PathBuf,
    /// `V3_AUDIENCE_MANIFEST_PATH` and `V3_AUDIENCE_MANIFEST_SHA256`: a custom audience release and its pin (both or neither).
    pub audience: Option<(std::path::PathBuf, String)>,
}

impl ScheduleSources {
    /// The trusted audience release (`audience_schedule.trusted_release()`).
    fn release(&self) -> Result<audience::AudienceRelease, PyError> {
        Ok(match &self.audience {
            Some((path, pin)) => curriculum::trusted_release(Some(path.as_path()), Some(pin.as_str()))?,
            None => {
                let bundled = self.root.join("services/privoke-fuzzer/data/audience-v3-manifest-v1.json");
                audience::load_release_from(&bundled, true, None)?
            }
        })
    }

    /// `validate_schedule(training, guard, source, policy)`: the actual rows against the pinned source.
    fn validate(&self, schedule: &Schedule, policy: Policy) -> Result<(), PyError> {
        let sampler = privoke_curriculum::value::get(&schedule.source, "sampler").and_then(privoke_curriculum::value::as_str);
        if sampler == Some(SAMPLER_AU3) {
            curriculum::validate_au3(schedule, policy, &self.release()?)?;
        } else {
            let sources = curriculum::load_sources_from(&bc01_input_paths(&self.root))?;
            curriculum::validate_bc01(schedule, policy, &sources)?;
        }
        Ok(())
    }
}

impl From<privoke_curriculum::Error> for PyError {
    fn from(error: privoke_curriculum::Error) -> Self {
        Self::value(error.to_string())
    }
}

impl From<privoke_training::TrainingError> for PyError {
    fn from(error: privoke_training::TrainingError) -> Self {
        Self::value(error.to_string())
    }
}

/// What the checks before the lock produce.
struct Prepared {
    policy_document: Value,
    source: Value,
}

/// `target(row)` of `v3/training.py`: an explicit, nonempty, unit-weight row whose named and packed targets agree.
fn target_of(row: &RuntimeTrainingExample) -> Result<u16, PyError> {
    if !row.has_target || row.weight != 1.0 || row.text.is_empty() {
        return Err(PyError::value("V3 fits require explicit nonempty unit-weight labeled rows."));
    }
    let disagree = || PyError::value("Named and packed training targets disagree.");
    let named = row.target.clone().unwrap_or_default();
    let packed = u16::try_from(named.packed).map_err(|_| disagree())?;
    let sensitivity = ["S0", "S1", "S2", "S3"][usize::from(packed & 0b11)];
    let visibility = visibility_name(packed).map_err(|_| disagree())?;
    let categories: Vec<&str> = category_names(packed);
    if named.sensitivity != sensitivity || named.visibility != visibility || named.categories != categories {
        return Err(disagree());
    }
    Ok(packed)
}

fn rows_of(rows: &[RuntimeTrainingExample]) -> Result<Vec<Row>, PyError> {
    rows.iter().map(|row| Ok(Row { text: row.text.clone(), packed: target_of(row)? })).collect()
}

fn raise(error: PyError) -> Status {
    Status::unknown(error.to_string())
}

impl Runtime {
    /// Checks 1 and 2: nothing is reserved or written until they hold.
    async fn prepare(&self, request: &v3::FitRequest) -> Result<Prepared, PyError> {
        let policy_document = contract::parse(&request.policy_json, MAX_MANIFEST_BYTES)?;
        let policy = contract::validate_policy(&policy_document)?;
        check_sha(&request.base)?;
        check_sha(&request.source_commitment)?;
        let source = contract::parse(&request.source_json, MAX_EVIDENCE_BYTES)?;
        if digest(&request.source_json) != request.source_commitment {
            return Err(PyError::value("Fit source commitment differs from supplied canonical bytes."));
        }
        let schedule = Schedule { training: request.train.clone(), guard: request.guard.clone(), source: source.clone() };
        let sources = self.schedules.clone();
        tokio::task::spawn_blocking(move || sources.validate(&schedule, policy))
            .await
            .map_err(|error| PyError::value(error.to_string()))??;
        Ok(Prepared { policy_document, source })
    }

    /// `FitCandidate`. `active` goes false when the caller gives up; the fit then stops at its next step and the row is `failed`.
    pub async fn fit_candidate(&self, request: v3::FitRequest, active: Arc<AtomicBool>) -> Result<v3::FitResponse, Status> {
        let scope = request.scope;
        let scoped = scope == v3::Scope::Heads as i32 || scope == v3::Scope::FullEncoder as i32;
        if request.layers != [SEMANTIC] || !scoped || request.request_id.is_empty() || request.request_id.chars().count() > 200 {
            return Err(Status::invalid_argument("Explicit bounded fit identity/scope and semantic-only selection required."));
        }
        let prepared = self.prepare(&request).await.map_err(raise)?;
        let request_bytes = request.encode_to_vec();
        let fingerprint = digest(&request_bytes);
        let _lock = self.cache.lock().await;
        if self.store().prior(&request.request_id).map_err(|error| Status::unknown(error.0))?.is_some() {
            return Err(Status::already_exists("Fit previously attempted; query status without physical replay."));
        }
        self.store().start(&request.request_id, &fingerprint).map_err(|error| Status::unknown(error.0))?;
        let work = self.directory.join("attempts").join(digest(request.request_id.as_bytes()));
        std::fs::create_dir_all(work.parent().unwrap_or(&self.directory)).map_err(|error| raise(error.into()))?;
        std::fs::create_dir(&work).map_err(|error| raise(error.into()))?;
        std::fs::write(work.join("request.pb"), &request_bytes).map_err(|error| raise(error.into()))?;
        match self.fit_locked(&request, &prepared, &work, active).await {
            Ok(response) => {
                self.store().complete(&request.request_id, &response.candidate).map_err(|error| Status::unknown(error.0))?;
                Ok(response)
            }
            Err(error) => {
                let _ = self.store().fail(&request.request_id, &error.to_string());
                Err(raise(error))
            }
        }
    }

    async fn fit_locked(
        &self,
        request: &v3::FitRequest,
        prepared: &Prepared,
        work: &Path,
        active: Arc<AtomicBool>,
    ) -> Result<v3::FitResponse, PyError> {
        let loaded = Arc::new(self.load(&request.base, true).await?);
        if loaded.manifest["model_id"].as_str() != Some(request.model_id.as_str()) {
            return Err(PyError::value("Fit model/base mismatch."));
        }
        if request.train.len() != curriculum_window(&prepared.policy_document)? * 64 || request.guard.len() != 16 {
            return Err(PyError::value("Frozen TRAIN window/guard counts differ."));
        }
        let train = rows_of(&request.train)?;
        let guard = rows_of(&request.guard)?;
        let input = FitInput {
            request_id: request.request_id.clone(),
            model_id: request.model_id.clone(),
            base: request.base.clone(),
            source_commitment: request.source_commitment.clone(),
            full: request.scope == v3::Scope::FullEncoder as i32,
            train,
            guard,
            train_wire_sha256: digest(&curriculum::wire_bytes(&request.train)),
            guard_wire_sha256: digest(&curriculum::wire_bytes(&request.guard)),
            policy: contract::to_serde(&prepared.policy_document)?,
        };
        let admission = self.admission;
        let model = Arc::clone(&loaded);
        let run = tokio::task::spawn_blocking(move || -> Result<v3_fit::Fit, PyError> {
            let base = model.tensors.as_ref().ok_or_else(|| PyError::value("Base tensors were not kept."))?;
            let cancel = move || active.load(Ordering::SeqCst);
            Ok(match admission {
                Admission::Pinned => v3_fit::fit(&model.model, base, &input, &cancel)?,
                Admission::Structural => v3_fit::fit_unchecked(&model.model, base, &input, &cancel)?,
            })
        });
        let result = run.await.map_err(|error| PyError::value(error.to_string()))??;
        let evidence = result.evidence;
        let candidate_bytes = safetensors_bytes(&result.candidate);
        std::fs::write(work.join("candidate.safetensors"), &candidate_bytes)?;
        let tensors = inventory_value(&result.candidate);
        let candidate_blob = digest(&candidate_bytes);
        let original = match &loaded.document {
            Value::Object(map) => match map.get("original") {
                Some(Value::String(text)) if !text.is_empty() => text.clone(),
                _ => request.base.clone(),
            },
            _ => return Err(PyError::value("Unsupported v3 manifest schema.")),
        };
        let scope = evidence["scope"].as_str().unwrap_or_default().to_string();
        let mut candidate = match loaded.document.clone() {
            Value::Object(map) => map,
            _ => return Err(PyError::value("Unsupported v3 manifest schema.")),
        };
        candidate.insert("parent".into(), Value::String(request.base.clone()));
        candidate.insert("original".into(), Value::String(original));
        candidate.insert("blob".into(), Value::String(candidate_blob.clone()));
        candidate.insert("tensors".into(), tensors.clone());
        candidate.insert("scope".into(), Value::String(scope));
        if self.admission == Admission::Pinned {
            let mut parity = candidate.clone();
            parity.insert("evidence".into(), Value::String("0".repeat(64)));
            contract::validate_manifest(&Value::Object(parity))?;
        }
        // The candidate is reconstructed from its serialized bytes before it can be staged: the same inventory, and the same
        // guard inference as the evidence records.
        let (reloaded, declared, guard_rows) = (candidate_bytes.clone(), tensors, evidence["candidate_guard"]["rows"].clone());
        let (check_model, guard_texts) = (Arc::clone(&loaded), request.guard.iter().map(|row| row.text.clone()).collect::<Vec<_>>());
        tokio::task::spawn_blocking(move || -> Result<(), PyError> {
            let parsed = safetensors::parse(&reloaded)?;
            check_inventory(&parsed, &contract::to_serde(&declared)?)?;
            let rebuilt = check_model.model.with_tensors(parsed)?;
            let rows = guard_rows.as_array().cloned().unwrap_or_default();
            for (text, expected) in guard_texts.iter().zip(&rows) {
                let prediction = rebuilt.predict(text)?;
                let same = u64::from(prediction.classification.pack()) == expected["prediction"].as_u64().unwrap_or(u64::MAX)
                    && (prediction.confidence - expected["confidence"].as_f64().unwrap_or(f64::NAN)).abs() == 0.0;
                if !same {
                    return Err(PyError::value("Serialized candidate/guard inference differs."));
                }
            }
            Ok(())
        })
        .await
        .map_err(|error| PyError::value(error.to_string()))??;
        let capabilities =
            Value::Object(self.capabilities.iter().map(|(key, value)| (key.clone(), Value::String(value.clone()))).collect());
        let mut document = match from_serde(&evidence)? {
            Value::Object(map) => map,
            _ => return Err(PyError::value("Evidence is not an object.")),
        };
        document.insert("candidate_blob".into(), Value::String(candidate_blob));
        document.insert("serialized_guard_parity".into(), Value::Bool(true));
        document.insert("capabilities".into(), capabilities);
        document.insert("source".into(), prepared.source.clone());
        document.insert("source_hashes".into(), source_hashes(&self.schedules.root)?);
        let evidence_bytes = canonical(&Value::Object(document))?;
        let evidence_sha = digest(&evidence_bytes);
        candidate.insert("evidence".into(), Value::String(evidence_sha.clone()));
        let manifest_bytes = canonical(&Value::Object(candidate))?;
        std::fs::write(work.join("evidence.json"), &evidence_bytes)?;
        std::fs::write(work.join("manifest.json"), &manifest_bytes)?;
        self.checkpoint.stage_checkpoint(stage_chunks(&evidence_bytes, b"")).await.map_err(|status| PyError::rpc(&status))?;
        let staged = self
            .checkpoint
            .stage_checkpoint(stage_chunks(&candidate_bytes, &manifest_bytes))
            .await
            .map_err(|status| PyError::rpc(&status))?;
        Ok(v3::FitResponse { candidate: staged.sha256, evidence: evidence_sha, evidence_json: evidence_bytes })
    }
}

/// `policy["window_batches"]` of a validated policy.
fn curriculum_window(policy: &Value) -> Result<usize, PyError> {
    Ok(Policy::from_value(policy)?.window_batches())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use privoke_contracts::proto::v1::RuntimeClassification;

    use super::*;

    fn row(text: &str, packed: u32, sensitivity: &str, visibility: &str, categories: &[&str]) -> RuntimeTrainingExample {
        RuntimeTrainingExample {
            text: text.to_string(),
            has_target: true,
            weight: 1.0,
            target: Some(RuntimeClassification {
                sensitivity: sensitivity.to_string(),
                visibility: visibility.to_string(),
                categories: categories.iter().map(ToString::to_string).collect(),
                packed,
            }),
        }
    }

    #[test]
    fn a_target_is_explicit_nonempty_unit_weight_and_named_like_its_packed_value() {
        // S1, P2 (0b01100), HEALTH (0b100000): 1 | 0b01100 | 0b100000 = 45.
        assert_eq!(target_of(&row("x", 45, "S1", "P2", &["HEALTH"])).unwrap(), 45);
        let refusals = [
            row("", 45, "S1", "P2", &["HEALTH"]),
            RuntimeTrainingExample { weight: 0.5, ..row("x", 45, "S1", "P2", &["HEALTH"]) },
            RuntimeTrainingExample { has_target: false, ..row("x", 45, "S1", "P2", &["HEALTH"]) },
        ];
        for refused in refusals {
            assert_eq!(target_of(&refused).unwrap_err().message, "V3 fits require explicit nonempty unit-weight labeled rows.");
        }
        for disagreeing in [
            row("x", 45, "S2", "P2", &["HEALTH"]),
            row("x", 45, "S1", "P3", &["HEALTH"]),
            row("x", 45, "S1", "P2", &[]),
            row("x", 99_999, "S1", "P2", &[]),
        ] {
            assert_eq!(target_of(&disagreeing).unwrap_err().message, "Named and packed training targets disagree.");
        }
    }
}
