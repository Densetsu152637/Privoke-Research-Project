//! The guarded update path: validation, compare-and-swap publication, durable receipts and the audit trail
//! (`server.py`'s `ParamUpdateService`, without the transport).
//!
//! # Order of effects
//!
//! One writer at a time (a process mutex, and the SQLite `BEGIN IMMEDIATE` transaction for other processes):
//!
//! 1. reconcile the receipt committed with the model into SQLite, checkpointing and reloading while one is missing;
//! 2. revalidate against the exact current artifact (its strategy-specific tensor bound and its window policy);
//! 3. answer a repeated request id from its receipt (a different payload under the same id is refused);
//! 4. apply the bounds, then the compare-and-swap on `base_version`;
//! 5. publish the weights and the receipt marker in one atomic rename (fsync of the file and of the directory);
//! 6. record the receipt, then the drift total, then the audit line, then commit.
//!
//! A crash after step 5 and before the commit loses nothing: the next writer finds the marker in the model and
//! reconciles it in step 1. A failure to write the audit line is logged and does not fail the RPC, because the model
//! is already committed and a retry would apply the gradient twice.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use privoke_contracts::digest::receipt_key;
use privoke_contracts::json::Value;
use privoke_contracts::proto::v1::{
    HealthResponse, ParameterUpdateAck, ParameterUpdateRequest, ParameterUpdateStatus, ParameterUpdateStatusRequest,
};

use crate::SERVICE_NAME;
use crate::apply::{self, apply_parameter_update};
use crate::artifact_io;
use crate::audit::{artifact_is_usable, persist_update_audit, storage_is_writable};
use crate::error::{Failure, LOOKUP_FAILED};
use crate::policy::DriftPolicy;
use crate::pyfmt::repr_str;
use crate::receipts::{DRIFT_METADATA_KEY, DriftRecord, RECEIPT_METADATA_KEY, Receipt, ReceiptStore, payload_digest};
use crate::util::{log, unix_seconds};
use crate::validate::{update_l2, validate_gradient_shapes_against_artifact, validate_parameter_update, validate_text};

/// `int(time.time())`, injectable so a corpus replay can use the recorded one-tick-per-call clock.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;
/// A fault-injection point `(phase, detail)`. Returning an error simulates a crash or storage failure at that point.
/// Phases: `receipt_put` (detail: the receipt's base version), and for bootstrap `after_checkpoint`, `before_prepare`,
/// `before_publish` and `after_publish`.
pub type Hook = Arc<dyn Fn(&str, &str) -> Result<(), String> + Send + Sync>;

/// The wall clock.
pub fn system_clock() -> Clock {
    Arc::new(unix_seconds)
}

/// A hook that never fails.
pub fn no_hook() -> Hook {
    Arc::new(|_phase: &str, _detail: &str| -> Result<(), String> { Ok(()) })
}

/// The message of an accepted update, as Python.
pub const ACK_MESSAGE: &str = "Parameter update applied to the persistent model artifact.";
/// The message of a status answer for a committed update.
pub const STATUS_MESSAGE: &str = "Previously committed parameter update.";

/// What the engine is configured with.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// The audit file; the receipt database is its sibling.
    pub storage_path: PathBuf,
    /// The mutable model artifact.
    pub model_artifact_path: PathBuf,
    /// The one model this service updates.
    pub expected_model_id: String,
    /// The per-coordinate bound.
    pub max_abs_gradient: f64,
    /// The per-update and cumulative bounds.
    pub drift: DriftPolicy,
}

/// The update engine. Share it behind an `Arc`.
pub struct Engine {
    config: EngineConfig,
    write_lock: Mutex<()>,
    clock: Clock,
    hook: Hook,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Engine").field("config", &self.config).finish_non_exhaustive()
    }
}

impl Engine {
    /// An engine with an explicit clock and fault hook.
    pub fn new(config: EngineConfig, clock: Clock, hook: Hook) -> Result<Self, Failure> {
        if let Some(parent) = config.storage_path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        Ok(Self { config, write_lock: Mutex::new(()), clock, hook })
    }

    /// An engine on the wall clock with no fault injection.
    pub fn with_system_clock(config: EngineConfig) -> Result<Self, Failure> {
        Self::new(config, system_clock(), no_hook())
    }

    /// The configuration.
    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// The clock, for the bootstrap.
    pub fn clock(&self) -> &Clock {
        &self.clock
    }

    /// The fault hook, for the bootstrap.
    pub fn hook(&self) -> &Hook {
        &self.hook
    }

    /// `SubmitParameterUpdate` without the transport.
    pub fn submit(&self, request: &ParameterUpdateRequest) -> Result<ParameterUpdateAck, Failure> {
        // Cheap refusal before taking the writer lock; the same checks run again under it on the exact current model.
        let current = artifact_io::load(&self.config.model_artifact_path)?;
        validate_parameter_update(request, &self.config.expected_model_id, self.config.max_abs_gradient, Some(&current.typed))?;
        let applied_version = self.apply(request)?;
        Ok(ParameterUpdateAck { accepted: true, model_id: request.model_id.clone(), applied_version, message: ACK_MESSAGE.to_string() })
    }

    fn apply(&self, request: &ParameterUpdateRequest) -> Result<String, Failure> {
        let _guard = self.write_lock.lock().unwrap_or_else(PoisonError::into_inner);
        let mut store = ReceiptStore::begin(&self.config.storage_path)?;
        match self.apply_locked(&mut store, request) {
            Ok(version) => {
                store.commit()?;
                Ok(version)
            }
            Err(failure) => {
                store.rollback();
                Err(failure)
            }
        }
    }

    fn apply_locked(&self, store: &mut ReceiptStore, request: &ParameterUpdateRequest) -> Result<String, Failure> {
        let path = &self.config.model_artifact_path;
        let mut loaded = artifact_io::load(path)?;
        while store.recover(&loaded.typed)? {
            store.checkpoint()?;
            loaded = artifact_io::load(path)?;
        }
        if loaded.typed.model_id != request.model_id {
            return Err(Failure::invalid(format!(
                "Artifact model_id is {}, not {}.",
                repr_str(&loaded.typed.model_id),
                repr_str(&request.model_id)
            )));
        }
        // Revalidate under the writer lock against the exact current artifact, including its strategy-specific tensor
        // bound; metadata is not authority.
        validate_parameter_update(request, &self.config.expected_model_id, self.config.max_abs_gradient, Some(&loaded.typed))?;
        let request_id = request.metadata.get("request_id").map(String::as_str).unwrap_or_default();
        if !request_id.is_empty() {
            let source = request.metadata.get("request_source_id").map(String::as_str).unwrap_or_default();
            let key = receipt_key(&request.source_id, request_id, source).map_err(|error| Failure::invalid(error.to_string()))?;
            if let Some(existing) = store.get(&key)? {
                if existing.payload_digest != payload_digest(request) {
                    return Err(Failure::invalid("request_id was already used for a different parameter update."));
                }
                return Ok(existing.applied_version);
            }
        }
        validate_gradient_shapes_against_artifact(request, &loaded.typed)?;

        let anchor = apply::release_anchor(&loaded, &request.base_version);
        let mut drift: Option<DriftRecord> = None;
        if self.config.drift.enforced() {
            if let Some(text) = loaded.typed.metadata().get(DRIFT_METADATA_KEY) {
                let record = DriftRecord::parse(text).ok_or_else(|| Failure::invalid("Committed model drift record is invalid."))?;
                store.raise_drift(&record.anchor, record.cumulative_l2)?;
            }
            // A stale base version is reported as stale whatever the budget says.
            if loaded.typed.version == request.base_version {
                let norm = update_l2(request);
                let total = self.config.drift.admit(&anchor, norm, store.drift_total(&anchor)?)?;
                drift = Some(DriftRecord { anchor: anchor.clone(), update_l2: norm, cumulative_l2: total });
            }
        }

        let applied = apply_parameter_update(&loaded, request, || (self.clock)())?;
        let applied_version = applied.applied_version;
        let receipt = Receipt::for_request(request, &applied_version)?;
        let mut root = applied.root;
        if let Value::Object(map) = &mut root {
            let metadata = artifact_io::metadata_mut(map);
            metadata.remove(RECEIPT_METADATA_KEY);
            if let Some(receipt) = &receipt {
                metadata.insert(RECEIPT_METADATA_KEY.to_string(), Value::String(receipt.to_json()?));
            }
            if let Some(record) = &drift {
                metadata.insert(DRIFT_METADATA_KEY.to_string(), Value::String(record.to_json()?));
            }
        }
        artifact_io::seal(&mut root)?;
        artifact_io::write_atomic(path, &root)?;
        let checksum = match &root {
            Value::Object(map) => match map.get("checksum") {
                Some(Value::String(checksum)) => checksum.clone(),
                _ => String::new(),
            },
            _ => String::new(),
        };
        if let Some(receipt) = &receipt {
            (self.hook)("receipt_put", &receipt.base_version).map_err(Failure::persistence)?;
            store.put(receipt)?;
        }
        if let Some(record) = &drift {
            store.raise_drift(&record.anchor, record.cumulative_l2)?;
        }
        if let Err(error) = persist_update_audit(&self.config.storage_path, request, &applied_version, &checksum) {
            // The model is already committed atomically. Failing the RPC here could make a retry apply the same
            // gradient twice.
            log(format_args!("parameter update audit persistence failed: {error}"));
        }
        Ok(applied_version)
    }

    /// `GetParameterUpdateStatus` without the transport.
    pub fn status(&self, request: &ParameterUpdateStatusRequest) -> Result<ParameterUpdateStatus, Failure> {
        validate_text(&request.source_id, "source_id", true, 128)?;
        validate_text(&request.request_id, "request_id", true, 128)?;
        validate_text(&request.model_id, "model_id", true, 128)?;
        validate_text(&request.request_source_id, "request_source_id", false, 128)?;
        validate_text(&request.request_fingerprint, "request_fingerprint", false, 128)?;
        if request.model_id != self.config.expected_model_id {
            return Err(Failure::invalid("Unexpected model_id."));
        }
        let found = {
            let _guard = self.write_lock.lock().unwrap_or_else(PoisonError::into_inner);
            self.lookup(request).map_err(|failure| Failure::internal(LOOKUP_FAILED, failure.detail()))?
        };
        let Some(receipt) = found else { return Ok(ParameterUpdateStatus::default()) };
        if receipt.request_fingerprint != request.request_fingerprint {
            return Err(Failure::AlreadyExists("request_id belongs to a different training request.".to_string()));
        }
        Ok(ParameterUpdateStatus {
            found: true,
            ack: Some(ParameterUpdateAck {
                accepted: true,
                model_id: receipt.model_id,
                applied_version: receipt.applied_version,
                message: STATUS_MESSAGE.to_string(),
            }),
            base_version: receipt.base_version,
            prompts_generated: u32::try_from(receipt.prompts_generated).unwrap_or_default(),
        })
    }

    fn lookup(&self, request: &ParameterUpdateStatusRequest) -> Result<Option<Receipt>, Failure> {
        let mut store = ReceiptStore::begin(&self.config.storage_path)?;
        let loaded = artifact_io::load(&self.config.model_artifact_path)?;
        store.recover(&loaded.typed)?;
        let key = receipt_key(&request.source_id, &request.request_id, &request.request_source_id)
            .map_err(|error| Failure::invalid(error.to_string()))?;
        let receipt = store.get(&key)?;
        store.commit()?;
        Ok(receipt)
    }

    /// `Health`: serving when the audit file is writable and the model loads from a writable directory.
    pub fn health(&self) -> HealthResponse {
        let serving = storage_is_writable(&self.config.storage_path) && artifact_is_usable(&self.config.model_artifact_path);
        HealthResponse { service: SERVICE_NAME.to_string(), status: if serving { "SERVING" } else { "NOT_SERVING" }.to_string() }
    }
}
