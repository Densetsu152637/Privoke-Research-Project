//! The receipt lookup, health and bootstrap hooks of the V1 model artifact (`server.py`'s service class without the
//! transport). The guarded update itself (`SubmitParameterUpdate`: validation, drift bounds, compare-and-swap, receipts and
//! audit) was removed in stage V3-R8b: V1 models are no longer trained.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use privoke_contracts::digest::receipt_key;
use privoke_contracts::proto::v1::{HealthResponse, ParameterUpdateAck, ParameterUpdateStatus, ParameterUpdateStatusRequest};

use crate::SERVICE_NAME;
use crate::artifact_io;
use crate::audit::{artifact_is_usable, storage_is_writable};
use crate::error::{Failure, LOOKUP_FAILED};
use crate::receipts::{Receipt, ReceiptStore};
use crate::util::{unix_seconds, validate_text};

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
