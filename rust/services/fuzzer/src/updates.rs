//! `training/parameter_updates.py` and the status lookup of `fuzzer_service.py`: the publication request and the client
//! of the parameter-update service.

use std::collections::BTreeMap;
use std::time::Duration;

use privoke_contracts::proto::v1::param_update_service_client::ParamUpdateServiceClient;
use privoke_contracts::proto::v1::{
    Parameter, ParameterUpdateAck, ParameterUpdateRequest, ParameterUpdateStatus, ParameterUpdateStatusRequest,
};
use privoke_curriculum::trainer::merge_publication_metadata;
use privoke_curriculum::value::{self, Value};
use privoke_transport::ClientTlsConfig;
use privoke_transport::client::connect;
use tonic::{Request, Status};

use crate::error::{Error, Result, invalid};
use crate::runtime::BatchUpdate;

/// The parameter-update service as the fuzzer uses it.
#[tonic::async_trait]
pub trait UpdateBackend: Send + Sync {
    /// `GetParameterUpdateStatus`: the receipt of an earlier request, if any.
    async fn status(&self, request: ParameterUpdateStatusRequest) -> std::result::Result<ParameterUpdateStatus, Status>;
    /// `SubmitParameterUpdate`.
    async fn submit(&self, request: ParameterUpdateRequest) -> std::result::Result<ParameterUpdateAck, Status>;
}

/// The mutual-TLS client of the parameter-update service. The fuzzer's certificate must be registered as a
/// `publisher`, and its common name must equal `FUZZER_ID`, the `source_id` it publishes as.
#[derive(Debug, Clone)]
pub struct GrpcUpdates {
    target: String,
    tls: ClientTlsConfig,
    timeout: Duration,
}

impl GrpcUpdates {
    /// A client for `target` (`host:port`).
    pub fn new(target: impl Into<String>, tls: ClientTlsConfig, timeout: Duration) -> Self {
        Self { target: target.into(), tls, timeout }
    }

    async fn client(&self) -> std::result::Result<ParamUpdateServiceClient<tonic::transport::Channel>, Status> {
        let channel = connect(&self.target, &self.tls).await.map_err(|error| Status::unavailable(error.to_string()))?;
        Ok(ParamUpdateServiceClient::new(channel))
    }
}

#[tonic::async_trait]
impl UpdateBackend for GrpcUpdates {
    async fn status(&self, request: ParameterUpdateStatusRequest) -> std::result::Result<ParameterUpdateStatus, Status> {
        let mut message = Request::new(request);
        message.set_timeout(self.timeout);
        Ok(self.client().await?.get_parameter_update_status(message).await?.into_inner())
    }

    async fn submit(&self, request: ParameterUpdateRequest) -> std::result::Result<ParameterUpdateAck, Status> {
        let mut message = Request::new(request);
        message.set_timeout(self.timeout);
        Ok(self.client().await?.submit_parameter_update(message).await?.into_inner())
    }
}

/// `emit_training_update` without the transport: the update's metadata, then `str(metric)` of every metric, then the
/// caller's extra metadata; the gradients as float32 tensors with their shapes.
///
/// A FULL Adam update publishes the projection of [`crate::full_adam_evidence::publication_metadata`], bound to the retained
/// complete cycle under `directory`. The compact opt-in publication of `train_before_candidate_v1` (RUST-S21G) is built here;
/// the window route publishes the compact projection of [`crate::window::publication_metadata`].
pub fn publication_request(
    source_id: &str,
    update: &BatchUpdate,
    extra: &BTreeMap<String, String>,
    directory: Option<&std::path::Path>,
    pins: &crate::window::Pins,
) -> Result<ParameterUpdateRequest> {
    let mut metadata = merge_publication_metadata(&update.metadata, &update.metrics, extra)?;
    if update.metadata.get("contextual_training_optimizer").map(String::as_str) == Some(crate::policy::WINDOW_POLICY) {
        metadata = crate::window::publication_metadata(update, metadata, extra, directory, pins)?;
    }
    if crate::full_adam_evidence::is_full_adam_family(update.metadata.get("contextual_training_optimizer").map(String::as_str)) {
        metadata = crate::full_adam_evidence::publication_metadata(update, metadata, extra, directory)?;
    }
    let opted_in = update.metadata.get("contextual_training_diagnostics_policy").map(String::as_str)
        == Some(crate::diagnostics::TRAIN_DIAGNOSTICS_POLICY);
    if metadata.len() > 64 && opted_in {
        // The physical RPC and the complete unprojected cycle must exist before the compact publication.
        metadata = compact_publication(update, metadata, extra, directory)?;
    }
    if opted_in && (metadata.len() > 64 || metadata.values().any(|text| text.len() > 2048)) {
        return invalid("Opt-in training publication metadata exceeds its unchanged limits.");
    }
    let gradients = update
        .gradients
        .iter()
        .map(|(name, values)| Parameter {
            name: name.clone(),
            values: values.iter().map(|value| *value as f32).collect(),
            shape: update.shapes.get(name).cloned().unwrap_or_else(|| vec![u32::try_from(values.len()).unwrap_or(u32::MAX)]),
        })
        .collect();
    Ok(ParameterUpdateRequest {
        source_id: source_id.to_string(),
        model_id: update.model_id.clone(),
        base_version: update.base_version.clone(),
        gradients,
        metadata: metadata.into_iter().collect(),
    })
}

/// The sampling and weight audit fields that a compact publication packs under `training_audit_v1`.
const COMPACT_WEIGHT_KEYS: [&str; 10] = [
    "training_clean_examples",
    "training_sensitive_examples",
    "raw_clean_weight",
    "raw_sensitive_weight",
    "raw_total_weight",
    "effective_clean_weight",
    "effective_sensitive_weight",
    "clean_objective_mass",
    "sensitive_objective_mass",
    "objective_strata",
];

/// The compact publication of an opted-in TRAIN diagnostics update (`emit_training_update`): the audit fields move into one
/// bounded string and the retained complete cycle is bound by `training_evidence_sha256` (the hash of its metadata, metrics and
/// execution evidence).
fn compact_publication(
    update: &BatchUpdate,
    metadata: BTreeMap<String, String>,
    extra: &BTreeMap<String, String>,
    directory: Option<&std::path::Path>,
) -> Result<BTreeMap<String, String>> {
    let key = |map: &BTreeMap<String, String>, name: &str| map.get(name).cloned().ok_or_else(|| Error(format!("'{name}'")));
    let scope = key(&update.metadata, "training_scope")?;
    let identity = value::sha256(
        value::dumps_compact(&value::strings(&[scope, key(extra, "request_source_id")?, key(extra, "request_id")?]))?.as_bytes(),
    );
    let Some(directory) = directory else { return invalid("Compact training publication requires durable complete evidence.") };
    let base = key(&update.metadata, "base_parameter_fingerprint")?;
    let retained = value::parse_bytes(&std::fs::read(directory.join("training-cycles").join(identity).join(format!("{base}.json")))?)?;
    let metrics = Value::Object(update.metrics.iter().map(|(name, number)| (name.clone(), Value::Float(*number))).collect());
    if value::get(&retained, "metadata") != Some(&value::from_string_map(&update.metadata))
        || value::get(&retained, "metrics") != Some(&metrics)
        || value::get(&retained, "execution_evidence") != Some(&update.execution_evidence)
        || value::get(&retained, "gate_passed") != Some(&Value::Bool(true))
    {
        return invalid("Compact publication differs from retained complete evidence.");
    }
    let audit: BTreeMap<String, String> = metadata
        .iter()
        .filter(|(name, _)| name.starts_with("sampling_") || COMPACT_WEIGHT_KEYS.contains(&name.as_str()))
        .map(|(name, text)| (name.clone(), text.clone()))
        .collect();
    let compact = format!("{{\"schema\":1,\"fields\":{}}}", value::dumps_compact(&value::from_string_map(&audit))?);
    if compact.len() > 2048 {
        return invalid("Compact training audit exceeds publication byte budget.");
    }
    let mut projected: BTreeMap<String, String> = metadata.into_iter().filter(|(name, _)| !audit.contains_key(name)).collect();
    projected.insert("training_audit_v1".to_string(), compact);
    let bound = value::object(
        ["metadata", "metrics", "execution_evidence"]
            .iter()
            .map(|name| value::get(&retained, name).cloned().map(|item| (*name, item)).ok_or_else(|| Error(format!("'{name}'"))))
            .collect::<Result<Vec<_>>>()?,
    );
    projected.insert("training_evidence_sha256".to_string(), value::sha256(value::dumps_compact(&bound)?.as_bytes()));
    Ok(projected)
}

/// The extra metadata of one publication (`_submit_update`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationContext<'a> {
    /// The caller's `request_id`.
    pub request_id: &'a str,
    /// The caller's `source_id` (after the FULL scope's rewrite).
    pub request_source_id: &'a str,
    /// The requested prompt count before the cap.
    pub requested_prompt_count: u32,
    /// The generated prompt count.
    pub generated_prompt_count: usize,
    /// The `training_pipeline` value.
    pub pipeline: &'a str,
    /// The `training_request_fingerprint` value.
    pub fingerprint: &'a str,
}

impl PublicationContext<'_> {
    /// The metadata map.
    pub fn metadata(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("request_id".to_string(), self.request_id.to_string()),
            ("request_source_id".to_string(), self.request_source_id.to_string()),
            ("requested_prompt_count".to_string(), self.requested_prompt_count.to_string()),
            ("generated_prompt_count".to_string(), self.generated_prompt_count.to_string()),
            ("training_pipeline".to_string(), self.pipeline.to_string()),
            ("training_request_fingerprint".to_string(), self.fingerprint.to_string()),
        ])
    }
}
