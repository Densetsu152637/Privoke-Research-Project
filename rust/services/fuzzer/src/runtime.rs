//! `runtime_client.py`: the gradient request, the admission of the response, and the mutual-TLS client of the runtime.
//!
//! The fuzzer never runs a detector layer: every request carries the explicit, non-empty layer list
//! `[DETECTION_LAYER_SEMANTIC]`, and a response that does not report exactly the three actual semantic executions is
//! refused. An empty layer list would select the complete detector pipeline, so no constructor here can produce one.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use base64::Engine as _;
use privoke_contracts::fingerprint::parameter_fingerprint;
use privoke_contracts::json::{self, Value};
use privoke_contracts::proto::v1::privoke_runtime_service_client::PrivokeRuntimeServiceClient;
use privoke_contracts::proto::v1::{
    ComputeSemanticGradientsRequest, ComputeSemanticGradientsResponse, DetectionLayer, RuntimeClassification, RuntimeTrainingExample,
};
use privoke_curriculum::Example;
use privoke_curriculum::classification::{category_names, sensitivity_names, visibility_names};
use privoke_curriculum::value;
use privoke_transport::ClientTlsConfig;
use privoke_transport::client::connect;
use prost::Message;
use tonic::metadata::MetadataValue;
use tonic::{Request, Status};

use crate::config::Scope;
use crate::error::{Error, Result, invalid};

/// `LAST_BLOCK_STRATEGY`.
pub const LAST_BLOCK_STRATEGY: &str = "contextual_last_block_sgd_v1";
/// `FULL_ENCODER_STRATEGY`.
pub const FULL_ENCODER_STRATEGY: &str = "contextual_full_encoder_sgd_v1";
const HEAD_STRATEGY: &str = "transformer_classification_head_finetune";
const LEGACY_ARCHITECTURE: &str = "privoke_tiny_transformer_v1";
const TASK_QUERY_ARCHITECTURE: &str = "privoke_tiny_transformer_v2";
const TASK_QUERY_READOUT: &str = "residual_task_query_v1";
const TASKS: [&str; 3] = ["sensitivity", "visibility", "category"];
const BLOCK_NAMES: [&str; 9] = [
    "attention.query.weight",
    "attention.key.weight",
    "attention.value.weight",
    "attention.output.weight",
    "attention.output.bias",
    "ffn.input.weight",
    "ffn.input.bias",
    "ffn.output.weight",
    "ffn.output.bias",
];
const SEMANTIC_LAYER: i32 = DetectionLayer::Semantic as i32;

/// `BatchTrainingUpdate`: what the runtime computed, ready for the guard and for publication.
#[derive(Debug, Clone, PartialEq)]
pub struct BatchUpdate {
    /// `model_id`.
    pub model_id: String,
    /// `base_version`.
    pub base_version: String,
    /// `gradients`, in the order the runtime sent them.
    pub gradients: Vec<(String, Vec<f64>)>,
    /// `parameter_shapes`.
    pub shapes: BTreeMap<String, Vec<u32>>,
    /// `metrics`.
    pub metrics: BTreeMap<String, f64>,
    /// `metadata`.
    pub metadata: BTreeMap<String, String>,
    /// `execution_evidence`.
    pub execution_evidence: Value,
}

/// The per-call options of a gradient request: the pre-gradient admission header a policy cycle sends as gRPC metadata,
/// and the long deadline of a FULL Adam fit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallOptions {
    /// The value of `x-privoke-training-admission-v1`, when the cycle carries a policy admission.
    pub header: Option<String>,
    /// The 180 second deadline of a FULL Adam fit of the full encoder, instead of `FUZZ_TIMEOUT_SECONDS`.
    pub long_deadline: bool,
}

/// `timeout=180.0` of `compute_semantic_gradients` for a FULL Adam fit of the full encoder.
pub const FULL_ADAM_DEADLINE: Duration = Duration::from_secs(180);

/// The client runtime as the fuzzer uses it.
#[tonic::async_trait]
pub trait RuntimeBackend: Send + Sync {
    /// `ComputeSemanticGradients` (heads) or `ComputeUnderlyingModelGradients` (full encoder).
    async fn compute_gradients(
        &self,
        scope: Scope,
        request: ComputeSemanticGradientsRequest,
        options: CallOptions,
    ) -> std::result::Result<ComputeSemanticGradientsResponse, Status>;
}

/// The mutual-TLS client of the runtime (or of the quarantined analysis service in front of it).
#[derive(Debug, Clone)]
pub struct GrpcRuntime {
    target: String,
    tls: ClientTlsConfig,
    timeout: Duration,
}

impl GrpcRuntime {
    /// A client for `target` (`host:port`) with the per-call deadline of `FUZZ_TIMEOUT_SECONDS`.
    pub fn new(target: impl Into<String>, tls: ClientTlsConfig, timeout: Duration) -> Self {
        Self { target: target.into(), tls, timeout }
    }
}

#[tonic::async_trait]
impl RuntimeBackend for GrpcRuntime {
    async fn compute_gradients(
        &self,
        scope: Scope,
        request: ComputeSemanticGradientsRequest,
        options: CallOptions,
    ) -> std::result::Result<ComputeSemanticGradientsResponse, Status> {
        let channel = connect(&self.target, &self.tls).await.map_err(|error| Status::unavailable(error.to_string()))?;
        let mut client = PrivokeRuntimeServiceClient::new(channel).max_decoding_message_size(16 * 1024 * 1024);
        let mut message = Request::new(request);
        message.set_timeout(if options.long_deadline { FULL_ADAM_DEADLINE } else { self.timeout });
        if let Some(header) = &options.header {
            let value = MetadataValue::try_from(header.as_str()).map_err(|error| Status::internal(error.to_string()))?;
            message.metadata_mut().insert(crate::policy::ADMISSION_HEADER, value);
        }
        let response = match scope {
            Scope::Heads => client.compute_semantic_gradients(message).await?,
            Scope::FullEncoder => client.compute_underlying_model_gradients(message).await?,
        };
        Ok(response.into_inner())
    }
}

/// The wire form of one example: the full target for training rows, the packed value alone for guard rows.
fn wire_example(example: &Example, guard: bool) -> Result<RuntimeTrainingExample> {
    let target = match example.target {
        None => None,
        Some(classification) if guard => {
            Some(RuntimeClassification { packed: u32::from(classification.pack()), ..RuntimeClassification::default() })
        }
        Some(classification) => Some(RuntimeClassification {
            sensitivity: classification.sensitivity().to_string(),
            visibility: classification.visibility()?.to_string(),
            categories: classification.categories().into_iter().map(str::to_string).collect(),
            packed: u32::from(classification.pack()),
        }),
    };
    Ok(RuntimeTrainingExample { text: example.text.clone(), has_target: target.is_some(), target, weight: example.weight })
}

/// The request of `compute_semantic_gradients` for a cycle without policy admission.
pub fn gradient_request(
    examples: &[Example],
    heldout: &[Example],
    model_id: &str,
    request_id: &str,
    learning_rate: f64,
    max_gradient: f64,
) -> Result<ComputeSemanticGradientsRequest> {
    if examples.is_empty() || heldout.is_empty() {
        return invalid("Semantic training requires a known scope and nonempty training and held-out batches.");
    }
    Ok(ComputeSemanticGradientsRequest {
        request_id: request_id.to_string(),
        model_id: model_id.to_string(),
        examples: examples.iter().map(|example| wire_example(example, false)).collect::<Result<_>>()?,
        heldout_examples: heldout.iter().map(|example| wire_example(example, true)).collect::<Result<_>>()?,
        learning_rate,
        max_gradient,
        layers: vec![SEMANTIC_LAYER],
    })
}

fn reject<T>(message: impl Into<String>) -> Result<T> {
    Err(Error(message.into()))
}

fn is_hex64(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn int_field(config: &Value, name: &str) -> Option<i64> {
    match value::get(config, name) {
        Some(Value::Int(digits)) => digits.parse::<i64>().ok(),
        _ => None,
    }
}

/// `query_readout(config)`.
fn query_readout(config: &Value) -> Result<bool> {
    match value::get(config, "readout") {
        None => Ok(false),
        Some(Value::Null) => reject("Tiny readout must be explicit when declared."),
        Some(Value::String(text)) if text == "legacy_pool_v1" => Ok(false),
        Some(Value::String(text)) if text == TASK_QUERY_READOUT => Ok(true),
        Some(_) => reject("Unsupported Tiny readout."),
    }
}

fn label_set(config: &Value, task: &str) -> Option<Vec<String>> {
    match value::get(config, &format!("{task}_labels")) {
        Some(Value::Array(items)) => items.iter().map(|item| value::as_str(item).map(str::to_string)).collect(),
        _ => None,
    }
}

pub(crate) fn exact_labels(config: &Value, task: &str) -> bool {
    let expected: BTreeSet<&str> = match task {
        "sensitivity" => sensitivity_names().collect(),
        "visibility" => visibility_names().collect(),
        _ => category_names().collect(),
    };
    label_set(config, task)
        .is_some_and(|labels| labels.len() == expected.len() && labels.iter().map(String::as_str).collect::<BTreeSet<_>>() == expected)
}

/// `validate_query_config`.
fn validate_query_config(config: &Value) -> Result<()> {
    for name in ["vocab_size", "hidden_size", "intermediate_size", "max_tokens", "num_layers", "num_attention_heads"] {
        let fallback = (name == "num_layers" || name == "num_attention_heads").then_some(1);
        let number = match value::get(config, name) {
            None => fallback,
            Some(_) => int_field(config, name),
        };
        if !number.is_some_and(|number| (1..=65_536).contains(&number)) {
            return reject("Invalid task-query Tiny dimensions.");
        }
    }
    let heads = int_field(config, "num_attention_heads").unwrap_or(1);
    let hidden = int_field(config, "hidden_size").unwrap_or(1);
    if int_field(config, "vocab_size").unwrap_or(0) < 2
        || int_field(config, "max_tokens").unwrap_or(0) > 512
        || int_field(config, "num_layers").unwrap_or(1) > 512
        || hidden % heads != 0
    {
        return reject("Invalid task-query Tiny capacity or attention heads.");
    }
    if TASKS.iter().any(|task| !exact_labels(config, task)) {
        return reject("Task-query Tiny requires exact label inventories.");
    }
    Ok(())
}

/// `validate_readout_identity(architecture, config)`.
fn validate_readout_identity(architecture: &str, config: &Value) -> Result<()> {
    let enabled = query_readout(config)?;
    if architecture != if enabled { TASK_QUERY_ARCHITECTURE } else { LEGACY_ARCHITECTURE } {
        return reject("Tiny architecture and readout configuration disagree.");
    }
    if enabled {
        validate_query_config(config)?;
    }
    Ok(())
}

pub(crate) fn head_names(config: &Value) -> Result<BTreeSet<String>> {
    let mut names: BTreeSet<String> =
        TASKS.iter().flat_map(|task| ["weight", "bias"].into_iter().map(move |part| format!("head.{task}.{part}"))).collect();
    if query_readout(config)? {
        names.extend(TASKS.iter().map(|task| format!("readout.{task}.query")));
    }
    Ok(names)
}

fn layer_count(config: &Value) -> Result<i64> {
    match value::get(config, "num_layers") {
        None => Ok(1),
        Some(_) => match int_field(config, "num_layers") {
            Some(layers) if (1..=512).contains(&layers) => Ok(layers),
            _ => reject("Contextual encoder layer count is invalid."),
        },
    }
}

fn block_prefix(layers: i64, layer: i64) -> String {
    if layers == 1 { String::new() } else { format!("layers.{layer}.") }
}

/// `contextual_trainable_names(config, strategy)`.
fn trainable_names(config: &Value, strategy: Option<&str>) -> Result<BTreeSet<String>> {
    let mut names = head_names(config)?;
    let Some(strategy) = strategy else { return Ok(names) };
    if strategy != LAST_BLOCK_STRATEGY && strategy != FULL_ENCODER_STRATEGY {
        return reject("Unsupported contextual training strategy.");
    }
    let layers = layer_count(config)?;
    if strategy == FULL_ENCODER_STRATEGY {
        names.insert("token_embedding".to_string());
        names.insert("position_embedding".to_string());
        for layer in 0..layers {
            names.extend(BLOCK_NAMES.iter().map(|name| format!("{}{name}", block_prefix(layers, layer))));
        }
    } else {
        names.extend(BLOCK_NAMES.iter().map(|name| format!("{}{name}", block_prefix(layers, layers - 1))));
    }
    Ok(names)
}

/// `full_encoder_tensor_shapes(config)`: the exact Tiny full-training inventory.
pub fn full_encoder_tensor_shapes(config: &Value) -> Result<BTreeMap<String, Vec<u64>>> {
    if query_readout(config)? {
        validate_query_config(config)?;
    }
    let dimension = |name: &str| int_field(config, name).filter(|number| (1..=65_536).contains(number));
    let (Some(vocab), Some(hidden), Some(intermediate), Some(context)) =
        (dimension("vocab_size"), dimension("hidden_size"), dimension("intermediate_size"), dimension("max_tokens"))
    else {
        return reject("Full encoder configuration dimensions are invalid.");
    };
    if context > 512 || vocab < 2 {
        return reject("Full encoder context/vocabulary exceeds its contract.");
    }
    let to_u64 = |number: i64| u64::try_from(number).unwrap_or(0);
    let (vocab, hidden, intermediate, context) = (to_u64(vocab), to_u64(hidden), to_u64(intermediate), to_u64(context));
    let mut result: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    result.insert("token_embedding".to_string(), vec![vocab, hidden]);
    result.insert("position_embedding".to_string(), vec![context, hidden]);
    if query_readout(config)? {
        for task in TASKS {
            result.insert(format!("readout.{task}.query"), vec![hidden]);
        }
    }
    for task in TASKS {
        let labels = match value::get(config, &format!("{task}_labels")) {
            Some(Value::Array(items)) if !items.is_empty() => items.len() as u64,
            _ => return reject("Full encoder requires explicit label inventories."),
        };
        result.insert(format!("head.{task}.weight"), vec![hidden, labels]);
        result.insert(format!("head.{task}.bias"), vec![labels]);
    }
    let layers = layer_count(config)?;
    for layer in 0..layers {
        let prefix = block_prefix(layers, layer);
        let shapes: [(&str, Vec<u64>); 9] = [
            ("attention.query.weight", vec![hidden, hidden]),
            ("attention.key.weight", vec![hidden, hidden]),
            ("attention.value.weight", vec![hidden, hidden]),
            ("attention.output.weight", vec![hidden, hidden]),
            ("attention.output.bias", vec![hidden]),
            ("ffn.input.weight", vec![hidden, intermediate]),
            ("ffn.input.bias", vec![intermediate]),
            ("ffn.output.weight", vec![intermediate, hidden]),
            ("ffn.output.bias", vec![hidden]),
        ];
        for (name, shape) in shapes {
            result.insert(format!("{prefix}{name}"), shape);
        }
    }
    let total: u64 = result.values().map(|shape| shape.iter().product::<u64>()).sum();
    if total > 65_536 {
        return reject("Full encoder configuration exceeds the total parameter budget.");
    }
    Ok(result)
}

fn contract_failure(message: impl std::fmt::Display) -> Error {
    Error(format!("Runtime training contract failed: {message}"))
}

fn required<'a>(metadata: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    metadata.get(key).map(String::as_str).ok_or_else(|| contract_failure(format!("'{key}'")))
}

/// `validate_training_response`: admit actual semantic execution and independently derived Tiny tensor shapes.
pub fn validate_training_response(
    request: &ComputeSemanticGradientsRequest,
    response: &ComputeSemanticGradientsResponse,
    scope: Scope,
    max_gradient: f64,
    require_full_capability: bool,
) -> Result<()> {
    if request.layers != [SEMANTIC_LAYER] {
        return reject("Training requires an explicit semantic-only request.");
    }
    if response.request_id != request.request_id
        || response.model_id != request.model_id
        || response.base_version.is_empty()
        || !response.error.is_empty()
    {
        return reject("Runtime training response identity is incomplete or mismatched.");
    }
    let mut phases = vec![
        ("training", request.examples.len()),
        ("base_heldout", request.heldout_examples.len()),
        ("candidate_heldout", request.heldout_examples.len()),
    ];
    if response
        .metadata
        .get("contextual_training_optimizer")
        .is_some_and(|name| crate::full_adam::RETENTION_POLICIES.contains(&name.as_str()))
    {
        phases.extend(crate::retention::execution_phases(&response.metadata)?);
    }
    if response.executions.len() != phases.len() {
        return reject("Runtime training requires all three actual semantic executions.");
    }
    for (execution, (phase, count)) in response.executions.iter().zip(phases) {
        if execution.phase != phase
            || execution.examples as usize != count
            || execution.status != "ok"
            || !execution.error.is_empty()
            || execution.layer != SEMANTIC_LAYER
        {
            return reject("Runtime training execution phase, layer, count or status is invalid.");
        }
    }
    let metadata = &response.metadata;
    let full = scope == Scope::FullEncoder;
    let artifact_strategy = metadata.get("artifact_training_strategy").map(String::as_str);
    let legacy_last = !full && !require_full_capability && artifact_strategy == Some(LAST_BLOCK_STRATEGY);
    let expected_scope = if legacy_last { "last_block" } else { scope.name() };
    if metadata.get("training_scope").map(String::as_str) != Some(expected_scope) {
        return reject("Runtime returned the wrong training scope.");
    }
    let expected_strategy = if full {
        FULL_ENCODER_STRATEGY
    } else if legacy_last {
        LAST_BLOCK_STRATEGY
    } else {
        HEAD_STRATEGY
    };
    if metadata.get("strategy").map(String::as_str) != Some(expected_strategy) {
        return reject("Runtime executed the wrong training strategy.");
    }
    if (full || require_full_capability) && artifact_strategy != Some(FULL_ENCODER_STRATEGY) {
        return reject("Automatic dual training requires a full-capable Tiny artifact before head publication.");
    }
    if (full || require_full_capability) && metadata.get("underlying_training_available").map(String::as_str) != Some("true") {
        return reject("Automatic dual training requires usable CPU autograd before head publication.");
    }
    for key in ["artifact_checksum", "base_parameter_fingerprint", "updated_parameter_fingerprint"] {
        if !metadata.get(key).is_some_and(|text| is_hex64(text)) {
            return reject("Runtime training lacks an exact artifact identity.");
        }
    }
    admit_tensors(request, response, full, legacy_last, max_gradient)
}

fn admit_tensors(
    request: &ComputeSemanticGradientsRequest,
    response: &ComputeSemanticGradientsResponse,
    full: bool,
    legacy_last: bool,
    max_gradient: f64,
) -> Result<()> {
    let metadata = &response.metadata;
    let config = json::parse(required(metadata, "model_config")?).map_err(contract_failure)?;
    let architecture = metadata.get("architecture").map_or(LEGACY_ARCHITECTURE, String::as_str);
    validate_readout_identity(architecture, &config).map_err(contract_failure)?;
    for task in TASKS {
        if !exact_labels(&config, task) {
            return Err(contract_failure("Invalid classification label inventory"));
        }
    }
    let strategy = if full {
        Some(FULL_ENCODER_STRATEGY)
    } else if legacy_last {
        Some(LAST_BLOCK_STRATEGY)
    } else {
        None
    };
    let expected_names = trainable_names(&config, strategy).map_err(contract_failure)?;
    let all_shapes = full_encoder_tensor_shapes(&config).map_err(contract_failure)?;
    let mut shapes: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for name in &expected_names {
        let shape = all_shapes.get(name).ok_or_else(|| contract_failure(format!("'{name}'")))?;
        shapes.insert(name.clone(), shape.clone());
    }
    // Legacy trainers clipped in float32, which may round a double request bound outward. Full-capable artifacts enforce
    // the exact double bound.
    let strict_bound = metadata.get("artifact_training_strategy").map(String::as_str) == Some(FULL_ENCODER_STRATEGY);
    let admitted_bound = if strict_bound { max_gradient } else { max_gradient.max(f64::from(max_gradient as f32)) };
    let names: Vec<&str> = response.gradients.iter().map(|parameter| parameter.name.as_str()).collect();
    if names.iter().collect::<BTreeSet<_>>().len() != names.len()
        || names.iter().copied().collect::<BTreeSet<_>>() != shapes.keys().map(String::as_str).collect::<BTreeSet<_>>()
    {
        return Err(contract_failure("Incomplete or unexpected tensor inventory"));
    }
    let declared = json::parse(required(metadata, "trained_parameter_names")?).map_err(contract_failure)?;
    let expected_declared = Value::Array(shapes.keys().map(|name| Value::String(name.clone())).collect());
    if declared != expected_declared {
        return Err(contract_failure("Incorrect declared inventory"));
    }
    let empty: BTreeMap<String, Vec<f64>> = shapes.keys().map(|name| (name.clone(), Vec::new())).collect();
    let expected_fingerprint = parameter_fingerprint(&empty, Some(&shapes)).map_err(contract_failure)?;
    if required(metadata, "trained_parameter_inventory_fingerprint")? != expected_fingerprint {
        return Err(contract_failure("Incorrect inventory fingerprint"));
    }
    let total: u64 = shapes.values().map(|shape| shape.iter().product::<u64>()).sum();
    if total > 65_536 {
        return Err(contract_failure("Excessive total tensor size"));
    }
    let limit = if full { 24_576 } else { 4_096 };
    for parameter in &response.gradients {
        let shape: Vec<u64> = parameter.shape.iter().map(|size| u64::from(*size)).collect();
        let expected = shapes.get(&parameter.name);
        if expected != Some(&shape)
            || parameter.values.len() as u64 != shape.iter().product::<u64>()
            || parameter.values.len() > limit
            || parameter.values.iter().any(|value| !value.is_finite() || f64::from(value.abs()) > admitted_bound)
        {
            return Err(contract_failure("Invalid tensor shape, size or delta"));
        }
    }
    let count = |key: &str| response.metrics.get(key).copied();
    if count("examples") != Some(request.examples.len() as f64) || count("heldout_examples") != Some(request.heldout_examples.len() as f64)
    {
        return Err(contract_failure("Incorrect metric counts"));
    }
    Ok(())
}

/// `compute_semantic_gradients` after the call, up to the admission of the response: a runtime error, the response contract
/// and, for a policy cycle, the policy evidence (`validate_training_policy_response`). Every failure is Python's
/// `RuntimeAnalysisError`.
pub fn validate_response(
    request: &ComputeSemanticGradientsRequest,
    response: &ComputeSemanticGradientsResponse,
    scope: Scope,
    max_gradient: f64,
    require_full_capability: bool,
    expectations: &crate::policy::Expectations,
) -> Result<()> {
    if !response.error.is_empty() {
        return reject(response.error.clone());
    }
    validate_training_response(request, response, scope, max_gradient, require_full_capability)?;
    if !expectations.is_empty() {
        crate::policy_response::validate_training_policy_response(request, response, expectations)?;
    }
    Ok(())
}

/// `compute_semantic_gradients` after the admission: admit the response and shape it as a [`BatchUpdate`].
pub fn admit_response(
    request: &ComputeSemanticGradientsRequest,
    response: &ComputeSemanticGradientsResponse,
    scope: Scope,
    max_gradient: f64,
    require_full_capability: bool,
) -> Result<BatchUpdate> {
    validate_response(request, response, scope, max_gradient, require_full_capability, &crate::policy::Expectations::default())?;
    update_from_response(request, response, scope)
}

/// The gradients, shapes, metrics, metadata and execution evidence of an admitted response.
pub fn update_from_response(
    request: &ComputeSemanticGradientsRequest,
    response: &ComputeSemanticGradientsResponse,
    scope: Scope,
) -> Result<BatchUpdate> {
    let mut gradients: Vec<(String, Vec<f64>)> = Vec::new();
    let mut shapes: BTreeMap<String, Vec<u32>> = BTreeMap::new();
    for parameter in &response.gradients {
        if gradients.iter().any(|(name, _)| name == &parameter.name) {
            return reject(format!("Client runtime returned duplicate gradient '{}'.", parameter.name));
        }
        gradients.push((parameter.name.clone(), parameter.values.iter().map(|value| f64::from(*value)).collect()));
        shapes.insert(parameter.name.clone(), parameter.shape.clone());
    }
    if response.model_id.is_empty() || response.base_version.is_empty() || gradients.is_empty() {
        return reject("Client runtime returned an incomplete semantic gradient batch.");
    }
    let encoder = base64::engine::general_purpose::STANDARD;
    let executions: Vec<Value> = response
        .executions
        .iter()
        .map(|execution| {
            value::object(vec![
                ("phase", value::string(&execution.phase)),
                ("layer", value::int(i64::from(execution.layer))),
                ("status", value::string(&execution.status)),
                ("examples", value::int(i64::from(execution.examples))),
                ("error", value::string(&execution.error)),
            ])
        })
        .collect();
    let rpc = if scope == Scope::FullEncoder { "ComputeUnderlyingModelGradients" } else { "ComputeSemanticGradients" };
    let evidence = value::object(vec![
        ("rpc", value::string(rpc)),
        ("request_layers", Value::Array(request.layers.iter().map(|layer| value::int(i64::from(*layer))).collect())),
        ("request_protobuf_base64", value::string(&encoder.encode(request.encode_to_vec()))),
        ("response_protobuf_base64", value::string(&encoder.encode(crate::pywire::compute_response_bytes(response)))),
        ("executions", Value::Array(executions)),
    ]);
    Ok(BatchUpdate {
        model_id: response.model_id.clone(),
        base_version: response.base_version.clone(),
        gradients,
        shapes,
        metrics: response.metrics.iter().map(|(key, number)| (key.clone(), *number)).collect(),
        metadata: response.metadata.iter().map(|(key, text)| (key.clone(), text.clone())).collect(),
        execution_evidence: evidence,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn config(text: &str) -> Value {
        json::parse(text).unwrap()
    }

    const TINY: &str = r#"{"category_labels":["HEALTH","POLITICS","RELIGION","CRIMINAL","FINANCIAL","SEXUAL","CHILD","LOCATION","IDENTITY","THIRD_PARTY"],
        "category_threshold":0.38,"hidden_size":24,"intermediate_size":48,"max_tokens":256,"num_attention_heads":1,"num_layers":1,
        "sensitivity_labels":["S0","S1","S2","S3"],"visibility_labels":["P0","P1","P2","P3","P4","PU"],"vocab_size":512}"#;

    #[test]
    fn the_recorded_tiny_inventory_has_the_expected_head_shapes() {
        let shapes = full_encoder_tensor_shapes(&config(TINY)).unwrap();
        assert_eq!(shapes["head.category.weight"], vec![24, 10]);
        assert_eq!(shapes["head.visibility.bias"], vec![6]);
        assert_eq!(shapes["token_embedding"], vec![512, 24]);
        assert_eq!(shapes["ffn.input.weight"], vec![24, 48]);
        let heads = trainable_names(&config(TINY), None).unwrap();
        assert_eq!(heads.len(), 6);
        let full = trainable_names(&config(TINY), Some(FULL_ENCODER_STRATEGY)).unwrap();
        assert_eq!(full.len(), 6 + 2 + 9);
    }

    #[test]
    fn a_multi_layer_model_prefixes_its_blocks() {
        let text = TINY.replace("\"num_layers\":1", "\"num_layers\":2");
        let names = trainable_names(&config(&text), Some(FULL_ENCODER_STRATEGY)).unwrap();
        assert!(names.contains("layers.1.ffn.output.bias"));
        let last = trainable_names(&config(&text), Some(LAST_BLOCK_STRATEGY)).unwrap();
        assert!(last.contains("layers.1.attention.query.weight") && !last.contains("layers.0.attention.query.weight"));
    }

    #[test]
    fn readout_and_budget_errors_have_the_python_messages() {
        let query = TINY.replace("\"vocab_size\":512", "\"vocab_size\":512,\"readout\":\"residual_task_query_v1\"");
        assert!(validate_readout_identity(LEGACY_ARCHITECTURE, &config(&query)).is_err());
        assert!(validate_readout_identity(TASK_QUERY_ARCHITECTURE, &config(&query)).is_ok());
        let odd = TINY.replace("\"readout\"", "\"x\"").replace("\"vocab_size\":512", "\"vocab_size\":512,\"readout\":\"other\"");
        assert_eq!(query_readout(&config(&odd)).unwrap_err().0, "Unsupported Tiny readout.");
        let big = TINY.replace("\"vocab_size\":512", "\"vocab_size\":5000");
        assert_eq!(
            full_encoder_tensor_shapes(&config(&big)).unwrap_err().0,
            "Full encoder configuration exceeds the total parameter budget."
        );
    }

    #[test]
    fn the_request_is_semantic_only_and_guard_rows_carry_the_packed_target_alone() {
        use privoke_curriculum::classification::Classification;
        let train = Example::new("a", Classification(28), 1.0, BTreeMap::new());
        let guard = Example::new("b", Classification(28), 1.0, BTreeMap::new());
        let request = gradient_request(&[train], &[guard], "m", "r", 0.03, 0.05).unwrap();
        assert_eq!(request.layers, vec![4]);
        assert!(!request.examples[0].target.as_ref().unwrap().sensitivity.is_empty());
        let guard_target = request.heldout_examples[0].target.as_ref().unwrap();
        assert!(guard_target.sensitivity.is_empty() && guard_target.categories.is_empty() && guard_target.packed == 28);
        assert!(gradient_request(&[], &[], "m", "r", 0.03, 0.05).is_err());
    }

    #[test]
    fn a_response_without_the_three_executions_is_refused() {
        use privoke_curriculum::classification::Classification;
        let train = Example::new("a", Classification(28), 1.0, BTreeMap::new());
        let request = gradient_request(std::slice::from_ref(&train), std::slice::from_ref(&train), "m", "r", 0.03, 0.05).unwrap();
        let response = ComputeSemanticGradientsResponse {
            request_id: "r".into(),
            model_id: "m".into(),
            base_version: "v".into(),
            ..ComputeSemanticGradientsResponse::default()
        };
        assert_eq!(
            validate_training_response(&request, &response, Scope::Heads, 0.05, false).unwrap_err().0,
            "Runtime training requires all three actual semantic executions."
        );
        let mut layered = request.clone();
        layered.layers.clear();
        assert_eq!(
            validate_training_response(&layered, &response, Scope::Heads, 0.05, false).unwrap_err().0,
            "Training requires an explicit semantic-only request."
        );
    }
}
