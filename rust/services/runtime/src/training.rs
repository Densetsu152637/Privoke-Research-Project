//! The gradient RPCs in the worker: `ComputeSemanticGradients`, `ComputeUnderlyingModelGradients` and
//! `ComputePresenceGradients` (`hosting/grpc_server.py`, `LLM/privoke/training.py`, `LLM/privoke/presence_training.py`) over
//! the stage 19 computations of `privoke-training`.
//!
//! The worker serves exactly the shapes stage 19 ported and verified against Python:
//!
//! * the single-update route, the explicit local-SGD routes (`local_sgd_1_v1`, `local_sgd_4_v1`), the TRAIN diagnostics
//!   route and the full-encoder backtracking route on full-capable Tiny artifacts, in the head scope (all but
//!   backtracking) and the full-encoder scope, with the held-out guard, for the legacy, class-balanced, mean-category,
//!   decision-margin and summed-margin objectives (each route admits the objectives Python admits), with no admission
//!   header, the objective-only header (schema 2, with or without the diagnostics policy) or the backtracking header
//!   (schema 1);
//! * the policy and admission checks of FULL Adam, window and ORIGINAL-retention artifacts: a request that lacks the
//!   matching header gets Python's refusal, as a response;
//! * sparse presence gradients.
//!
//! Anything else is answered `UNSUPPORTED_ROUTE` **before any model is read or any gradient is computed**, so nothing has
//! run and the controller sends the same request to the Python worker (never twice): a header of another schema (FULL
//! Adam, retention, window), an artifact that is not full-capable, one whose FULL Adam, window or retention policy admits
//! the request (their training loops are Python's), a row without an explicit target, a pinned V3 package. The FULL Adam
//! fit itself stays on the Python worker: its audit trace hashes the float64 gradient bytes, which match Python's only
//! when the gradients are bitwise equal.
//!
//! The response metadata is Python's (`_compute_training_gradients`, `compute_presence_gradients`); the model cache key
//! hashes the same contract fields and the fingerprints are the stage 1 contract over the same float32 values.

use std::collections::BTreeMap;
use std::sync::Arc;

use privoke_contracts::canonical::{self, Variant};
use privoke_contracts::digest::sha256_hex;
use privoke_contracts::fingerprint::parameter_fingerprint;
use privoke_contracts::json::{Duplicates, ParseOptions, Value as StrictValue, parse_with};
use privoke_contracts::proto::v1::{ComputePresenceGradientsRequest, ComputeSemanticGradientsRequest, RuntimeTrainingExample};
use privoke_contracts::pyfloat;
use privoke_rules::preprocessing::normalize_text;
use privoke_rules::pyunicode;
use privoke_semantic::tiny::{Readout, TASK_QUERY_READOUT, TinyConfig};
use privoke_training::admission::{Admitted, BACKTRACKING_POLICY, Header, Route, TRAIN_DIAGNOSTICS_POLICY, admit};
use privoke_training::objective::{Example, Target};
use privoke_training::presence::{PresenceExample, PresenceRequest, PresenceSnapshot, compute_presence_gradients};
use privoke_training::rpc::{self, Request as GradientRequest, Snapshot, compute_gradients};

use crate::frames::{FrameError, Method, Request, code};
use crate::model::{category_names, visibility_name};
use crate::presence::{build_presence, validate_presence_model_id};
use crate::request::py_strip;
use crate::semantic::PRETRAINED_CONTEXT_MODEL_ID;
use crate::service::{decode, empty_layers};
use crate::store::{Artifact, ArtifactStore, LoadError, PRESENCE_ARCHITECTURE};
use crate::wire;

/// The gRPC invocation metadata key the training admission travels under.
pub const ADMISSION_HEADER: &str = "x-privoke-training-admission-v1";
const FULL_STRATEGY: &str = "contextual_full_encoder_sgd_v1";
const OBJECTIVE_KEY: &str = "contextual_training_objective";
const LEGACY_OBJECTIVE: &str = "legacy_sum_category";
const SUM_MARGIN: &str = "class_balanced_contextual_sum_category_decision_margin_v1";
const MEAN_OBJECTIVES: [&str; 2] = ["class_balanced_contextual_mean_category_v1", "class_balanced_contextual_decision_margin_v1"];
/// The objectives that a backtracking admission header (schema 1) may name and this worker serves.
const BACKTRACKING_OBJECTIVES: [&str; 3] = [LEGACY_OBJECTIVE, "class_balanced_contextual_v1", SUM_MARGIN];
const AUDIT_KEYS: [&str; 9] = [
    "training_clean_examples",
    "training_sensitive_examples",
    "raw_clean_weight",
    "raw_sensitive_weight",
    "raw_total_weight",
    "effective_clean_weight",
    "effective_sensitive_weight",
    "clean_objective_mass",
    "sensitive_objective_mass",
];
const TASK_LOSS_KEYS: [&str; 3] = ["supervised_sensitivity_ce_loss", "supervised_visibility_ce_loss", "supervised_category_bce_loss"];
const HEAD_STRATEGY: &str = "transformer_classification_head_finetune";
const MAX_TRAINING_EXAMPLES: usize = 1_024;
const MAX_TRAINING_TEXT_CHARS: usize = 200_000;
const MAX_ADMISSION_BYTES: usize = 2_048;
const SEMANTIC_LAYER: i32 = 4;
const ABSENT: i32 = 1;
const PRESENT: i32 = 2;

/// Why a gradient request did not produce a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The text the Python worker puts in the response's `error`.
    Message(String),
    /// A shape this worker does not serve, found before anything ran: the Python worker answers the call.
    Declined(String),
}

impl From<LoadError> for Failure {
    fn from(error: LoadError) -> Self {
        match error {
            LoadError::Message(text) => Self::Message(text),
            LoadError::Declined(reason) => Self::Declined(reason),
        }
    }
}

fn message(text: impl Into<String>) -> Failure {
    Failure::Message(text.into())
}

fn declined(reason: impl Into<String>) -> Failure {
    Failure::Declined(reason.into())
}

/// The gradient RPCs over the worker's model roots.
#[derive(Debug)]
pub struct Trainer {
    store: Arc<ArtifactStore>,
    max_text_chars: usize,
}

impl Trainer {
    /// A trainer reading models from `store`; texts are limited to `max_text_chars` characters.
    pub fn new(store: Arc<ArtifactStore>, max_text_chars: usize) -> Self {
        Self { store, max_text_chars }
    }

    /// One gradient request: the serialised response, or `UNSUPPORTED_ROUTE` when the shape is not served here.
    pub fn handle(&self, request: &Request) -> Result<Vec<u8>, FrameError> {
        let outcome = match request.method {
            Method::ComputeSemanticGradients => self.semantic(request, false),
            Method::ComputeUnderlyingModelGradients => self.semantic(request, true),
            Method::ComputePresenceGradients => self.presence(request),
            other => {
                return Err(FrameError::new(
                    code::UNKNOWN_METHOD,
                    format!("{} is not a gradient method.", other.name()),
                    request.request_id,
                ));
            }
        };
        match outcome {
            Ok(payload) => Ok(payload),
            Err(Outcome::Frame(error)) => Err(error),
            Err(Outcome::Failed { request_id, failure: Failure::Message(text) }) => Ok(error_response(&request_id, &text)),
            Err(Outcome::Failed { failure: Failure::Declined(reason), .. }) => Err(FrameError::new(
                code::UNSUPPORTED_ROUTE,
                format!("The Python worker serves this request: {reason}."),
                request.request_id,
            )),
        }
    }

    fn semantic(&self, request: &Request, full_encoder: bool) -> Result<Vec<u8>, Outcome> {
        let message = decode::<ComputeSemanticGradientsRequest>(request, "ComputeSemanticGradientsRequest").map_err(Outcome::Frame)?;
        if message.layers.is_empty() {
            return Err(Outcome::Frame(empty_layers(request)));
        }
        self.semantic_response(&message, &request.metadata, full_encoder)
            .map_err(|failure| Outcome::Failed { request_id: message.request_id.clone(), failure })
    }

    fn presence(&self, request: &Request) -> Result<Vec<u8>, Outcome> {
        let message = decode::<ComputePresenceGradientsRequest>(request, "ComputePresenceGradientsRequest").map_err(Outcome::Frame)?;
        if message.layers.is_empty() {
            return Err(Outcome::Frame(empty_layers(request)));
        }
        self.presence_response(&message).map_err(|failure| Outcome::Failed { request_id: message.request_id.clone(), failure })
    }

    /// The request-level checks of `grpc_server._compute_training_gradients`, in Python's order.
    fn check_semantic_request(&self, request: &ComputeSemanticGradientsRequest) -> Result<(), Failure> {
        if py_strip(&request.model_id).is_empty() {
            return Err(message("model_id is required."));
        }
        if request.examples.is_empty() {
            return Err(message("At least one training example is required."));
        }
        if request.layers.as_slice() != [SEMANTIC_LAYER] {
            return Err(message("Training requires exactly the explicit semantic-only layer selection."));
        }
        if request.heldout_examples.is_empty() {
            return Err(message("Training RPC requires nonempty heldout examples for both candidate guard phases."));
        }
        self.check_batch(
            request.examples.iter().map(|item| item.text.as_str()).chain(request.heldout_examples.iter().map(|item| item.text.as_str())),
        )
    }

    fn check_batch<'a>(&self, texts: impl Iterator<Item = &'a str>) -> Result<(), Failure> {
        let lengths: Vec<usize> = texts.map(|text| text.chars().count()).collect();
        if lengths.len() > MAX_TRAINING_EXAMPLES {
            return Err(message(format!("Training batches may contain at most {MAX_TRAINING_EXAMPLES} examples.")));
        }
        if lengths.iter().sum::<usize>() > MAX_TRAINING_TEXT_CHARS {
            return Err(message(format!("Training batch text may contain at most {MAX_TRAINING_TEXT_CHARS} characters.")));
        }
        if lengths.iter().any(|length| *length == 0 || *length > self.max_text_chars) {
            return Err(message(format!("Training example text must contain 1 to {} characters.", self.max_text_chars)));
        }
        Ok(())
    }

    fn semantic_response(
        &self,
        request: &ComputeSemanticGradientsRequest,
        metadata: &[(String, String)],
        full_encoder: bool,
    ) -> Result<Vec<u8>, Failure> {
        let admission = parse_admission(metadata)?;
        if !full_encoder && admission.as_ref().is_some_and(|header| header.backtracking.is_some()) {
            return Err(message("Backtracking admission is FULL-only."));
        }
        self.check_semantic_request(request)?;
        let train = rows(&request.examples)?;
        let heldout = rows(&request.heldout_examples)?;
        if request.model_id == PRETRAINED_CONTEXT_MODEL_ID {
            return Err(message("Pretrained contextual online training is unsupported; use offline head fitting."));
        }
        let artifact = self.store.read(&request.model_id)?;
        let route = served_artifact(&artifact, admission.as_ref(), full_encoder)?;
        let objective = route.objective.clone();
        let config_value = artifact.value.get("config").ok_or_else(|| message("Model config must be a JSON object."))?;
        let config = TinyConfig::from_json(config_value, &artifact.architecture).map_err(|error| message(error.to_string()))?;
        let snapshot = Snapshot {
            artifact: artifact.value.clone(),
            full_capable: true,
            objective: objective.clone(),
            optimizer: route.optimizer.clone(),
            diagnostics: route.diagnostics,
            backtracking: route.backtracking.clone(),
        };
        let computation = GradientRequest {
            examples: train.clone(),
            heldout: heldout.clone(),
            learning_rate: request.learning_rate,
            max_gradient: request.max_gradient,
            full_encoder,
        };
        let batch = compute_gradients(&snapshot, &computation).map_err(|error| message(error.to_string()))?;
        // `reject_overlength`: a full-capable artifact refuses a text over its token context. Python raises it at the
        // first prediction, after every contract check above, so it is checked once the computation has passed them.
        let limit = config.max_tokens;
        if train.iter().chain(heldout.iter()).any(|row| token_count(&row.text) + 1 > limit) {
            return Err(message(format!("Tiny full-training input exceeds its {limit}-token context including the start token.")));
        }
        let metadata = semantic_metadata(&artifact, &config, &batch, objective.as_deref(), request, full_encoder)?;
        let shapes: BTreeMap<String, Vec<u64>> =
            batch.gradients.keys().filter_map(|name| artifact.shapes.get(name).map(|shape| (name.clone(), shape.clone()))).collect();
        Ok(gradient_response(&Parts {
            request_id: &request.request_id,
            model_id: &artifact.model_id,
            version: &artifact.version,
            gradients: &batch.gradients,
            shapes: &shapes,
            metrics: &batch.metrics,
            metadata: &metadata,
            executions: &batch.executions,
            error: &batch.error,
        }))
    }

    fn presence_response(&self, request: &ComputePresenceGradientsRequest) -> Result<Vec<u8>, Failure> {
        if request.layers.as_slice() != [SEMANTIC_LAYER] {
            return Err(message("Presence training requires explicit semantic-only layers."));
        }
        if request.heldout_examples.is_empty() {
            return Err(message("Presence training requires nonempty heldout examples."));
        }
        validate_presence_model_id(&request.model_id).map_err(Failure::Message)?;
        if py_strip(&request.request_id).is_empty() {
            return Err(message("request_id is required."));
        }
        if request.examples.is_empty() {
            return Err(message("At least one training example is required."));
        }
        self.check_batch(
            request.examples.iter().map(|item| item.text.as_str()).chain(request.heldout_examples.iter().map(|item| item.text.as_str())),
        )?;
        let mut converted = Vec::new();
        for item in request.examples.iter().chain(request.heldout_examples.iter()) {
            let target = match item.target {
                PRESENT => true,
                ABSENT => false,
                _ => return Err(message("Presence targets must be explicitly PRESENT or ABSENT.")),
            };
            converted.push(PresenceExample { text: item.text.clone(), target, weight: item.weight, group_id: item.group_id.clone() });
        }
        let heldout = converted.split_off(request.examples.len());
        let artifact = self.store.read(&request.model_id)?;
        if artifact.architecture != PRESENCE_ARCHITECTURE {
            return Err(message("Streamed model is not an annotation-presence artifact."));
        }
        build_presence(&artifact).map_err(Failure::Message)?;
        let snapshot = PresenceSnapshot { artifact: artifact.value.clone(), version: artifact.version.clone() };
        let computation =
            PresenceRequest { examples: converted, heldout, learning_rate: request.learning_rate, max_gradient: request.max_gradient };
        let batch = compute_presence_gradients(&snapshot, &computation).map_err(|error| message(error.to_string()))?;
        let mut metadata = batch.metadata.clone();
        let strings = [
            ("strategy", "sparse_annotation_presence_head_finetune".to_string()),
            ("task", "annotation_presence".to_string()),
            ("architecture", PRESENCE_ARCHITECTURE.to_string()),
            ("artifact_checksum", artifact.checksum.clone()),
            ("learning_rate", float_text(request.learning_rate)?),
            ("max_gradient", float_text(request.max_gradient)?),
            ("model_cache_key", cache_key(&artifact)?),
            ("text_preprocessing", "training_text_key_v1".to_string()),
            ("publication_arithmetic", "float32_parameters_float64_features_fsum_v1".to_string()),
        ];
        metadata.extend(strings.into_iter().map(|(key, value)| (key.to_string(), value)));
        for key in ["source_revision", "protocol_sha256", "prepared_manifest_sha256", "train_sha256", "validation_sha256"] {
            if let Some(value) = artifact.metadata.get(key) {
                metadata.insert(key.to_string(), value.clone());
            }
        }
        let shapes: BTreeMap<String, Vec<u64>> =
            batch.gradients.keys().filter_map(|name| artifact.shapes.get(name).map(|shape| (name.clone(), shape.clone()))).collect();
        Ok(gradient_response(&Parts {
            request_id: &request.request_id,
            model_id: &artifact.model_id,
            version: &artifact.version,
            gradients: &batch.gradients,
            shapes: &shapes,
            metrics: &batch.metrics,
            metadata: &metadata,
            executions: &batch.executions,
            error: "",
        }))
    }
}

/// How a request ended without a response payload.
enum Outcome {
    /// A protocol fault: an error frame.
    Frame(FrameError),
    /// A failure of the request itself, which carries the request's own id.
    Failed { request_id: String, failure: Failure },
}

/// The admission header this worker serves: the objective-only record (schema 2, the summed-margin objective with the
/// diagnostics policy or none) and the backtracking record (schema 1).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Admission {
    /// `expected_objective`.
    objective: String,
    /// `expected_diagnostics_policy` (`None` for JSON `null`).
    diagnostics: Option<String>,
    /// `expected_backtracking_preparation_sha256` of a backtracking record.
    backtracking: Option<String>,
}

impl Admission {
    /// The header as the Python `parse_training_admission_metadata` returns it.
    fn header(&self) -> Header {
        let mut header = Header::from([
            ("expected_objective".to_string(), Some(self.objective.clone())),
            ("expected_diagnostics_policy".to_string(), self.diagnostics.clone()),
        ]);
        if let Some(sha) = &self.backtracking {
            header.insert("expected_backtracking_policy".to_string(), Some(BACKTRACKING_POLICY.to_string()));
            header.insert("expected_backtracking_preparation_sha256".to_string(), Some(sha.clone()));
        }
        header
    }
}

fn is_sha256(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The admission header of the request, or `None` when it carries none. A header of any other schema, or a malformed
/// one, is declined: Python decides what it means.
fn parse_admission(metadata: &[(String, String)]) -> Result<Option<Admission>, Failure> {
    let mut headers = metadata.iter().filter(|(key, _)| key.as_str() == ADMISSION_HEADER).map(|(_, value)| value);
    let Some(header) = headers.next() else { return Ok(None) };
    if headers.next().is_some() {
        return Err(declined("the request repeats the admission header"));
    }
    if header.len() > MAX_ADMISSION_BYTES {
        return Err(declined("the admission header is over its byte budget"));
    }
    let options = ParseOptions { duplicates: Duplicates::Reject, ..ParseOptions::default() };
    let StrictValue::Object(record) =
        parse_with(header, options).map_err(|_| declined("the admission header is not a clean JSON record"))?
    else {
        return Err(declined("the admission header is not a JSON object"));
    };
    let text = |key: &str| match record.get(key) {
        Some(StrictValue::String(value)) => Some(value.as_str()),
        _ => None,
    };
    let diagnostics = match record.get("expected_diagnostics_policy") {
        Some(StrictValue::Null) => Some(None),
        Some(StrictValue::String(policy)) if policy == TRAIN_DIAGNOSTICS_POLICY => Some(Some(policy.clone())),
        _ => None,
    };
    let unserved = || declined("only the objective-only (schema 2) and backtracking (schema 1) admissions are served by the Rust worker");
    match (record.get("schema"), diagnostics) {
        (Some(StrictValue::Int(schema)), Some(diagnostics)) if schema == "2" => {
            let keys = ["schema", "expected_objective", "expected_diagnostics_policy"];
            if record.len() == keys.len()
                && keys.iter().all(|key| record.contains_key(*key))
                && text("expected_objective") == Some(SUM_MARGIN)
            {
                Ok(Some(Admission { objective: SUM_MARGIN.to_string(), diagnostics, backtracking: None }))
            } else {
                Err(unserved())
            }
        }
        (Some(StrictValue::Int(schema)), Some(Some(policy))) if schema == "1" => {
            let keys = [
                "schema",
                "expected_objective",
                "expected_diagnostics_policy",
                "expected_backtracking_policy",
                "expected_backtracking_preparation_sha256",
            ];
            let objective = text("expected_objective").filter(|name| BACKTRACKING_OBJECTIVES.contains(name));
            let preparation = text("expected_backtracking_preparation_sha256").filter(|sha| is_sha256(sha));
            match (objective, preparation) {
                (Some(objective), Some(sha))
                    if record.len() == keys.len()
                        && keys.iter().all(|key| record.contains_key(*key))
                        && text("expected_backtracking_policy") == Some(BACKTRACKING_POLICY) =>
                {
                    Ok(Some(Admission { objective: objective.to_string(), diagnostics: Some(policy), backtracking: Some(sha.to_string()) }))
                }
                _ => Err(unserved()),
            }
        }
        _ => Err(unserved()),
    }
}

/// Checks the artifact against what this worker serves and against the admission, in Python's order, and returns the
/// route it selects.
fn served_artifact(artifact: &Artifact, admission: Option<&Admission>, full_encoder: bool) -> Result<Route, Failure> {
    if artifact.architecture == PRESENCE_ARCHITECTURE {
        return Err(declined("the artifact is a presence model"));
    }
    let header = admission.map(Admission::header);
    let route = match admit(header.as_ref(), &artifact.metadata, full_encoder).map_err(|error| message(error.to_string()))? {
        Admitted::Elsewhere(reason) => return Err(declined(reason)),
        Admitted::Route(route) => route,
    };
    if artifact.metadata.get("contextual_training_strategy").map(String::as_str) != Some(FULL_STRATEGY) {
        return Err(declined("the artifact is not full-capable; the routes are verified on full-capable artifacts"));
    }
    Ok(route)
}

/// The optional contract fields of `ParameterSnapshot.cache_key` (`parameter_stream.py`).
const CACHE_KEY_OPTIONAL: [&str; 10] = [
    "contextual_training_optimizer",
    "contextual_training_diagnostics_policy",
    "contextual_training_backtracking_policy",
    "contextual_training_backtracking_preparation",
    "contextual_candidate_eligibility",
    "full_projected_adam_config_v1",
    "original_train_retention_manifest_sha256",
    "train_window_config_v1",
    "train_window_manifest_sha256",
    "original_train_component_manifest_sha256",
];

/// The training rows of a request. A row without an explicit target is Python's to answer.
fn rows(items: &[RuntimeTrainingExample]) -> Result<Vec<Example>, Failure> {
    items
        .iter()
        .map(|item| {
            if !item.has_target {
                return Err(declined("a training row has no explicit target"));
            }
            let packed = item.target.as_ref().map_or(0, |target| target.packed);
            let packed = u16::try_from(packed)
                .ok()
                .filter(|packed| *packed <= 0x7FFF)
                .ok_or_else(|| declined("a target is not a packed classification"))?;
            let visibility = visibility_name(packed).map_err(|_| declined("a target has an unknown visibility"))?;
            let sensitivity = ["S0", "S1", "S2", "S3"][usize::from(packed & 0b11)];
            let target = Target {
                sensitivity: sensitivity.to_string(),
                visibility: visibility.to_string(),
                categories: category_names(packed).into_iter().map(str::to_string).collect(),
            };
            Ok(Example { text: item.text.clone(), target, weight: item.weight })
        })
        .collect()
}

/// The number of tokens `TOKEN_PATTERN.findall(text.lower())` finds in the normalised text
/// (`[A-Za-z]+(?:'[A-Za-z]+)?|\d+|[^\w\s]`).
fn token_count(text: &str) -> usize {
    let normalised = normalize_text(text).unwrap_or_else(|_| text.to_string());
    let chars: Vec<char> = pyunicode::lower(&normalised).chars().collect();
    let (mut count, mut index) = (0usize, 0usize);
    while index < chars.len() {
        let c = chars[index];
        if c.is_ascii_alphabetic() {
            while index < chars.len() && chars[index].is_ascii_alphabetic() {
                index += 1;
            }
            if index + 1 < chars.len() && chars[index] == '\'' && chars[index + 1].is_ascii_alphabetic() {
                index += 1;
                while index < chars.len() && chars[index].is_ascii_alphabetic() {
                    index += 1;
                }
            }
            count += 1;
        } else if pyunicode::is_decimal(c) {
            while index < chars.len() && pyunicode::is_decimal(chars[index]) {
                index += 1;
            }
            count += 1;
        } else {
            if !pyunicode::is_word(c) && !pyunicode::is_space(c) {
                count += 1;
            }
            index += 1;
        }
    }
    count
}

fn float_text(value: f64) -> Result<String, Failure> {
    pyfloat::repr(value).map_err(|_| message("Parameter must be finite."))
}

/// `ParameterSnapshot.cache_key`: the model identity and the hash of the contract fields of its metadata.
fn cache_key(artifact: &Artifact) -> Result<String, Failure> {
    let fingerprint = parameter_fingerprint(&artifact.parameters, Some(&artifact.shapes)).map_err(|error| message(error.to_string()))?;
    let field = |name: &str| artifact.metadata.get(name).map_or(StrictValue::Null, |value| StrictValue::String(value.clone()));
    let mut fields = BTreeMap::from([
        ("architecture".to_string(), field("architecture")),
        ("model_config".to_string(), field("model_config")),
        ("trainable_parameters".to_string(), field("trainable_parameters")),
        ("contextual_training_strategy".to_string(), field("contextual_training_strategy")),
        ("contextual_training_objective".to_string(), field("contextual_training_objective")),
    ]);
    // The opt-in contract fields join the identity only when the artifact declares them (the legacy identity is unchanged).
    for key in CACHE_KEY_OPTIONAL {
        if let Some(value) = artifact.metadata.get(key) {
            fields.insert(key.to_string(), StrictValue::String(value.clone()));
        }
    }
    let fields = StrictValue::Object(fields);
    let contract = canonical::to_string(&fields, Variant::Utf8).map_err(|error| message(error.to_string()))?;
    Ok(format!("{}:{}:{}:{}", artifact.model_id, artifact.version, fingerprint, sha256_hex(contract.as_bytes())))
}

/// `json.dumps(config.to_mapping(), sort_keys=True, separators=(",", ":"))`: the readout key is left out for the legacy
/// readout.
fn model_config_json(config: &TinyConfig) -> Result<String, Failure> {
    let list = |values: &[String]| serde_json::to_string(values).map_err(|error| message(error.to_string()));
    let mut out = format!(
        "{{\"category_labels\":{},\"category_threshold\":{},\"hidden_size\":{},\"intermediate_size\":{},\"max_tokens\":{},\"num_attention_heads\":{},\"num_layers\":{}",
        list(&config.category_labels)?,
        float_text(config.category_threshold)?,
        config.hidden_size,
        config.intermediate_size,
        config.max_tokens,
        config.num_attention_heads,
        config.num_layers,
    );
    if config.readout == Readout::TaskQuery {
        out.push_str(&format!(",\"readout\":\"{TASK_QUERY_READOUT}\""));
    }
    out.push_str(&format!(
        ",\"sensitivity_labels\":{},\"visibility_labels\":{},\"vocab_size\":{}}}",
        list(&config.sensitivity_labels)?,
        list(&config.visibility_labels)?,
        config.vocab_size
    ));
    Ok(out)
}

fn semantic_metadata(
    artifact: &Artifact,
    config: &TinyConfig,
    batch: &rpc::Batch,
    objective: Option<&str>,
    request: &ComputeSemanticGradientsRequest,
    full_encoder: bool,
) -> Result<BTreeMap<String, String>, Failure> {
    let fingerprint = |values: &BTreeMap<String, Vec<f64>>, shapes: Option<&BTreeMap<String, Vec<u64>>>| {
        parameter_fingerprint(values, shapes).map_err(|error| message(error.to_string()))
    };
    let candidate: BTreeMap<String, Vec<f64>> =
        batch.candidate.iter().map(|(name, values)| (name.clone(), values.iter().map(|value| f64::from(*value)).collect())).collect();
    let inventory: BTreeMap<String, Vec<f64>> = batch.inventory.iter().map(|name| (name.clone(), Vec::new())).collect();
    let inventory_shapes: BTreeMap<String, Vec<u64>> =
        batch.inventory.iter().filter_map(|name| artifact.shapes.get(name).map(|shape| (name.clone(), shape.clone()))).collect();
    let names: &Vec<String> = &batch.inventory;
    let mut metadata = BTreeMap::new();
    let mut put = |key: &str, value: String| {
        metadata.insert(key.to_string(), value);
    };
    put("executed_contextual_training_objective", objective.unwrap_or(LEGACY_OBJECTIVE).to_string());
    put("strategy", (if full_encoder { FULL_STRATEGY } else { HEAD_STRATEGY }).to_string());
    put("artifact_training_strategy", FULL_STRATEGY.to_string());
    put("underlying_training_available", "true".to_string());
    put("training_scope", batch.scope.to_string());
    put("trained_parameter_names", serde_json::to_string(&names).map_err(|error| message(error.to_string()))?);
    put("trained_parameter_inventory_fingerprint", fingerprint(&inventory, Some(&inventory_shapes))?);
    put("artifact_checksum", artifact.checksum.clone());
    put("architecture", artifact.architecture.clone());
    put("model_config", model_config_json(config)?);
    put("base_parameter_fingerprint", fingerprint(&artifact.parameters, None)?);
    if batch.error.is_empty() {
        put("updated_parameter_fingerprint", fingerprint(&candidate, None)?);
    }
    put("learning_rate", float_text(request.learning_rate)?);
    put("max_gradient", float_text(request.max_gradient)?);
    put("model_cache_key", cache_key(artifact)?);
    put("text_preprocessing", "canonical_detector_normalize_text".to_string());
    for (key, value) in &batch.metadata {
        put(key, value.clone());
    }
    let metric = |name: &str| batch.metrics.get(name).copied().ok_or_else(|| message(format!("The computation reported no {name}.")));
    if let Some(name) = objective {
        put(OBJECTIVE_KEY, name.to_string());
        put("objective_strata", "classification_is_sensitive".to_string());
        for key in AUDIT_KEYS {
            put(key, float_text(metric(key)?)?);
        }
        if MEAN_OBJECTIVES.contains(&name) {
            put("category_normalization", "mean_per_label".to_string());
            put("category_count", config.category_labels.len().to_string());
            put("diagnostic_loss", "weighted_classification_distance".to_string());
            for key in TASK_LOSS_KEYS.into_iter().chain(["supervised_objective_loss"]) {
                put(key, float_text(metric(key)?)?);
            }
        }
    }
    Ok(metadata)
}

/// The parts of a gradient response (`ComputeSemanticGradientsResponse`, `ComputePresenceGradientsResponse`).
struct Parts<'a> {
    request_id: &'a str,
    model_id: &'a str,
    version: &'a str,
    gradients: &'a BTreeMap<String, Vec<f32>>,
    shapes: &'a BTreeMap<String, Vec<u64>>,
    metrics: &'a BTreeMap<String, f64>,
    metadata: &'a BTreeMap<String, String>,
    executions: &'a [(String, usize)],
    error: &'a str,
}

fn gradient_response(parts: &Parts) -> Vec<u8> {
    let mut out = Vec::new();
    wire::string(&mut out, 1, parts.request_id);
    wire::string(&mut out, 2, parts.model_id);
    wire::string(&mut out, 3, parts.version);
    for (name, values) in parts.gradients {
        let mut delta = Vec::new();
        wire::string(&mut delta, 1, name);
        wire::packed_f32(&mut delta, 2, values);
        let shape: Vec<u32> = parts.shapes.get(name).into_iter().flatten().map(|size| u32::try_from(*size).unwrap_or(u32::MAX)).collect();
        wire::packed_u32(&mut delta, 3, &shape);
        wire::message(&mut out, 4, &delta);
    }
    wire::double_map(&mut out, 5, parts.metrics);
    wire::string_map(&mut out, 6, parts.metadata);
    if !parts.error.is_empty() {
        wire::string(&mut out, 7, parts.error);
    }
    for (phase, examples) in parts.executions {
        let mut execution = Vec::new();
        wire::string(&mut execution, 1, phase);
        wire::enumeration(&mut execution, 2, SEMANTIC_LAYER);
        wire::string(&mut execution, 3, "ok");
        wire::uint32(&mut execution, 4, u32::try_from(*examples).unwrap_or(u32::MAX));
        wire::message(&mut out, 8, &execution);
    }
    out
}

/// A failed request: its own id and the error (`metadata` is empty, as Python's `training_metadata` is for these).
fn error_response(request_id: &str, text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    wire::string(&mut out, 1, request_id);
    wire::string(&mut out, 7, text);
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn header(value: &str) -> Vec<(String, String)> {
        vec![(ADMISSION_HEADER.to_string(), value.to_string())]
    }

    #[test]
    fn tokens_are_counted_as_the_python_pattern_finds_them() {
        assert_eq!(token_count("Don't stop, it's 42! x_y caf\u{e9} \u{4e2d}"), 9);
        assert_eq!(token_count("a'b' 'c 1\u{661}2"), 5);
        assert_eq!(token_count(""), 0);
        assert_eq!(token_count("one two three four five six seven eight nine ten eleven"), 11);
    }

    const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn backtracking_header(objective: &str) -> String {
        format!(
            "{{\"schema\": 1, \"expected_objective\": \"{objective}\", \"expected_diagnostics_policy\": \"train_before_candidate_v1\", \"expected_backtracking_policy\": \"full_train_backtracking_v1\", \"expected_backtracking_preparation_sha256\": \"{SHA}\"}}"
        )
    }

    #[test]
    fn the_objective_only_and_backtracking_admissions_are_served() {
        assert_eq!(parse_admission(&[]), Ok(None));
        let schema2 = format!("{{\"schema\": 2, \"expected_objective\": \"{SUM_MARGIN}\", \"expected_diagnostics_policy\": null}}");
        let objective_only = Admission { objective: SUM_MARGIN.to_string(), diagnostics: None, backtracking: None };
        assert_eq!(parse_admission(&header(&schema2)), Ok(Some(objective_only)));
        // The diagnostics policy of the objective-only record is served too.
        let with_diagnostics =
            Admission { objective: SUM_MARGIN.to_string(), diagnostics: Some(TRAIN_DIAGNOSTICS_POLICY.to_string()), backtracking: None };
        assert_eq!(parse_admission(&header(&schema2.replace("null", "\"train_before_candidate_v1\""))), Ok(Some(with_diagnostics)));
        for objective in [LEGACY_OBJECTIVE, "class_balanced_contextual_v1", SUM_MARGIN] {
            let served = Admission {
                objective: objective.to_string(),
                diagnostics: Some(TRAIN_DIAGNOSTICS_POLICY.to_string()),
                backtracking: Some(SHA.to_string()),
            };
            assert_eq!(parse_admission(&header(&backtracking_header(objective))), Ok(Some(served)), "{objective}");
        }
        let others: Vec<String> = vec![
            "{\"schema\": 3}".to_string(),
            "not json".to_string(),
            "[]".to_string(),
            schema2.replace("\"schema\": 2", "\"schema\": 1"),
            schema2.replace("2,", "2, \"schema\": 2,"),
            schema2.replace(SUM_MARGIN, "class_balanced_contextual_v1"),
            schema2.replace("null", "\"another_policy_v1\""),
            backtracking_header("class_balanced_contextual_mean_category_v1"),
            backtracking_header("x").replace(SHA, "00"),
            backtracking_header(LEGACY_OBJECTIVE).replace("full_train_backtracking_v1", "other_v1"),
            backtracking_header(LEGACY_OBJECTIVE).replace("\"train_before_candidate_v1\"", "null"),
            backtracking_header(LEGACY_OBJECTIVE).replace(", \"expected_backtracking_policy\": \"full_train_backtracking_v1\"", ""),
        ];
        for other in &others {
            assert!(matches!(parse_admission(&header(other)), Err(Failure::Declined(_))), "{other}");
        }
        let mut twice = header(&schema2);
        twice.extend(header(&schema2));
        assert!(matches!(parse_admission(&twice), Err(Failure::Declined(_))));
    }

    #[test]
    fn rows_without_a_target_are_declined_and_targets_are_unpacked() {
        let plain = RuntimeTrainingExample { text: "x".into(), weight: 1.0, ..RuntimeTrainingExample::default() };
        assert!(matches!(rows(&[plain]), Err(Failure::Declined(_))));
        // S2, visibility PU (0b11100), the IDENTITY category bit.
        let packed = 0b10 | 0b11100 | (1 << 13);
        let target = privoke_contracts::proto::v1::RuntimeClassification { packed, ..Default::default() };
        let row = RuntimeTrainingExample { text: "x".into(), has_target: true, target: Some(target), weight: 2.0 };
        let rows = rows(&[row]).unwrap();
        assert_eq!((rows[0].target.sensitivity.as_str(), rows[0].target.visibility.as_str(), rows[0].weight), ("S2", "PU", 2.0));
    }

    #[test]
    fn the_model_config_is_python_sorted_compact_json() {
        let config = serde_json::json!({
            "category_labels": ["HEALTH", "POLITICS", "RELIGION", "CRIMINAL", "FINANCIAL", "SEXUAL", "CHILD", "LOCATION", "IDENTITY", "THIRD_PARTY"],
            "category_threshold": 0.42, "hidden_size": 8, "intermediate_size": 8, "max_tokens": 12, "num_attention_heads": 2,
            "num_layers": 2, "sensitivity_labels": ["S0", "S1", "S2", "S3"],
            "visibility_labels": ["P0", "P1", "P2", "P3", "P4", "PU"], "vocab_size": 24
        });
        let parsed = TinyConfig::from_json(&config, "privoke_tiny_transformer_v1").unwrap();
        let text = model_config_json(&parsed).unwrap();
        assert!(text.starts_with("{\"category_labels\":[\"HEALTH\",\"POLITICS\""), "{text}");
        assert!(text.contains("\"category_threshold\":0.42,\"hidden_size\":8,"), "{text}");
        assert!(text.ends_with("\"visibility_labels\":[\"P0\",\"P1\",\"P2\",\"P3\",\"P4\",\"PU\"],\"vocab_size\":24}"), "{text}");
        assert!(!text.contains("readout"));
    }
}
