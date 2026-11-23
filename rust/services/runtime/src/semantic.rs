//! The semantic layer of the worker: a model read from a read-only model root, classified with the stage 14 crate, with
//! the metadata and identity fields the Python runtime attaches (`StreamedTransformerPrivacyModel.classify`,
//! `NativeV3PrivacyModel.classify`, `pipeline._semantic_snapshot_identity`).
//!
//! The worker has no network, so models arrive the way the Python worker gets them (`worker_main.LocalModelProvider`):
//! the front end fetches and checks them and the worker only reads. A root holds `<model_id>.json` (a legacy Tiny
//! artifact) or `<model_id>/manifest.json` with the four assets of a pinned V3 package, or the controller's cache layout
//! `<model_id>/<pin>/manifest.json`. The external classifier (`PRIVOKE_LLM_CHOICE=open`) is not served here, as in the
//! Python worker, which forces the streamed choice: it needs the network, which the worker never has.
//!
//! The pretrained contextual encoder (`privoke-pretrained-context-minilm`) is served too: its `<model_id>.json` holds
//! the three offline heads, and its frozen MiniLM backbone and tokenizer are read from a read-only directory of verified
//! assets (`model.onnx`, `tokenizer.json`; the Python runtime's `PRIVOKE_PRETRAINED_CONTEXT_DIR`). Without that directory
//! the model is the layer's error, as in the Python runtime.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use privoke_contracts::digest::sha256_hex;
use privoke_contracts::fingerprint::parameter_fingerprint;
use privoke_contracts::pyfloat;
use privoke_contracts::v3::admitted_manifest;
use privoke_semantic::bert::BertConfig;
use privoke_semantic::context::{self, ContextEncoder, ContextModel};
use privoke_semantic::labels::{is_empty_classification, visibility_value};
use privoke_semantic::layer::{Finding as ModelFinding, LayerOutcome, SemanticClassifier, analyse_semantic_layer};
use privoke_semantic::{SemanticError, TinyModel, V3Model};
use serde_json::Value;

use privoke_rules::preprocessing::normalize_text;

use crate::gate::{Gate, GateStatus, GateTrace, Label};
use crate::model::Finding;
use crate::pipeline::{LayerExecution, Status};
use crate::presence::PresenceModels;
use crate::request::Layer;

/// `ARCHITECTURE` of `privoke_model/v3_contract.py`.
const V3_ARCHITECTURE: &str = "privoke_pretrained_bert_v3";
/// The device name the Tiny and V3 models report; this worker computes on the CPU.
const COMPUTE_DEVICE: &str = "cpu";
/// Threads of the V3 kernels (the stage 14 default), reported as `torch_threads`.
const V3_THREADS: usize = privoke_semantic::v3::DEFAULT_THREADS;
/// `PRETRAINED_CONTEXT_MODEL_ID`.
pub const PRETRAINED_CONTEXT_MODEL_ID: &str = context::MODEL_ID;
/// The prefix of the response metadata that names the pretrained contextual model (`privoke.pretrained_context.*`).
pub const CONTEXT_IDENTITY_PREFIX: &str = "privoke.pretrained_context.";

enum Kind {
    Tiny(Box<TinyModel>),
    V3(Box<V3Model>),
    Context(Box<ContextModel>),
}

/// A loaded model and the identity its results carry.
pub struct Loaded {
    kind: Kind,
    /// Fields of every result's metadata (the part that does not depend on the text).
    result_metadata: BTreeMap<String, String>,
    /// `privoke.semantic.*` of the response (`_semantic_snapshot_identity`), without the prefix.
    identity: BTreeMap<String, String>,
    /// `privoke.pretrained_context.*` of the response, with the prefix: present for a pretrained contextual model even
    /// when its layer failed (`pretrained_context_identity`), empty for every other model.
    context_identity: BTreeMap<String, String>,
    model_id: String,
    version: String,
    category_labels: Vec<String>,
}

impl std::fmt::Debug for Loaded {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Loaded").field("model_id", &self.model_id).field("version", &self.version).finish_non_exhaustive()
    }
}

enum Source {
    /// A cached `<id>.snapshot.pb` of the analysis service.
    Snapshot(PathBuf),
    Tiny(PathBuf),
    Package(PathBuf),
}

/// Where the frozen contextual backbone is read from, and what admits it.
#[derive(Debug, Clone)]
struct ContextAssets {
    directory: PathBuf,
    model_sha256: String,
    tokenizer_sha256: String,
    config: BertConfig,
}

/// The model roots of the worker and the models loaded from them.
#[derive(Debug)]
pub struct SemanticLayer {
    roots: Vec<PathBuf>,
    latest: Option<String>,
    context: Option<ContextAssets>,
    cache: Mutex<HashMap<String, (String, Arc<Loaded>)>>,
}

fn valid_model_id(model_id: &str) -> bool {
    let mut chars = model_id.chars();
    let Some(first) = chars.next() else { return false };
    model_id.chars().count() <= 128
        && first.is_ascii_alphanumeric()
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
}

fn round(value: f64, places: usize) -> f64 {
    format!("{value:.places$}").parse::<f64>().unwrap_or(value)
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))
}

impl SemanticLayer {
    /// A layer over the model roots, which must be directories. `latest` is what the alias `latest` resolves to.
    pub fn new(roots: Vec<PathBuf>, latest: Option<String>) -> Result<Self, String> {
        for root in &roots {
            if !root.is_dir() {
                return Err(format!("Model root is not a directory: {}", root.display()));
            }
        }
        Ok(Self { roots, latest, context: None, cache: Mutex::new(HashMap::new()) })
    }

    /// Serves the pretrained contextual encoder from `directory`, which holds `model.onnx` and `tokenizer.json`: both are
    /// verified against the pins of the contract (`BACKBONE_SHA256`, `TOKENIZER_SHA256`) before they are parsed.
    #[must_use]
    pub fn with_pretrained_context_dir(self, directory: impl Into<PathBuf>) -> Self {
        self.with_pretrained_context_assets(directory, context::BACKBONE_SHA256, context::TOKENIZER_SHA256, context::minilm_config())
    }

    /// As [`SemanticLayer::with_pretrained_context_dir`], admitting the two files by the given SHA-256 values and reading
    /// the backbone with the given configuration. The product passes the pinned values; the tests a small synthetic
    /// backbone, whose heads still have the pinned width.
    #[must_use]
    pub fn with_pretrained_context_assets(
        mut self,
        directory: impl Into<PathBuf>,
        model_sha256: &str,
        tokenizer_sha256: &str,
        config: BertConfig,
    ) -> Self {
        self.context = Some(ContextAssets {
            directory: directory.into(),
            model_sha256: model_sha256.to_string(),
            tokenizer_sha256: tokenizer_sha256.to_string(),
            config,
        });
        self
    }

    fn locate(&self, model_id: &str) -> Result<Source, String> {
        // A cached snapshot comes first, in any root, as in the Python worker's shim.
        for root in &self.roots {
            let cached = crate::snapshot::path(root, model_id);
            if cached.is_file() {
                return Ok(Source::Snapshot(cached));
            }
        }
        for root in &self.roots {
            let package = root.join(model_id);
            if package.join("manifest.json").is_file() {
                return Ok(Source::Package(package));
            }
            if package.is_dir() {
                let mut pinned: Vec<PathBuf> = std::fs::read_dir(&package)
                    .map(|entries| {
                        entries.flatten().map(|entry| entry.path()).filter(|path| path.join("manifest.json").is_file()).collect()
                    })
                    .unwrap_or_default();
                pinned.sort();
                if let Some(first) = pinned.into_iter().next() {
                    return Ok(Source::Package(first));
                }
            }
            let artifact = root.join(format!("{model_id}.json"));
            if artifact.is_file() {
                return Ok(Source::Tiny(artifact));
            }
        }
        Err(format!("Model {model_id} is not available in the worker model roots."))
    }

    /// `LocalModelProvider.fetch`, with the snapshot cache: a model is rebuilt only when its bytes change.
    pub fn fetch(&self, requested: &str) -> Result<Arc<Loaded>, String> {
        let model_id = if requested == "latest" {
            self.latest.clone().ok_or_else(|| "latest is not resolvable in the worker; name the model explicitly.".to_string())?
        } else {
            requested.to_string()
        };
        if !valid_model_id(&model_id) {
            return Err("model_id is not a valid model identifier.".to_string());
        }
        let (bytes, path_for_package, cached) = match self.locate(&model_id)? {
            Source::Snapshot(path) => (read(&path)?, None, true),
            Source::Tiny(path) => (read(&path)?, None, false),
            Source::Package(directory) => (read(&directory.join("manifest.json"))?, Some(directory), false),
        };
        let key = sha256_hex(&bytes);
        if let Some((cached_key, loaded)) = self.cache.lock().unwrap_or_else(PoisonError::into_inner).get(&model_id)
            && *cached_key == key
        {
            return Ok(Arc::clone(loaded));
        }
        let loaded = Arc::new(match (path_for_package, cached) {
            (Some(directory), _) => load_package(&model_id, &directory, &bytes, &key)?,
            (None, true) => self.load_value(&model_id, &crate::snapshot::decode(&model_id, &bytes)?.value)?,
            (None, false) => self.load_artifact(&model_id, &bytes)?,
        });
        self.cache.lock().unwrap_or_else(PoisonError::into_inner).insert(model_id, (key, Arc::clone(&loaded)));
        Ok(loaded)
    }

    /// The layer for one prompt: normalise, classify, map spans back (`analyse_semantic_layer`), and attach the metadata
    /// and the identity. A model that cannot be read, or cannot classify the text, is the layer's error.
    pub fn run(&self, text: &str, model_id: Option<&str>) -> LayerExecution {
        let failed = |message: String, identity: Option<BTreeMap<String, String>>| LayerExecution {
            layer: Layer::Semantic,
            status: Status::Error,
            results: Vec::new(),
            error: Some(message),
            identity,
            gate: None,
        };
        let loaded = match self.fetch(model_id.unwrap_or("latest")) {
            Ok(loaded) => loaded,
            Err(message) => return failed(message, None),
        };
        let adapter = Adapter { model: &loaded, metadata: RefCell::new(BTreeMap::new()) };
        match analyse_semantic_layer(&adapter, text) {
            LayerOutcome::Ok(hits) => {
                let results = findings(hits, &adapter.metadata.into_inner());
                let mut identity = loaded.identity.clone();
                identity.extend(loaded.context_identity.clone());
                LayerExecution { layer: Layer::Semantic, status: Status::Ok, results, error: None, identity: Some(identity), gate: None }
            }
            // A pretrained contextual model that was loaded names itself even when it could not classify the prompt.
            LayerOutcome::Error(message) => failed(message, (!loaded.context_identity.is_empty()).then(|| loaded.context_identity.clone())),
        }
    }

    /// An artifact that is not a V3 package: the pretrained contextual heads, or a legacy Tiny model.
    fn load_artifact(&self, model_id: &str, bytes: &[u8]) -> Result<Loaded, String> {
        let value: Value = serde_json::from_slice(bytes).map_err(|error| format!("Could not load model artifact: {error}"))?;
        self.load_value(model_id, &value)
    }

    /// The model of an artifact's JSON (read from a file, or rebuilt from a cached snapshot).
    fn load_value(&self, model_id: &str, value: &Value) -> Result<Loaded, String> {
        let architecture = value.get("architecture").and_then(Value::as_str).unwrap_or_default();
        if architecture == context::ARCHITECTURE || model_id == PRETRAINED_CONTEXT_MODEL_ID {
            return load_context(model_id, value, self.context.as_ref());
        }
        load_tiny(model_id, value)
    }

    /// The semantic layer behind a presence gate (`pipeline._execute_semantic_with_presence_gate`). The semantic model
    /// classifies first; the gate model's probability for the normalised prompt, against the request's threshold or the
    /// model's own, decides whether the findings are kept. The trace says what happened in every case, and a gated
    /// execution carries no model identity (Python attaches none).
    pub fn run_gated(&self, presence: &PresenceModels, text: &str, model_id: Option<&str>, gate: &Gate) -> LayerExecution {
        let mut trace = GateTrace::not_run(gate, None);
        let failed = |trace: GateTrace, message: String, results: Vec<Finding>| LayerExecution {
            layer: Layer::Semantic,
            status: Status::Error,
            results,
            error: Some(message),
            identity: None,
            gate: Some(trace),
        };
        let loaded = match self.fetch(model_id.unwrap_or("latest")) {
            Ok(loaded) => loaded,
            Err(message) => {
                trace.error = Some(message.clone());
                return failed(trace, message, Vec::new());
            }
        };
        let identity = |key: &str| loaded.identity.get(key).cloned().unwrap_or_default();
        trace.contextual_model_id = identity("model_id");
        trace.contextual_model_version = identity("model_version");
        trace.contextual_artifact_checksum = identity("artifact_checksum");
        trace.contextual_parameter_fingerprint = identity("parameter_fingerprint");
        let adapter = Adapter { model: &loaded, metadata: RefCell::new(BTreeMap::new()) };
        let results = match analyse_semantic_layer(&adapter, text) {
            LayerOutcome::Ok(hits) => findings(hits, &adapter.metadata.into_inner()),
            LayerOutcome::Error(message) => {
                trace.error = Some(message.clone());
                return failed(trace, message, Vec::new());
            }
        };
        match decide_presence(presence, text, gate) {
            Ok(decision) => {
                let present = decision.probability >= decision.decision_threshold;
                trace.status = GateStatus::Applied;
                trace.model_id.clone_from(&decision.model.model_id);
                trace.model_version.clone_from(&decision.model.version);
                trace.artifact_checksum.clone_from(&decision.model.artifact_checksum);
                trace.parameter_fingerprint.clone_from(&decision.model.parameter_fingerprint);
                trace.probability = Some(decision.probability);
                trace.model_threshold = Some(decision.model_threshold);
                trace.decision_threshold = Some(decision.decision_threshold);
                trace.predicted_label = Some(if present { Label::Present } else { Label::Absent });
                trace.semantic_results.clone_from(&results);
                LayerExecution {
                    layer: Layer::Semantic,
                    status: Status::Ok,
                    results: if present { results } else { Vec::new() },
                    error: None,
                    identity: None,
                    gate: Some(trace),
                }
            }
            Err(message) => {
                trace.status = GateStatus::Error;
                trace.semantic_results.clone_from(&results);
                trace.error = Some(message.clone());
                failed(trace, message, results)
            }
        }
    }
}

/// What the gate model decided for a prompt.
struct Decision {
    model: Arc<crate::presence::LoadedPresence>,
    probability: f64,
    model_threshold: f64,
    decision_threshold: f64,
}

/// The gate's probability for the normalised prompt and the checks on its three numbers.
fn decide_presence(presence: &PresenceModels, text: &str, gate: &Gate) -> Result<Decision, String> {
    let model = presence.fetch(&gate.model_id)?;
    let normalised = normalize_text(text).map_err(|error| error.to_string())?;
    let probability = model.model.predict_probability(&normalised);
    let model_threshold = model.threshold;
    let decision_threshold = gate.threshold.unwrap_or(model_threshold);
    for (name, value) in [
        ("presence probability", probability),
        ("presence model threshold", model_threshold),
        ("presence decision threshold", decision_threshold),
    ] {
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            return Err(format!("{name} must be finite and in [0, 1]."));
        }
    }
    Ok(Decision { model, probability, model_threshold, decision_threshold })
}

/// The findings of a semantic layer that ran: the layer's hits with the model's metadata on each.
fn findings(hits: Vec<privoke_semantic::LayerHit>, metadata: &BTreeMap<String, String>) -> Vec<Finding> {
    hits.into_iter()
        .map(|hit| Finding {
            classification: hit.classification,
            section: hit.text,
            reasoning: hit.reasoning,
            span: hit.span,
            confidence: Some(hit.confidence),
            metadata: metadata.clone(),
        })
        .collect()
}

fn load_tiny(model_id: &str, value: &Value) -> Result<Loaded, String> {
    let object = value.as_object().ok_or_else(|| "Model artifact must be a JSON object.".to_string())?;
    let text = |name: &str| object.get(name).and_then(Value::as_str);
    let architecture = text("architecture").unwrap_or_default();
    if architecture == "privoke_scratch_presence_transformer_v1" || model_id.starts_with("privoke-scratch-presence-") {
        return Err("Scratch-presence artifacts are not served by the W1 worker.".to_string());
    }
    if text("model_id") != Some(model_id) {
        return Err("Artifact model_id differs from its file name.".to_string());
    }
    let model = TinyModel::from_artifact(value).map_err(|error| error.to_string())?;
    let mut parameters: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    let mut shapes: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    let mut count = 0usize;
    for (name, tensor) in object.get("parameters").and_then(Value::as_object).into_iter().flatten() {
        let values: Vec<f64> = tensor
            .get("values")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_f64)
            .map(|v| f64::from(v as f32))
            .collect();
        count += values.len();
        shapes
            .insert(name.clone(), tensor.get("shape").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_u64).collect());
        parameters.insert(name.clone(), values);
    }
    let fingerprint = parameter_fingerprint(&parameters, Some(&shapes)).map_err(|error| error.to_string())?;
    let version = text("version").unwrap_or_default().to_string();
    let checksum = text("checksum").unwrap_or("unknown").to_string();
    let result_metadata = BTreeMap::from([
        ("classifier".to_string(), "privoke_streamed_transformer".to_string()),
        ("architecture".to_string(), architecture.to_string()),
        ("model_id".to_string(), model_id.to_string()),
        ("model_version".to_string(), version.clone()),
        ("parameter_count".to_string(), count.to_string()),
        ("parameter_fingerprint".to_string(), fingerprint.clone()),
        ("artifact_checksum".to_string(), checksum.clone()),
        ("compute_device".to_string(), COMPUTE_DEVICE.to_string()),
    ]);
    let identity = BTreeMap::from([
        ("model_id".to_string(), model_id.to_string()),
        ("model_version".to_string(), version.clone()),
        ("artifact_checksum".to_string(), checksum),
        ("parameter_fingerprint".to_string(), fingerprint),
        ("architecture".to_string(), architecture.to_string()),
    ]);
    let category_labels = model.config().category_labels.clone();
    Ok(Loaded {
        kind: Kind::Tiny(Box::new(model)),
        result_metadata,
        identity,
        context_identity: BTreeMap::new(),
        model_id: model_id.to_string(),
        version,
        category_labels,
    })
}

fn load_package(model_id: &str, directory: &Path, manifest_bytes: &[u8], pin: &str) -> Result<Loaded, String> {
    let manifest = admitted_manifest(manifest_bytes, Some(model_id)).map_err(|error| error.to_string())?;
    if manifest.model_id != model_id {
        return Err("Model package identity differs from the pinned manifest.".to_string());
    }
    let model = V3Model::load_release(directory, model_id).map_err(|error| error.to_string())?.with_threads(V3_THREADS);
    let value: Value = serde_json::from_slice(manifest_bytes).map_err(|error| error.to_string())?;
    let backbone = value.pointer("/source/weights_sha256").and_then(Value::as_str).unwrap_or_default().to_string();
    let identity_fields = [
        ("model_id", model_id.to_string()),
        ("model_version", pin.to_string()),
        ("artifact_checksum", pin.to_string()),
        ("parameter_fingerprint", manifest.blob.clone()),
        ("architecture", V3_ARCHITECTURE.to_string()),
    ];
    let mut identity: BTreeMap<String, String> = identity_fields.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    identity.insert("backbone_sha256".to_string(), backbone);
    identity.insert("tokenizer_sha256".to_string(), manifest.vocab.clone());
    let mut result_metadata = identity.clone();
    result_metadata.insert("parameter_count".to_string(), manifest.parameter_count.to_string());
    for target in [&mut identity, &mut result_metadata] {
        target.insert("compute_device".to_string(), COMPUTE_DEVICE.to_string());
        target.insert("torch_threads".to_string(), V3_THREADS.to_string());
    }
    Ok(Loaded {
        kind: Kind::V3(Box::new(model)),
        result_metadata,
        identity,
        context_identity: BTreeMap::new(),
        model_id: model_id.to_string(),
        version: pin.to_string(),
        category_labels: Vec::new(),
    })
}

/// The labels of the three heads in the order of the contract (`LABELS`), as the config of an artifact lists them.
fn context_labels() -> [(&'static str, Vec<&'static str>); 3] {
    [
        ("sensitivity_labels", privoke_semantic::labels::SENSITIVITY.iter().map(|(name, _)| *name).collect()),
        ("visibility_labels", privoke_semantic::labels::VISIBILITY.iter().map(|(name, _)| *name).collect()),
        ("category_labels", privoke_semantic::labels::CATEGORY.iter().map(|(name, _)| *name).collect()),
    ]
}

/// `validate_pretrained_artifact` (and the generic part of `validate_artifact`, except the checksum, which the fetch that
/// delivered the file has verified, as for the Tiny artifacts): the exact key sets, the pinned constants of the config,
/// the label order, the threshold, the release identity and the six frozen head tensors.
fn validate_context(object: &serde_json::Map<String, Value>) -> Result<(f64, usize), String> {
    let fail = |message: &str| Err::<(), String>(message.to_string());
    const ARTIFACT_KEYS: [&str; 9] =
        ["schema_version", "model_id", "version", "generated_at_unix", "architecture", "config", "parameters", "metadata", "checksum"];
    if object.len() != ARTIFACT_KEYS.len() || ARTIFACT_KEYS.iter().any(|key| !object.contains_key(*key)) {
        fail("Pretrained contextual artifact has unsupported fields/architecture.")?;
    }
    if object.get("architecture").and_then(Value::as_str) != Some(context::ARCHITECTURE) {
        fail("Pretrained contextual artifact has unsupported fields/architecture.")?;
    }
    let config = object.get("config").and_then(Value::as_object);
    let constants = [
        ("task", Value::from("contextual_privacy")),
        ("backbone_model_id", Value::from("sentence-transformers/all-MiniLM-L6-v2")),
        ("backbone_revision", Value::from("1110a243fdf4706b3f48f1d95db1a4f5529b4d41")),
        ("backbone_sha256", Value::from(context::BACKBONE_SHA256)),
        ("tokenizer_sha256", Value::from(context::TOKENIZER_SHA256)),
        ("hidden_size", Value::from(context::HIDDEN_SIZE)),
        ("pooling", Value::from("masked_mean_l2_v1")),
        ("normalization", Value::from("detector_normalize_text_v1")),
        ("category_semantics", Value::from("asserted_personal_disclosure_v1")),
        ("arithmetic", Value::from("float32_onnx_numpy_heads_v1")),
    ];
    let labels = context_labels();
    let config_keys = constants.len() + 1 + labels.len() + 1; // constants, max_tokens, the label lists, the threshold
    let Some(config) = config.filter(|config| config.len() == config_keys) else {
        return Err("Pretrained contextual config/model ID is unsupported.".to_string());
    };
    if object.get("model_id").and_then(Value::as_str) != Some(PRETRAINED_CONTEXT_MODEL_ID)
        || config.keys().any(|key| {
            !(constants.iter().any(|(name, _)| *name == key.as_str())
                || key == "max_tokens"
                || key == "category_threshold"
                || labels.iter().any(|(name, _)| *name == key.as_str()))
        })
    {
        return Err("Pretrained contextual config/model ID is unsupported.".to_string());
    }
    for (name, expected) in &constants {
        if config.get(*name) != Some(expected) {
            return Err("Pretrained contextual encoder contract does not match.".to_string());
        }
    }
    let max_tokens = config.get("max_tokens").and_then(Value::as_u64).and_then(|value| usize::try_from(value).ok());
    let Some(max_tokens) = max_tokens.filter(|value| context::SUPPORTED_MAX_TOKENS.contains(value)) else {
        return Err("Pretrained contextual max_tokens must be exactly 256 or 512.".to_string());
    };
    for (name, expected) in &labels {
        let listed: Option<Vec<&str>> =
            config.get(*name).and_then(Value::as_array).map(|items| items.iter().filter_map(Value::as_str).collect());
        if listed.as_deref() != Some(expected.as_slice())
            || config.get(*name).and_then(Value::as_array).map(Vec::len) != Some(expected.len())
        {
            return Err("Pretrained contextual label order does not match.".to_string());
        }
    }
    let threshold = match config.get("category_threshold") {
        Some(Value::Number(number)) => number.as_f64().filter(|value| value.is_finite() && *value > 0.0 && *value < 1.0),
        _ => None,
    };
    let Some(threshold) = threshold else {
        return Err("Pretrained category threshold must be finite and between zero and one.".to_string());
    };
    if object.get("schema_version").and_then(Value::as_i64) != Some(1) {
        return Err("Pretrained contextual schema is unsupported.".to_string());
    }
    let version = object.get("version").and_then(Value::as_str).unwrap_or_default();
    let mut chars = version.chars();
    let version_ok = chars.next().is_some_and(|first| first.is_ascii_alphanumeric())
        && version.len() <= 128
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '_' | '-'));
    if !version_ok || object.get("generated_at_unix").and_then(Value::as_i64).is_none_or(|stamp| stamp <= 0) {
        return Err("Pretrained contextual version is invalid.".to_string());
    }
    let strings = object.get("metadata").and_then(Value::as_object).is_some_and(|metadata| metadata.values().all(Value::is_string));
    if !strings {
        return Err("Pretrained contextual metadata must contain strings.".to_string());
    }
    if object.get("checksum").and_then(Value::as_str).is_none_or(|checksum| checksum.len() != 64) {
        return Err("Model artifact has no valid checksum.".to_string());
    }
    Ok((threshold, max_tokens))
}

/// Head tensors by name: shape and float32 values.
type Heads = BTreeMap<String, (Vec<usize>, Vec<f32>)>;

/// The six head tensors of a validated artifact: `(name, shape, values rounded to float32)`.
fn context_heads(object: &serde_json::Map<String, Value>) -> Result<Heads, String> {
    let tensors = object
        .get("parameters")
        .and_then(Value::as_object)
        .ok_or_else(|| "Pretrained contextual tensor fields do not match.".to_string())?;
    let mut expected: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (task, labels) in [("sensitivity", 4usize), ("visibility", 6), ("category", 10)] {
        expected.insert(format!("head.{task}.weight"), vec![context::HIDDEN_SIZE, labels]);
        expected.insert(format!("head.{task}.bias"), vec![labels]);
    }
    if tensors.len() != expected.len() || expected.keys().any(|name| !tensors.contains_key(name)) {
        return Err("Pretrained contextual model requires exactly six head tensors.".to_string());
    }
    let mut heads = BTreeMap::new();
    for (name, shape) in &expected {
        let tensor = tensors.get(name).and_then(Value::as_object).filter(|tensor| tensor.len() == 3);
        let Some(tensor) = tensor else { return Err("Pretrained contextual tensor fields do not match.".to_string()) };
        let (Some(listed), Some(values), Some(trainable)) =
            (tensor.get("shape").and_then(Value::as_array), tensor.get("values").and_then(Value::as_array), tensor.get("trainable"))
        else {
            return Err("Pretrained contextual tensor fields do not match.".to_string());
        };
        let listed: Option<Vec<usize>> = listed.iter().map(|size| size.as_u64().and_then(|size| usize::try_from(size).ok())).collect();
        if listed.as_ref() != Some(shape) {
            return Err("Pretrained contextual head shape does not match.".to_string());
        }
        if *trainable != Value::Bool(false) {
            return Err("Pretrained contextual heads permit offline fitting only.".to_string());
        }
        if values.len() != shape.iter().product::<usize>() {
            return Err("Pretrained contextual head length does not match.".to_string());
        }
        let mut rounded = Vec::with_capacity(values.len());
        for value in values {
            let number = match value {
                Value::Number(number) => number.as_f64(),
                _ => None,
            };
            let Some(number) = number else { return Err("Pretrained contextual head values must be numeric.".to_string()) };
            let narrowed = number as f32;
            if !narrowed.is_finite() {
                return Err("Parameter is outside finite float32 range.".to_string());
            }
            rounded.push(narrowed);
        }
        heads.insert(name.clone(), (shape.clone(), rounded));
    }
    Ok(heads)
}

/// A pretrained contextual model: the heads of the artifact over the frozen encoder of the asset directory.
fn load_context(model_id: &str, value: &Value, assets: Option<&ContextAssets>) -> Result<Loaded, String> {
    let object = value.as_object().ok_or_else(|| "Model artifact must be a JSON object.".to_string())?;
    if object.get("model_id").and_then(Value::as_str) != Some(model_id) {
        return Err("Artifact model_id differs from its file name.".to_string());
    }
    let (threshold, max_tokens) = validate_context(object)?;
    let heads = context_heads(object)?;
    let assets = assets.ok_or_else(|| "PRIVOKE_PRETRAINED_CONTEXT_DIR must name verified local encoder assets.".to_string())?;
    let encoder = ContextEncoder::load_directory_admitted_by(
        &assets.directory,
        max_tokens,
        &assets.model_sha256,
        &assets.tokenizer_sha256,
        &assets.config,
    )
    .map_err(|error| error.to_string())?;
    let head = |task: &str, part: &str| heads.get(&format!("head.{task}.{part}")).map(|(_, values)| values.as_slice()).unwrap_or_default();
    let model = ContextModel::new(
        encoder,
        [head("sensitivity", "weight"), head("visibility", "weight"), head("category", "weight")],
        [head("sensitivity", "bias"), head("visibility", "bias"), head("category", "bias")],
        threshold,
    )
    .map_err(|error| error.to_string())?;

    let mut parameters: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    let mut shapes: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    let mut count = 0usize;
    for (name, (shape, values)) in &heads {
        count += values.len();
        parameters.insert(name.clone(), values.iter().map(|value| f64::from(*value)).collect());
        shapes.insert(name.clone(), shape.iter().map(|size| *size as u64).collect());
    }
    let fingerprint = parameter_fingerprint(&parameters, Some(&shapes)).map_err(|error| error.to_string())?;
    let text = |name: &str| object.get(name).and_then(Value::as_str).unwrap_or_default().to_string();
    let (version, checksum) = (text("version"), text("checksum"));
    let result_metadata = BTreeMap::from([
        ("classifier".to_string(), "privoke_pretrained_context".to_string()),
        ("architecture".to_string(), context::ARCHITECTURE.to_string()),
        ("model_id".to_string(), model_id.to_string()),
        ("model_version".to_string(), version.clone()),
        ("parameter_count".to_string(), count.to_string()),
        ("parameter_fingerprint".to_string(), fingerprint.clone()),
        ("artifact_checksum".to_string(), checksum.clone()),
        ("compute_device".to_string(), COMPUTE_DEVICE.to_string()),
        ("backbone_sha256".to_string(), context::BACKBONE_SHA256.to_string()),
        ("tokenizer_sha256".to_string(), context::TOKENIZER_SHA256.to_string()),
    ]);
    // `_semantic_snapshot_identity`: the backbone and tokenizer digests only when the snapshot metadata carries them.
    let mut identity = BTreeMap::from([
        ("model_id".to_string(), model_id.to_string()),
        ("model_version".to_string(), version.clone()),
        ("artifact_checksum".to_string(), checksum.clone()),
        ("parameter_fingerprint".to_string(), fingerprint.clone()),
        ("architecture".to_string(), context::ARCHITECTURE.to_string()),
    ]);
    for name in ["backbone_sha256", "tokenizer_sha256"] {
        if let Some(digest) = object.get("metadata").and_then(|metadata| metadata.get(name)).and_then(Value::as_str) {
            identity.insert(name.to_string(), digest.to_string());
        }
    }
    // `pipeline._execute_pretrained_context`: the identity the response carries whatever the layer's outcome.
    let context_identity = [
        ("model_id", model_id.to_string()),
        ("model_version", version.clone()),
        ("artifact_checksum", checksum),
        ("parameter_fingerprint", fingerprint),
        ("backbone_sha256", context::BACKBONE_SHA256.to_string()),
        ("tokenizer_sha256", context::TOKENIZER_SHA256.to_string()),
    ]
    .into_iter()
    .map(|(name, value)| (format!("{CONTEXT_IDENTITY_PREFIX}{name}"), value))
    .collect();
    let category_labels = privoke_semantic::labels::CATEGORY.iter().map(|(name, _)| (*name).to_string()).collect();
    Ok(Loaded {
        kind: Kind::Context(Box::new(model)),
        result_metadata,
        identity,
        context_identity,
        model_id: model_id.to_string(),
        version,
        category_labels,
    })
}

/// Lets the stage 14 layer function classify with a loaded model and keeps the metadata of the finding it made.
struct Adapter<'a> {
    model: &'a Loaded,
    metadata: RefCell<BTreeMap<String, String>>,
}

impl SemanticClassifier for Adapter<'_> {
    fn classify(&self, text: &str) -> Result<Vec<ModelFinding>, SemanticError> {
        let loaded = self.model;
        let mut metadata = loaded.result_metadata.clone();
        let findings = match &loaded.kind {
            Kind::V3(model) => model.classify(text)?,
            Kind::Tiny(model) => {
                let prediction = model.predict(text);
                streamed_findings(loaded, text, &prediction.decision, &prediction.category_probabilities, &mut metadata)
            }
            Kind::Context(model) => {
                let prediction = model.predict(text)?;
                streamed_findings(loaded, text, &prediction.prediction, &prediction.category_probabilities, &mut metadata)
            }
        };
        *self.metadata.borrow_mut() = metadata;
        Ok(findings)
    }
}

/// `StreamedTransformerPrivacyModel.classify`: the one finding of a streamed transformer, or none for the empty
/// classification, with the rounded category probabilities in the metadata.
fn streamed_findings(
    loaded: &Loaded,
    text: &str,
    decision: &privoke_semantic::Prediction,
    category_probabilities: &[f32],
    metadata: &mut BTreeMap<String, String>,
) -> Vec<ModelFinding> {
    let classification = decision.classification;
    let visibility = visibility_value(&decision.visibility).unwrap_or(0);
    if is_empty_classification(classification.sensitivity(), classification.categories(), visibility) {
        return Vec::new();
    }
    let mut probabilities: Vec<(&String, f64)> = loaded
        .category_labels
        .iter()
        .zip(category_probabilities)
        .map(|(label, probability)| (label, round(f64::from(*probability), 4)))
        .collect();
    probabilities.sort_by(|a, b| a.0.cmp(b.0));
    let body: Vec<String> = probabilities
        .iter()
        .map(|(label, value)| format!("\"{label}\": {}", pyfloat::repr(*value).unwrap_or_else(|_| "0.0".to_string())))
        .collect();
    metadata.insert("category_probabilities".to_string(), format!("{{{}}}", body.join(", ")));
    vec![ModelFinding {
        classification,
        confidence: decision.confidence,
        reasoning: format!(
            "Streamed transformer {} {} predicted {}/{}.",
            loaded.model_id, loaded.version, decision.sensitivity, decision.visibility
        ),
        span: if text.is_empty() { None } else { Some((0, text.chars().count())) },
        section: text.to_string(),
    }]
}
