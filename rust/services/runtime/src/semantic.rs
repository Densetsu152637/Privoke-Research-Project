//! The semantic layer of the worker: a model read from a read-only model root, classified with the stage 14 crate, with
//! the metadata and identity fields the Python runtime attaches (`StreamedTransformerPrivacyModel.classify`,
//! `NativeV3PrivacyModel.classify`, `pipeline._semantic_snapshot_identity`).
//!
//! The worker has no network, so models arrive the way the Python worker gets them (`worker_main.LocalModelProvider`):
//! the front end fetches and checks them and the worker only reads. A root holds `<model_id>.json` (a legacy Tiny
//! artifact) or `<model_id>/manifest.json` with the four assets of a pinned V3 package, or the controller's cache layout
//! `<model_id>/<pin>/manifest.json`. The external classifier (`PRIVOKE_LLM_CHOICE=open`) is not served here, as in the
//! Python worker, which forces the streamed choice: it needs the network, which the worker never has.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use privoke_contracts::digest::sha256_hex;
use privoke_contracts::fingerprint::parameter_fingerprint;
use privoke_contracts::pyfloat;
use privoke_contracts::v3::admitted_manifest;
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
/// `PRETRAINED_CONTEXT_MODEL_ID`: served by the Python worker only.
pub const PRETRAINED_CONTEXT_MODEL_ID: &str = "privoke-pretrained-context-minilm";

enum Kind {
    Tiny(Box<TinyModel>),
    V3(Box<V3Model>),
}

/// A loaded model and the identity its results carry.
pub struct Loaded {
    kind: Kind,
    /// Fields of every result's metadata (the part that does not depend on the text).
    result_metadata: BTreeMap<String, String>,
    /// `privoke.semantic.*` of the response (`_semantic_snapshot_identity`), without the prefix.
    identity: BTreeMap<String, String>,
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
    Tiny(PathBuf),
    Package(PathBuf),
}

/// The model roots of the worker and the models loaded from them.
#[derive(Debug)]
pub struct SemanticLayer {
    roots: Vec<PathBuf>,
    latest: Option<String>,
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
        Ok(Self { roots, latest, cache: Mutex::new(HashMap::new()) })
    }

    fn locate(&self, model_id: &str) -> Result<Source, String> {
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
        let (bytes, path_for_package) = match self.locate(&model_id)? {
            Source::Tiny(path) => (read(&path)?, None),
            Source::Package(directory) => (read(&directory.join("manifest.json"))?, Some(directory)),
        };
        let key = sha256_hex(&bytes);
        if let Some((cached_key, loaded)) = self.cache.lock().unwrap_or_else(PoisonError::into_inner).get(&model_id)
            && *cached_key == key
        {
            return Ok(Arc::clone(loaded));
        }
        let loaded = Arc::new(match path_for_package {
            Some(directory) => load_package(&model_id, &directory, &bytes, &key)?,
            None => load_tiny(&model_id, &bytes)?,
        });
        self.cache.lock().unwrap_or_else(PoisonError::into_inner).insert(model_id, (key, Arc::clone(&loaded)));
        Ok(loaded)
    }

    /// The layer for one prompt: normalise, classify, map spans back (`analyse_semantic_layer`), and attach the metadata
    /// and the identity. A model that cannot be read, or cannot classify the text, is the layer's error.
    pub fn run(&self, text: &str, model_id: Option<&str>) -> LayerExecution {
        let failed = |message: String| LayerExecution {
            layer: Layer::Semantic,
            status: Status::Error,
            results: Vec::new(),
            error: Some(message),
            identity: None,
            gate: None,
        };
        let loaded = match self.fetch(model_id.unwrap_or("latest")) {
            Ok(loaded) => loaded,
            Err(message) => return failed(message),
        };
        let adapter = Adapter { model: &loaded, metadata: RefCell::new(BTreeMap::new()) };
        match analyse_semantic_layer(&adapter, text) {
            LayerOutcome::Ok(hits) => {
                let results = findings(hits, &adapter.metadata.into_inner());
                LayerExecution {
                    layer: Layer::Semantic,
                    status: Status::Ok,
                    results,
                    error: None,
                    identity: Some(loaded.identity.clone()),
                    gate: None,
                }
            }
            LayerOutcome::Error(message) => failed(message),
        }
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

fn load_tiny(model_id: &str, bytes: &[u8]) -> Result<Loaded, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|error| format!("Could not load model artifact: {error}"))?;
    let object = value.as_object().ok_or_else(|| "Model artifact must be a JSON object.".to_string())?;
    let text = |name: &str| object.get(name).and_then(Value::as_str);
    let architecture = text("architecture").unwrap_or_default();
    if architecture == "privoke_scratch_presence_transformer_v1"
        || architecture == "privoke_pretrained_context_v1"
        || model_id.starts_with("privoke-scratch-presence-")
        || model_id == PRETRAINED_CONTEXT_MODEL_ID
    {
        return Err("Scratch-presence and pretrained-context artifacts are not served by the W1 worker.".to_string());
    }
    if text("model_id") != Some(model_id) {
        return Err("Artifact model_id differs from its file name.".to_string());
    }
    let model = TinyModel::from_artifact(&value).map_err(|error| error.to_string())?;
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
    Ok(Loaded { kind: Kind::Tiny(Box::new(model)), result_metadata, identity, model_id: model_id.to_string(), version, category_labels })
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
        model_id: model_id.to_string(),
        version: pin.to_string(),
        category_labels: Vec::new(),
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
                // `StreamedTransformerPrivacyModel.classify`.
                let prediction = model.predict(text);
                let decision = &prediction.decision;
                let classification = decision.classification;
                let visibility = visibility_value(&decision.visibility).unwrap_or(0);
                if is_empty_classification(classification.sensitivity(), classification.categories(), visibility) {
                    Vec::new()
                } else {
                    let mut probabilities: Vec<(&String, f64)> = loaded
                        .category_labels
                        .iter()
                        .zip(&prediction.category_probabilities)
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
            }
        };
        *self.metadata.borrow_mut() = metadata;
        Ok(findings)
    }
}
