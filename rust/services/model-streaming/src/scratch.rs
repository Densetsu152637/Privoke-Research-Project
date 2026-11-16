//! Scratch presence transformer artifacts ("privoke-scratch-presence-*"). Port of `scratch_presence.go`.

use std::collections::BTreeMap;

use privoke_contracts::json::Value;

use crate::artifact::{MAX_ARTIFACT_BYTES, ModelArtifact};
use crate::error::{Error, Result};
use crate::fail;
use crate::jsonx::{self, Object};

/// The scratch architecture.
pub const SCRATCH_PRESENCE_ARCHITECTURE: &str = "privoke_scratch_presence_transformer_v1";
/// Bound on the compact scratch config.
pub const MAX_SCRATCH_CONFIG_BYTES: usize = 8192;

/// Profile dimensions: vocabulary, hidden, intermediate, tokens, layers, heads.
pub fn profile_dimensions(profile: &str) -> Option<[i64; 6]> {
    match profile {
        "efficient" => Some([512, 24, 48, 64, 1, 2]),
        "balanced" => Some([512, 32, 64, 96, 2, 4]),
        "quality" => Some([768, 32, 64, 128, 3, 4]),
        _ => None,
    }
}

/// The profile names.
pub const PROFILES: [&str; 3] = ["efficient", "balanced", "quality"];
const MODES: [&str; 2] = ["head-only", "full-encoder"];

/// The six admitted scratch model IDs.
pub fn is_scratch_model_id(id: &str) -> bool {
    PROFILES.iter().any(|profile| MODES.iter().any(|suffix| id == format!("privoke-scratch-presence-{profile}-{suffix}")))
}

/// Every scratch model ID.
pub fn scratch_model_ids() -> Vec<String> {
    let mut ids = Vec::new();
    for profile in PROFILES {
        for suffix in MODES {
            ids.push(format!("privoke-scratch-presence-{profile}-{suffix}"));
        }
    }
    ids
}

/// The decoded scratch config.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ScratchConfig {
    /// `task`.
    pub task: String,
    /// `profile`.
    pub profile: String,
    /// `training_mode`.
    pub training_mode: String,
    /// `vocab_size`.
    pub vocab_size: i64,
    /// `hidden_size`.
    pub hidden_size: i64,
    /// `intermediate_size`.
    pub intermediate_size: i64,
    /// `max_tokens`.
    pub max_tokens: i64,
    /// `num_layers`.
    pub num_layers: i64,
    /// `num_attention_heads`.
    pub num_attention_heads: i64,
    /// `normalization`.
    pub normalization: String,
    /// `tokenizer`.
    pub tokenizer: String,
    /// `pooling`.
    pub pooling: String,
    /// `arithmetic`.
    pub arithmetic: String,
    /// `threshold`.
    pub threshold: f64,
}

impl ScratchConfig {
    /// Go `json.Unmarshal(config, &scratchConfig{})`.
    pub fn decode(config: &str) -> Result<Self> {
        let fields = jsonx::object_of(config)?;
        Ok(Self {
            task: jsonx::string(fields.get("task"))?,
            profile: jsonx::string(fields.get("profile"))?,
            training_mode: jsonx::string(fields.get("training_mode"))?,
            vocab_size: jsonx::int64(fields.get("vocab_size"))?,
            hidden_size: jsonx::int64(fields.get("hidden_size"))?,
            intermediate_size: jsonx::int64(fields.get("intermediate_size"))?,
            max_tokens: jsonx::int64(fields.get("max_tokens"))?,
            num_layers: jsonx::int64(fields.get("num_layers"))?,
            num_attention_heads: jsonx::int64(fields.get("num_attention_heads"))?,
            normalization: jsonx::string(fields.get("normalization"))?,
            tokenizer: jsonx::string(fields.get("tokenizer"))?,
            pooling: jsonx::string(fields.get("pooling"))?,
            arithmetic: jsonx::string(fields.get("arithmetic"))?,
            threshold: jsonx::float64(fields.get("threshold"))?,
        })
    }

    /// The config as the JSON text Go's `json.Marshal` would write (test support).
    pub fn to_json(&self) -> String {
        let mut map = Object::new();
        let int = |value: i64| Value::Int(value.to_string());
        let text = |value: &str| Value::String(value.to_string());
        map.insert("task".into(), text(&self.task));
        map.insert("profile".into(), text(&self.profile));
        map.insert("training_mode".into(), text(&self.training_mode));
        map.insert("vocab_size".into(), int(self.vocab_size));
        map.insert("hidden_size".into(), int(self.hidden_size));
        map.insert("intermediate_size".into(), int(self.intermediate_size));
        map.insert("max_tokens".into(), int(self.max_tokens));
        map.insert("num_layers".into(), int(self.num_layers));
        map.insert("num_attention_heads".into(), int(self.num_attention_heads));
        map.insert("normalization".into(), text(&self.normalization));
        map.insert("tokenizer".into(), text(&self.tokenizer));
        map.insert("pooling".into(), text(&self.pooling));
        map.insert("arithmetic".into(), text(&self.arithmetic));
        map.insert("threshold".into(), Value::Float(self.threshold));
        crate::artifact::canonical_text(&Value::Object(map)).unwrap_or_default()
    }
}

/// `validateScratchJSON`: reject duplicates before any map decoding can discard their evidence, then require the
/// exact root, tensor and flag shapes.
pub fn validate_scratch_json(text: &str) -> Result<()> {
    if text.len() > MAX_ARTIFACT_BYTES || !jsonx::valid_json_unicode(text.as_bytes()) {
        fail!("invalid scratch JSON bytes");
    }
    let root = jsonx::parse_strict(text).map_err(|_| Error("duplicate scratch JSON field".into()))?;
    jsonx::exact_fields(
        Some(&root),
        &["schema_version", "model_id", "version", "generated_at_unix", "architecture", "config", "parameters", "metadata", "checksum"],
    )?;
    let Value::Object(fields) = &root else { fail!("artifact must be an object") };
    let tensors = match fields.get("parameters") {
        Some(Value::Object(map)) => map,
        Some(Value::Null) | None => return Ok(()),
        Some(_) => fail!("parameters is not an object"),
    };
    for tensor in tensors.values() {
        jsonx::exact_fields(Some(tensor), &["shape", "values", "trainable"])?;
        let Value::Object(fields) = tensor else { fail!("tensor is not an object") };
        if !matches!(fields.get("trainable"), Some(Value::Bool(_))) {
            fail!("scratch trainable flag must be explicit boolean");
        }
    }
    Ok(())
}

fn is_hash(text: &str, length: usize) -> bool {
    text.len() == length && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// `^v1\.0\.0\+epoch\.([1-9]|10)$`: the epoch digits.
fn scratch_epoch(version: &str) -> Option<&str> {
    let epoch = version.strip_prefix("v1.0.0+epoch.")?;
    matches!(epoch, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "10").then_some(epoch)
}

/// `^[1-9][0-9]{0,3}$`.
fn is_step_count(text: &str) -> bool {
    let bytes = text.as_bytes();
    (1..=4).contains(&bytes.len()) && (b'1'..=b'9').contains(&bytes[0]) && bytes.iter().all(u8::is_ascii_digit)
}

/// `validateScratchArtifact`.
pub fn validate_scratch_artifact(artifact: &ModelArtifact) -> Result<()> {
    if artifact.architecture != SCRATCH_PRESENCE_ARCHITECTURE || !is_scratch_model_id(&artifact.model_id) {
        fail!("scratch architecture/model ID mismatch");
    }
    let config_value = jsonx::parse(&artifact.config)?;
    jsonx::exact_fields(
        Some(&config_value),
        &[
            "task",
            "profile",
            "training_mode",
            "vocab_size",
            "hidden_size",
            "intermediate_size",
            "max_tokens",
            "num_layers",
            "num_attention_heads",
            "normalization",
            "tokenizer",
            "pooling",
            "arithmetic",
            "threshold",
        ],
    )?;
    match jsonx::compact(&artifact.config) {
        Some(compact) if compact.len() <= MAX_SCRATCH_CONFIG_BYTES => {}
        _ => fail!("scratch config exceeds 8 KiB or is invalid"),
    }
    if !jsonx::valid_json_unicode(artifact.config.as_bytes()) {
        fail!("invalid scratch config Unicode");
    }
    let Ok(config) = ScratchConfig::decode(&artifact.config) else { fail!("invalid scratch config") };
    let Some(dims) = profile_dimensions(&config.profile) else { fail!("scratch profile dimensions mismatch") };
    if dims
        != [
            config.vocab_size,
            config.hidden_size,
            config.intermediate_size,
            config.max_tokens,
            config.num_layers,
            config.num_attention_heads,
        ]
    {
        fail!("scratch profile dimensions mismatch");
    }
    let suffix = match config.training_mode.as_str() {
        "end_to_end" => "full-encoder",
        "head_only" => "head-only",
        _ => fail!("unsupported scratch training mode"),
    };
    if artifact.model_id != format!("privoke-scratch-presence-{}-{suffix}", config.profile) {
        fail!("scratch mode/profile identity mismatch");
    }
    if config.task != "annotation_presence"
        || config.normalization != "detector_normalize_text_v1"
        || config.tokenizer != "legacy_sha256_bucket_tokens_v1"
        || config.pooling != "half_first_half_real_mean_v1"
        || config.arithmetic != "float32_numpy_encoder_clipped_sigmoid_v1"
        || config.threshold != 0.5
    {
        fail!("unsupported scratch inference contract");
    }
    if !is_hash(&artifact.checksum, 64) {
        fail!("invalid scratch artifact checksum");
    }
    let Some(epoch) = scratch_epoch(&artifact.version) else { fail!("invalid scratch checkpoint version") };
    validate_scratch_metadata(artifact.metadata(), epoch)?;
    let expected = scratch_shapes(&config);
    if artifact.parameters.len() != expected.len() {
        fail!("scratch tensor inventory mismatch");
    }
    for (name, shape) in &expected {
        let Some(tensor) = artifact.parameters.get(name) else { fail!("scratch tensor shape mismatch") };
        if tensor.shape != *shape {
            fail!("scratch tensor shape mismatch");
        }
        let size: usize = shape.iter().map(|dimension| *dimension as usize).product();
        if tensor.values.len() != size {
            fail!("scratch tensor count mismatch");
        }
        let trainable = config.training_mode == "end_to_end" || name == "head.presence.weight" || name == "head.presence.bias";
        if tensor.trainable != trainable {
            fail!("scratch offline trainability mismatch");
        }
        for value in &tensor.values {
            if !value.is_finite() || f64::from(*value as f32) != *value {
                fail!("scratch tensor requires exact finite float32 values");
            }
        }
    }
    Ok(())
}

/// `scratchShapes`: the exact tensor inventory for a config.
pub fn scratch_shapes(config: &ScratchConfig) -> BTreeMap<String, Vec<u32>> {
    let (hidden, intermediate) = (config.hidden_size as u32, config.intermediate_size as u32);
    let mut expected: BTreeMap<String, Vec<u32>> = BTreeMap::new();
    expected.insert("token_embedding".into(), vec![config.vocab_size as u32, hidden]);
    expected.insert("position_embedding".into(), vec![config.max_tokens as u32, hidden]);
    expected.insert("head.presence.weight".into(), vec![hidden, 1]);
    expected.insert("head.presence.bias".into(), vec![1]);
    let block: [(&str, Vec<u32>); 9] = [
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
    for layer in 0..config.num_layers {
        let prefix = if config.num_layers == 1 { String::new() } else { format!("layers.{layer}.") };
        for (name, shape) in &block {
            expected.insert(format!("{prefix}{name}"), shape.clone());
        }
    }
    expected
}

/// `validateScratchMetadata`.
pub fn validate_scratch_metadata(metadata: &BTreeMap<String, String>, epoch: &str) -> Result<()> {
    let keys = [
        "training_route",
        "source_revision",
        "study_plan_sha256",
        "prepared_manifest_sha256",
        "initialization_sha256",
        "trainer_contract_sha256",
        "checkpoint_epoch",
        "training_steps",
        "training_seed",
    ];
    if metadata.len() != keys.len() {
        fail!("scratch metadata inventory mismatch");
    }
    for key in keys {
        let Some(value) = metadata.get(key) else { fail!("missing scratch metadata") };
        if !value.is_ascii() {
            fail!("scratch metadata must be ASCII");
        }
    }
    if metadata["training_route"] != "offline_release_fit_v1"
        || metadata["training_seed"] != "12102026"
        || !is_hash(&metadata["source_revision"], 40)
        || metadata["checkpoint_epoch"] != epoch
    {
        fail!("invalid scratch provenance");
    }
    for key in ["study_plan_sha256", "prepared_manifest_sha256", "initialization_sha256", "trainer_contract_sha256"] {
        if !is_hash(&metadata[key], 64) {
            fail!("invalid scratch provenance digest");
        }
    }
    let steps = &metadata["training_steps"];
    if !is_step_count(steps) || steps.parse::<u32>().map_or(true, |count| count > 2500) {
        fail!("invalid scratch training steps");
    }
    Ok(())
}
