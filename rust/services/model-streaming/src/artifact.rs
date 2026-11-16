//! The model artifact: strict decoding, checksum verification and the per-architecture validators.
//!
//! This is a line-for-line port of `artifact.go`. The loader proceeds in the Go order: size bound, raw root
//! declarations and the scratch/pretrained duplicate guard, typed decode, raw trainable flags, checksum, validation.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use privoke_contracts::canonical::{self, Variant};
use privoke_contracts::digest;
use privoke_contracts::json::Value;

use crate::error::{Error, Result};
use crate::fail;
use crate::jsonx::{self, Object};
use crate::{contextual, presence, pretrained, scratch};

/// The supported schema version.
pub const EXPECTED_SCHEMA: i64 = 1;
/// The legacy Tiny transformer.
pub const EXPECTED_ARCHITECTURE: &str = "privoke_tiny_transformer_v1";
/// The Tiny transformer with task-query readouts.
pub const TASK_QUERY_ARCHITECTURE: &str = "privoke_tiny_transformer_v2";
/// Largest artifact file.
pub const MAX_ARTIFACT_BYTES: usize = 8 * 1024 * 1024;
/// Largest total of tensor values.
pub const MAX_PARAMETER_VALUES: usize = 65536;
/// Sparse presence model.
pub const PRESENCE_ARCHITECTURE: &str = "privoke_sparse_presence_v1";
/// Presence config bound after canonicalisation.
pub const MAX_PRESENCE_CONFIG_BYTES: usize = 2 * 1024 * 1024;
/// Presence coefficient block size.
pub const PRESENCE_BLOCK_SIZE: usize = 4096;

/// One tensor of an artifact.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Tensor {
    /// Row-major dimensions.
    pub shape: Vec<u32>,
    /// Values as written (float64 on disk, float32 on the wire).
    pub values: Vec<f64>,
    /// Whether the tensor may be trained.
    pub trainable: bool,
}

/// A decoded model artifact.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ModelArtifact {
    /// `schema_version`.
    pub schema_version: i64,
    /// `model_id`.
    pub model_id: String,
    /// `version`.
    pub version: String,
    /// `generated_at_unix`.
    pub generated_at_unix: i64,
    /// `architecture`.
    pub architecture: String,
    /// The raw `config` value exactly as written in the file (served verbatim as `model_config`).
    pub config: String,
    /// `parameters`.
    pub parameters: BTreeMap<String, Tensor>,
    /// `metadata`; `None` when the file has no object there.
    pub metadata: Option<BTreeMap<String, String>>,
    /// `checksum`.
    pub checksum: String,
}

impl ModelArtifact {
    /// The metadata map, empty when absent.
    pub fn metadata(&self) -> &BTreeMap<String, String> {
        static EMPTY: BTreeMap<String, String> = BTreeMap::new();
        self.metadata.as_ref().unwrap_or(&EMPTY)
    }

    /// Mutable metadata, creating the map.
    pub fn metadata_mut(&mut self) -> &mut BTreeMap<String, String> {
        self.metadata.get_or_insert_with(BTreeMap::new)
    }
}

/// An artifact that passed every check, with the SHA-256 of its file bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct LoadedArtifact {
    /// The artifact.
    pub artifact: ModelArtifact,
    /// SHA-256 of the exact file bytes.
    pub file_checksum: String,
}

/// `loadModelArtifact`: read a regular, non-symlink file and load it.
pub fn load_model_artifact(path: &Path, expected_model_id: &str) -> Result<LoadedArtifact> {
    let raw = read_artifact_file(path)?;
    load_model_artifact_bytes(&raw, expected_model_id)
}

/// `loadModelArtifactBytes`.
pub fn load_model_artifact_bytes(raw: &[u8], expected_model_id: &str) -> Result<LoadedArtifact> {
    if raw.is_empty() || raw.len() > MAX_ARTIFACT_BYTES {
        fail!("artifact bytes exceed supported range");
    }
    let Ok(text) = std::str::from_utf8(raw) else { fail!("decode artifact: invalid UTF-8") };
    let root = jsonx::parse(text).map_err(|error| Error(format!("decode artifact identity: {error}")))?;
    let members = jsonx::root_members(text).map_err(|error| Error(format!("decode artifact identity: {error}")))?;
    if scratch_declared(&members)? {
        scratch::validate_scratch_json(text)?;
    }
    let config = members.iter().rev().find(|member| member.key == "config").map(|member| member.raw.as_str());
    let artifact = decode_artifact(&root, config).map_err(|error| Error(format!("decode artifact: {error}")))?;
    if matches!(artifact.architecture.as_str(), PRESENCE_ARCHITECTURE | EXPECTED_ARCHITECTURE | TASK_QUERY_ARCHITECTURE) {
        validate_raw_tensor_flags(&root)?;
    }
    let checksum = calculate_artifact_checksum(&root).map_err(|error| Error(format!("calculate artifact checksum: {error}")))?;
    if artifact.checksum != checksum {
        fail!("artifact checksum does not match its contents");
    }
    validate_model_artifact(&artifact, expected_model_id)?;
    Ok(LoadedArtifact { artifact, file_checksum: digest::sha256_hex(raw) })
}

/// Decode without validating (test and tool support: the Go tests `json.Unmarshal` a file into `modelArtifact`).
pub fn decode_artifact_bytes(raw: &[u8]) -> Result<ModelArtifact> {
    let Ok(text) = std::str::from_utf8(raw) else { fail!("decode artifact: invalid UTF-8") };
    let root = jsonx::parse(text)?;
    let members = jsonx::root_members(text)?;
    let config = members.iter().rev().find(|member| member.key == "config").map(|member| member.raw.as_str());
    decode_artifact(&root, config)
}

fn read_artifact_file(path: &Path) -> Result<Vec<u8>> {
    let info = std::fs::symlink_metadata(path).map_err(|error| Error(format!("stat artifact: {error}")))?;
    if info.file_type().is_symlink() {
        fail!("artifact must not be a symbolic link");
    }
    if info.len() == 0 || info.len() > MAX_ARTIFACT_BYTES as u64 {
        fail!("artifact size {} is outside the supported range", info.len());
    }
    let file = std::fs::File::open(path).map_err(|error| Error(format!("open artifact: {error}")))?;
    read_bounded(file)
}

/// Read at most `MAX_ARTIFACT_BYTES + 1` bytes and enforce the bound.
pub fn read_bounded(file: std::fs::File) -> Result<Vec<u8>> {
    let mut raw = Vec::new();
    file.take(MAX_ARTIFACT_BYTES as u64 + 1).read_to_end(&mut raw).map_err(|error| Error(format!("read artifact: {error}")))?;
    if raw.is_empty() || raw.len() > MAX_ARTIFACT_BYTES {
        fail!("artifact bytes exceed supported range");
    }
    Ok(raw)
}

/// `calculateArtifactChecksum`: SHA-256 of the canonical UTF-8 JSON (U+2028 and U+2029 escaped, keys sorted, floats
/// as Python `repr`) of the document without its `checksum` member.
pub fn calculate_artifact_checksum(root: &Value) -> std::result::Result<String, canonical::CanonicalError> {
    digest::artifact_checksum_of_artifact(root)
}

/// `scratchDeclaredInRaw`: any root `architecture` or `model_id` member, duplicates included, naming a scratch or
/// pretrained-contextual identity.
fn scratch_declared(members: &[jsonx::Member]) -> Result<bool> {
    let mut declared = false;
    for member in members {
        if member.key != "architecture" && member.key != "model_id" {
            continue;
        }
        if let Ok(Value::String(text)) = jsonx::parse(&member.raw) {
            let hit = if member.key == "architecture" {
                text == scratch::SCRATCH_PRESENCE_ARCHITECTURE || text == pretrained::ARCHITECTURE
            } else {
                scratch::is_scratch_model_id(&text) || text == pretrained::MODEL_ID
            };
            declared |= hit;
        }
    }
    Ok(declared)
}

fn decode_artifact(root: &Value, config: Option<&str>) -> Result<ModelArtifact> {
    let empty = Object::new();
    let object = match root {
        Value::Object(map) => map,
        Value::Null => &empty,
        _ => fail!("artifact must be an object"),
    };
    let parameters = match object.get("parameters") {
        None | Some(Value::Null) => BTreeMap::new(),
        Some(Value::Object(map)) => {
            let mut parameters = BTreeMap::new();
            for (name, tensor) in map {
                parameters.insert(name.clone(), decode_tensor(tensor)?);
            }
            parameters
        }
        Some(_) => fail!("parameters is not an object"),
    };
    Ok(ModelArtifact {
        schema_version: jsonx::int64(object.get("schema_version"))?,
        model_id: jsonx::string(object.get("model_id"))?,
        version: jsonx::string(object.get("version"))?,
        generated_at_unix: jsonx::int64(object.get("generated_at_unix"))?,
        architecture: jsonx::string(object.get("architecture"))?,
        config: config.unwrap_or_default().to_string(),
        parameters,
        metadata: jsonx::string_map(object.get("metadata"))?,
        checksum: jsonx::string(object.get("checksum"))?,
    })
}

fn decode_tensor(value: &Value) -> Result<Tensor> {
    match value {
        Value::Null => Ok(Tensor::default()),
        Value::Object(map) => Ok(Tensor {
            shape: jsonx::uint32_list_strict(map.get("shape"))?,
            values: jsonx::float64_list_strict(map.get("values"))?,
            trainable: jsonx::boolean(map.get("trainable"))?,
        }),
        _ => fail!("tensor is not an object"),
    }
}

/// `validatePresenceRawTensorFlags`: every tensor carries an explicit boolean `trainable` (Go decodes the flag as a
/// plain bool, so a missing or `null` value would otherwise pass as `false`).
pub fn validate_raw_tensor_flags(root: &Value) -> Result<()> {
    let Value::Object(payload) = root else {
        if matches!(root, Value::Null) {
            fail!("unexpected end of JSON input");
        }
        fail!("artifact must be an object");
    };
    let Some(parameters) = payload.get("parameters") else { fail!("unexpected end of JSON input") };
    let map = match parameters {
        Value::Null => return Ok(()),
        Value::Object(map) => map,
        _ => fail!("parameters is not an object"),
    };
    static EMPTY: Object = Object::new();
    for (name, tensor) in map {
        let fields = match tensor {
            Value::Null => &EMPTY,
            Value::Object(fields) => fields,
            _ => fail!("tensor {name:?} is not an object"),
        };
        if !matches!(fields.get("trainable"), Some(Value::Bool(_))) {
            fail!("tensor {name:?} requires an explicit boolean trainable flag");
        }
    }
    Ok(())
}

/// `validateModelArtifact`.
pub fn validate_model_artifact(artifact: &ModelArtifact, expected_model_id: &str) -> Result<()> {
    if artifact.schema_version != EXPECTED_SCHEMA {
        fail!("unsupported artifact schema {}", artifact.schema_version);
    }
    if !matches!(
        artifact.architecture.as_str(),
        EXPECTED_ARCHITECTURE
            | TASK_QUERY_ARCHITECTURE
            | PRESENCE_ARCHITECTURE
            | scratch::SCRATCH_PRESENCE_ARCHITECTURE
            | pretrained::ARCHITECTURE
    ) {
        fail!("unsupported artifact architecture {:?}", artifact.architecture);
    }
    if !expected_model_id.is_empty() && artifact.model_id != expected_model_id {
        fail!("artifact model {:?} does not match configured model {:?}", artifact.model_id, expected_model_id);
    }
    validate_artifact_metadata(artifact)?;
    validate_artifact_parameters(&artifact.parameters)?;
    if artifact.architecture == scratch::SCRATCH_PRESENCE_ARCHITECTURE || scratch::is_scratch_model_id(&artifact.model_id) {
        return scratch::validate_scratch_artifact(artifact);
    }
    if artifact.architecture == pretrained::ARCHITECTURE || artifact.model_id == pretrained::MODEL_ID {
        return pretrained::validate_pretrained_context_artifact(artifact);
    }
    if artifact.architecture == PRESENCE_ARCHITECTURE {
        return presence::validate_presence_artifact(artifact);
    }
    contextual::validate_contextual_training_artifact(artifact)
}

/// `validateIdentifier`.
pub fn validate_identifier(field: &str, value: &str, required: bool) -> std::result::Result<(), IdentifierError> {
    if required && value.is_empty() {
        return Err(IdentifierError(format!("{field} is required")));
    }
    if value.len() > 256 {
        return Err(IdentifierError(format!("{field} exceeds 256 bytes")));
    }
    if value.chars().any(|character| (character as u32) < 32 || character as u32 == 127) {
        return Err(IdentifierError(format!("{field} contains control characters")));
    }
    Ok(())
}

/// `validateConfiguredIdentifier`.
pub fn validate_configured_identifier(field: &str, value: &str) -> std::result::Result<(), IdentifierError> {
    if value.is_empty() {
        return Err(IdentifierError(format!("{field} must not be empty")));
    }
    validate_identifier(field, value, true)
}

/// A rejected identifier. The gRPC layer reports it as `INVALID_ARGUMENT` with exactly this message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct IdentifierError(pub String);

impl From<IdentifierError> for Error {
    fn from(error: IdentifierError) -> Self {
        Self(error.0)
    }
}

fn validate_artifact_metadata(artifact: &ModelArtifact) -> Result<()> {
    validate_configured_identifier("artifact model_id", &artifact.model_id)?;
    validate_configured_identifier("artifact version", &artifact.version)?;
    if artifact.generated_at_unix <= 0 {
        fail!("artifact generated_at_unix must be positive");
    }
    if artifact.config.is_empty() || jsonx::parse(&artifact.config).is_err() {
        fail!("artifact config must be valid JSON");
    }
    if !is_sha256_hex_any_case(&artifact.checksum) {
        fail!("artifact checksum must be a SHA-256 value");
    }
    if artifact.parameters.is_empty() {
        fail!("artifact has no parameters");
    }
    Ok(())
}

fn is_sha256_hex_any_case(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_artifact_parameters(parameters: &BTreeMap<String, Tensor>) -> Result<()> {
    let mut total = 0usize;
    for (name, tensor) in parameters {
        validate_identifier("parameter name", name, true)?;
        validate_tensor(name, tensor)?;
        total += tensor.values.len();
        if total > MAX_PARAMETER_VALUES {
            fail!("artifact exceeds {MAX_PARAMETER_VALUES} values");
        }
    }
    Ok(())
}

fn validate_tensor(name: &str, tensor: &Tensor) -> Result<()> {
    if tensor.shape.is_empty() || tensor.values.is_empty() {
        fail!("parameter {name:?} has no shape or values");
    }
    let mut expected = 1u64;
    for dimension in &tensor.shape {
        if *dimension == 0 {
            fail!("parameter {name:?} has a zero dimension");
        }
        expected = expected.wrapping_mul(u64::from(*dimension));
        if expected > MAX_PARAMETER_VALUES as u64 {
            fail!("parameter {name:?} is too large");
        }
    }
    if expected != tensor.values.len() as u64 {
        fail!("parameter {name:?} shape does not match values");
    }
    if tensor.values.iter().any(|value| !value.is_finite()) {
        fail!("parameter {name:?} contains a non-finite value");
    }
    Ok(())
}

/// Canonical UTF-8 text of a decoded value, as Go's encoder writes it (no HTML escaping).
pub fn canonical_text(value: &Value) -> Result<String> {
    canonical::to_string(value, Variant::Utf8Go).map_err(|error| Error(error.to_string()))
}

/// Test and tool support: the artifact as a JSON value with the checksum filled in.
pub fn to_value(artifact: &ModelArtifact) -> Result<Value> {
    let mut root = Object::new();
    root.insert("schema_version".into(), Value::Int(artifact.schema_version.to_string()));
    root.insert("model_id".into(), Value::String(artifact.model_id.clone()));
    root.insert("version".into(), Value::String(artifact.version.clone()));
    root.insert("generated_at_unix".into(), Value::Int(artifact.generated_at_unix.to_string()));
    root.insert("architecture".into(), Value::String(artifact.architecture.clone()));
    root.insert("config".into(), jsonx::parse(&artifact.config)?);
    let mut parameters = Object::new();
    for (name, tensor) in &artifact.parameters {
        let mut fields = Object::new();
        fields.insert("shape".into(), Value::Array(tensor.shape.iter().map(|d| Value::Int(d.to_string())).collect()));
        fields.insert("values".into(), Value::Array(tensor.values.iter().map(|v| Value::Float(*v)).collect()));
        fields.insert("trainable".into(), Value::Bool(tensor.trainable));
        parameters.insert(name.clone(), Value::Object(fields));
    }
    root.insert("parameters".into(), Value::Object(parameters));
    root.insert(
        "metadata".into(),
        match &artifact.metadata {
            Some(map) => Value::Object(map.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect()),
            None => Value::Null,
        },
    );
    root.insert("checksum".into(), Value::String(artifact.checksum.clone()));
    Ok(Value::Object(root))
}

/// Test and tool support: serialise with a freshly computed checksum.
pub fn to_checked_bytes(artifact: &ModelArtifact) -> Result<Vec<u8>> {
    let mut value = to_value(artifact)?;
    let checksum = calculate_artifact_checksum(&value).map_err(|error| Error(error.to_string()))?;
    if let Value::Object(map) = &mut value {
        map.insert("checksum".into(), Value::String(checksum));
    }
    canonical::to_bytes(&value, Variant::Utf8Go).map_err(|error| Error(error.to_string()))
}
