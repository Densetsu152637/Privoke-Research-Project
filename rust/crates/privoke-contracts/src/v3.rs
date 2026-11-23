//! The pinned standard AU3 (V3) manifest rules of `v3_contract.py` and `standard_v3.py`.

use std::collections::BTreeMap;

use crate::canonical::{self, Variant};
use crate::digest::sha256_hex;
use crate::json::{self, Duplicates, ParseOptions, Value};
use crate::publication::{self, KeySet, PublicationError, Statement};

/// Bytes streamed per `ModelAssetChunk`.
pub const CHUNK_BYTES: usize = 1024 * 1024;
/// Largest admitted asset.
pub const MAX_BLOB_BYTES: u64 = 80 * 1024 * 1024;
/// Largest admitted manifest.
pub const MAX_MANIFEST_BYTES: usize = 256 * 1024;
/// The only admitted architecture.
pub const ARCHITECTURE: &str = "privoke_pretrained_bert_v3";
/// SHA-256 of the shared vocabulary.
pub const VOCAB_SHA256: &str = "07eced375cec144d27c900241f3e339478dec958f92fddbc551f295c992038a3";
/// The model served by `latest`.
pub const STANDARD_LATEST: &str = "privoke-v3-balanced";
/// Asset names the package RPCs may stream.
pub const ASSET_NAMES: [&str; 4] = ["model.safetensors", "config.json", "vocab.txt", "evidence.json"];

/// One admitted pretrained tier.
#[derive(Debug, Clone, Copy)]
pub struct Tier {
    /// Tier name (`efficient`, `balanced`, `quality`).
    pub name: &'static str,
    /// Official source repository.
    pub repository: &'static str,
    /// Official source revision.
    pub revision: &'static str,
    /// Hidden size.
    pub hidden_size: u64,
    /// Encoder layers.
    pub num_hidden_layers: u64,
    /// Attention heads.
    pub num_attention_heads: u64,
    /// Complete parameter count.
    pub parameters: u64,
    /// SHA-256 of the official weights.
    pub weights_sha256: &'static str,
    /// SHA-256 of the official config.
    pub config_sha256: &'static str,
    /// SHA-256 of the pinned released manifest.
    pub manifest_pin: &'static str,
}

/// The three admitted tiers, in the order of the Python `TIERS` table.
pub const TIERS: [Tier; 3] = [
    Tier {
        name: "efficient",
        repository: "google/bert_uncased_L-4_H-128_A-2",
        revision: "c29bee83fc7f003ac8c5e6e135529da4ecddb7c3",
        hidden_size: 128,
        num_hidden_layers: 4,
        num_attention_heads: 2,
        parameters: 4_785_044,
        weights_sha256: "2e37a60f99c30c244da3a2ada3653faf378689783c5b6500d7291acc2516e199",
        config_sha256: "191ec8105cc6eb8ce2d64c117f7c5830f6028c06da4d7a0d3672414f2c77ad98",
        manifest_pin: "1f45a21bd7bd0c931dad215f823008193e7af7359bc68527c1f5dd4e7fbbeffd",
    },
    Tier {
        name: "balanced",
        repository: "google/bert_uncased_L-2_H-256_A-4",
        revision: "4e937a8675e5afd9a4836735c186ec01695bc3ea",
        hidden_size: 256,
        num_hidden_layers: 2,
        num_attention_heads: 4,
        parameters: 9_596_180,
        weights_sha256: "67b710645b099510dba08b7605a60859fff59714628e1d9d1ffa9e0956b51783",
        config_sha256: "ba873b4875d069697fa5bab011ea9e3f63b7f8186701bdf5356b4d8622d8f5c1",
        manifest_pin: "99b36171056bb0398584a0b0556d9d7ff2640d0acac4b124a126327451a80589",
    },
    Tier {
        name: "quality",
        repository: "google/bert_uncased_L-12_H-256_A-4",
        revision: "2ab9a0f41435a4d23d4cbc11cc3e7c922545f13d",
        hidden_size: 256,
        num_hidden_layers: 12,
        num_attention_heads: 4,
        parameters: 17_493_780,
        weights_sha256: "1be1c8c6a57894a139fdf526fb8435f6acb6ea01600569a4ac3cfd405dc5f875",
        config_sha256: "9efa18e50a359c542d79f9c00a23049c2d78aa07c1fd11827c6e2487b3333cd7",
        manifest_pin: "bb17d355fe1ad13c7052e922fb6de607d82cdafb1f4440fee1a47f35d42caf39",
    },
];

/// Why a manifest was not admitted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    /// The payload is not valid JSON under the strict rules.
    #[error("manifest JSON is invalid: {0}")]
    Json(#[from] json::JsonError),
    /// The payload exceeds its byte bound.
    #[error("JSON exceeds its explicit byte bound")]
    TooLarge,
    /// The payload is not UTF-8.
    #[error("manifest is not UTF-8")]
    NotUtf8,
    /// Canonical JSON bytes are required.
    #[error("canonical JSON bytes required")]
    NotCanonical,
    /// A rule of the manifest contract failed.
    #[error("{0}")]
    Invalid(&'static str),
    /// The manifest is not one of the pinned standard releases.
    #[error("model is not a pinned standard AU3 release")]
    NotPinned,
    /// The request names a different model than the manifest.
    #[error("model package identity differs from request")]
    IdentityDiffers,
}

/// The fields of an admitted manifest that servers and clients act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// `privoke-v3-<tier>`.
    pub model_id: String,
    /// Tier name.
    pub tier: String,
    /// `original`, `heads` or `full_encoder`.
    pub scope: String,
    /// SHA-256 of `model.safetensors`.
    pub blob: String,
    /// SHA-256 of `config.json`.
    pub config: String,
    /// SHA-256 of `vocab.txt`.
    pub vocab: String,
    /// SHA-256 of `evidence.json`, when present.
    pub evidence: Option<String>,
    /// Complete parameter count.
    pub parameter_count: u64,
}

/// `v3_contract.parse`: strict, duplicate-free, finite and byte-for-byte canonical.
pub fn parse_canonical(payload: &[u8], limit: usize) -> Result<Value, ManifestError> {
    if payload.len() > limit {
        return Err(ManifestError::TooLarge);
    }
    let text = std::str::from_utf8(payload).map_err(|_| ManifestError::NotUtf8)?;
    let value = json::parse_with(text, ParseOptions { duplicates: Duplicates::Reject, ..ParseOptions::default() })?;
    let canonical = canonical::to_bytes(&value, Variant::Utf8Lf).map_err(|_| ManifestError::NotCanonical)?;
    if canonical != payload {
        return Err(ManifestError::NotCanonical);
    }
    Ok(value)
}

fn is_sha(value: &Value) -> bool {
    matches!(value, Value::String(text) if text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Int(digits) => digits != "0",
        Value::Float(number) => *number != 0.0,
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

fn string<'a>(map: &'a BTreeMap<String, Value>, key: &str) -> Option<&'a str> {
    match map.get(key) {
        Some(Value::String(text)) => Some(text),
        _ => None,
    }
}

const REQUIRED: [&str; 13] = [
    "schema",
    "architecture",
    "model_id",
    "tier",
    "parent",
    "original",
    "blob",
    "config",
    "vocab",
    "source",
    "tensors",
    "parameter_count",
    "scope",
];

/// `v3_contract.validate_manifest`.
pub fn validate_manifest(value: &Value) -> Result<Manifest, ManifestError> {
    let invalid = ManifestError::Invalid;
    let Value::Object(map) = value else {
        return Err(invalid("Unsupported v3 manifest schema."));
    };
    let mut expected: Vec<&str> = REQUIRED.to_vec();
    expected.push("evidence");
    expected.sort_unstable();
    let present: Vec<&str> = map.keys().map(String::as_str).collect();
    if present != expected || map.get("schema") != Some(&Value::Int("1".into())) || string(map, "architecture") != Some(ARCHITECTURE) {
        return Err(invalid("Unsupported v3 manifest schema."));
    }
    let tier_name = string(map, "tier").unwrap_or_default();
    let tier = TIERS.iter().find(|tier| tier.name == tier_name).ok_or(invalid("Unadmitted v3 model/tier."))?;
    let model_id = string(map, "model_id").unwrap_or_default();
    if model_id != format!("privoke-v3-{}", tier.name) {
        return Err(invalid("Unadmitted v3 model/tier."));
    }
    for key in ["blob", "config", "vocab"] {
        if !map.get(key).is_some_and(is_sha) {
            return Err(invalid("Expected a lowercase SHA-256 identity."));
        }
    }
    for key in ["parent", "original", "evidence"] {
        if map.get(key).is_some_and(truthy) && !map.get(key).is_some_and(is_sha) {
            return Err(invalid("Expected a lowercase SHA-256 identity."));
        }
    }
    let Some(Value::Object(source)) = map.get("source") else {
        return Err(invalid("Pretrained provenance differs from admitted official revision."));
    };
    if string(source, "repository") != Some(tier.repository) || string(source, "revision") != Some(tier.revision) {
        return Err(invalid("Pretrained provenance differs from admitted official revision."));
    }
    for key in ["weights_sha256", "config_sha256", "vocab_sha256"] {
        if !source.get(key).is_some_and(is_sha) {
            return Err(invalid("Expected a lowercase SHA-256 identity."));
        }
    }
    if string(source, "weights_sha256") != Some(tier.weights_sha256)
        || string(source, "config_sha256") != Some(tier.config_sha256)
        || string(source, "vocab_sha256") != Some(VOCAB_SHA256)
    {
        return Err(invalid("Pretrained source asset hashes differ from admitted official bytes."));
    }
    if string(map, "config") != string(source, "config_sha256") || string(map, "vocab") != string(source, "vocab_sha256") {
        return Err(invalid("Runtime config/tokenizer differs from admitted pretrained source."));
    }
    let Some(Value::Object(tensors)) = map.get("tensors") else {
        return Err(invalid("Invalid v3 tensor inventory."));
    };
    if tensors.is_empty() || tensors.len() > 256 {
        return Err(invalid("Invalid v3 tensor inventory."));
    }
    let mut count: u64 = 0;
    for (name, tensor) in tensors {
        let Value::Object(fields) = tensor else {
            return Err(invalid("Invalid v3 tensor declaration."));
        };
        let keys: Vec<&str> = fields.keys().map(String::as_str).collect();
        if name.chars().count() > 256 || keys != ["dtype", "sha256", "shape"] || string(fields, "dtype") != Some("F32") {
            return Err(invalid("Invalid v3 tensor declaration."));
        }
        let Some(Value::Array(shape)) = fields.get("shape") else {
            return Err(invalid("Invalid v3 tensor shape."));
        };
        if shape.is_empty() {
            return Err(invalid("Invalid v3 tensor shape."));
        }
        let mut elements: u64 = 1;
        for size in shape {
            let Value::Int(digits) = size else {
                return Err(invalid("Invalid v3 tensor shape."));
            };
            let size: u64 = digits.parse().map_err(|_| invalid("Invalid v3 tensor shape."))?;
            if size == 0 {
                return Err(invalid("Invalid v3 tensor shape."));
            }
            elements = elements.checked_mul(size).ok_or(invalid("Invalid v3 tensor shape."))?;
        }
        if !fields.get("sha256").is_some_and(is_sha) {
            return Err(invalid("Expected a lowercase SHA-256 identity."));
        }
        count = count.checked_add(elements).ok_or(invalid("Invalid v3 tensor shape."))?;
    }
    let declared = match map.get("parameter_count") {
        Some(Value::Int(digits)) => digits.parse::<u64>().ok(),
        _ => None,
    };
    if declared != Some(count) || count != tier.parameters {
        return Err(invalid("Complete model parameter count differs from admitted tier."));
    }
    let scope = string(map, "scope").unwrap_or_default();
    if !["original", "heads", "full_encoder"].contains(&scope) {
        return Err(invalid("Invalid v3 training scope."));
    }
    let lineage = ["parent", "original", "evidence"].map(|key| map.get(key).is_some_and(truthy));
    if scope == "original" {
        if lineage.iter().any(|present| *present) {
            return Err(invalid("ORIGINAL has no parent/training evidence."));
        }
    } else if !lineage.iter().all(|present| *present) {
        return Err(invalid("Candidate requires immutable parent, ORIGINAL and evidence."));
    }
    Ok(Manifest {
        model_id: model_id.to_string(),
        tier: tier.name.to_string(),
        scope: scope.to_string(),
        blob: string(map, "blob").unwrap_or_default().to_string(),
        config: string(map, "config").unwrap_or_default().to_string(),
        vocab: string(map, "vocab").unwrap_or_default().to_string(),
        evidence: string(map, "evidence").filter(|text| !text.is_empty()).map(str::to_string),
        parameter_count: count,
    })
}

/// `standard_v3.admitted_manifest`: a valid manifest whose bytes hash to the pin of its model.
///
/// `model_id` may be `None`, `latest` or the manifest's own model.
pub fn admitted_manifest(payload: &[u8], model_id: Option<&str>) -> Result<Manifest, ManifestError> {
    let manifest = validate_manifest(&parse_canonical(payload, MAX_MANIFEST_BYTES)?)?;
    let pinned = TIERS.iter().find(|tier| manifest.model_id == format!("privoke-v3-{}", tier.name)).map(|tier| tier.manifest_pin);
    if pinned != Some(sha256_hex(payload).as_str()) {
        return Err(ManifestError::NotPinned);
    }
    if let Some(requested) = model_id
        && !requested.is_empty()
        && requested != "latest"
        && requested != manifest.model_id
    {
        return Err(ManifestError::IdentityDiffers);
    }
    Ok(manifest)
}

/// The pinned manifest SHA-256 for a standard model id.
pub fn standard_pin(model_id: &str) -> Option<&'static str> {
    TIERS.iter().find(|tier| model_id == format!("privoke-v3-{}", tier.name)).map(|tier| tier.manifest_pin)
}

// ---------------------------------------------------------------------------------------------------------------------------
// Lineage and signature admission of a published version (stage V3-R4a of the routine-training plan).
// ---------------------------------------------------------------------------------------------------------------------------

/// Why [`admit_lineage`] refused a version.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LineageError {
    /// The manifest is not a valid, canonical manifest, or names another model than the request.
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    /// The statement is malformed, names an unknown key or does not verify.
    #[error(transparent)]
    Publication(#[from] PublicationError),
    /// The model has no compiled pinned ORIGINAL.
    #[error("model has no compiled pinned ORIGINAL")]
    NoPin,
    /// An unsigned manifest that is not the compiled pin.
    #[error("an unsigned manifest is admitted only as the pinned ORIGINAL")]
    Unsigned,
    /// The unsigned pinned ORIGINAL after a signed version was accepted for the model.
    #[error("unsigned ORIGINAL refused: a signed version was already accepted for this model")]
    Downgrade,
    /// The statement names another model than the manifest.
    #[error("publication statement names another model than the manifest")]
    StatementModel,
    /// The statement names another manifest than the one presented.
    #[error("publication statement names another manifest")]
    StatementManifest,
    /// The statement's `parent` or `original` differs from the manifest's own fields.
    #[error("publication statement lineage differs from the manifest")]
    StatementLineage,
    /// The statement's sequence is below the persisted high-water mark.
    #[error("publication sequence {got} is below the accepted high-water mark {seen}")]
    Replay {
        /// The persisted high-water mark.
        seen: u64,
        /// The statement's sequence.
        got: u64,
    },
    /// The statement's sequence equals the high-water mark but names another manifest.
    #[error("publication sequence {0} is already accepted for another manifest")]
    SequenceConflict(u64),
    /// The manifest is not the pin and does not descend from the compiled pinned ORIGINAL.
    #[error("manifest does not descend from the pinned ORIGINAL")]
    WrongOriginal,
    /// The persisted high-water record could not be read or is not usable.
    #[error("high-water record: {0}")]
    HighWater(String),
}

/// What the client has compiled in and persisted for [`admit_lineage`].
pub trait LineageState {
    /// The compiled pinned ORIGINAL manifest SHA-256 of `model_id`, if the model has one.
    fn tier_pin(&self, model_id: &str) -> Option<String>;
    /// The highest publication statement already accepted for `model_id` (re-verified by the implementation), if any.
    fn high_water(&self, model_id: &str) -> Result<Option<Statement>, String>;
}

/// A version that passed [`admit_lineage`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineageAdmitted {
    /// The validated manifest.
    pub manifest: Manifest,
    /// SHA-256 of the manifest bytes.
    pub manifest_sha: String,
    /// The verified statement; `None` only for the unsigned pinned ORIGINAL on a first start.
    pub statement: Option<Statement>,
}

/// A manifest's `parent` or `original` as the text a statement repeats: a digest or the empty text.
fn lineage_field(value: &Value, key: &str) -> Option<String> {
    let Value::Object(map) = value else { return None };
    match map.get(key) {
        Some(Value::String(text)) => Some(text.clone()),
        Some(Value::Null) => Some(String::new()),
        _ => None,
    }
}

/// Admit a version by lineage and signature. This is the client rule for a trained V3 version; [`admitted_manifest`] stays the
/// pin-only rule that the model loaders share.
///
/// `payload` is the manifest as served, `statement` its wire statement (empty when the server sent none) and `requested` the
/// model id the client asked for (`latest`, a model id or empty). `keys` is the key set compiled into the client and `state`
/// holds the compiled tier pin and the persisted high-water statement. The version is admitted when:
///
/// 1. the manifest is canonical and satisfies the manifest contract, and names the requested model;
/// 2. a statement is present, verifies under a `key_id` of `keys`, and names this model and this manifest;
/// 3. the statement's `parent` and `original` equal the manifest's own fields;
/// 4. its sequence is above the high-water mark, or equal to it with the same manifest;
/// 5. the manifest is the compiled tier pin (a signed rollback to the ORIGINAL), or its `original` equals the pin.
///
/// Without a statement only the compiled pin is admitted, and only while the model has no high-water mark (first start): an
/// unsigned ORIGINAL after a signed version is a downgrade.
pub fn admit_lineage(
    payload: &[u8],
    statement: &[u8],
    requested: Option<&str>,
    keys: &KeySet,
    state: &dyn LineageState,
) -> Result<LineageAdmitted, LineageError> {
    let value = parse_canonical(payload, MAX_MANIFEST_BYTES)?;
    let manifest = validate_manifest(&value)?;
    if let Some(requested) = requested
        && !requested.is_empty()
        && requested != "latest"
        && requested != manifest.model_id
    {
        return Err(ManifestError::IdentityDiffers.into());
    }
    let pin = state.tier_pin(&manifest.model_id).ok_or(LineageError::NoPin)?;
    let manifest_sha = sha256_hex(payload);
    let is_pin = manifest_sha == pin;
    let high_water = state.high_water(&manifest.model_id).map_err(LineageError::HighWater)?;
    if let Some(seen) = &high_water
        && seen.model_id != manifest.model_id
    {
        return Err(LineageError::HighWater("the record names another model".to_string()));
    }

    if statement.is_empty() {
        return match (is_pin, high_water) {
            (true, None) => Ok(LineageAdmitted { manifest, manifest_sha, statement: None }),
            (true, Some(_)) => Err(LineageError::Downgrade),
            (false, _) => Err(LineageError::Unsigned),
        };
    }

    let statement = publication::verify(keys, statement)?;
    if statement.model_id != manifest.model_id {
        return Err(LineageError::StatementModel);
    }
    if statement.manifest_sha != manifest_sha {
        return Err(LineageError::StatementManifest);
    }
    let (parent, original) = (lineage_field(&value, "parent"), lineage_field(&value, "original"));
    if parent.as_deref() != Some(statement.parent.as_str()) || original.as_deref() != Some(statement.original.as_str()) {
        return Err(LineageError::StatementLineage);
    }
    if let Some(seen) = &high_water {
        if statement.sequence < seen.sequence {
            return Err(LineageError::Replay { seen: seen.sequence, got: statement.sequence });
        }
        if statement.sequence == seen.sequence && statement.manifest_sha != seen.manifest_sha {
            return Err(LineageError::SequenceConflict(statement.sequence));
        }
    }
    if !is_pin && (manifest.scope == "original" || statement.original != pin) {
        return Err(LineageError::WrongOriginal);
    }
    Ok(LineageAdmitted { manifest, manifest_sha, statement: Some(statement) })
}

// ---------------------------------------------------------------------------------------------------------------------------
// The execution-evidence contract of `v3_contract.py`, shared by the V3 fit, the V3 fuzzer and the param-update checkpoint store.
// ---------------------------------------------------------------------------------------------------------------------------

/// A rule of the V3 contract that failed. The text is the Python `ValueError` message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ContractError(pub String);

fn fail<T>(message: &str) -> Result<T, ContractError> {
    Err(ContractError(message.to_string()))
}

/// Whether `text` is a lowercase hexadecimal SHA-256.
pub fn is_sha_text(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_sha_serde(value: &serde_json::Value) -> bool {
    value.as_str().is_some_and(is_sha_text)
}

/// `check_sha(value)`.
pub fn check_sha(text: &str) -> Result<(), ContractError> {
    if is_sha_text(text) { Ok(()) } else { fail("Expected a lowercase SHA-256 identity.") }
}

fn parse_error(error: ManifestError) -> ContractError {
    ContractError(match error {
        ManifestError::TooLarge => "JSON exceeds its explicit byte bound.".to_string(),
        ManifestError::NotCanonical => "Canonical JSON bytes required.".to_string(),
        ManifestError::Json(json::JsonError::DuplicateKey(_)) => "Duplicate JSON field.".to_string(),
        ManifestError::Json(json::JsonError::NonFinite(_)) => "Nonfinite JSON.".to_string(),
        other => other.to_string(),
    })
}

/// `parse(payload, limit)` with the Python messages.
pub fn parse(payload: &[u8], limit: usize) -> Result<Value, ContractError> {
    parse_canonical(payload, limit).map_err(parse_error)
}

/// A strictly parsed document as a `serde_json` value, for the evidence validators.
pub fn to_serde(document: &Value) -> Result<serde_json::Value, ContractError> {
    use serde_json::Value as Serde;
    Ok(match document {
        Value::Null => Serde::Null,
        Value::Bool(flag) => Serde::Bool(*flag),
        Value::Int(digits) => {
            if let Ok(number) = digits.parse::<i64>() {
                Serde::from(number)
            } else if let Ok(number) = digits.parse::<u64>() {
                Serde::from(number)
            } else {
                return fail("Integer outside the supported range.");
            }
        }
        Value::Float(number) => match serde_json::Number::from_f64(*number) {
            Some(number) => Serde::Number(number),
            None => return fail("Nonfinite JSON."),
        },
        Value::String(text) => Serde::String(text.clone()),
        Value::Array(items) => Serde::Array(items.iter().map(to_serde).collect::<Result<Vec<_>, _>>()?),
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (key, item) in map {
                out.insert(key.clone(), to_serde(item)?);
            }
            Serde::Object(out)
        }
    })
}

/// The frozen policy of `validate_policy`: the pilot variant has two steps over one block, otherwise `steps` is 64, 256 or 512.
pub fn frozen_policy(steps: i64, pilot: bool) -> serde_json::Value {
    let (window_batches, epochs) = if pilot { (1, 2) } else { (8, steps / 8) };
    serde_json::json!({
        "schema": 1, "optimizer": "adamw", "head_lr": 0.001, "encoder_lr": 0.00002, "betas": [0.9, 0.999], "eps": 1e-8,
        "weight_decay": 0.0, "clip_norm": 1.0, "microbatch": 4, "steps": steps, "window_batches": window_batches, "batch_rows": 64,
        "epochs": epochs, "guard_rows": 16, "dropout": false, "max_tokens": 512, "category_threshold": 0.5,
        "objective": "sensitivity_ce+visibility_ce+category_mean_bce", "checkpoint_selection": "final_only",
        "publication": "joint_improve_action_harm_zero_v1"
    })
}

/// `validate_policy(policy, pilot=)`.
pub fn validate_policy(policy: &serde_json::Value, pilot: bool) -> Result<(), ContractError> {
    let steps = if pilot {
        2
    } else {
        match policy["steps"].as_i64() {
            Some(steps @ (64 | 256 | 512)) => steps,
            _ => return fail("Predeclared v3 work budget must be 64, 256 or 512 steps."),
        }
    };
    if *policy != frozen_policy(steps, pilot) {
        return fail("Policy differs from the frozen v3 contract.");
    }
    Ok(())
}

const ACTIONS: [&str; 3] = ["ALLOW", "WARN", "BLOCK"];
const VISIBILITY_MASK: u16 = 0b1_1100;
const PRIVATE_UNKNOWN: u16 = 0b1_1100;
const IDENTIFIER_BITS: u16 = 0b001_0000_0000_0000 | 0b010_0000_0000_0000;
const VISIBILITY_VALUES: [u16; 6] = [0b00100, 0b01000, 0b01100, 0b10000, 0b10100, 0b11100];

/// Whether `packed` is a classification the contract can name (`Classification(packed).pack() == packed`, `to_dict()`).
pub fn valid_packed(packed: u64) -> bool {
    let Ok(packed) = u16::try_from(packed) else { return false };
    packed & 0x8000 == 0 && VISIBILITY_VALUES.contains(&(packed & VISIBILITY_MASK))
}

/// `action_value`: the production action of a packed classification as 0 allow, 1 warn, 2 block.
pub fn action_value(packed: u16, confidence: Option<f64>) -> i64 {
    let severity = i64::from(packed & 0b11);
    let identifiers = (packed & IDENTIFIER_BITS).count_ones();
    if confidence.is_some_and(|value| value < 0.5) {
        return i64::from(severity == 3 || (severity == 2 && identifiers > 0));
    }
    if severity >= 2 {
        return severity - 1;
    }
    let visibility = packed & VISIBILITY_MASK;
    let private = visibility != PRIVATE_UNKNOWN && visibility >= 0b01100;
    i64::from(identifiers > 0 && (identifiers > 1 || private))
}

/// Rows where a candidate action is farther from the target than the base's, in either direction.
pub fn harm_count(base: &serde_json::Value, candidate: &serde_json::Value) -> usize {
    let value = |row: &serde_json::Value, key: &str| row[key].as_i64().unwrap_or(0);
    base.as_array()
        .into_iter()
        .flatten()
        .zip(candidate.as_array().into_iter().flatten())
        .filter(|(a, b)| {
            let (a, b) = (*a, *b);
            [-1i64, 1].iter().any(|direction| {
                (direction * (value(b, "action_value") - value(b, "target_action_value"))).max(0)
                    > (direction * (value(a, "action_value") - value(a, "target_action_value"))).max(0)
            })
        })
        .count()
}

/// `tensor_changes`: the changed tensor names and the counts per group, from the tensor digests of two inventories.
pub fn tensor_changes(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
    layers: usize,
) -> (Vec<String>, serde_json::Value) {
    let changed: Vec<String> = before.iter().filter(|(name, sha)| after.get(*name) != Some(*sha)).map(|(name, _)| name.clone()).collect();
    let under = |prefix: &str| changed.iter().filter(|name| name.starts_with(prefix)).count();
    let blocks: Vec<usize> = (0..layers).map(|index| under(&format!("encoder.encoder.layer.{index}."))).collect();
    let counts = serde_json::json!({
        "heads": under("heads."), "encoder": under("encoder."), "embeddings": under("encoder.embeddings."),
        "first_block": under("encoder.encoder.layer.0."),
        "last_block": under(&format!("encoder.encoder.layer.{}.", layers.saturating_sub(1))),
        "pooler": under("encoder.pooler."), "blocks": blocks
    });
    (changed, counts)
}

fn validate_guard(value: &serde_json::Value, denominator: usize) -> Result<Vec<serde_json::Value>, ContractError> {
    let rows = value["rows"].as_array().cloned().unwrap_or_default();
    if value["examples"].as_u64() != Some(denominator as u64) || rows.len() != denominator {
        return fail("Guard row denominator differs from policy.");
    }
    for row in &rows {
        for key in ["target", "prediction"] {
            if !row[key].as_u64().is_some_and(valid_packed) {
                return fail("Invalid packed guard classification.");
            }
        }
        for key in ["action", "target_action"] {
            let name = row[key].as_str().unwrap_or_default();
            let position = ACTIONS.iter().position(|candidate| *candidate == name);
            if position.map(|p| p as i64) != row[format!("{key}_value")].as_i64() {
                return fail("Guard action name/value mismatch.");
            }
        }
        let Some(confidence) = row["confidence"].as_f64().filter(|c| c.is_finite() && (0.0..=1.0).contains(c)) else {
            return fail("Actual guard confidence required.");
        };
        for (packed, score, action) in [("prediction", confidence, "action"), ("target", 0.999, "target_action")] {
            let packed = u16::try_from(row[packed].as_u64().unwrap_or(0)).unwrap_or(0);
            if ACTIONS[usize::try_from(action_value(packed, Some(score))).unwrap_or(0)] != row[action].as_str().unwrap_or_default() {
                return fail("Guard action differs from production classification policy.");
            }
        }
        let joint = row["target"] == row["prediction"] && row["action"] == row["target_action"];
        if row["joint_correct"].as_bool() != Some(joint) {
            return fail("Guard joint correctness differs from rows.");
        }
    }
    let joint = rows.iter().filter(|row| row["joint_correct"] == true).count() as u64;
    if value["joint_correct"].as_u64() != Some(joint) {
        return fail("Guard joint count differs from rows.");
    }
    if value["action_correct"].as_u64() != Some(rows.iter().filter(|row| row["action"] == row["target_action"]).count() as u64) {
        return fail("Guard action count differs from rows.");
    }
    Ok(rows)
}

/// `validate_execution`: the evidence must reconcile the actual work, every block and the guard arithmetic.
pub fn validate_execution(evidence: &serde_json::Value, finalized: bool) -> Result<(), ContractError> {
    use serde_json::{Map, Value as Serde, json};
    let scope = evidence["scope"].as_str().unwrap_or_default();
    if evidence["schema"] != 1 || evidence["layers"] != json!([4]) || !matches!(scope, "heads" | "full_encoder") {
        return fail("Actual explicit semantic-only training evidence required.");
    }
    let policy = &evidence["policy"];
    validate_policy(policy, policy["steps"] == 2)?;
    for key in ["base", "source_commitment", "train_wire_sha256", "guard_wire_sha256"] {
        if !is_sha_serde(&evidence[key]) {
            return fail("Expected a lowercase SHA-256 identity.");
        }
    }
    if evidence["request_id"].as_str().is_none_or(str::is_empty) {
        return fail("Execution request identity required.");
    }
    let tier_name = evidence["tier"].as_str().unwrap_or_default();
    let Some(tier) = TIERS.iter().find(|tier| tier.name == tier_name) else {
        return fail("Execution model/tier identity required.");
    };
    if evidence["model_id"] != format!("privoke-v3-{tier_name}") {
        return fail("Execution model/tier identity required.");
    }
    if evidence["parameter_count"].as_u64() != Some(tier.parameters) {
        return fail("Execution complete parameter count mismatch.");
    }
    let full = scope == "full_encoder";
    // The head width is 20 = 4 + 6 + 10 labels; the parameters are `20 * (hidden + 1)`.
    let expected_trainable = if full { tier.parameters } else { 20 * (tier.hidden_size + 1) };
    if evidence["trainable_count"].as_u64() != Some(expected_trainable) {
        return fail("Execution trainable parameter count mismatch.");
    }
    let (steps, rows, micro, guard_rows) = (
        policy["steps"].as_u64().unwrap_or(0),
        policy["batch_rows"].as_u64().unwrap_or(0),
        policy["microbatch"].as_u64().unwrap_or(1),
        policy["guard_rows"].as_u64().unwrap_or(0),
    );
    let microbatches = steps * rows / micro;
    let layers = tier.num_hidden_layers;
    let layer_count = layers as usize;
    let expected = json!({
        "optimizer_steps": steps, "train_rows": steps * rows, "microbatch_forward": microbatches, "microbatch_backward": microbatches,
        "encoder_block_forward": microbatches * layers, "encoder_block_backward": if full { microbatches * layers } else { 0 }
    });
    if evidence["counts"] != expected {
        return fail("Actual work counters differ from frozen policy.");
    }
    let blocks = json!({
        "forward": vec![microbatches; layer_count], "backward": vec![if full { microbatches } else { 0 }; layer_count]
    });
    if evidence["block_counts"] != blocks {
        return fail("Every encoder block must attest actual forward/backward work.");
    }
    let phases = &evidence["phases"];
    let expected_phases = [("training", steps * rows), ("base_heldout", guard_rows), ("candidate_heldout", guard_rows)];
    if phases.as_object().map(Map::len) != Some(3)
        || expected_phases.iter().any(|(name, n)| phases[*name] != json!({"layer": 4, "status": "ok", "examples": n}))
    {
        return fail("Successful exact-denominator semantic phases required.");
    }
    let changes = &evidence["changes"];
    let block_changes: Vec<u64> = changes["blocks"].as_array().map(|b| b.iter().filter_map(Serde::as_u64).collect()).unwrap_or_default();
    if changes["heads"].as_u64().unwrap_or(0) == 0 || block_changes.len() as u64 != layers {
        return fail("Observed head and complete block changes required.");
    }
    if !full && (changes["encoder"] != 0 || block_changes.iter().any(|n| *n != 0)) {
        return fail("HEADS changed pretrained encoder.");
    }
    if full
        && (["encoder", "embeddings", "first_block", "last_block", "pooler"].iter().any(|key| changes[*key].as_u64().unwrap_or(0) == 0)
            || block_changes.contains(&0))
    {
        return fail("FULL requires changes in embeddings, every encoder block, and pooler.");
    }
    let losses = evidence["losses"].as_array().cloned().unwrap_or_default();
    if losses.len() as u64 != steps || losses.iter().any(|v| !v.as_f64().is_some_and(f64::is_finite)) {
        return fail("Finite per-step loss trace required.");
    }
    let trace = evidence["gradient_trace"].as_array().cloned().unwrap_or_default();
    if trace.len() as u64 != steps
        || trace
            .iter()
            .enumerate()
            .any(|(i, row)| row["step"].as_u64() != Some(i as u64 + 1) || !row["norm_before_clip"].as_f64().is_some_and(f64::is_finite))
    {
        return fail("Complete finite per-step gradient trace required.");
    }
    if full && !trace.iter().skip(1).any(|row| row["encoder_nonzero_gradients"].as_u64().unwrap_or(0) > 0) {
        return fail("FULL requires observed encoder gradients after the zero-head step.");
    }
    let before = validate_guard(&evidence["base_guard"], guard_rows as usize)?;
    let after = validate_guard(&evidence["candidate_guard"], guard_rows as usize)?;
    if before.iter().zip(&after).any(|(a, b)| a["target"] != b["target"] || a["target_action"] != b["target_action"]) {
        return fail("Base/candidate guard targets differ.");
    }
    if evidence["action_harms"].as_u64() != Some(harm_count(&json!(before), &json!(after)) as u64) {
        return fail("Action harm count differs from guard rows.");
    }
    if finalized {
        if !is_sha_serde(&evidence["candidate_blob"]) {
            return fail("Expected a lowercase SHA-256 identity.");
        }
        if evidence["serialized_guard_parity"] != true {
            return fail("Serialized guard parity required.");
        }
    }
    Ok(())
}

/// `publication_passes`: the candidate improves the joint count and harms no action.
pub fn publication_passes(evidence: &serde_json::Value) -> Result<bool, ContractError> {
    validate_execution(evidence, true)?;
    Ok(evidence["candidate_guard"]["joint_correct"].as_u64() > evidence["base_guard"]["joint_correct"].as_u64()
        && evidence["action_harms"] == 0)
}
