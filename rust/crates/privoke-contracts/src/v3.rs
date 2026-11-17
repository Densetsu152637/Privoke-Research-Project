//! The pinned standard AU3 (V3) manifest rules of `v3_contract.py` and `standard_v3.py`.

use std::collections::BTreeMap;

use crate::canonical::{self, Variant};
use crate::digest::sha256_hex;
use crate::json::{self, Duplicates, ParseOptions, Value};

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
