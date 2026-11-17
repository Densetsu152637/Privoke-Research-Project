//! SHA-256 identities, artifact checksums, receipt keys and derived seeds.

use sha2::{Digest, Sha256};

use crate::canonical::{self, CanonicalError, Variant};
use crate::json::Value;

/// Lowercase hexadecimal SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// `artifact_checksum`: SHA-256 of the artifact's canonical UTF-8 JSON with U+2028 and U+2029 escaped.
///
/// The argument is the artifact without its `checksum` member; see [`artifact_checksum_of_artifact`].
pub fn artifact_checksum(payload: &Value) -> Result<String, CanonicalError> {
    Ok(sha256_hex(&canonical::to_bytes(payload, Variant::Utf8Go)?))
}

/// The checksum of an artifact object, ignoring any top-level `checksum` member.
pub fn artifact_checksum_of_artifact(artifact: &Value) -> Result<String, CanonicalError> {
    match artifact {
        Value::Object(map) => {
            let mut body = map.clone();
            body.remove("checksum");
            artifact_checksum(&Value::Object(body))
        }
        other => artifact_checksum(other),
    }
}

/// `receipt_key` of the parameter-update service: SHA-256 of `[source_id, request_source_id, request_id]`.
pub fn receipt_key(source_id: &str, request_id: &str, request_source_id: &str) -> Result<String, CanonicalError> {
    let key = Value::Array(vec![
        Value::String(source_id.to_string()),
        Value::String(request_source_id.to_string()),
        Value::String(request_id.to_string()),
    ]);
    Ok(sha256_hex(&canonical::to_bytes(&key, Variant::Ascii)?))
}

/// The window-training sampler tag hashed into every derived seed.
pub const WINDOW_SAMPLER: &str = "taxonomy_benign_train_window_v1";

/// `window_training.derived_seed`: the first eight SHA-256 bytes, big endian, of `[SAMPLER, seed, purpose, index]`.
pub fn derived_seed(seed: u64, purpose: &str, index: u64) -> Result<u64, CanonicalError> {
    let record = Value::Array(vec![
        Value::String(WINDOW_SAMPLER.to_string()),
        Value::Int(seed.to_string()),
        Value::String(purpose.to_string()),
        Value::Int(index.to_string()),
    ]);
    let digest = Sha256::digest(canonical::to_bytes(&record, Variant::Ascii)?);
    let mut head = [0u8; 8];
    head.copy_from_slice(&digest[..8]);
    Ok(u64::from_be_bytes(head))
}
