//! `shared/python/privoke_model/v3_contract.py` as the V3 fuzzer uses it.
//!
//! Nothing of the contract is reimplemented here:
//!
//! * `parse` (duplicate rejection, finite numbers, byte-for-byte canonical) is [`privoke_contracts::v3::parse_canonical`];
//! * `canonical` and `digest` are the curriculum value helpers over the same canonical writer;
//! * `validate_policy` is [`privoke_curriculum::v3::Policy::from_value`];
//! * `validate_manifest` is [`privoke_contracts::v3::validate_manifest`];
//! * `validate_execution`, `validate_guard` and `publication_passes` are the stage 19 ports in
//!   [`privoke_training::v3_fit`], which work on [`serde_json::Value`]. [`to_serde`] converts a strictly parsed document.
//!
//! The error texts are the Python `ValueError` messages.

use privoke_contracts::json::{self, Value};
use privoke_contracts::v3::{self, Manifest, ManifestError};
use privoke_curriculum::v3::Policy;
use privoke_curriculum::value;
use privoke_training::v3_fit;
use serde_json::Value as Serde;

use crate::error::{Error, Result, invalid};

/// The bound on the evidence document (`MAX_BLOB_BYTES`).
pub const MAX_EVIDENCE_BYTES: usize = 80 * 1024 * 1024;
/// The bound on a manifest (`MAX_MANIFEST_BYTES`, the default of `parse`).
pub const MAX_MANIFEST_BYTES: usize = v3::MAX_MANIFEST_BYTES;

/// `digest(payload)`: the lowercase hexadecimal SHA-256.
pub fn digest(payload: &[u8]) -> String {
    value::sha256(payload)
}

/// `canonical(value)`: sorted keys, compact separators, UTF-8, one trailing newline.
pub fn canonical(document: &Value) -> Result<Vec<u8>> {
    Ok(value::canonical_bytes(document)?)
}

/// `check_sha(value)`.
pub fn check_sha(text: &str) -> Result<()> {
    if text.len() == 64 && text.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(())
    } else {
        invalid("Expected a lowercase SHA-256 identity.")
    }
}

fn parse_error(error: ManifestError) -> Error {
    Error(match error {
        ManifestError::TooLarge => "JSON exceeds its explicit byte bound.".to_string(),
        ManifestError::NotCanonical => "Canonical JSON bytes required.".to_string(),
        ManifestError::Json(json::JsonError::DuplicateKey(_)) => "Duplicate JSON field.".to_string(),
        ManifestError::Json(json::JsonError::NonFinite(_)) => "Nonfinite JSON.".to_string(),
        other => other.to_string(),
    })
}

/// `parse(payload, limit)`.
pub fn parse(payload: &[u8], limit: usize) -> Result<Value> {
    v3::parse_canonical(payload, limit).map_err(parse_error)
}

/// `validate_policy(policy, pilot=policy["steps"] == 2)`.
pub fn validate_policy(policy: &Value) -> Result<Policy> {
    Ok(Policy::from_value(policy)?)
}

/// `validate_manifest(value)`.
pub fn validate_manifest(document: &Value) -> Result<Manifest> {
    v3::validate_manifest(document).map_err(|error| Error(error.to_string()))
}

/// A strictly parsed document as a `serde_json` value, for the stage 19 validators.
pub fn to_serde(document: &Value) -> Result<Serde> {
    Ok(match document {
        Value::Null => Serde::Null,
        Value::Bool(flag) => Serde::Bool(*flag),
        Value::Int(digits) => {
            if let Ok(number) = digits.parse::<i64>() {
                Serde::from(number)
            } else if let Ok(number) = digits.parse::<u64>() {
                Serde::from(number)
            } else {
                return invalid("Integer outside the supported range.");
            }
        }
        Value::Float(number) => match serde_json::Number::from_f64(*number) {
            Some(number) => Serde::Number(number),
            None => return invalid("Nonfinite JSON."),
        },
        Value::String(text) => Serde::String(text.clone()),
        Value::Array(items) => Serde::Array(items.iter().map(to_serde).collect::<Result<Vec<_>>>()?),
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (key, item) in map {
                out.insert(key.clone(), to_serde(item)?);
            }
            Serde::Object(out)
        }
    })
}

/// `validate_execution(evidence)` (finalized).
pub fn validate_execution(evidence: &Serde) -> Result<()> {
    Ok(v3_fit::validate_execution(evidence, true)?)
}

/// `publication_passes(evidence)`.
pub fn publication_passes(evidence: &Serde) -> Result<bool> {
    Ok(v3_fit::publication_passes(evidence)?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_requires_canonical_bytes_and_unique_fields() {
        assert!(parse(b"{\"a\":1}\n", 100).is_ok());
        assert_eq!(parse(b"{\"a\": 1}\n", 100).unwrap_err().0, "Canonical JSON bytes required.");
        assert_eq!(parse(b"{\"a\":1}", 100).unwrap_err().0, "Canonical JSON bytes required.");
        assert_eq!(parse(b"{\"a\":1,\"a\":2}\n", 100).unwrap_err().0, "Duplicate JSON field.");
        assert_eq!(parse(b"{\"a\":1}\n", 3).unwrap_err().0, "JSON exceeds its explicit byte bound.");
        assert_eq!(parse(b"{\"a\":NaN}\n", 100).unwrap_err().0, "Nonfinite JSON.");
    }

    #[test]
    fn a_strictly_parsed_document_converts_exactly() {
        let document = parse(b"{\"a\":[1,2.5,\"x\",null,true],\"b\":-3}\n", 100).unwrap();
        let converted = to_serde(&document).unwrap();
        assert_eq!(converted, serde_json::json!({"a": [1, 2.5, "x", null, true], "b": -3}));
        let large = parse(b"{\"a\":99999999999999999999999}\n", 100).unwrap();
        assert!(to_serde(&large).is_err());
    }

    #[test]
    fn the_frozen_policy_is_admitted_and_a_changed_one_is_not() {
        let frozen = Policy { steps: 64 }.to_value();
        assert_eq!(validate_policy(&frozen).unwrap(), Policy { steps: 64 });
        assert_eq!(validate_policy(&Policy::PILOT.to_value()).unwrap(), Policy::PILOT);
        let mut changed = frozen.clone();
        if let Value::Object(map) = &mut changed {
            map.insert("clip_norm".to_string(), Value::Float(2.0));
        }
        assert_eq!(validate_policy(&changed).unwrap_err().0, "Policy differs from the frozen v3 contract.");
        let mut budget = frozen;
        if let Value::Object(map) = &mut budget {
            map.insert("steps".to_string(), value::int(65));
        }
        assert_eq!(validate_policy(&budget).unwrap_err().0, "Predeclared v3 work budget must be 64, 256 or 512 steps.");
    }

    #[test]
    fn a_digest_is_a_lowercase_sha_256() {
        let sha = digest(b"abc");
        assert_eq!(sha, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert!(check_sha(&sha).is_ok());
        assert!(check_sha("ABC").is_err());
        assert!(check_sha(&sha.to_uppercase()).is_err());
    }
}
