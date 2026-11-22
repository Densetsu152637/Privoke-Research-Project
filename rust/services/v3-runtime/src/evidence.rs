//! The serialisation helpers of a fit: the JSON value of the evidence, the safetensors bytes of the candidate and the digests of
//! the Python sources the evidence commits to.

use std::collections::BTreeMap;
use std::path::Path;

use privoke_contracts::json::Value;
use privoke_semantic::safetensors::Tensor;
use privoke_v3_fuzzer::contract::digest;
use serde_json::Value as Serde;

use crate::pyerr::PyError;

/// The Python files whose bytes the fit evidence commits to (`source_hashes`): the server, the model, the fit and the contract.
pub const EVIDENCE_SOURCES: [&str; 4] = [
    "services/pretrained-v3/src/runtime_server.py",
    "extension/client-runtime/src/v3/model.py",
    "extension/client-runtime/src/v3/training.py",
    "shared/python/privoke_model/v3_contract.py",
];

/// A `serde_json` value as the strict JSON value the canonical writer takes: integers keep their digits, floats their bits.
pub fn from_serde(value: &Serde) -> Result<Value, PyError> {
    Ok(match value {
        Serde::Null => Value::Null,
        Serde::Bool(flag) => Value::Bool(*flag),
        Serde::Number(number) => {
            if let Some(integer) = number.as_i64() {
                Value::Int(integer.to_string())
            } else if let Some(integer) = number.as_u64() {
                Value::Int(integer.to_string())
            } else {
                match number.as_f64() {
                    Some(float) if float.is_finite() => Value::Float(float),
                    _ => return Err(PyError::value("Nonfinite JSON.")),
                }
            }
        }
        Serde::String(text) => Value::String(text.clone()),
        Serde::Array(items) => Value::Array(items.iter().map(from_serde).collect::<Result<Vec<_>, _>>()?),
        Serde::Object(map) => {
            let mut out = BTreeMap::new();
            for (key, item) in map {
                out.insert(key.clone(), from_serde(item)?);
            }
            Value::Object(out)
        }
    })
}

/// `{name: {"shape": [...], "dtype": "F32", "sha256": ...}}`: the tensor inventory of a checkpoint (`inventory(state)`).
pub fn inventory_value(tensors: &BTreeMap<String, Tensor>) -> Value {
    let mut out = BTreeMap::new();
    for (name, tensor) in tensors {
        let shape = tensor.shape.iter().map(|dimension| Value::Int(dimension.to_string())).collect();
        let entry = BTreeMap::from([
            ("shape".to_string(), Value::Array(shape)),
            ("dtype".to_string(), Value::String("F32".to_string())),
            ("sha256".to_string(), Value::String(tensor.sha256.clone())),
        ]);
        out.insert(name.clone(), Value::Object(entry));
    }
    Value::Object(out)
}

/// The bytes `safetensors.torch.save_file(state, path)` writes for float32 tensors and no metadata: the header (tensors ordered by
/// name, `dtype`, `shape` and `data_offsets` per entry, compact JSON, padded with spaces to a multiple of eight bytes), then the
/// little-endian values in the same order. `tensors` is ordered by name already.
pub fn safetensors_bytes(tensors: &BTreeMap<String, Tensor>) -> Vec<u8> {
    let mut header = String::from("{");
    let mut offset = 0usize;
    for (index, (name, tensor)) in tensors.iter().enumerate() {
        let end = offset + tensor.data.len() * 4;
        if index > 0 {
            header.push(',');
        }
        let shape: Vec<String> = tensor.shape.iter().map(ToString::to_string).collect();
        let key = serde_json::to_string(name).unwrap_or_else(|_| "\"\"".to_string());
        header.push_str(&format!("{key}:{{\"dtype\":\"F32\",\"shape\":[{}],\"data_offsets\":[{offset},{end}]}}", shape.join(",")));
        offset = end;
    }
    header.push('}');
    while !header.len().is_multiple_of(8) {
        header.push(' ');
    }
    let mut out = Vec::with_capacity(8 + header.len() + offset);
    out.extend_from_slice(&(header.len() as u64).to_le_bytes());
    out.extend_from_slice(header.as_bytes());
    for tensor in tensors.values() {
        for value in &tensor.data {
            out.extend_from_slice(&value.to_le_bytes());
        }
    }
    out
}

/// `source_hashes`: the digest of each source file under `root`, by repository-relative path.
pub fn source_hashes(root: &Path) -> Result<Value, PyError> {
    let mut out = BTreeMap::new();
    for relative in EVIDENCE_SOURCES {
        let bytes = std::fs::read(root.join(relative))?;
        out.insert(relative.to_string(), Value::String(digest(&bytes)));
    }
    Ok(Value::Object(out))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use privoke_semantic::safetensors::parse;

    use super::*;

    #[test]
    fn the_writer_reproduces_the_bytes_python_saved() {
        let package =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/privoke-semantic/tests/fixtures/v3_synthetic/model.safetensors");
        let original = std::fs::read(package).unwrap();
        let tensors = parse(&original).unwrap();
        assert_eq!(safetensors_bytes(&tensors), original, "save_file(state) and safetensors_bytes write the same file");
    }

    #[test]
    fn serde_numbers_keep_their_kind() {
        let value = from_serde(&serde_json::json!({"a": 1, "b": 1.0, "c": [0.5, -3], "d": null, "e": "x", "f": true})).unwrap();
        let Value::Object(map) = value else { panic!("object") };
        assert_eq!(map["a"], Value::Int("1".into()));
        assert_eq!(map["b"], Value::Float(1.0));
        assert_eq!(map["c"], Value::Array(vec![Value::Float(0.5), Value::Int("-3".into())]));
    }

    #[test]
    fn the_evidence_sources_are_hashed_under_a_root() {
        let directory = tempfile::tempdir().unwrap();
        for relative in EVIDENCE_SOURCES {
            let path = directory.path().join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, relative.as_bytes()).unwrap();
        }
        let Value::Object(map) = source_hashes(directory.path()).unwrap() else { panic!("object") };
        assert_eq!(map.len(), 4);
        assert_eq!(map[EVIDENCE_SOURCES[1]], Value::String(digest(EVIDENCE_SOURCES[1].as_bytes())));
        assert!(source_hashes(&directory.path().join("missing")).is_err());
    }
}
