//! A minimal reader for the safetensors container, restricted to what V3 checkpoints hold: complete, finite,
//! little-endian float32 tensors (`inventory` in `v3/model.py` refuses anything else).

use std::collections::BTreeMap;

use privoke_contracts::digest::sha256_hex;
use serde_json::Value;

use crate::error::SemanticError;

/// Upper bound on the JSON header, as in the reference implementation of the format.
const MAX_HEADER_BYTES: usize = 100 * 1024 * 1024;

/// One float32 tensor.
#[derive(Debug, Clone)]
pub struct Tensor {
    /// Dimensions.
    pub shape: Vec<usize>,
    /// Values, row-major.
    pub data: Vec<f32>,
    /// SHA-256 of the raw little-endian bytes (the `sha256` of the manifest inventory).
    pub sha256: String,
}

fn shape_of(entry: &Value) -> Option<Vec<usize>> {
    entry.get("shape")?.as_array()?.iter().map(|dim| usize::try_from(dim.as_u64()?).ok()).collect()
}

fn offsets_of(entry: &Value) -> Option<(usize, usize)> {
    let pair = entry.get("data_offsets")?.as_array()?;
    if pair.len() != 2 {
        return None;
    }
    Some((usize::try_from(pair[0].as_u64()?).ok()?, usize::try_from(pair[1].as_u64()?).ok()?))
}

/// Parse a safetensors file into its tensors, by name.
pub fn parse(bytes: &[u8]) -> Result<BTreeMap<String, Tensor>, SemanticError> {
    let invalid = |message: &str| SemanticError::artifact(format!("Checkpoint requires complete finite float32 tensors: {message}"));
    let prefix: [u8; 8] = bytes.get(..8).and_then(|head| head.try_into().ok()).ok_or_else(|| invalid("no header"))?;
    let header_len = usize::try_from(u64::from_le_bytes(prefix)).map_err(|_| invalid("header length"))?;
    if header_len > MAX_HEADER_BYTES || header_len > bytes.len() - 8 {
        return Err(invalid("header length"));
    }
    let header: Value = serde_json::from_slice(&bytes[8..8 + header_len]).map_err(|_| invalid("header is not JSON"))?;
    let Value::Object(entries) = header else {
        return Err(invalid("header is not an object"));
    };
    let data = &bytes[8 + header_len..];
    let mut tensors = BTreeMap::new();
    for (name, entry) in &entries {
        if name == "__metadata__" {
            continue;
        }
        let dtype = entry.get("dtype").and_then(Value::as_str);
        if dtype != Some("F32") {
            return Err(invalid(&format!("{name} is not F32")));
        }
        let shape = shape_of(entry).ok_or_else(|| invalid(&format!("{name} has no shape")))?;
        let (start, end) = offsets_of(entry).ok_or_else(|| invalid(&format!("{name} has no offsets")))?;
        let count = shape.iter().try_fold(1usize, |acc, dim| acc.checked_mul(*dim));
        let expected = count.and_then(|count| count.checked_mul(4)).ok_or_else(|| invalid(&format!("{name} is too large")))?;
        if start > end || end > data.len() || end - start != expected {
            return Err(invalid(&format!("{name} has inconsistent offsets")));
        }
        let raw = &data[start..end];
        let values: Vec<f32> = raw.chunks_exact(4).map(|word| f32::from_le_bytes([word[0], word[1], word[2], word[3]])).collect();
        if values.iter().any(|value| !value.is_finite()) {
            return Err(invalid(&format!("{name} is not finite")));
        }
        tensors.insert(name.clone(), Tensor { shape, data: values, sha256: sha256_hex(raw) });
    }
    Ok(tensors)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn file(header: &str, payload: &[u8]) -> Vec<u8> {
        let mut out = (header.len() as u64).to_le_bytes().to_vec();
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn floats(values: &[f32]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    #[test]
    fn reads_float32_tensors() {
        let header = r#"{"a":{"dtype":"F32","shape":[2,2],"data_offsets":[0,16]},"b":{"dtype":"F32","shape":[1],"data_offsets":[16,20]},"__metadata__":{"x":"y"}}"#;
        let bytes = file(header, &floats(&[1.0, 2.0, 3.0, 4.0, -0.5]));
        let tensors = parse(&bytes).unwrap();
        assert_eq!(tensors["a"].shape, vec![2, 2]);
        assert_eq!(tensors["a"].data, vec![1.0, 2.0, 3.0, 4.0]);
        assert_eq!(tensors["b"].data, vec![-0.5]);
        assert_eq!(tensors["b"].sha256, sha256_hex(&floats(&[-0.5])));
        assert_eq!(tensors.len(), 2);
    }

    #[test]
    fn refuses_other_dtypes_non_finite_values_and_bad_offsets() {
        let bad_dtype = file(r#"{"a":{"dtype":"F16","shape":[1],"data_offsets":[0,2]}}"#, &[0, 0]);
        assert!(parse(&bad_dtype).is_err());
        let not_finite = file(r#"{"a":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}"#, &floats(&[f32::NAN]));
        assert!(parse(&not_finite).is_err());
        let short = file(r#"{"a":{"dtype":"F32","shape":[2],"data_offsets":[0,4]}}"#, &floats(&[1.0, 2.0]));
        assert!(parse(&short).is_err());
        let beyond = file(r#"{"a":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}"#, &floats(&[1.0]));
        assert!(parse(&beyond).is_err());
        assert!(parse(&[1, 2, 3]).is_err());
        assert!(parse(&u64::MAX.to_le_bytes()).is_err());
    }
}
