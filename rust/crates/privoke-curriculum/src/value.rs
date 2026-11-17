//! JSON values as the Python curricula use them: dict rows, canonical bytes and `json.dumps` text.
//!
//! Rows stay [`Value`] objects, not typed structs, because several digests are taken over the whole dict
//! (`canonical(row)`), and a field that a struct dropped would silently change the digest.

use std::collections::BTreeMap;

pub use privoke_contracts::json::Value;
use privoke_contracts::{canonical, digest, json, pyfloat};

use crate::error::{Error, Result, invalid};

/// A JSON object under construction.
pub type Object = BTreeMap<String, Value>;

/// `json.loads(payload.decode("utf-8"))`.
pub fn parse_bytes(bytes: &[u8]) -> Result<Value> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::Invalid("payload is not valid UTF-8".to_string()))?;
    Ok(json::parse(text)?)
}

/// A string value.
pub fn string(text: &str) -> Value {
    Value::String(text.to_string())
}

/// An integer value.
pub fn int(number: i64) -> Value {
    Value::Int(number.to_string())
}

/// An unsigned integer value.
pub fn uint(number: u64) -> Value {
    Value::Int(number.to_string())
}

/// A list of strings.
pub fn strings<S: AsRef<str>>(items: &[S]) -> Value {
    Value::Array(items.iter().map(|item| string(item.as_ref())).collect())
}

/// An object from pairs.
pub fn object<K: Into<String>>(pairs: Vec<(K, Value)>) -> Value {
    Value::Object(pairs.into_iter().map(|(key, value)| (key.into(), value)).collect())
}

/// `row.get(key)`.
pub fn get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    match value {
        Value::Object(map) => map.get(key),
        _ => None,
    }
}

/// `row[key]`, refusing a missing key as Python's `KeyError` would.
pub fn require<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    get(value, key).ok_or_else(|| Error::Invalid(format!("missing key {key}")))
}

/// The string at `key`.
pub fn str_at<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    match require(value, key)? {
        Value::String(text) => Ok(text),
        _ => invalid(format!("{key} must be a string")),
    }
}

/// The string, if the value is one.
pub fn as_str(value: &Value) -> Option<&str> {
    match value {
        Value::String(text) => Some(text),
        _ => None,
    }
}

/// The list at `key`.
pub fn array_at<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    match require(value, key)? {
        Value::Array(items) => Ok(items),
        _ => invalid(format!("{key} must be a list")),
    }
}

/// The list, if the value is one.
pub fn as_array(value: &Value) -> Option<&Vec<Value>> {
    match value {
        Value::Array(items) => Some(items),
        _ => None,
    }
}

/// The object at `key`.
pub fn object_at<'a>(value: &'a Value, key: &str) -> Result<&'a Object> {
    match require(value, key)? {
        Value::Object(map) => Ok(map),
        _ => invalid(format!("{key} must be an object")),
    }
}

/// The object, if the value is one.
pub fn as_object(value: &Value) -> Option<&Object> {
    match value {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

/// The integer, if the value is a JSON integer (not a float, not a bool).
pub fn as_i64(value: &Value) -> Option<i64> {
    match value {
        Value::Int(digits) => digits.parse().ok(),
        _ => None,
    }
}

/// The integer at `key`.
pub fn i64_at(value: &Value, key: &str) -> Result<i64> {
    as_i64(require(value, key)?).ok_or_else(|| Error::Invalid(format!("{key} must be an integer")))
}

/// A number as a float, as Python compares `int` and `float` (`1 == 1.0`).
pub fn as_number(value: &Value) -> Option<f64> {
    match value {
        Value::Int(digits) => digits.parse::<f64>().ok(),
        Value::Float(number) => Some(*number),
        _ => None,
    }
}

/// The bool, if the value is one.
pub fn as_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(flag) => Some(*flag),
        _ => None,
    }
}

/// `canonical(value)` of the curricula: sorted keys, compact separators, UTF-8, one trailing newline.
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>> {
    Ok(canonical::to_bytes(value, canonical::Variant::Utf8Lf)?)
}

/// `hashlib.sha256(data).hexdigest()`.
pub fn sha256(data: &[u8]) -> String {
    digest::sha256_hex(data)
}

/// `digest(canonical(value))`.
pub fn digest_of(value: &Value) -> Result<String> {
    Ok(sha256(&canonical_bytes(value)?))
}

/// `json.dumps(value, sort_keys=True, separators=(",", ":"))` with `ensure_ascii=True` and no newline.
pub fn dumps_compact(value: &Value) -> Result<String> {
    Ok(canonical::to_string(value, canonical::Variant::Ascii)?)
}

/// `json.dumps(value, sort_keys=True)`: default `", "` and `": "` separators, `ensure_ascii=True`.
pub fn dumps(value: &Value) -> Result<String> {
    let mut out = String::new();
    write_default(&mut out, value)?;
    Ok(out)
}

fn write_default(out: &mut String, value: &Value) -> Result<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int(digits) => out.push_str(digits),
        Value::Float(number) => out.push_str(&pyfloat::repr(*number).map_err(|_| Error::Invalid("non-finite float".to_string()))?),
        Value::String(text) => write_ascii_string(out, text),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write_default(out, item)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (index, (key, item)) in map.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write_ascii_string(out, key);
                out.push_str(": ");
                write_default(out, item)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_ascii_string(out: &mut String, text: &str) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(character),
            other => {
                let mut units = [0u16; 2];
                for unit in other.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
}

/// `isinstance(value, dict)` shaped tests for rows: a JSON object.
pub fn is_object(value: &Value) -> bool {
    matches!(value, Value::Object(_))
}

/// A `dict[str, str]` metadata object as a map; `None` when a value is not a string.
pub fn string_map(value: &Value) -> Option<BTreeMap<String, String>> {
    let map = as_object(value)?;
    let mut out = BTreeMap::new();
    for (key, item) in map {
        out.insert(key.clone(), as_str(item)?.to_string());
    }
    Some(out)
}

/// A string map as an object value.
pub fn from_string_map(map: &BTreeMap<String, String>) -> Value {
    Value::Object(map.iter().map(|(key, text)| (key.clone(), string(text))).collect())
}
