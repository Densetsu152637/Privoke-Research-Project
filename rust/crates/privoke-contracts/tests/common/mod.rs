//! Shared helpers for reading the stage 0 conformance corpus with the crate's own strict JSON parser.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use privoke_contracts::json;
pub use privoke_contracts::json::Value;

pub fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/conformance")
}

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

pub fn load(name: &str) -> Value {
    let path = corpus_dir().join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    json::parse(&text).unwrap_or_else(|error| panic!("{name}: {error}"))
}

pub fn get<'a>(value: &'a Value, key: &str) -> &'a Value {
    match value {
        Value::Object(map) => map.get(key).unwrap_or_else(|| panic!("missing key {key}")),
        other => panic!("not an object looking for {key}: {other:?}"),
    }
}

pub fn opt<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    match value {
        Value::Object(map) => map.get(key),
        _ => None,
    }
}

pub fn text(value: &Value) -> &str {
    match value {
        Value::String(text) => text,
        other => panic!("not a string: {other:?}"),
    }
}

pub fn array(value: &Value) -> &[Value] {
    match value {
        Value::Array(items) => items,
        other => panic!("not an array: {other:?}"),
    }
}

pub fn object(value: &Value) -> &BTreeMap<String, Value> {
    match value {
        Value::Object(map) => map,
        other => panic!("not an object: {other:?}"),
    }
}

pub fn number(value: &Value) -> f64 {
    match value {
        Value::Int(digits) => digits.parse().unwrap(),
        Value::Float(number) => *number,
        other => panic!("not a number: {other:?}"),
    }
}

pub fn unsigned(value: &Value) -> u64 {
    match value {
        Value::Int(digits) => digits.parse().unwrap(),
        other => panic!("not an integer: {other:?}"),
    }
}
