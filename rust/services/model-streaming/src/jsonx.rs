//! Helpers that reproduce Go `encoding/json` decoding behaviour over the strict contract parser.
//!
//! Go decodes into typed fields leniently in two ways the validators depend on: a JSON `null` leaves a field at its
//! zero value, and a value of the wrong type is an error. These helpers take `Option<&Value>` (absent or present) and
//! follow those rules. Keys are matched exactly (Go also folds case; a case variant is ignored here, which only ever
//! rejects more).

use std::collections::BTreeMap;

use privoke_contracts::json::{self, Duplicates, ParseOptions, Value};

use crate::error::{Error, Result};
use crate::fail;

/// A decoded JSON object.
pub type Object = BTreeMap<String, Value>;

/// Parse with `json.loads` semantics (the last duplicate key wins).
pub fn parse(text: &str) -> Result<Value> {
    json::parse(text).map_err(|error| Error(error.to_string()))
}

/// Parse and refuse a repeated key anywhere in the document.
pub fn parse_strict(text: &str) -> Result<Value> {
    json::parse_with(text, ParseOptions { duplicates: Duplicates::Reject, ..ParseOptions::default() })
        .map_err(|error| Error(error.to_string()))
}

/// Go: `json.Unmarshal(raw, &map[string]json.RawMessage)`. `null` decodes to an empty map; any non-object fails.
pub fn object_of(text: &str) -> Result<Object> {
    match parse(text)? {
        Value::Object(map) => Ok(map),
        Value::Null => Ok(Object::new()),
        _ => fail!("JSON value is not an object"),
    }
}

/// Go string field: absent or `null` is `""`.
pub fn string(value: Option<&Value>) -> Result<String> {
    match value {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(text)) => Ok(text.clone()),
        Some(_) => fail!("JSON value is not a string"),
    }
}

/// Go `bool` field: absent or `null` is `false`.
pub fn boolean(value: Option<&Value>) -> Result<bool> {
    match value {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(flag)) => Ok(*flag),
        Some(_) => fail!("JSON value is not a boolean"),
    }
}

/// Go `int64` (and `int`) field: an integer literal that fits, otherwise an error. Absent or `null` is 0.
pub fn int64(value: Option<&Value>) -> Result<i64> {
    match value {
        None | Some(Value::Null) => Ok(0),
        Some(Value::Int(digits)) => digits.parse::<i64>().map_err(|_| Error("integer overflows int64".into())),
        Some(_) => fail!("JSON value is not an integer"),
    }
}

/// Go `uint32` field.
pub fn uint32(value: Option<&Value>) -> Result<u32> {
    match value {
        None | Some(Value::Null) => Ok(0),
        Some(Value::Int(digits)) => digits.parse::<u32>().map_err(|_| Error("integer overflows uint32".into())),
        Some(_) => fail!("JSON value is not an unsigned integer"),
    }
}

/// Go `float64` field. Absent or `null` is 0; any finite number is accepted.
pub fn float64(value: Option<&Value>) -> Result<f64> {
    match value {
        None | Some(Value::Null) => Ok(0.0),
        Some(Value::Float(number)) => Ok(*number),
        Some(Value::Int(digits)) => match digits.parse::<f64>() {
            Ok(number) if number.is_finite() => Ok(number),
            _ => fail!("number overflows float64"),
        },
        Some(_) => fail!("JSON value is not a number"),
    }
}

/// Go `*float64`: `null` is an error (the validators use it where a pointer distinguishes null from absence).
pub fn required_float64(value: &Value) -> Result<f64> {
    match value {
        Value::Null => fail!("JSON null where a number is required"),
        other => float64(Some(other)),
    }
}

/// Go `*string`: `null` is an error.
pub fn required_string(value: &Value) -> Result<String> {
    match value {
        Value::String(text) => Ok(text.clone()),
        _ => fail!("JSON value is not a string"),
    }
}

/// Go `[]string` field: absent or `null` is empty; an element that is `null` becomes `""`.
pub fn string_list(value: Option<&Value>) -> Result<Vec<String>> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items.iter().map(|item| string(Some(item))).collect(),
        Some(_) => fail!("JSON value is not an array of strings"),
    }
}

/// Go `[]int` field.
pub fn int_list(value: Option<&Value>) -> Result<Vec<i64>> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items.iter().map(|item| int64(Some(item))).collect(),
        Some(_) => fail!("JSON value is not an array of integers"),
    }
}

/// `[]uint32` with the strict rule that an element may not be `null`.
pub fn uint32_list_strict(value: Option<&Value>) -> Result<Vec<u32>> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::Null => fail!("null in an integer array"),
                other => uint32(Some(other)),
            })
            .collect(),
        Some(_) => fail!("JSON value is not an array of unsigned integers"),
    }
}

/// `[]float64` with the strict rule that an element may not be `null`.
pub fn float64_list_strict(value: Option<&Value>) -> Result<Vec<f64>> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::Null => fail!("null in a number array"),
                other => float64(Some(other)),
            })
            .collect(),
        Some(_) => fail!("JSON value is not an array of numbers"),
    }
}

/// Go `map[string]string`: `null` is no map, a `null` value is `""`, other non-strings fail.
pub fn string_map(value: Option<&Value>) -> Result<Option<BTreeMap<String, String>>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(map)) => {
            let mut out = BTreeMap::new();
            for (key, item) in map {
                out.insert(key.clone(), string(Some(item))?);
            }
            Ok(Some(out))
        }
        Some(_) => fail!("JSON value is not an object of strings"),
    }
}

/// Go `exactJSONFields`: the value must be an object (or null, which counts as empty) holding exactly the
/// `expected` keys, none of them `null`.
pub fn exact_fields(value: Option<&Value>, expected: &[&str]) -> Result<()> {
    let Some(value) = value else { fail!("unexpected end of JSON input") };
    let empty = Object::new();
    let fields = match value {
        Value::Object(map) => map,
        Value::Null => &empty,
        _ => fail!("JSON value is not an object"),
    };
    if fields.len() != expected.len() {
        fail!("presence config has missing or unknown fields");
    }
    for name in expected {
        match fields.get(*name) {
            Some(Value::Null) | None => fail!("presence config is missing/null {name:?}"),
            Some(_) => {}
        }
    }
    Ok(())
}

/// Go `json.Compact`: drop insignificant whitespace. `None` if the text is not syntactically valid JSON.
pub fn compact(text: &str) -> Option<String> {
    parse(text).ok()?;
    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut escaped = false;
    for character in text.chars() {
        if in_string {
            out.push(character);
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
        } else if character == '"' {
            in_string = true;
            out.push(character);
        } else if !matches!(character, ' ' | '\t' | '\n' | '\r') {
            out.push(character);
        }
    }
    Some(out)
}

/// One member of the root object, with the exact bytes of its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// The decoded key.
    pub key: String,
    /// The raw value text as it appears in the document, without surrounding whitespace.
    pub raw: String,
}

/// Every member of the root object in document order, duplicates included (Go's raw token walk). The document must
/// already be known to be valid JSON.
pub fn root_members(text: &str) -> Result<Vec<Member>> {
    let bytes = text.as_bytes();
    let mut position = skip_whitespace(bytes, 0);
    if bytes.get(position) != Some(&b'{') {
        fail!("artifact must be an object");
    }
    position += 1;
    let mut members = Vec::new();
    loop {
        position = skip_whitespace(bytes, position);
        match bytes.get(position) {
            Some(b'}') => return Ok(members),
            Some(b',') => {
                position += 1;
                continue;
            }
            Some(b'"') => {}
            _ => fail!("invalid artifact key"),
        }
        let key_end = skip_string(bytes, position)?;
        let Value::String(key) = parse(&text[position..key_end])? else { fail!("invalid artifact key") };
        position = skip_whitespace(bytes, key_end);
        if bytes.get(position) != Some(&b':') {
            fail!("expected a colon after an artifact key");
        }
        position = skip_whitespace(bytes, position + 1);
        let end = skip_value(bytes, position)?;
        members.push(Member { key, raw: text[position..end].to_string() });
        position = end;
    }
}

fn skip_whitespace(bytes: &[u8], mut position: usize) -> usize {
    while matches!(bytes.get(position), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        position += 1;
    }
    position
}

fn skip_string(bytes: &[u8], start: usize) -> Result<usize> {
    let mut position = start + 1;
    while let Some(byte) = bytes.get(position) {
        match byte {
            b'\\' => position += 2,
            b'"' => return Ok(position + 1),
            _ => position += 1,
        }
    }
    fail!("unterminated JSON string")
}

fn skip_value(bytes: &[u8], start: usize) -> Result<usize> {
    match bytes.get(start) {
        Some(b'"') => skip_string(bytes, start),
        Some(b'{' | b'[') => {
            let mut depth = 0usize;
            let mut position = start;
            while let Some(byte) = bytes.get(position) {
                match byte {
                    b'"' => position = skip_string(bytes, position)?,
                    b'{' | b'[' => {
                        depth += 1;
                        position += 1;
                    }
                    b'}' | b']' => {
                        depth -= 1;
                        position += 1;
                        if depth == 0 {
                            return Ok(position);
                        }
                    }
                    _ => position += 1,
                }
            }
            fail!("unterminated JSON container")
        }
        Some(_) => {
            let mut position = start;
            while let Some(byte) = bytes.get(position) {
                if matches!(byte, b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r') {
                    break;
                }
                position += 1;
            }
            Ok(position)
        }
        None => fail!("unexpected end of JSON input"),
    }
}

/// Go `validJSONUnicode`: raw bytes with no lone surrogate escape, scanned exactly as the Go code does.
pub fn valid_json_unicode(raw: &[u8]) -> bool {
    if std::str::from_utf8(raw).is_err() {
        return false;
    }
    let hex = |slice: &[u8]| -> Option<u16> {
        if !slice.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        u16::from_str_radix(std::str::from_utf8(slice).ok()?, 16).ok()
    };
    let mut index = 0;
    while index < raw.len() {
        if raw[index] != b'\\' {
            index += 1;
            continue;
        }
        index += 1;
        if index >= raw.len() {
            return false;
        }
        if raw[index] != b'u' {
            index += 1;
            continue;
        }
        if index + 4 >= raw.len() {
            return false;
        }
        let Some(value) = hex(&raw[index + 1..index + 5]) else { return false };
        index += 4;
        if (0xDC00..=0xDFFF).contains(&value) {
            return false;
        }
        if !(0xD800..=0xDBFF).contains(&value) {
            index += 1;
            continue;
        }
        if index + 6 >= raw.len() || raw[index + 1] != b'\\' || raw[index + 2] != b'u' {
            return false;
        }
        let Some(low) = hex(&raw[index + 3..index + 7]) else { return false };
        if !(0xDC00..=0xDFFF).contains(&low) {
            return false;
        }
        index += 7;
    }
    true
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn root_members_keep_duplicates_and_raw_bytes() {
        let text = "{ \"a\" : 1 ,\r\n \"a\":{\"x\" : [1, 2]}, \"b\":\"q\\\"}\" }";
        let members = root_members(text).unwrap();
        assert_eq!(members.len(), 3);
        assert_eq!(members[0].raw, "1");
        assert_eq!(members[1].raw, "{\"x\" : [1, 2]}");
        assert_eq!(members[2].raw, "\"q\\\"}\"");
    }

    #[test]
    fn compact_keeps_string_whitespace() {
        assert_eq!(compact("{ \"a b\" : [ 1 , 2 ] }").unwrap(), "{\"a b\":[1,2]}");
        assert!(compact("{").is_none());
    }
}
