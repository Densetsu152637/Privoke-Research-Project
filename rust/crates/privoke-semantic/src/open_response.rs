//! Parsing of the external classifier's response (`LLM/open_classifier.py::classify` after the request, and
//! `classification/external_output.py`, `classification_results.py`).
//!
//! The error texts are Python's `RuntimeError` messages, because the pipeline reports `str(exception)` as the layer's
//! error. Nothing raw from the model or the prompt is ever put in a message.

use privoke_rules::classification::{Classification, Sensitivity, category, visibility};
use serde_json::{Map, Value};

use crate::error::SemanticError;
use crate::layer::Finding;

const NO_RESULTS: &str = "Semantic classifier returned no valid results.";
const MALFORMED: &str = "Semantic classifier returned malformed classification results.";
const INVALID_JSON: &str = "Semantic classifier returned invalid JSON.";
const NO_CHOICES: &str = "Semantic classifier returned no completion choices.";
/// The body of a successful HTTP answer is not a chat completion (Python raises the SDK's own decoding error here).
const INVALID_HTTP: &str = "Semantic classifier returned an invalid HTTP response.";
/// The most a response body may hold (the reply to a 512-token request is a few kilobytes).
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Metadata keys the result type drops (`classification_results._parse_metadata`).
const RESERVED_METADATA: [&str; 3] = ["signal", "signals", "source"];
const SENSITIVITIES: [(&str, Sensitivity); 4] =
    [("S0", Sensitivity::S0), ("S1", Sensitivity::S1), ("S2", Sensitivity::S2), ("S3", Sensitivity::S3)];
const VISIBILITIES: [(&str, u16); 6] = [
    ("P0", visibility::P0),
    ("P1", visibility::P1),
    ("P2", visibility::P2),
    ("P3", visibility::P3),
    ("P4", visibility::P4),
    ("PU", visibility::PU),
];
const CATEGORIES: [(&str, u16); 10] = [
    ("HEALTH", category::HEALTH),
    ("POLITICS", category::POLITICS),
    ("RELIGION", category::RELIGION),
    ("CRIMINAL", category::CRIMINAL),
    ("FINANCIAL", category::FINANCIAL),
    ("SEXUAL", category::SEXUAL),
    ("CHILD", category::CHILD),
    ("LOCATION", category::LOCATION),
    ("IDENTITY", category::IDENTITY),
    ("THIRD_PARTY", category::THIRD_PARTY),
];

/// One validated finding of the external classifier, with everything `ClassificationResult` holds.
#[derive(Debug, Clone, PartialEq)]
pub struct ExternalResult {
    /// The packed classification.
    pub classification: Classification,
    /// `section_of_text`.
    pub section_of_text: String,
    /// `reasoning`.
    pub reasoning: String,
    /// `span` in characters (code points) of the classified text, when the model gave one.
    pub span: Option<(usize, usize)>,
    /// `confidence`, which the model may omit (`None` in Python).
    pub confidence: Option<f64>,
    /// `metadata` without the reserved `signal`, `signals` and `source` keys.
    pub metadata: Map<String, Value>,
}

/// The confidence the layer assumes when the model gave none. The Python policy never treats a missing confidence as
/// low, so `1.0` keeps the same action; stage 17 can read [`ExternalResult::confidence`] to keep the distinction.
pub const MISSING_CONFIDENCE: f64 = 1.0;

impl ExternalResult {
    /// The layer finding for this result (`confidence` of `None` becomes [`MISSING_CONFIDENCE`]).
    pub fn into_finding(self) -> Finding {
        Finding {
            classification: self.classification,
            confidence: self.confidence.unwrap_or(MISSING_CONFIDENCE),
            reasoning: self.reasoning,
            span: self.span,
            section: self.section_of_text,
        }
    }
}

fn error(message: &str) -> SemanticError {
    SemanticError::Input(message.to_string())
}

/// Result of one HTTP exchange: status, and the findings of the first completion when it succeeded.
///
/// * a non-2xx status is the SDK's `APIStatusError`: the message is `Error code: <status>` (the body is never echoed);
/// * a 2xx body that is not a chat completion is [`INVALID_HTTP`];
/// * no choices, a null or blank content, or content that is not JSON follow `classify` exactly.
pub fn parse_http_response(status: u16, body: &[u8], text: &str) -> Result<Vec<ExternalResult>, SemanticError> {
    if !(200..300).contains(&status) {
        return Err(SemanticError::Input(format!("Error code: {status}")));
    }
    let Ok(Value::Object(completion)) = serde_json::from_slice::<Value>(body) else {
        return Err(error(INVALID_HTTP));
    };
    let first = match completion.get("choices") {
        Some(Value::Array(choices)) if !choices.is_empty() => &choices[0],
        _ => return Err(error(NO_CHOICES)),
    };
    let content = first.get("message").and_then(|message| message.get("content"));
    match content {
        Some(Value::String(content)) => parse_completion_content(content, text),
        _ => Err(error(INVALID_JSON)),
    }
}

/// The message content of the first choice to results: `json.loads` (blank content included), then
/// [`build_external_results`].
pub fn parse_completion_content(content: &str, text: &str) -> Result<Vec<ExternalResult>, SemanticError> {
    let Some(parsed) = python_json(content) else {
        return Err(error(INVALID_JSON));
    };
    build_external_results(&parsed, text)
}

/// `build_external_results(content, text)`: strict validation, then `build_results`.
pub fn build_external_results(content: &Value, text: &str) -> Result<Vec<ExternalResult>, SemanticError> {
    if let Value::Object(map) = content {
        if map.len() == 1 && matches!(map.get("results"), Some(Value::Array(items)) if items.is_empty()) {
            return Ok(Vec::new());
        }
    }
    let raw: &[Value] = match content {
        Value::Object(map) => match map.get("results").or_else(|| map.get("classification_results")) {
            Some(Value::Array(items)) => items,
            Some(_) => return Err(error(NO_RESULTS)),
            None => std::slice::from_ref(content),
        },
        Value::Array(items) => items,
        _ => return Err(error(NO_RESULTS)),
    };
    if raw.is_empty() {
        return Err(error(NO_RESULTS));
    }
    let mut chars: Option<Vec<char>> = None;
    for item in raw {
        validate_item(item, text, &mut chars)?;
    }
    Ok(raw.iter().filter_map(build_result).collect())
}

fn name_in<T: Copy>(value: Option<&Value>, table: &[(&str, T)]) -> Option<T> {
    let name = value?.as_str()?;
    table.iter().find(|(candidate, _)| *candidate == name).map(|(_, item)| *item)
}

fn is_integer(value: &Value) -> bool {
    matches!(value, Value::Number(number) if number.is_i64() || number.is_u64())
}

fn validate_item(item: &Value, text: &str, chars: &mut Option<Vec<char>>) -> Result<(), SemanticError> {
    let malformed = || error(MALFORMED);
    let Value::Object(item) = item else {
        return Err(malformed());
    };
    name_in(item.get("sensitivity"), &SENSITIVITIES).ok_or_else(malformed)?;
    name_in(item.get("visibility"), &VISIBILITIES).ok_or_else(malformed)?;
    let Some(Value::Array(categories)) = item.get("categories") else {
        return Err(malformed());
    };
    if categories.iter().any(|name| name_in(Some(name), &CATEGORIES).is_none()) {
        return Err(malformed());
    }
    if !matches!(item.get("section_of_text"), Some(Value::String(_))) || !matches!(item.get("reasoning"), Some(Value::String(_))) {
        return Err(malformed());
    }
    match item.get("confidence") {
        None | Some(Value::Null) => {}
        Some(Value::Number(number)) => {
            let value = number.as_f64().ok_or_else(malformed)?;
            if !value.is_finite() || !(0.0..=1.0).contains(&value) {
                return Err(malformed());
            }
        }
        Some(_) => return Err(malformed()),
    }
    if item.get("metadata").is_some_and(|metadata| !metadata.is_object()) {
        return Err(malformed());
    }
    match item.get("span") {
        None | Some(Value::Null) => {}
        Some(Value::Array(span)) => {
            let [start, end] = span.as_slice() else {
                return Err(malformed());
            };
            if !is_integer(start) || !is_integer(end) {
                return Err(malformed());
            }
            let (Some(start), Some(end)) = (start.as_u64(), end.as_u64()) else {
                return Err(malformed());
            };
            let characters = chars.get_or_insert_with(|| text.chars().collect());
            let length = characters.len() as u64;
            if !(start < end && end <= length) {
                return Err(malformed());
            }
            // `start` and `end` are bounded by the length of `text`, so they fit in `usize`.
            let covered: String = characters[start as usize..end as usize].iter().collect();
            if item.get("section_of_text").and_then(Value::as_str) != Some(covered.as_str()) {
                return Err(malformed());
            }
        }
        Some(_) => return Err(malformed()),
    }
    Ok(())
}

/// `parse_result` for one item that passed [`validate_item`] (items that are not objects are skipped, as
/// `build_results` does).
fn build_result(item: &Value) -> Option<ExternalResult> {
    let item = item.as_object()?;
    let sensitivity = name_in(item.get("sensitivity"), &SENSITIVITIES).unwrap_or(Sensitivity::S0);
    let visibility = name_in(item.get("visibility"), &VISIBILITIES).unwrap_or(visibility::PU);
    let categories = item
        .get("categories")
        .and_then(Value::as_array)
        .map_or(0, |names| names.iter().filter_map(|name| name_in(Some(name), &CATEGORIES)).fold(0, |all, bit| all | bit));
    let span = match item.get("span") {
        Some(Value::Array(span)) => match span.as_slice() {
            [start, end] => start.as_u64().zip(end.as_u64()).map(|(start, end)| (start as usize, end as usize)),
            _ => None,
        },
        _ => None,
    };
    let metadata = item
        .get("metadata")
        .and_then(Value::as_object)
        .map(|metadata| {
            metadata
                .iter()
                .filter(|(key, _)| !RESERVED_METADATA.contains(&key.as_str()))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        })
        .unwrap_or_default();
    Some(ExternalResult {
        classification: Classification::new(sensitivity, visibility, categories),
        section_of_text: item.get("section_of_text").and_then(Value::as_str).unwrap_or_default().to_string(),
        reasoning: item.get("reasoning").and_then(Value::as_str).unwrap_or_default().to_string(),
        span,
        confidence: item.get("confidence").and_then(Value::as_f64),
        metadata,
    })
}

/// `json.loads`: standard JSON, plus the non-finite constants Python accepts (`NaN`, `Infinity`, `-Infinity`).
///
/// A non-finite constant can only matter as a value that fails validation (a confidence, a span bound) or as an
/// ignored extra, so each is read as the string with the same name; the result is the same either way.
fn python_json(content: &str) -> Option<Value> {
    if let Ok(value) = serde_json::from_str::<Value>(content) {
        return Some(value);
    }
    if !content.contains("NaN") && !content.contains("Infinity") {
        return None;
    }
    serde_json::from_str::<Value>(&quote_non_finite(content)).ok()
}

fn quote_non_finite(content: &str) -> String {
    let mut output = String::with_capacity(content.len() + 16);
    let mut rest = content;
    let mut in_string = false;
    let mut escaped = false;
    while let Some(next) = rest.chars().next() {
        if in_string {
            output.push(next);
            if escaped {
                escaped = false;
            } else if next == '\\' {
                escaped = true;
            } else if next == '"' {
                in_string = false;
            }
            rest = &rest[next.len_utf8()..];
            continue;
        }
        if next == '"' {
            in_string = true;
            output.push(next);
            rest = &rest[1..];
            continue;
        }
        if let Some(constant) = ["-Infinity", "Infinity", "NaN"].iter().find(|constant| rest.starts_with(**constant)) {
            output.push('"');
            output.push_str(constant);
            output.push('"');
            rest = &rest[constant.len()..];
            continue;
        }
        output.push(next);
        rest = &rest[next.len_utf8()..];
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(result: Result<Vec<ExternalResult>, SemanticError>) -> String {
        result.err().map(|error| error.to_string()).unwrap_or_default()
    }

    #[test]
    fn empty_envelope_is_no_risk() {
        assert!(build_external_results(&serde_json::json!({"results": []}), "x").unwrap_or_default().is_empty());
    }

    #[test]
    fn bare_empty_array_is_an_error() {
        assert_eq!(message(build_external_results(&serde_json::json!([]), "x")), NO_RESULTS);
    }

    #[test]
    fn quote_non_finite_leaves_strings_alone() {
        assert_eq!(
            quote_non_finite(r#"{"a": "NaN \" Infinity", "b": NaN, "c": -Infinity}"#),
            r#"{"a": "NaN \" Infinity", "b": "NaN", "c": "-Infinity"}"#
        );
    }

    #[test]
    fn non_finite_confidence_is_malformed() {
        let content = r#"{"results": [{"sensitivity": "S2", "visibility": "PU", "categories": [], "section_of_text": "x", "reasoning": "r", "confidence": NaN}]}"#;
        assert_eq!(message(parse_completion_content(content, "x")), MALFORMED);
    }

    #[test]
    fn status_error_never_echoes_the_body() {
        let error = parse_http_response(401, b"{\"error\": \"secret detail\"}", "x").err().map(|error| error.to_string());
        assert_eq!(error.as_deref(), Some("Error code: 401"));
    }
}
