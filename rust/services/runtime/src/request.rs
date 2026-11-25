//! Request validation of `AnalyzePrompt`: `hosting/serialization.parse_prompt_request` and the layer, regex-order and
//! presence-gate checks of `hosting/grpc_server.py`, with Python's messages.

use privoke_contracts::proto::v1::AnalyzePromptRequest;
use privoke_rules::pyunicode;

use crate::model::{visibility_by_name, visibility_names};

/// The longest prompt the runtime accepts, in characters (`DEFAULT_MAX_TEXT_CHARS`).
pub const DEFAULT_MAX_TEXT_CHARS: usize = 20_000;
const MAX_CONTEXT_FIELD_CHARS: usize = 256;
const MAX_METADATA_ENTRIES: usize = 64;
const MAX_METADATA_KEY_CHARS: usize = 128;
const MAX_METADATA_VALUE_CHARS: usize = 2_048;
const MAX_METADATA_TOTAL_CHARS: usize = 16_384;

/// The detection layers, in the pipeline's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Layer {
    /// The regex layer.
    Regex,
    /// The NER layer.
    Ner,
    /// The semantic layer.
    Semantic,
}

impl Layer {
    /// `DETECTION_LAYERS` order.
    pub const ALL: [Layer; 3] = [Layer::Regex, Layer::Ner, Layer::Semantic];

    /// The layer's name in Python (`regex`, `ner`, `semantic`).
    pub fn name(self) -> &'static str {
        match self {
            Self::Regex => "regex",
            Self::Ner => "ner",
            Self::Semantic => "semantic",
        }
    }

    /// The `DetectionLayer` enum value.
    pub fn proto_value(self) -> i32 {
        match self {
            Self::Regex => 2,
            Self::Ner => 3,
            Self::Semantic => 4,
        }
    }
}

/// A validated prompt request (`PromptInspectionRequest`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptRequest {
    /// The prompt, exactly as sent.
    pub text: String,
    /// `source`, stripped, `None` when empty.
    pub source: Option<String>,
    /// `target_app`, stripped, `None` when empty.
    pub target_app: Option<String>,
    /// `request_id`, stripped, `None` when empty.
    pub request_id: Option<String>,
    /// The packed visibility the request names, if any.
    pub visibility_hint: Option<u16>,
    /// The hint's name (`P0` to `PU`).
    pub visibility_hint_name: Option<&'static str>,
}

/// `str.strip()`.
pub(crate) fn py_strip(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let (start, end) = pyunicode::strip_range(&chars);
    chars[start..end].iter().collect()
}

fn optional_string(raw: &str, name: &str) -> Result<Option<String>, String> {
    // The servicer passes `request.field or None`, so an empty field is `None` and is not validated.
    if raw.is_empty() {
        return Ok(None);
    }
    let value = py_strip(raw);
    if value.chars().count() > MAX_CONTEXT_FIELD_CHARS {
        return Err(format!("'{name}' exceeds {MAX_CONTEXT_FIELD_CHARS} characters."));
    }
    if value.chars().any(|c| (c as u32) < 32 || c as u32 == 127) {
        return Err(format!("'{name}' must not contain control characters."));
    }
    Ok(if value.is_empty() { None } else { Some(value) })
}

/// `len(json.dumps(value))` for a string with the default `ensure_ascii=True`.
fn json_dumps_len(value: &str) -> usize {
    let mut length = 2;
    for c in value.chars() {
        length += match c {
            '"' | '\\' | '\n' | '\r' | '\t' | '\u{8}' | '\u{c}' => 2,
            c if (c as u32) < 0x20 => 6,
            c if (c as u32) <= 0x7E => 1,
            c if (c as u32) == 0x7F => 6,
            c if (c as u32) <= 0xFFFF => 6,
            _ => 12,
        };
    }
    length
}

fn validate_metadata(metadata: &std::collections::BTreeMap<String, String>) -> Result<(), String> {
    if metadata.len() > MAX_METADATA_ENTRIES {
        return Err(format!("'metadata' exceeds {MAX_METADATA_ENTRIES} entries."));
    }
    let mut total = 0usize;
    for (key, value) in metadata {
        let key_chars = key.chars().count();
        if key.is_empty() || key_chars > MAX_METADATA_KEY_CHARS {
            return Err(format!("Metadata keys must be non-empty strings no longer than {MAX_METADATA_KEY_CHARS} characters."));
        }
        if key.chars().any(|c| (c as u32) < 32 || c as u32 == 127) {
            return Err("Metadata keys must not contain control characters.".to_string());
        }
        let encoded = json_dumps_len(value);
        if encoded > MAX_METADATA_VALUE_CHARS {
            return Err(format!("A metadata value exceeds {MAX_METADATA_VALUE_CHARS} serialized characters."));
        }
        total += key_chars + encoded;
    }
    if total > MAX_METADATA_TOTAL_CHARS {
        return Err(format!("'metadata' exceeds {MAX_METADATA_TOTAL_CHARS} serialized characters."));
    }
    Ok(())
}

/// `parse_prompt_request` for the fields of an `AnalyzePromptRequest`. The `Err` text is what Python reports in the
/// response's `error` field.
pub fn parse_prompt_request(request: &AnalyzePromptRequest, max_text_chars: usize) -> Result<PromptRequest, String> {
    let text = &request.text;
    if py_strip(text).is_empty() {
        return Err("Prompt text must not be empty.".to_string());
    }
    if text.chars().count() > max_text_chars {
        return Err(format!("Prompt text exceeds {max_text_chars} characters."));
    }
    validate_metadata(&request.metadata)?;
    let source = optional_string(&request.source, "source")?;
    let (visibility_hint, visibility_hint_name) = parse_visibility_hint(&request.visibility_hint)?;
    let target_app = optional_string(&request.target_app, "target_app")?;
    let request_id = optional_string(&request.request_id, "request_id")?;
    Ok(PromptRequest { text: text.clone(), source, target_app, request_id, visibility_hint, visibility_hint_name })
}

fn parse_visibility_hint(raw: &str) -> Result<(Option<u16>, Option<&'static str>), String> {
    if raw.is_empty() {
        return Ok((None, None));
    }
    let upper = pyunicode::upper(raw);
    match visibility_by_name(&upper) {
        Some(value) => {
            let name = visibility_names().into_iter().find(|name| *name == upper);
            Ok((Some(value), name))
        }
        None => Err(format!("'visibility_hint' must be one of: {}.", visibility_names().join(", "))),
    }
}

/// `_requested_layers` followed by the pipeline's `_normalise_layers`: the named layers in pipeline order. An empty list
/// or `DETECTION_LAYER_RUNTIME` selects all three, which the worker refuses before it gets here.
pub fn requested_layers(values: &[i32]) -> Result<Vec<Layer>, String> {
    if values.is_empty() || values.contains(&1) {
        return Ok(Layer::ALL.to_vec());
    }
    let mut named = Vec::new();
    for value in values {
        let layer = Layer::ALL.iter().copied().find(|layer| layer.proto_value() == *value);
        match layer {
            Some(layer) => {
                if !named.contains(&layer) {
                    named.push(layer);
                }
            }
            None => return Err(format!("Unsupported detection layer value: {value}")),
        }
    }
    named.sort();
    Ok(named)
}

/// `_regex_first`: `None` follows `PRIVOKE_WAIT_FOR_REGEX`.
pub fn regex_first(value: i32) -> Result<Option<bool>, String> {
    match value {
        0 => Ok(None),
        1 => Ok(Some(true)),
        2 => Ok(Some(false)),
        other => Err(format!("Unsupported regex execution order: {other}")),
    }
}

/// The presence models a semantic presence gate may name (`SEMANTIC_PRESENCE_MODEL_IDS`).
pub fn is_gate_model(model_id: &str) -> bool {
    if matches!(model_id, "privoke-presence-efficient" | "privoke-presence-balanced" | "privoke-presence-quality") {
        return true;
    }
    ["efficient", "balanced", "quality"]
        .iter()
        .any(|profile| ["head-only", "full-encoder"].iter().any(|mode| model_id == format!("privoke-scratch-presence-{profile}-{mode}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn request(text: &str) -> AnalyzePromptRequest {
        AnalyzePromptRequest { text: text.to_string(), ..AnalyzePromptRequest::default() }
    }

    #[test]
    fn text_rules_use_python_strip_and_code_points() {
        assert_eq!(parse_prompt_request(&request(" \u{a0}\n "), 10).unwrap_err(), "Prompt text must not be empty.");
        assert_eq!(parse_prompt_request(&request("abcdefghijk"), 10).unwrap_err(), "Prompt text exceeds 10 characters.");
        assert!(parse_prompt_request(&request("\u{1f600}\u{1f600}\u{1f600}\u{1f600}\u{1f600}"), 5).is_ok());
        let ok = parse_prompt_request(&request("hello"), 10).unwrap();
        assert_eq!((ok.source, ok.request_id, ok.visibility_hint), (None, None, None));
    }

    #[test]
    fn context_fields_are_stripped_and_checked() {
        let mut r = request("hello");
        r.source = "  app  ".into();
        r.request_id = "   ".into();
        r.target_app = "a\u{7}b".into();
        assert_eq!(parse_prompt_request(&r, 10).unwrap_err(), "'target_app' must not contain control characters.");
        r.target_app = String::new();
        let ok = parse_prompt_request(&r, 10).unwrap();
        assert_eq!(ok.source.as_deref(), Some("app"));
        assert_eq!(ok.request_id, None);
        r.source = "x".repeat(257);
        assert_eq!(parse_prompt_request(&r, 10).unwrap_err(), "'source' exceeds 256 characters.");
    }

    #[test]
    fn visibility_hint_is_case_insensitive_and_named() {
        let mut r = request("hello");
        r.visibility_hint = "p3".into();
        let ok = parse_prompt_request(&r, 10).unwrap();
        assert_eq!((ok.visibility_hint, ok.visibility_hint_name), (Some(0b10000), Some("P3")));
        r.visibility_hint = "secret".into();
        assert_eq!(parse_prompt_request(&r, 10).unwrap_err(), "'visibility_hint' must be one of: P0, P1, P2, P3, P4, PU.");
    }

    #[test]
    fn metadata_limits_count_json_dumps_characters() {
        assert_eq!(json_dumps_len("ab"), 4);
        assert_eq!(json_dumps_len("a\"b\u{e9}\u{1f600}"), 2 + 1 + 2 + 1 + 6 + 12);
        let mut r = request("hello");
        for index in 0..65 {
            r.metadata.insert(format!("k{index}"), "v".into());
        }
        assert_eq!(parse_prompt_request(&r, 10).unwrap_err(), "'metadata' exceeds 64 entries.");
        r.metadata.clear();
        r.metadata.insert("k".into(), "\u{e9}".repeat(342));
        assert_eq!(parse_prompt_request(&r, 10).unwrap_err(), "A metadata value exceeds 2048 serialized characters.");
        r.metadata.clear();
        r.metadata.insert(String::new(), "v".into());
        assert!(parse_prompt_request(&r, 10).unwrap_err().starts_with("Metadata keys must be non-empty"));
    }

    #[test]
    fn layers_come_back_in_pipeline_order_without_duplicates() {
        assert_eq!(requested_layers(&[3, 2, 3]).unwrap(), vec![Layer::Regex, Layer::Ner]);
        assert_eq!(requested_layers(&[0]).unwrap_err(), "Unsupported detection layer value: 0");
        assert_eq!(requested_layers(&[]).unwrap().len(), 3);
        assert_eq!(regex_first(2), Ok(Some(false)));
        assert_eq!(regex_first(7).unwrap_err(), "Unsupported regex execution order: 7");
    }

    #[test]
    fn gate_models_are_the_declared_presence_ids() {
        assert!(is_gate_model("privoke-presence-balanced"));
        assert!(is_gate_model("privoke-scratch-presence-quality-head-only"));
        assert!(!is_gate_model("privoke-balanced"));
    }
}
