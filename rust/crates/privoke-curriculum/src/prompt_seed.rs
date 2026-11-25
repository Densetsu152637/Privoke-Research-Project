//! `prompt_generation.types` and `prompt_generation.loader` with `json_records`: prompt seeds and dataset loading.

use std::collections::BTreeMap;
use std::path::Path;

use crate::classification::{self, Classification, py_str};
use crate::defaults::default_prompt_dataset;
use crate::error::{Error, Result, invalid, read_file};
use crate::value::{self, Value};

/// `PromptSeed`.
#[derive(Debug, Clone, PartialEq)]
pub struct PromptSeed {
    /// `template`.
    pub template: String,
    /// `classification`.
    pub classification: Classification,
    /// `metadata`.
    pub metadata: BTreeMap<String, String>,
}

impl PromptSeed {
    /// `packed_classification`.
    pub fn packed(&self) -> u16 {
        self.classification.pack()
    }
}

/// `first_value(item, *keys)`: the first truthy value.
pub fn first_value<'a>(item: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|key| value::get(item, key).filter(|found| classification::is_truthy(found)))
}

/// `string_metadata(raw)`: `{str(k): str(v)}`, or empty for a non-mapping.
pub fn string_metadata(raw: Option<&Value>) -> BTreeMap<String, String> {
    match raw.and_then(value::as_object) {
        Some(map) => map.iter().map(|(key, item)| (key.clone(), py_str(item))).collect(),
        None => BTreeMap::new(),
    }
}

/// `load_json_records(path, collection_keys=..., ...)`.
pub fn load_json_records(path: &Path, collection_keys: &[&str], missing_message: &str, shape_message: &str) -> Result<Vec<Value>> {
    if !path.exists() {
        return invalid(format!("{missing_message}: {}", path.display()));
    }
    let bytes = read_file(path)?;
    let text = String::from_utf8(bytes).map_err(|_| Error::Invalid("records are not valid UTF-8".to_string()))?;
    let is_jsonl = path.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("jsonl"));
    let records = if is_jsonl {
        let mut lines = Vec::new();
        for line in text.lines() {
            if !line.trim().is_empty() {
                lines.push(privoke_contracts::json::parse(line)?);
            }
        }
        Value::Array(lines)
    } else {
        let payload = privoke_contracts::json::parse(&text)?;
        match &payload {
            Value::Object(_) => collection_keys
                .iter()
                .find_map(|key| value::get(&payload, key).filter(|found| classification::is_truthy(found)).cloned())
                .unwrap_or(Value::Array(Vec::new())),
            _ => payload,
        }
    };
    match records {
        Value::Array(items) => Ok(items),
        _ => invalid(shape_message),
    }
}

/// `prompt_seed_from_mapping(item)`.
pub fn prompt_seed_from_mapping(item: &Value) -> Result<PromptSeed> {
    if !value::is_object(item) {
        return invalid("Prompt dataset entries must be objects.");
    }
    let template = match first_value(item, &["template", "text", "prompt"]).and_then(value::as_str) {
        Some(text) if !text.trim().is_empty() => text.to_string(),
        _ => return invalid("Prompt dataset entries need template/text/prompt."),
    };
    let Some(classification) = classification::from_mapping(item)? else {
        return invalid("Prompt dataset entries need packed_classification or classification.");
    };
    Ok(PromptSeed { template, classification, metadata: string_metadata(value::get(item, "metadata")) })
}

/// `load_prompt_dataset(dataset_path)`.
pub fn load_prompt_dataset(dataset_path: Option<&Path>) -> Result<Vec<PromptSeed>> {
    let Some(path) = dataset_path else {
        return default_prompt_dataset();
    };
    let items = load_json_records(
        path,
        &["prompts", "examples", "data"],
        "Prompt dataset does not exist",
        "Prompt dataset must be a JSON array or JSONL file.",
    )?;
    items.iter().map(prompt_seed_from_mapping).collect()
}
