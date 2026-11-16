//! Secret-detection rules imported from the Gitleaks default catalogue (`rules_gitleaks.py`).
//!
//! The catalogue is the tracked `extension/client-runtime/src/regex/external_rules/gitleaks.toml`,
//! embedded at build time. A source rule is imported unless it has an allowlist, no id or regex,
//! duplicates an earlier converted pattern, or Python's `re` rejects the converted pattern.

use std::collections::HashSet;

use crate::classification::{Classification, Sensitivity, category, visibility};
use crate::pyre::PyRegex;
use crate::rules::RuleDefinition;

const CATALOGUE: &str = include_str!("../../../../extension/client-runtime/src/regex/external_rules/gitleaks.toml");

const POSIX_CLASSES: [(&str, &str); 7] = [
    ("[:alnum:]", "A-Za-z0-9"),
    ("[:alpha:]", "A-Za-z"),
    ("[:digit:]", "0-9"),
    ("[:xdigit:]", "A-Fa-f0-9"),
    ("[:lower:]", "a-z"),
    ("[:upper:]", "A-Z"),
    ("[:space:]", r"\s"),
];

/// The conversion `_python_regex`: drop `(?i)` and replace POSIX classes.
pub fn python_regex(pattern: &str) -> String {
    let mut converted = pattern.replace("(?i)", "");
    for (posix, python) in POSIX_CLASSES {
        converted = converted.replace(posix, python);
    }
    converted
}

/// `_safe_name`: lowercase, runs of other characters become `_`, outer `_` stripped.
pub fn safe_name(rule_id: &str) -> String {
    let mut out = String::new();
    let mut in_run = false;
    for c in rule_id.to_lowercase().chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' {
            out.push(c);
            in_run = false;
        } else if !in_run {
            out.push('_');
            in_run = true;
        }
    }
    out.trim_matches('_').to_owned()
}

fn truthy(value: Option<&toml::Value>) -> bool {
    match value {
        None => false,
        Some(toml::Value::Table(table)) => !table.is_empty(),
        Some(toml::Value::Array(items)) => !items.is_empty(),
        Some(toml::Value::String(text)) => !text.is_empty(),
        Some(toml::Value::Boolean(flag)) => *flag,
        Some(_) => true,
    }
}

/// The imported rules with their compiled patterns, in catalogue order.
pub fn gitleaks_rules() -> Result<Vec<(RuleDefinition, PyRegex)>, toml::de::Error> {
    let config: toml::Table = toml::from_str(CATALOGUE)?;
    let mut rules = Vec::new();
    let mut seen = HashSet::new();
    let sources = config.get("rules").and_then(toml::Value::as_array).cloned().unwrap_or_default();
    for source in &sources {
        let id = source.get("id").and_then(toml::Value::as_str).unwrap_or("");
        let pattern = source.get("regex").and_then(toml::Value::as_str).unwrap_or("");
        if id.is_empty() || pattern.is_empty() || truthy(source.get("allowlist")) || truthy(source.get("allowlists")) {
            continue;
        }
        let pattern = python_regex(pattern);
        if seen.contains(&pattern) {
            continue;
        }
        let Ok(compiled) = PyRegex::new(&pattern, true) else { continue };
        seen.insert(pattern.clone());
        rules.push((
            RuleDefinition {
                name: format!("gitleaks_{}", safe_name(id)),
                pattern,
                classification: Classification::new(Sensitivity::S3, visibility::PU, category::IDENTITY),
                signal: "gitleaks_secret".to_owned(),
                validator: None,
                downgrades: Vec::new(),
            },
            compiled,
        ));
    }
    Ok(rules)
}
