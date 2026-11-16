//! The four `json.dumps` layouts the Python contracts use, all with `sort_keys=True` and `separators=(",", ":")`.

use crate::json::Value;
use crate::pyfloat;

/// Which Python expression to reproduce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// `ensure_ascii=True`: `full_adam.canonical`, receipts, admission headers. Non-ASCII and DEL become `\uXXXX`.
    Ascii,
    /// `ensure_ascii=False`, strict UTF-8: the tensor fingerprint layout.
    Utf8,
    /// `Utf8` with U+2028 and U+2029 escaped, as Go's encoder does: `artifact_checksum`.
    Utf8Go,
    /// `Utf8` followed by one LF: `v3_contract.canonical`, `sensitive_retention.canonical_bytes`.
    Utf8Lf,
}

impl Variant {
    /// The name used by the conformance corpus.
    pub fn from_corpus_name(name: &str) -> Option<Self> {
        match name {
            "ascii" => Some(Self::Ascii),
            "utf8" => Some(Self::Utf8),
            "utf8_go" => Some(Self::Utf8Go),
            "utf8_lf" => Some(Self::Utf8Lf),
            _ => None,
        }
    }
}

/// Why a value cannot be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CanonicalError {
    /// A float is NaN or infinite.
    #[error("non-finite float cannot be canonicalised")]
    NonFinite,
}

impl From<pyfloat::NonFinite> for CanonicalError {
    fn from(_: pyfloat::NonFinite) -> Self {
        Self::NonFinite
    }
}

/// Render `value` as canonical text.
pub fn to_string(value: &Value, variant: Variant) -> Result<String, CanonicalError> {
    let mut out = String::new();
    write_value(&mut out, value, variant)?;
    if variant == Variant::Utf8Lf {
        out.push('\n');
    }
    Ok(out)
}

/// Render `value` as canonical UTF-8 bytes.
pub fn to_bytes(value: &Value, variant: Variant) -> Result<Vec<u8>, CanonicalError> {
    to_string(value, variant).map(String::into_bytes)
}

pub(crate) fn write_value(out: &mut String, value: &Value, variant: Variant) -> Result<(), CanonicalError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int(digits) => out.push_str(digits),
        Value::Float(number) => out.push_str(&pyfloat::repr(*number)?),
        Value::String(text) => write_string(out, text, variant),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(out, item, variant)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (index, (key, item)) in map.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(out, key, variant);
                out.push(':');
                write_value(out, item, variant)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Write a JSON string literal exactly as Python's encoder does.
pub(crate) fn write_string(out: &mut String, text: &str, variant: Variant) {
    let ascii = variant == Variant::Ascii;
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
            '\u{2028}' if variant == Variant::Utf8Go => out.push_str("\\u2028"),
            '\u{2029}' if variant == Variant::Utf8Go => out.push_str("\\u2029"),
            ' '..='~' => out.push(character),
            character if (character as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", character as u32)),
            character if !ascii => out.push(character),
            character => {
                let mut units = [0u16; 2];
                for unit in character.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
}
