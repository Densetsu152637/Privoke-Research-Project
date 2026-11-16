//! Python-compatible text and number behaviour that the artifact, receipt and journal formats depend on.
//!
//! * [`dumps`]: the `json.dumps` layouts of the Python service (`sort_keys=True` throughout).
//! * [`repr_str`]: `repr(str)`, which appears in error messages the corpus records.
//! * [`py_int`]: `int(str)` for ASCII digits.
//! * [`float32`] and [`round8`]: the numeric steps of `apply_parameter_update`.

use privoke_contracts::canonical::{self, CanonicalError, Variant};
use privoke_contracts::json::Value;
use privoke_contracts::pyfloat;

/// A `json.dumps` layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// `separators=(",", ":")`: receipts and drift records.
    Compact,
    /// The default separators `(", ", ": ")`: the training-cycle journal.
    Spaced,
    /// `indent=2`: the model artifact file.
    Indented,
}

/// A quoted JSON string literal with Python's `ensure_ascii=True` escaping.
pub fn json_string(text: &str) -> String {
    canonical::to_string(&Value::String(text.to_string()), Variant::Ascii).unwrap_or_default()
}

/// Render `value` with sorted keys in `layout`. Floats are Python `repr`, strings are ASCII-escaped.
pub fn dumps(value: &Value, layout: Layout) -> Result<String, CanonicalError> {
    let mut out = String::new();
    write_value(&mut out, value, layout, 0)?;
    Ok(out)
}

fn newline(out: &mut String, depth: usize) {
    out.push('\n');
    for _ in 0..depth {
        out.push_str("  ");
    }
}

fn element_break(out: &mut String, layout: Layout, depth: usize, first: bool) {
    match layout {
        Layout::Compact => {
            if !first {
                out.push(',');
            }
        }
        Layout::Spaced => {
            if !first {
                out.push_str(", ");
            }
        }
        Layout::Indented => {
            if !first {
                out.push(',');
            }
            newline(out, depth);
        }
    }
}

fn write_value(out: &mut String, value: &Value, layout: Layout, depth: usize) -> Result<(), CanonicalError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Int(digits) => out.push_str(digits),
        Value::Float(number) => out.push_str(&pyfloat::repr(*number).map_err(|_| CanonicalError::NonFinite)?),
        Value::String(text) => out.push_str(&json_string(text)),
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return Ok(());
            }
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                element_break(out, layout, depth + 1, index == 0);
                write_value(out, item, layout, depth + 1)?;
            }
            if layout == Layout::Indented {
                newline(out, depth);
            }
            out.push(']');
        }
        Value::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return Ok(());
            }
            out.push('{');
            for (index, (key, item)) in map.iter().enumerate() {
                element_break(out, layout, depth + 1, index == 0);
                out.push_str(&json_string(key));
                out.push_str(if layout == Layout::Compact { ":" } else { ": " });
                write_value(out, item, layout, depth + 1)?;
            }
            if layout == Layout::Indented {
                newline(out, depth);
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Whether Python's `str.isprintable` would call `character` printable. This is an approximation for non-ASCII
/// characters (no Unicode category tables): C0 and C1 controls, no-break and zero-width spacing, bidirectional and
/// line separators, the byte order mark, interlinear annotation and the private-use area are escaped.
fn printable(character: char) -> bool {
    let code = u32::from(character);
    if code < 0x20 || code == 0x7f {
        return false;
    }
    if code < 0x7f {
        return true;
    }
    !(matches!(code, 0x80..=0xa0 | 0xad | 0x61c | 0x180e | 0x200b..=0x200f | 0x2028..=0x202e | 0x2060..=0x206f | 0xfeff | 0xfff9..=0xfffb)
        || (0xe000..=0xf8ff).contains(&code)
        || (0xf0000..=0x10ffff).contains(&code))
}

/// Python's `repr(text)`: single quotes unless the text holds a single quote and no double quote.
pub fn repr_str(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for character in text.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if other == quote => {
                out.push('\\');
                out.push(other);
            }
            other if printable(other) => out.push(other),
            other => {
                let code = u32::from(other);
                if code < 0x100 {
                    out.push_str(&format!("\\x{code:02x}"));
                } else if code < 0x10000 {
                    out.push_str(&format!("\\u{code:04x}"));
                } else {
                    out.push_str(&format!("\\U{code:08x}"));
                }
            }
        }
    }
    out.push(quote);
    out
}

/// Python's `int(text)` for decimal ASCII digits: surrounding whitespace, one optional sign, single underscores
/// between digits. `None` for anything else, and for a value beyond `i128`. Non-ASCII digits are refused, which is
/// stricter than Python.
pub fn py_int(text: &str) -> Option<i128> {
    let trimmed = text.trim();
    let (negative, digits) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    if digits.is_empty() || digits.starts_with('_') || digits.ends_with('_') || digits.contains("__") {
        return None;
    }
    let mut value: i128 = 0;
    for character in digits.chars() {
        if character == '_' {
            continue;
        }
        let digit = character.to_digit(10)?;
        value = value.checked_mul(10)?.checked_add(i128::from(digit))?;
    }
    Some(if negative { -value } else { value })
}

/// The service's `float32`: round to the nearest float32 and widen, or refuse a value float32 cannot hold.
pub fn float32(value: f64) -> Result<f64, String> {
    let narrowed = value as f32;
    if narrowed.is_infinite() && value.is_finite() {
        return Err("Parameter is outside finite float32 range.".to_string());
    }
    if !narrowed.is_finite() {
        return Err("Parameter must be finite.".to_string());
    }
    Ok(f64::from(narrowed))
}

/// Python's `round(value, 8)`: the correctly rounded decimal with eight places, converted back.
pub fn round8(value: f64) -> f64 {
    format!("{value:.8}").parse::<f64>().unwrap_or(value)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::collections::BTreeMap;

    use super::*;

    fn object(entries: Vec<(&str, Value)>) -> Value {
        Value::Object(entries.into_iter().map(|(key, value)| (key.to_string(), value)).collect::<BTreeMap<_, _>>())
    }

    #[test]
    fn layouts_match_python() {
        let value = object(vec![
            ("b", Value::Array(vec![Value::Int("1".into()), Value::Float(0.5), Value::Array(vec![])])),
            ("a", object(vec![])),
            ("c", Value::String("\u{e9}\n".into())),
        ]);
        assert_eq!(dumps(&value, Layout::Compact).unwrap(), r#"{"a":{},"b":[1,0.5,[]],"c":"\u00e9\n"}"#);
        assert_eq!(dumps(&value, Layout::Spaced).unwrap(), r#"{"a": {}, "b": [1, 0.5, []], "c": "\u00e9\n"}"#);
        assert_eq!(
            dumps(&value, Layout::Indented).unwrap(),
            "{\n  \"a\": {},\n  \"b\": [\n    1,\n    0.5,\n    []\n  ],\n  \"c\": \"\\u00e9\\n\"\n}"
        );
    }

    #[test]
    fn repr_follows_python_quoting() {
        assert_eq!(repr_str("head.bias"), "'head.bias'");
        assert_eq!(repr_str("it's"), "\"it's\"");
        assert_eq!(repr_str("a'b\"c"), "'a\\'b\"c'");
        assert_eq!(repr_str("tab\there"), "'tab\\there'");
        assert_eq!(repr_str("nul\u{0}"), "'nul\\x00'");
        assert_eq!(repr_str("c1\u{85}"), "'c1\\x85'");
        assert_eq!(repr_str("caf\u{e9}"), "'caf\u{e9}'");
    }

    #[test]
    fn int_parsing_matches_python() {
        assert_eq!(py_int("32"), Some(32));
        assert_eq!(py_int(" +7 "), Some(7));
        assert_eq!(py_int("-0"), Some(0));
        assert_eq!(py_int("1_000"), Some(1000));
        assert_eq!(py_int("007"), Some(7));
        for bad in ["", "-", "1__0", "_1", "1_", "1.0", "many", "0x10", "1e3"] {
            assert_eq!(py_int(bad), None, "{bad}");
        }
    }

    #[test]
    fn float32_and_round8() {
        assert_eq!(float32(0.5).unwrap(), 0.5);
        assert_eq!(float32(0.1).unwrap(), f64::from(0.1_f32));
        assert!(float32(1e39).is_err());
        assert!(float32(f64::NAN).is_err());
        assert_eq!(round8(0.123456789_f64), 0.12345679);
        assert_eq!(round8(1.0), 1.0);
        assert!(round8(-1e-9).is_sign_negative());
    }
}
