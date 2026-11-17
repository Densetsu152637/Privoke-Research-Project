//! Python's text behaviour the samplers depend on: `training_text_key`, `str.format` over named fields and the
//! invariance transforms of `training.transforms`.
//!
//! Character classes (`\w`, `\d`, `str.isspace`), `str.lower()` and NFKC come from `privoke_rules::pyunicode`, which
//! follows the reference interpreter's Unicode tables rather than any Rust crate's.

use std::collections::BTreeMap;

use privoke_rules::pyunicode;

use crate::error::{Result, invalid};
use crate::pyrandom::Random;

/// `privoke_model.training_data.training_text_key`.
pub fn training_text_key(text: &str) -> String {
    let lowered = pyunicode::lower(&pyunicode::nfkc(text));
    let replaced = lowered.replace("[at]", "@").replace("(at)", "@");
    let joined = drop_digit_gaps(&replaced);
    let chars: Vec<char> = joined.chars().collect();
    let mut tokens: Vec<String> = Vec::new();
    let mut current = String::new();
    for character in chars {
        if pyunicode::is_space(character) {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            current.push(character);
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens.join(" ")
}

/// `re.sub(r"(?<=\d)[ \t]+(?=\d)", "", text)` with Python's Unicode `\d`.
fn drop_digit_gaps(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == ' ' || chars[index] == '\t' {
            let start = index;
            while index < chars.len() && (chars[index] == ' ' || chars[index] == '\t') {
                index += 1;
            }
            let before = start > 0 && pyunicode::is_decimal(chars[start - 1]);
            let after = index < chars.len() && pyunicode::is_decimal(chars[index]);
            if !(before && after) {
                out.extend(&chars[start..index]);
            }
        } else {
            out.push(chars[index]);
            index += 1;
        }
    }
    out
}

/// `template.format(**values)` for the plain `{name}` fields and `{{` `}}` escapes the curricula use.
///
/// Format specs, conversions, attribute and index access and positional fields raise in Python only when the
/// field is missing; here they are refused outright, because no shipped template uses them.
pub fn format_named(template: &str, values: &BTreeMap<&str, &str>) -> Result<String> {
    let chars: Vec<char> = template.chars().collect();
    let mut out = String::with_capacity(template.len());
    let mut index = 0;
    while index < chars.len() {
        let character = chars[index];
        if character == '{' {
            if chars.get(index + 1) == Some(&'{') {
                out.push('{');
                index += 2;
                continue;
            }
            let Some(length) = chars[index + 1..].iter().position(|&c| c == '}') else {
                return invalid("Single '{' encountered in format string");
            };
            let name: String = chars[index + 1..index + 1 + length].iter().collect();
            if name.is_empty() || name.contains(['{', '!', ':', '.', '[']) {
                return invalid("Unsupported format field");
            }
            match values.get(name.as_str()) {
                Some(value) => out.push_str(value),
                None => return invalid(format!("Unknown format field {name}")),
            }
            index += length + 2;
        } else if character == '}' {
            if chars.get(index + 1) == Some(&'}') {
                out.push('}');
                index += 2;
            } else {
                return invalid("Single '}' encountered in format string");
            }
        } else {
            out.push(character);
            index += 1;
        }
    }
    Ok(out)
}

fn matches_ignorecase(character: char, wanted: char) -> bool {
    if character.is_ascii() {
        return character.to_ascii_lowercase() == wanted;
    }
    pyunicode::ignorecase_ascii(character).is_some_and(|folded| folded.to_ascii_lowercase() == wanted)
}

/// `re.sub(r"\bJohn Doe\b", replacement, text, flags=re.IGNORECASE)`.
fn replace_john_doe(text: &str, replacement: &str) -> String {
    const WORD: [char; 8] = ['j', 'o', 'h', 'n', ' ', 'd', 'o', 'e'];
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < chars.len() {
        let fits = index + WORD.len() <= chars.len()
            && WORD
                .iter()
                .zip(&chars[index..])
                .all(|(&wanted, &character)| if wanted == ' ' { character == ' ' } else { matches_ignorecase(character, wanted) });
        let start_ok = index == 0 || !pyunicode::is_word(chars[index - 1]);
        let end = index + WORD.len();
        let end_ok = end >= chars.len() || !pyunicode::is_word(chars[end]);
        if fits && start_ok && end_ok {
            out.push_str(replacement);
            index = end;
        } else {
            out.push(chars[index]);
            index += 1;
        }
    }
    out
}

/// `synthetic_common_name`.
pub fn synthetic_common_name(text: &str) -> String {
    replace_john_doe(text, "Alex Smith")
}

/// `redact_common_name`.
pub fn redact_common_name(text: &str) -> String {
    replace_john_doe(text, "[REDACTED_NAME]")
}

/// The three invariance variants of a text, in `transform_variants` order.
pub fn transform_variants(text: &str) -> [String; 3] {
    [text.to_string(), format!("Please review this prompt: {text}"), synthetic_common_name(text)]
}

/// `random_pii_transform(text, rng)`: one of identity, the review prefix or the synthetic name.
pub fn random_pii_transform(text: &str, rng: &mut Random) -> Result<String> {
    let choice = rng.choice_index(3)?;
    Ok(match choice {
        0 => text.to_string(),
        1 => format!("Please review this prompt: {text}"),
        _ => synthetic_common_name(text),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_matches_python_rules() {
        assert_eq!(training_text_key("  My SSN is 123 456 789 (at) X [at] Y\t "), "my ssn is 123456789 @ x @ y");
        assert_eq!(training_text_key("a  1 b"), "a 1 b");
    }

    #[test]
    fn format_handles_escapes_and_fields() {
        let mut values = BTreeMap::new();
        values.insert("name", "Ann");
        assert_eq!(format_named("{{x}} {name}!", &values).unwrap_or_default(), "{x} Ann!");
        assert!(format_named("{missing}", &values).is_err());
        assert!(format_named("}", &values).is_err());
    }

    #[test]
    fn john_doe_needs_word_boundaries() {
        assert_eq!(synthetic_common_name("john DOE and xjohn doe, John Doe."), "Alex Smith and xjohn doe, Alex Smith.");
    }
}
