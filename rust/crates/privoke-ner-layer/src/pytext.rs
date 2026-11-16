//! Python's `str` semantics over code points, as the NER code reads them.
//!
//! `isalpha`, `isupper`, `islower` and spaCy's `is_punct` come from tables generated from the reference interpreter
//! ([`crate::unicode_tables`]); whitespace, `isdigit`, `\w`, `\d` and `lower()` come from `privoke_rules::pyunicode`,
//! which is generated from the same interpreter. Rust's own `char` predicates are never used: they follow another
//! Unicode version and other definitions (`char::is_alphabetic` is the `Alphabetic` property, not `str.isalpha`).

use privoke_rules::pyunicode;

use crate::unicode_tables as t;

fn in_ranges(table: &[(u32, u32)], cp: u32) -> bool {
    table
        .binary_search_by(|&(lo, hi)| {
            if cp < lo {
                std::cmp::Ordering::Greater
            } else if cp > hi {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// `str.isalpha()` of one character.
pub fn is_alpha(c: char) -> bool {
    if c.is_ascii() { c.is_ascii_alphabetic() } else { in_ranges(t::ALPHA, c as u32) }
}

/// `str.isupper()` of one character.
pub fn is_upper(c: char) -> bool {
    if c.is_ascii() { c.is_ascii_uppercase() } else { in_ranges(t::UPPER, c as u32) }
}

/// `str.islower()` of one character.
pub fn is_lower(c: char) -> bool {
    if c.is_ascii() { c.is_ascii_lowercase() } else { in_ranges(t::LOWER, c as u32) }
}

/// spaCy's `is_punct` for one character: general category `P*`.
pub fn is_punct(c: char) -> bool {
    if c.is_ascii() {
        c.is_ascii_punctuation() && !matches!(c, '$' | '+' | '<' | '=' | '>' | '^' | '`' | '|' | '~')
    } else {
        in_ranges(t::PUNCT, c as u32)
    }
}

/// `str.isdigit()` of one character.
pub fn is_digit(c: char) -> bool {
    pyunicode::is_digit(c)
}

/// Python `\d` (`str.isdecimal()`).
pub fn is_decimal(c: char) -> bool {
    pyunicode::is_decimal(c)
}

/// Python `\w`.
pub fn is_word(c: char) -> bool {
    pyunicode::is_word(c)
}

/// `str.isspace()` of one character.
pub fn is_space(c: char) -> bool {
    pyunicode::is_space(c)
}

/// `str.isspace()` of a string: at least one character and all whitespace.
pub fn all_space(chars: &[char]) -> bool {
    !chars.is_empty() && chars.iter().all(|&c| is_space(c))
}

/// `str.lower()`, including the final-sigma rule.
pub fn lower(text: &str) -> String {
    pyunicode::lower(text)
}

/// `str.lower()` over characters.
pub fn lower_chars(chars: &[char]) -> Vec<char> {
    pyunicode::lower(&string(chars)).chars().collect()
}

/// `"".join(ch.lower() if len(ch.lower()) == 1 else ch for ch in text)`: lower-casing that keeps every offset.
pub fn fold_case(chars: &[char]) -> Vec<char> {
    let mut out = String::with_capacity(chars.len());
    for &c in chars {
        if pyunicode::lower_len(c) == 1 {
            pyunicode::push_lower(c, &mut out);
        } else {
            out.push(c);
        }
    }
    out.chars().collect()
}

/// `text[start:end]` with Python's clamping of out-of-range slice bounds.
pub fn slice(chars: &[char], start: usize, end: usize) -> &[char] {
    let end = end.min(chars.len());
    let start = start.min(end);
    &chars[start..end]
}

/// The characters as a `String`.
pub fn string(chars: &[char]) -> String {
    chars.iter().collect()
}

/// `str.strip()`.
pub fn strip(chars: &[char]) -> &[char] {
    let (a, b) = pyunicode::strip_range(chars);
    &chars[a..b]
}

/// `str.lstrip()`.
pub fn lstrip(chars: &[char]) -> &[char] {
    let start = chars.iter().position(|&c| !is_space(c)).unwrap_or(chars.len());
    &chars[start..]
}

/// `str.rstrip()`.
pub fn rstrip(chars: &[char]) -> &[char] {
    let end = chars.iter().rposition(|&c| !is_space(c)).map_or(0, |i| i + 1);
    &chars[..end]
}

/// `str.rstrip(chars)` for an explicit character set.
pub fn rstrip_set<'a>(chars: &'a [char], set: &[char]) -> &'a [char] {
    let end = chars.iter().rposition(|c| !set.contains(c)).map_or(0, |i| i + 1);
    &chars[..end]
}

/// `str.strip(chars)` for an explicit character set.
pub fn strip_set<'a>(chars: &'a [char], set: &[char]) -> &'a [char] {
    let start = chars.iter().position(|c| !set.contains(c)).unwrap_or(chars.len());
    let end = chars.iter().rposition(|c| !set.contains(c)).map_or(start, |i| i + 1);
    &chars[start..end.max(start)]
}

/// `str.split()`: runs of non-whitespace.
pub fn split(chars: &[char]) -> Vec<&[char]> {
    split_ranges(chars).into_iter().map(|(a, b)| &chars[a..b]).collect()
}

/// Ranges `(start, end)` of the runs of non-whitespace (`re.finditer(r"\S+", ...)`).
pub fn split_ranges(chars: &[char]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, &c) in chars.iter().enumerate() {
        if is_space(c) {
            if let Some(s) = start.take() {
                out.push((s, i));
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start {
        out.push((s, chars.len()));
    }
    out
}

/// `text.find(needle, start)` over characters (`None` for Python's `-1`).
pub fn find_char(chars: &[char], needle: char, start: usize) -> Option<usize> {
    if start > chars.len() {
        return None;
    }
    chars[start..].iter().position(|&c| c == needle).map(|i| i + start)
}

/// `text.rfind(needle, 0, end)`.
pub fn rfind_char(chars: &[char], needle: char, end: usize) -> Option<usize> {
    let end = end.min(chars.len());
    chars[..end].iter().rposition(|&c| c == needle)
}

/// `needle in haystack` for strings.
pub fn contains_str(chars: &[char], needle: &str) -> bool {
    let n: Vec<char> = needle.chars().collect();
    if n.is_empty() {
        return true;
    }
    chars.windows(n.len()).any(|w| w == n.as_slice())
}

/// `text.startswith(prefix)`.
pub fn starts_with(chars: &[char], prefix: &str) -> bool {
    let mut it = chars.iter();
    prefix.chars().all(|p| it.next() == Some(&p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_predicates_differ_from_rust() {
        // U+0345 COMBINING GREEK YPOGEGRAMMENI has the Alphabetic property but is a Mn mark.
        assert!(!is_alpha('\u{345}'));
        assert!(char::is_alphabetic('\u{345}'));
        assert!(is_alpha('\u{4e2d}'));
        assert!(is_upper('\u{c9}') && !is_upper('\u{e9}'));
        assert!(is_punct('!') && is_punct('\u{2014}') && !is_punct('$') && !is_punct('+'));
        assert!(!is_punct('a'));
    }

    #[test]
    fn fold_keeps_length() {
        let text: Vec<char> = "I\u{130}LE \u{3a3}".chars().collect();
        let folded = fold_case(&text);
        assert_eq!(folded.len(), text.len());
        assert_eq!(string(&folded), "i\u{130}le \u{3c3}");
    }

    #[test]
    fn strip_and_split_follow_python_whitespace() {
        let text: Vec<char> = "\u{3000}ab  c\n".chars().collect();
        assert_eq!(string(strip(&text)), "ab  c");
        assert_eq!(split(&text).iter().map(|s| string(s)).collect::<Vec<_>>(), vec!["ab", "c"]);
        assert_eq!(string(rstrip_set(&['a', '.', '.'], &['.'])), "a");
    }
}
