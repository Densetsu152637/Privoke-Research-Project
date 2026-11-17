//! Python's text semantics over code points: the `\w`, `\d` and `\s` classes, `str.lower()`,
//! `str.upper()`, `str.isdigit()`, `str.split()` whitespace and `unicodedata.normalize("NFKC")`.
//!
//! Every predicate reads the tables in [`crate::unicode_tables`], which are generated from the
//! reference interpreter, so the answers follow Python's Unicode version
//! ([`crate::unicode_tables::UNICODE_VERSION`]) and not the version of any Rust crate.

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

/// Python `\w` for `str` patterns: `str.isalnum()` or `_`.
pub fn is_word(c: char) -> bool {
    if c.is_ascii() { c.is_ascii_alphanumeric() || c == '_' } else { in_ranges(t::WORD, c as u32) }
}

/// Python `\d` for `str` patterns: `str.isdecimal()`.
pub fn is_decimal(c: char) -> bool {
    if c.is_ascii() { c.is_ascii_digit() } else { in_ranges(t::DECIMAL, c as u32) }
}

/// `str.isdigit()` for one character.
pub fn is_digit(c: char) -> bool {
    if c.is_ascii() { c.is_ascii_digit() } else { in_ranges(t::ISDIGIT, c as u32) }
}

/// Python `\s` and `str.isspace()` for one character.
pub fn is_space(c: char) -> bool {
    if c.is_ascii() { matches!(c, '\t'..='\r' | '\x1c'..='\x1f' | ' ') } else { in_ranges(t::SPACE, c as u32) }
}

/// Unicode general category `Cf`.
pub fn is_format(c: char) -> bool {
    in_ranges(t::FORMAT, c as u32)
}

/// Decimal value of a `\d` character, as `int(char)` computes it.
pub fn decimal_value(c: char) -> Option<u32> {
    if c.is_ascii_digit() {
        return Some(c as u32 - '0' as u32);
    }
    let cp = c as u32;
    let index = t::DECIMAL_VALUES.partition_point(|&(_, hi, _)| hi < cp);
    let &(lo, hi, base) = t::DECIMAL_VALUES.get(index)?;
    (lo..=hi).contains(&cp).then(|| u32::from(base) + (cp - lo))
}

/// `unicodedata.combining(c)`.
pub fn combining_class(c: char) -> u8 {
    if c.is_ascii() {
        return 0;
    }
    let cp = c as u32;
    let index = t::COMBINING.partition_point(|&(_, hi, _)| hi < cp);
    match t::COMBINING.get(index) {
        Some(&(lo, hi, class)) if (lo..=hi).contains(&cp) => class,
        _ => 0,
    }
}

fn map_lookup(table: &'static [(u32, &'static str)], cp: u32) -> Option<&'static str> {
    table.binary_search_by_key(&cp, |&(key, _)| key).ok().map(|index| table[index].1)
}

/// `chr.lower()` for one character, appended to `out`. The context-dependent final sigma is
/// handled by [`lower`].
pub fn push_lower(c: char, out: &mut String) {
    if c.is_ascii() {
        out.push(c.to_ascii_lowercase());
    } else if let Some(mapped) = map_lookup(t::LOWER, c as u32) {
        out.push_str(mapped);
    } else {
        out.push(c);
    }
}

/// Number of characters in `chr.lower()` of one character.
pub fn lower_len(c: char) -> usize {
    if c.is_ascii() { 1 } else { map_lookup(t::LOWER, c as u32).map_or(1, |mapped| mapped.chars().count()) }
}

/// `str.lower()`, including the final-sigma rule.
pub fn lower(text: &str) -> String {
    if text.is_ascii() {
        return text.to_ascii_lowercase();
    }
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    for (index, &c) in chars.iter().enumerate() {
        if c == '\u{3a3}' {
            out.push(if sigma_is_final(&chars, index) { '\u{3c2}' } else { '\u{3c3}' });
        } else {
            push_lower(c, &mut out);
        }
    }
    out
}

fn sigma_is_final(chars: &[char], index: usize) -> bool {
    let mut before = index;
    while before > 0 && in_ranges(t::CASE_IGNORABLE, chars[before - 1] as u32) {
        before -= 1;
    }
    if before == 0 || !in_ranges(t::CASED, chars[before - 1] as u32) {
        return false;
    }
    let mut after = index + 1;
    while after < chars.len() && in_ranges(t::CASE_IGNORABLE, chars[after] as u32) {
        after += 1;
    }
    after == chars.len() || !in_ranges(t::CASED, chars[after] as u32)
}

/// `str.upper()`.
pub fn upper(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_ascii() {
            out.push(c.to_ascii_uppercase());
        } else if let Some(mapped) = map_lookup(t::UPPER, c as u32) {
            out.push_str(mapped);
        } else {
            out.push(c);
        }
    }
    out
}

/// The ASCII letter that `re.IGNORECASE` equates with a non-ASCII character, if any.
pub fn ignorecase_ascii(c: char) -> Option<char> {
    t::ICASE_ASCII.binary_search_by_key(&(c as u32), |&(cp, _)| cp).ok().map(|index| t::ICASE_ASCII[index].1)
}

/// `str.strip()` semantics on a character slice: whitespace is `str.isspace()`.
pub fn strip_range(chars: &[char]) -> (usize, usize) {
    let start = chars.iter().position(|&c| !is_space(c)).unwrap_or(chars.len());
    let end = chars.iter().rposition(|&c| !is_space(c)).map_or(start, |index| index + 1);
    (start, end)
}

/// `len(text.split())`.
pub fn split_count(chars: &[char]) -> usize {
    let mut count = 0;
    let mut inside = false;
    for &c in chars {
        if is_space(c) {
            inside = false;
        } else if !inside {
            inside = true;
            count += 1;
        }
    }
    count
}

// ---- NFKC -------------------------------------------------------------------------------------

const S_BASE: u32 = 0xAC00;
const L_BASE: u32 = 0x1100;
const V_BASE: u32 = 0x1161;
const T_BASE: u32 = 0x11A7;
const L_COUNT: u32 = 19;
const V_COUNT: u32 = 21;
const T_COUNT: u32 = 28;
const N_COUNT: u32 = V_COUNT * T_COUNT;
const S_COUNT: u32 = L_COUNT * N_COUNT;

fn decompose_into(c: char, out: &mut Vec<char>) {
    if c.is_ascii() {
        out.push(c);
        return;
    }
    let cp = c as u32;
    if (S_BASE..S_BASE + S_COUNT).contains(&cp) {
        let index = cp - S_BASE;
        let push = |value: u32, out: &mut Vec<char>| out.extend(char::from_u32(value));
        push(L_BASE + index / N_COUNT, out);
        push(V_BASE + (index % N_COUNT) / T_COUNT, out);
        if !index.is_multiple_of(T_COUNT) {
            push(T_BASE + index % T_COUNT, out);
        }
        return;
    }
    match t::NFKD.binary_search_by_key(&cp, |&(key, _)| key) {
        Ok(index) => out.extend(t::NFKD[index].1.iter().filter_map(|&value| char::from_u32(value))),
        Err(_) => out.push(c),
    }
}

fn compose_pair(first: char, second: char) -> Option<char> {
    let (a, b) = (first as u32, second as u32);
    if (L_BASE..L_BASE + L_COUNT).contains(&a) && (V_BASE..V_BASE + V_COUNT).contains(&b) {
        return char::from_u32(S_BASE + ((a - L_BASE) * V_COUNT + (b - V_BASE)) * T_COUNT);
    }
    if (S_BASE..S_BASE + S_COUNT).contains(&a) && (a - S_BASE).is_multiple_of(T_COUNT) && (T_BASE + 1..T_BASE + T_COUNT).contains(&b) {
        return char::from_u32(a + (b - T_BASE));
    }
    t::COMPOSE.binary_search_by_key(&(a, b), |&(x, y, _)| (x, y)).ok().and_then(|i| char::from_u32(t::COMPOSE[i].2))
}

/// `unicodedata.normalize("NFKC", text)`.
pub fn nfkc(text: &str) -> String {
    if text.is_ascii() {
        return text.to_owned();
    }
    let mut buffer: Vec<char> = Vec::with_capacity(text.len());
    for c in text.chars() {
        decompose_into(c, &mut buffer);
    }
    // Canonical ordering: stable sort of each run of non-starters by combining class.
    let mut start = 0;
    while start < buffer.len() {
        if combining_class(buffer[start]) == 0 {
            start += 1;
            continue;
        }
        let mut end = start;
        while end < buffer.len() && combining_class(buffer[end]) != 0 {
            end += 1;
        }
        buffer[start..end].sort_by_key(|&c| combining_class(c));
        start = end;
    }
    // Canonical composition.
    let mut out: Vec<char> = Vec::with_capacity(buffer.len());
    let mut starter: Option<usize> = None;
    let mut last_class = 0u8;
    for c in buffer {
        let class = combining_class(c);
        if let Some(position) = starter
            && (last_class < class || last_class == 0)
            && let Some(composed) = compose_pair(out[position], c)
        {
            out[position] = composed;
            continue;
        }
        if class == 0 {
            starter = Some(out.len());
        }
        last_class = class;
        out.push(c);
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_follow_python() {
        assert!(is_word('_') && is_word('\u{b2}') && !is_word('\u{301}') && !is_word('-'));
        assert!(is_decimal('\u{663}') && !is_decimal('\u{b2}') && is_digit('\u{b2}'));
        assert!(is_space('\u{1c}') && is_space('\u{85}') && !is_space('\u{200b}'));
        assert_eq!(decimal_value('\u{663}'), Some(3));
        assert_eq!(decimal_value('x'), None);
    }

    #[test]
    fn case_mapping_follows_python() {
        assert_eq!(lower("\u{130}"), "i\u{307}");
        assert_eq!(lower("\u{391}\u{3a3}"), "\u{3b1}\u{3c2}");
        assert_eq!(lower("\u{3a3}\u{391}"), "\u{3c3}\u{3b1}");
        assert_eq!(upper("stra\u{df}e"), "STRASSE");
        assert_eq!(ignorecase_ascii('\u{131}'), Some('i'));
        assert_eq!(ignorecase_ascii('\u{17f}'), Some('s'));
    }

    #[test]
    fn nfkc_composes_decomposes_and_reorders() {
        assert_eq!(nfkc("\u{fb01}"), "fi");
        assert_eq!(nfkc("e\u{301}"), "\u{e9}");
        assert_eq!(nfkc("\u{ff21}\u{2460}"), "A1");
        assert_eq!(nfkc("a\u{323}\u{307}"), "\u{1ea1}\u{307}");
        assert_eq!(nfkc("a\u{307}\u{323}"), "\u{1ea1}\u{307}");
        assert_eq!(nfkc("\u{1100}\u{1161}\u{11a8}"), "\u{ac01}");
        assert_eq!(nfkc("\u{ac01}"), "\u{ac01}");
    }
}
