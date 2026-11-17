//! Structural validators and context checks applied to regex hits (`rule_validators.py`).

use crate::pyunicode::{self, decimal_value, is_decimal, is_digit, is_space, is_word};

/// Context words that keep a failed-checksum card number a card number.
pub const CARD_CONTEXT: &[&str] =
    &["card", "credit", "debit", "visa", "mastercard", "amex", "cvv", "cvc", "payment", "expiry", "expires", "expiration"];
/// Context words for IBANs.
pub const IBAN_CONTEXT: &[&str] = &["iban", "bank", "account", "transfer", "wire", "payment", "swift", "bic", "sort code"];
/// Context words for social security numbers.
pub const SSN_CONTEXT: &[&str] = &["ssn", "social security", "tax file", "national insurance"];
/// Licence-specific context words (`rules_presidio.py`).
pub const DRIVER_LICENSE_CONTEXT: &[&str] = &["license", "licence", "lic", "lic#", "dl", "dls", "cdl", "cdls"];
/// Context words for the short `mm/yy` date pattern.
pub const DATE_CONTEXT_WORDS: &[&str] = &[
    "date",
    "dated",
    "expiry",
    "expires",
    "expiration",
    "exp",
    "valid",
    "due",
    "born",
    "birth",
    "birthday",
    "dob",
    "issued",
    "since",
    "until",
    "deadline",
];

/// A regex match as the validators see it: the full text and the span.
#[derive(Clone, Copy, Debug)]
pub struct MatchView<'a> {
    /// The searched text (`match.string`).
    pub text: &'a [char],
    /// Match start.
    pub start: usize,
    /// Match end.
    pub end: usize,
    /// Span of the `value` group, when the rule has one.
    pub value: Option<(usize, usize)>,
}

impl MatchView<'_> {
    fn matched(&self) -> &[char] {
        &self.text[self.start..self.end]
    }
}

fn digits(value: &[char]) -> Vec<char> {
    value.iter().copied().filter(|&c| is_decimal(c)).collect()
}

fn decimal_values(value: &[char]) -> Vec<u32> {
    digits(value).into_iter().filter_map(decimal_value).collect()
}

/// Luhn check of a 12 to 19 digit number.
pub fn luhn_valid(value: &[char]) -> bool {
    let values = decimal_values(value);
    if !(12..=19).contains(&values.len()) {
        return false;
    }
    let mut total = 0;
    for (index, &digit) in values.iter().rev().enumerate() {
        let mut digit = digit;
        if index % 2 == 1 {
            digit *= 2;
            if digit > 9 {
                digit -= 9;
            }
        }
        total += digit;
    }
    total % 10 == 0
}

/// IBAN mod-97 check.
pub fn iban_valid(value: &[char]) -> bool {
    let compact: String = value.iter().copied().filter(|&c| !is_space(c) && c != '-').collect();
    let compact: Vec<char> = pyunicode::upper(&compact).chars().collect();
    if !(15..=34).contains(&compact.len()) {
        return false;
    }
    let mut remainder = 0u64;
    for &c in compact[4..].iter().chain(&compact[..4]) {
        let digit = if c.is_ascii_digit() || c.is_ascii_uppercase() {
            c.to_digit(36)
        } else if is_decimal(c) {
            decimal_value(c)
        } else {
            None
        };
        let Some(digit) = digit else { return false };
        let width = if digit >= 10 { 100 } else { 10 };
        remainder = (remainder * width + u64::from(digit)) % 97;
    }
    remainder == 1
}

/// NHS number mod-11 check.
pub fn nhs_number_valid(value: &[char]) -> bool {
    let digits = decimal_values(value);
    if digits.len() != 10 {
        return false;
    }
    let total: u32 = (0..9).map(|index| digits[index] * (10 - index as u32)).sum();
    let mut check = 11 - total % 11;
    if check == 11 {
        check = 0;
    }
    check != 10 && check == digits[9]
}

/// US SSN range check (no checksum exists).
pub fn us_ssn_valid(value: &[char]) -> bool {
    let digits = digits(value);
    if digits.len() != 9 {
        return false;
    }
    let area: String = digits[..3].iter().collect();
    let group: String = digits[3..5].iter().collect();
    let serial: String = digits[5..].iter().collect();
    if area == "000" || area == "666" || area.starts_with('9') {
        return false;
    }
    group != "00" && serial != "0000"
}

/// Number-like token: 8+ characters, 5+ digits and at least one letter.
pub fn alphanumeric_identifier_shape(value: &[char]) -> bool {
    let compact: Vec<char> = value.iter().copied().filter(|&c| !is_space(c) && c != '-').collect();
    let digit_count = digits(&compact).len();
    compact.len() >= 8 && digit_count >= 5 && digit_count < compact.len()
}

/// Whole-word context lookup around a match (never a substring test).
pub fn has_context_word(view: &MatchView<'_>, words: &[&str], before: usize, after: usize) -> bool {
    let from = view.start.saturating_sub(before);
    let to = (view.end + after).min(view.text.len());
    let window: Vec<char> = pyunicode::lower(&view.text[from..to].iter().collect::<String>()).chars().collect();
    words.iter().any(|word| {
        let needle: Vec<char> = pyunicode::lower(word).chars().collect();
        if needle.is_empty() || needle.len() > window.len() {
            return false;
        }
        (0..=window.len() - needle.len()).any(|at| {
            window[at..at + needle.len()] == needle[..]
                && (at == 0 || !is_word(window[at - 1]))
                && (at + needle.len() == window.len() || !is_word(window[at + needle.len()]))
        })
    })
}

/// `has_context_word` with the default window (80 before, 40 after).
pub fn has_context(view: &MatchView<'_>, words: &[&str]) -> bool {
    has_context_word(view, words, 80, 40)
}

/// Accept hits with enough digits, or weaker hits that have a context word.
pub fn digits_or_context(view: &MatchView<'_>, min_digits: usize, words: &[&str]) -> bool {
    digits(view.matched()).len() >= min_digits || has_context(view, words)
}

/// The value of a labelled-identifier hit: a digit present, 5-24 compact characters, not a date.
pub fn has_identifier_shape(view: &MatchView<'_>, date_value: &crate::pyre::PyRegex) -> bool {
    let Some((start, end)) = view.value else { return false };
    let value = &view.text[start..end];
    let compact: Vec<char> = value.iter().copied().filter(|&c| !is_space(c) && c != '-').collect();
    let (lo, hi) = pyunicode::strip_range(value);
    let stripped = crate::pyre::Haystack::from_chars(value[lo..hi].to_vec());
    // `date_value` is anchored at both ends, so a hit is `fullmatch`.
    if matches!(date_value.search(&stripped), Ok(Some(_))) {
        return false;
    }
    (5..=24).contains(&compact.len()) && compact.iter().any(|&c| is_digit(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chars(text: &str) -> Vec<char> {
        text.chars().collect()
    }

    #[test]
    fn checksums() {
        assert!(luhn_valid(&chars("4111 1111 1111 1111")));
        assert!(!luhn_valid(&chars("4111 1111 1111 1112")));
        assert!(luhn_valid(&chars("\u{664}111 1111 1111 1111")));
        assert!(iban_valid(&chars("GB82 WEST 1234 5698 7654 32")));
        assert!(!iban_valid(&chars("GB82 WEST 1234 5698 7654 33")));
        assert!(nhs_number_valid(&chars("943 476 5919")));
        assert!(us_ssn_valid(&chars("123-45-6789")));
        assert!(!us_ssn_valid(&chars("666-45-6789")));
    }

    #[test]
    fn context_words_are_whole_words() {
        let text = chars("my visas are here 4111");
        let view = MatchView { text: &text, start: 18, end: 22, value: None };
        assert!(!has_context(&view, &["visa"]));
        let text = chars("my visa is 4111");
        let view = MatchView { text: &text, start: 11, end: 15, value: None };
        assert!(has_context(&view, &["visa"]));
    }
}
