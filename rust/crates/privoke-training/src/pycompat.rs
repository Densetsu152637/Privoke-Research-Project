//! Python's `math.fsum` and `training_text_key`, shared by the V1 presence inference and the V3 fit.
//!
//! These lived in [`crate::objective`] and [`crate::rpc`] (V1 gradient modules, retired by stage V3-R8). They moved here,
//! unchanged in behaviour, so that deleting those modules leaves the presence gate's inference intact; both modules re-export
//! them for the code that still imports them there.

use privoke_rules::pyunicode;

/// `math.fsum`: the exactly rounded sum (Shewchuk's partials).
pub fn fsum(values: impl IntoIterator<Item = f64>) -> f64 {
    let mut partials: Vec<f64> = Vec::new();
    for mut x in values {
        let mut kept = 0;
        for index in 0..partials.len() {
            let mut y = partials[index];
            if x.abs() < y.abs() {
                std::mem::swap(&mut x, &mut y);
            }
            let hi = x + y;
            let lo = y - (hi - x);
            if lo != 0.0 {
                partials[kept] = lo;
                kept += 1;
            }
            x = hi;
        }
        partials.truncate(kept);
        partials.push(x);
    }
    partials.iter().rev().fold(0.0, |acc, p| acc + p)
}

/// `training_text_key` (`\d` is Unicode `Nd`, whitespace is Python's `str.isspace`): NFKC, lower case, `[at]` and `(at)` as `@`, digit-adjacent blanks removed, whitespace collapsed.
pub fn training_text_key(text: &str) -> String {
    let lowered = pyunicode::lower(&pyunicode::nfkc(text)).replace("[at]", "@").replace("(at)", "@");
    let chars: Vec<char> = lowered.chars().collect();
    let mut joined = String::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == ' ' || chars[index] == '\t' {
            let start = index;
            while index < chars.len() && (chars[index] == ' ' || chars[index] == '\t') {
                index += 1;
            }
            let digit_before = start > 0 && pyunicode::is_decimal(chars[start - 1]);
            let digit_after = index < chars.len() && pyunicode::is_decimal(chars[index]);
            if !(digit_before && digit_after) {
                joined.extend(&chars[start..index]);
            }
        } else {
            joined.push(chars[index]);
            index += 1;
        }
    }
    // `str.split()`: runs of Python whitespace (`str.isspace`) separate the words.
    joined.split(pyunicode::is_space).filter(|word| !word.is_empty()).collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fsum_is_exactly_rounded() {
        assert_eq!(fsum([1e16, 1.0, -1e16]), 1.0);
        assert_eq!(fsum([0.1; 10]), 1.0);
        assert_eq!(fsum([]), 0.0);
    }

    #[test]
    fn the_text_key_normalises_like_python() {
        assert_eq!(training_text_key("  Mail ME [at] Example  "), "mail me @ example");
        assert_eq!(training_text_key("1 2\t3 ab"), "123 ab");
    }
}
