//! Canonical detector text with provenance into the original prompt (`detection/preprocessing.py`).
//!
//! Offsets are code point indexes, as in Python.

use std::collections::HashSet;
use std::sync::LazyLock;

use crate::pyre::{Haystack, PatternError, PyMatch, PyRegex};
use crate::pyunicode;

/// Failure while normalising.
#[derive(Debug, thiserror::Error)]
pub enum NormalizeError {
    /// A pattern failed to compile or run.
    #[error(transparent)]
    Pattern(#[from] PatternError),
    /// Python raises `KeyError` for a spelled digit that is not in its table (for example a
    /// dotless `i`); the message is `str(KeyError(word))`.
    #[error("'{0}'")]
    UnknownDigitWord(String),
}

/// Canonical text with the original interval that produced each character.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedText {
    text: String,
    chars: Vec<char>,
    original: Vec<char>,
    origins: Vec<(usize, usize)>,
}

impl NormalizedText {
    /// The canonical text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The canonical text as characters.
    pub fn chars(&self) -> &[char] {
        &self.chars
    }

    /// The original prompt as characters.
    pub fn original(&self) -> &[char] {
        &self.original
    }

    /// Original interval of each canonical character.
    pub fn origins(&self) -> &[(usize, usize)] {
        &self.origins
    }

    /// `NormalizedText.original_span`: the original interval covering a canonical span, or
    /// `None` for an empty or out-of-range span.
    pub fn original_span(&self, span: (usize, usize)) -> Option<(usize, usize)> {
        let (start, end) = span;
        if !(start < end && end <= self.chars.len()) {
            return None;
        }
        let selected = &self.origins[start..end];
        Some((selected.iter().map(|o| o.0).min()?, selected.iter().map(|o| o.1).max()?))
    }
}

/// Optional canonicalisations that undo common input obfuscation; all default off.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RobustnessOptions {
    /// Drop Unicode format characters (category `Cf`).
    pub strip_format_chars: bool,
    /// Join obfuscated digit identifiers (spelled digits, single-digit chains).
    pub canonicalise_digits: bool,
    /// Rewrite e-mail addresses spelled with words or brackets.
    pub canonicalise_email_words: bool,
}

/// `env_bool(name, default)` of the Python runtime, over any variable lookup: true for `1`,
/// `true`, `yes` and `on` in any case, false for any other value, `default` when unset.
pub fn env_bool_with(lookup: &impl Fn(&str) -> Option<String>, name: &str, default: bool) -> bool {
    match lookup(name) {
        Some(value) => matches!(pyunicode::lower(&value).as_str(), "1" | "true" | "yes" | "on"),
        None => default,
    }
}

/// `env_bool` over the process environment.
pub fn env_bool(name: &str, default: bool) -> bool {
    env_bool_with(&|key| std::env::var(key).ok(), name, default)
}

impl RobustnessOptions {
    /// The `PRIVOKE_*` flags (`RobustnessOptions.from_config`).
    pub fn from_env() -> Self {
        Self::from_lookup(&|key| std::env::var(key).ok())
    }

    /// The `PRIVOKE_*` flags read through `lookup`.
    pub fn from_lookup(lookup: &impl Fn(&str) -> Option<String>) -> Self {
        Self {
            strip_format_chars: env_bool_with(lookup, "PRIVOKE_STRIP_FORMAT_CHARS", false),
            canonicalise_digits: env_bool_with(lookup, "PRIVOKE_CANONICALISE_DIGITS", false),
            canonicalise_email_words: env_bool_with(lookup, "PRIVOKE_CANONICALISE_EMAIL_WORDS", false),
        }
    }
}

const LABEL: &str = r"[\w%+\-]+";
const DOT_MARK: &str = r"(?:[ \t]?[\[(]dot[\])][ \t]?|[ \t]+dot[ \t]+)";
const DIGIT_WORD_TABLE: [(&str, u8); 11] = [
    ("zero", 0),
    ("oh", 0),
    ("one", 1),
    ("two", 2),
    ("three", 3),
    ("four", 4),
    ("five", 5),
    ("six", 6),
    ("seven", 7),
    ("eight", 8),
    ("nine", 9),
];
const MIN_SPELLED_DIGITS: usize = 7;
const MIN_UNAMBIGUOUS_SPELLED_DIGITS: usize = 4;
const COMMON_TLDS: &[&str] = &[
    "com", "org", "net", "edu", "gov", "mil", "int", "info", "biz", "app", "dev", "xyz", "online", "site", "tech", "blog", "shop", "cloud",
    "mobi", "name", "pro",
];
const NOT_A_LOCAL_PART: &[&str] = &[
    "i",
    "me",
    "my",
    "mine",
    "you",
    "your",
    "yours",
    "he",
    "him",
    "his",
    "she",
    "her",
    "hers",
    "it",
    "its",
    "we",
    "us",
    "our",
    "ours",
    "they",
    "them",
    "their",
    "theirs",
    "who",
    "whom",
    "what",
    "which",
    "that",
    "this",
    "these",
    "those",
    "here",
    "there",
    "then",
    "now",
    "when",
    "where",
    "how",
    "why",
    "one",
    "someone",
    "anyone",
    "everyone",
    "and",
    "or",
    "but",
    "so",
    "if",
    "of",
    "on",
    "in",
    "to",
    "for",
    "with",
    "from",
    "by",
    "as",
    "is",
    "are",
    "was",
    "were",
    "be",
    "been",
    "am",
    "do",
    "does",
    "did",
    "has",
    "have",
    "had",
    "look",
    "looks",
    "looked",
    "looking",
    "see",
    "sees",
    "saw",
    "seen",
    "meet",
    "meets",
    "met",
    "arrive",
    "arrives",
    "arrived",
    "stay",
    "stays",
    "stayed",
    "stare",
    "glance",
    "check",
    "checks",
    "checked",
    "call",
    "calls",
    "called",
    "text",
    "wait",
    "waiting",
    "available",
    "live",
    "lives",
    "lived",
    "work",
    "works",
    "worked",
    "working",
    "found",
    "find",
    "start",
    "starts",
    "started",
    "stop",
    "stopped",
    "smile",
    "smiled",
    "laugh",
    "laughed",
    "come",
    "comes",
    "came",
    "go",
    "goes",
    "went",
];

struct Patterns {
    dot_mark: PyRegex,
    email_with_at_sign: PyRegex,
    email_with_at_word: PyRegex,
    spelled_run: PyRegex,
    spelled_token: PyRegex,
    single_digit_chain: PyRegex,
}

fn digit_word() -> String {
    let mut words: Vec<&str> = DIGIT_WORD_TABLE.iter().map(|&(word, _)| word).collect();
    words.sort_by_key(|word| std::cmp::Reverse(word.len())); // stable: ties keep table order
    format!("(?:{})", words.join("|"))
}

static PATTERNS: LazyLock<Result<Patterns, String>> = LazyLock::new(|| {
    let build = || -> Result<Patterns, PatternError> {
        let dot_or_plain = format!(r"(?:{DOT_MARK}|\.)");
        let word = digit_word();
        let separator = r"(?:[ \t]*-[ \t]*|[ \t]+)";
        Ok(Patterns {
            dot_mark: PyRegex::new(DOT_MARK, true)?,
            email_with_at_sign: PyRegex::new(
                &format!(
                    r"(?<![\w.%+\-])({LABEL}(?:{dot_or_plain}{LABEL})*)([ \t]*@[ \t]*)({LABEL}(?:{dot_or_plain}{LABEL})*{dot_or_plain}[A-Za-z]{{2,24}})(?![\w@\-])"
                ),
                true,
            )?,
            email_with_at_word: PyRegex::new(
                &format!(
                    r"(?<![\w.%+\-])({LABEL}(?:{dot_or_plain}{LABEL})*)[ \t]+at[ \t]+({LABEL}(?:{dot_or_plain}{LABEL})*{DOT_MARK}([A-Za-z]{{2,24}}))(?![\w@\-])"
                ),
                true,
            )?,
            spelled_run: PyRegex::new(&format!(r"(?<![\w]){word}(?:{separator}{word})*(?![\w])"), true)?,
            spelled_token: PyRegex::new(&format!(r"({word})|([ \t]*-[ \t]*)|([ \t]+)"), true)?,
            single_digit_chain: PyRegex::new(r"(?<!\d)\d([.\-/])(?:\d\1)+\d(?!\w)", false)?,
        })
    };
    build().map_err(|error| error.to_string())
});

fn patterns() -> Result<&'static Patterns, NormalizeError> {
    PATTERNS.as_ref().map_err(|message| NormalizeError::Pattern(PatternError::Engine(message.clone())))
}

/// A rewrite segment: replacement text, then its source range in canonical coordinates.
type Segment = (Vec<char>, usize, usize);

struct Work {
    chars: Vec<char>,
    origins: Vec<(usize, usize)>,
}

impl Work {
    fn interval(&self, start: usize, end: usize) -> (usize, usize) {
        let source = &self.origins[start..end];
        (source.iter().map(|o| o.0).min().unwrap_or(0), source.iter().map(|o| o.1).max().unwrap_or(0))
    }

    /// `substitute`: every match becomes `replacement`, covering the interval of its source.
    fn substitute(&mut self, matches: &[(usize, usize)], replacement: &[char]) {
        let mut chars = Vec::with_capacity(self.chars.len());
        let mut origins = Vec::with_capacity(self.chars.len());
        let mut cursor = 0;
        for &(start, end) in matches {
            chars.extend_from_slice(&self.chars[cursor..start]);
            origins.extend_from_slice(&self.origins[cursor..start]);
            chars.extend_from_slice(replacement);
            let interval = self.interval(start, end);
            origins.extend(std::iter::repeat_n(interval, replacement.len()));
            cursor = end;
        }
        chars.extend_from_slice(&self.chars[cursor..]);
        origins.extend_from_slice(&self.origins[cursor..]);
        self.chars = chars;
        self.origins = origins;
    }

    /// `rewrite`: apply `plan` to each match; segments tile the match.
    fn rewrite(
        &mut self,
        regex: &PyRegex,
        mut plan: impl FnMut(&Self, &PyMatch) -> Result<Option<Vec<Segment>>, NormalizeError>,
    ) -> Result<(), NormalizeError> {
        let hay = Haystack::from_chars(self.chars.clone());
        let mut chars = Vec::with_capacity(self.chars.len());
        let mut origins = Vec::with_capacity(self.chars.len());
        let mut cursor = 0;
        for found in regex.find_iter(&hay)? {
            let Some(segments) = plan(self, &found)? else { continue };
            chars.extend_from_slice(&self.chars[cursor..found.start]);
            origins.extend_from_slice(&self.origins[cursor..found.start]);
            for (replacement, seg_start, seg_end) in segments {
                if replacement[..] == self.chars[seg_start..seg_end] {
                    origins.extend_from_slice(&self.origins[seg_start..seg_end]);
                } else if !replacement.is_empty() {
                    let interval = self.interval(seg_start, seg_end);
                    origins.extend(std::iter::repeat_n(interval, replacement.len()));
                }
                chars.extend(replacement);
            }
            cursor = found.end;
        }
        chars.extend_from_slice(&self.chars[cursor..]);
        origins.extend_from_slice(&self.origins[cursor..]);
        self.chars = chars;
        self.origins = origins;
        Ok(())
    }

    /// Segments for `canonical[start..end]` with dot markers replaced by `.`.
    fn dotted(&self, patterns: &Patterns, start: usize, end: usize) -> Result<Vec<Segment>, NormalizeError> {
        let slice = Haystack::from_chars(self.chars[start..end].to_vec());
        let mut segments = Vec::new();
        let mut cursor = start;
        for mark in patterns.dot_mark.find_iter(&slice)? {
            let (mark_start, mark_end) = (start + mark.start, start + mark.end);
            if mark_start > cursor {
                segments.push((self.chars[cursor..mark_start].to_vec(), cursor, mark_start));
            }
            segments.push((vec!['.'], mark_start, mark_end));
            cursor = mark_end;
        }
        if cursor < end {
            segments.push((self.chars[cursor..end].to_vec(), cursor, end));
        }
        Ok(segments)
    }
}

fn group_text(chars: &[char], span: Option<(usize, usize)>) -> String {
    span.map_or_else(String::new, |(a, b)| chars[a..b].iter().collect())
}

fn is_blank(c: char) -> bool {
    c == ' ' || c == '\t'
}

fn plan_email_at_sign(work: &Work, found: &PyMatch) -> Result<Option<Vec<Segment>>, NormalizeError> {
    let patterns = patterns()?;
    let slice = Haystack::from_chars(work.chars[found.start..found.end].to_vec());
    if patterns.dot_mark.search(&slice)?.is_none() {
        return Ok(None); // nothing spelled out: leave real addresses untouched
    }
    let (Some(local), Some(at), Some(domain)) = (found.group(1), found.group(2), found.group(3)) else { return Ok(None) };
    let mut segments = work.dotted(patterns, local.0, local.1)?;
    segments.push((vec!['@'], at.0, at.1));
    segments.extend(work.dotted(patterns, domain.0, domain.1)?);
    Ok(Some(segments))
}

fn plan_email_at_word(work: &Work, found: &PyMatch) -> Result<Option<Vec<Segment>>, NormalizeError> {
    let patterns = patterns()?;
    let (Some(local), Some(domain), Some(tld)) = (found.group(1), found.group(2), found.group(3)) else { return Ok(None) };
    let tld_text = group_text(&work.chars, Some(tld));
    let local_text = pyunicode::lower(&group_text(&work.chars, Some(local)));
    let last_word = local_text.rsplit([' ', '\t']).next().unwrap_or("");
    if !(tld_text.chars().count() == 2 || COMMON_TLDS.contains(&pyunicode::lower(&tld_text).as_str()))
        || NOT_A_LOCAL_PART.contains(&local_text.as_str())
        || NOT_A_LOCAL_PART.contains(&last_word)
    {
        return Ok(None);
    }
    let mut segments = work.dotted(patterns, local.0, local.1)?;
    segments.push((vec!['@'], local.1, domain.0));
    segments.extend(work.dotted(patterns, domain.0, domain.1)?);
    Ok(Some(segments))
}

fn plan_spelled_digits(work: &Work, found: &PyMatch) -> Result<Option<Vec<Segment>>, NormalizeError> {
    let patterns = patterns()?;
    let slice = Haystack::from_chars(work.chars[found.start..found.end].to_vec());
    let tokens = patterns.spelled_token.find_iter(&slice)?;
    let mut words = Vec::new();
    let mut digits = Vec::new();
    for token in &tokens {
        if let Some((a, b)) = token.group(1) {
            let word = pyunicode::lower(&slice.slice(a, b));
            let Some(&(_, value)) = DIGIT_WORD_TABLE.iter().find(|(name, _)| *name == word) else {
                return Err(NormalizeError::UnknownDigitWord(word));
            };
            digits.push(i32::from(value));
            words.push(word);
        }
    }
    if digits.len() < MIN_SPELLED_DIGITS || words.iter().filter(|w| *w != "oh").count() < MIN_UNAMBIGUOUS_SPELLED_DIGITS {
        return Ok(None);
    }
    let steps: HashSet<i32> = digits.windows(2).map(|pair| pair[1] - pair[0]).collect();
    if steps.len() == 1 && (steps.contains(&1) || steps.contains(&-1)) {
        return Ok(None); // a counting sequence is not an identifier
    }
    let mut segments = Vec::new();
    for token in &tokens {
        let (start, end) = (found.start + token.start, found.start + token.end);
        if let Some((a, b)) = token.group(1) {
            let word = pyunicode::lower(&slice.slice(a, b));
            let value = DIGIT_WORD_TABLE.iter().find(|(name, _)| *name == word).map_or(0, |&(_, v)| v);
            segments.push((vec![char::from(b'0' + value)], start, end));
        } else if token.group(2).is_some() {
            segments.push((vec!['-'], start, end)); // keep the stated grouping
        } else {
            segments.push((Vec::new(), start, end));
        }
    }
    Ok(Some(segments))
}

fn plan_digit_chain(work: &Work, found: &PyMatch) -> Result<Option<Vec<Segment>>, NormalizeError> {
    let Some((a, b)) = found.group(1) else { return Ok(None) };
    let separator = work.chars[a];
    let minimum = match separator {
        '-' => 4,
        _ => 7,
    };
    if (found.end - found.start).div_ceil(2) < minimum {
        return Ok(None);
    }
    debug_assert_eq!(b, a + 1);
    Ok(Some(
        (found.start..found.end).map(|i| (if work.chars[i] == separator { Vec::new() } else { vec![work.chars[i]] }, i, i + 1)).collect(),
    ))
}

/// Canonical text (lowercased, no robustness): `normalize_text`.
pub fn normalize_text(text: &str) -> Result<String, NormalizeError> {
    Ok(normalize_with_offsets(text, true, None)?.text)
}

/// `normalize_with_offsets(text, lowercase=..., robustness=...)`.
///
/// `robustness: None` follows Python: off for the lowercased view and the `PRIVOKE_*` flags
/// for the case-preserved view.
pub fn normalize_with_offsets(
    text: &str,
    lowercase: bool,
    robustness: Option<RobustnessOptions>,
) -> Result<NormalizedText, NormalizeError> {
    let robustness = robustness.unwrap_or_else(|| if lowercase { RobustnessOptions::default() } else { RobustnessOptions::from_env() });
    let original: Vec<char> = text.chars().collect();

    // NFKC per cluster; combining marks and Hangul composition stay with their starter.
    let mut characters: Vec<char> = Vec::with_capacity(original.len());
    let mut origins: Vec<(usize, usize)> = Vec::with_capacity(original.len());
    let mut cluster = String::new();
    let mut cluster_start = 0;
    let flush = |cluster: &str, start: usize, end: usize, characters: &mut Vec<char>, origins: &mut Vec<(usize, usize)>| {
        let normalized = pyunicode::nfkc(cluster);
        for c in normalized.chars() {
            characters.push(c);
            origins.push((start, end));
        }
    };
    for (index, &character) in original.iter().enumerate() {
        if robustness.strip_format_chars && pyunicode::is_format(character) {
            continue;
        }
        let joins = !cluster.is_empty()
            && (pyunicode::combining_class(character) != 0 || {
                if cluster.is_ascii() && character.is_ascii() {
                    false
                } else {
                    let mut joined = cluster.clone();
                    joined.push(character);
                    pyunicode::nfkc(&joined) != pyunicode::nfkc(&cluster) + &pyunicode::nfkc(&character.to_string())
                }
            });
        if joins {
            cluster.push(character);
        } else {
            if !cluster.is_empty() {
                flush(&cluster, cluster_start, index, &mut characters, &mut origins);
            }
            cluster.clear();
            cluster.push(character);
            cluster_start = index;
        }
    }
    if !cluster.is_empty() {
        flush(&cluster, cluster_start, original.len(), &mut characters, &mut origins);
    }

    let mut work = Work { chars: characters, origins };
    if lowercase {
        let lowered: String = pyunicode::lower(&work.chars.iter().collect::<String>());
        let mut lowered_origins = Vec::with_capacity(lowered.len());
        for (c, origin) in work.chars.iter().zip(&work.origins) {
            lowered_origins.extend(std::iter::repeat_n(*origin, pyunicode::lower_len(*c)));
        }
        work.chars = lowered.chars().collect();
        work.origins = lowered_origins;
    }

    // substitute(r'\[at\]|\(at\)', '@', IGNORECASE)
    let hits: Vec<(usize, usize)> = find_at_markers(&work.chars);
    work.substitute(&hits, &['@']);
    if robustness.canonicalise_email_words {
        let patterns = patterns()?;
        work.rewrite(&patterns.email_with_at_sign, plan_email_at_sign)?;
        work.rewrite(&patterns.email_with_at_word, plan_email_at_word)?;
    }
    if robustness.canonicalise_digits {
        let patterns = patterns()?;
        work.rewrite(&patterns.spelled_run, plan_spelled_digits)?;
        work.rewrite(&patterns.single_digit_chain, plan_digit_chain)?;
    }
    // substitute(r'(?<=\d)[ \t]+(?=\d)', '')
    let runs = blank_runs(&work.chars);
    let gaps: Vec<(usize, usize)> = runs
        .iter()
        .copied()
        .filter(|&(start, end)| {
            start > 0 && end < work.chars.len() && pyunicode::is_decimal(work.chars[start - 1]) && pyunicode::is_decimal(work.chars[end])
        })
        .collect();
    work.substitute(&gaps, &[]);
    // substitute(r'[ \t]+', ' ')
    let runs = blank_runs(&work.chars);
    work.substitute(&runs, &[' ']);
    // substitute(r'\n+', '\n')
    let newlines = newline_runs(&work.chars);
    work.substitute(&newlines, &['\n']);

    let left = work.chars.iter().position(|&c| !pyunicode::is_space(c)).unwrap_or(work.chars.len());
    let right = work.chars.iter().rposition(|&c| !pyunicode::is_space(c)).map_or(left, |index| index + 1);
    let (left, right) = (left.min(right), right);
    let chars: Vec<char> = work.chars[left..right].to_vec();
    Ok(NormalizedText { text: chars.iter().collect(), chars, original, origins: work.origins[left..right].to_vec() })
}

fn find_at_markers(chars: &[char]) -> Vec<(usize, usize)> {
    let mut found = Vec::new();
    let mut index = 0;
    while index + 4 <= chars.len() {
        let window = &chars[index..index + 4];
        let opening = window[0];
        let closing = window[3];
        let inner_is_at = window[1].eq_ignore_ascii_case(&'a') && window[2].eq_ignore_ascii_case(&'t');
        if inner_is_at && ((opening == '[' && closing == ']') || (opening == '(' && closing == ')')) {
            found.push((index, index + 4));
            index += 4;
        } else {
            index += 1;
        }
    }
    found
}

fn blank_runs(chars: &[char]) -> Vec<(usize, usize)> {
    runs_of(chars, is_blank)
}

fn newline_runs(chars: &[char]) -> Vec<(usize, usize)> {
    runs_of(chars, |c| c == '\n')
}

fn runs_of(chars: &[char], member: impl Fn(char) -> bool) -> Vec<(usize, usize)> {
    let mut runs = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        if member(chars[index]) {
            let start = index;
            while index < chars.len() && member(chars[index]) {
                index += 1;
            }
            runs.push((start, index));
        } else {
            index += 1;
        }
    }
    runs
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn norm(text: &str, lowercase: bool, options: RobustnessOptions) -> NormalizedText {
        normalize_with_offsets(text, lowercase, Some(options)).expect("normalises")
    }

    #[test]
    fn robustness_flags_follow_env_bool() {
        let env = |pairs: &'static [(&str, &str)]| {
            move |key: &str| pairs.iter().find(|(name, _)| *name == key).map(|(_, value)| (*value).to_owned())
        };
        assert_eq!(RobustnessOptions::from_lookup(&env(&[])), RobustnessOptions::default());
        let on = RobustnessOptions::from_lookup(&env(&[
            ("PRIVOKE_STRIP_FORMAT_CHARS", "1"),
            ("PRIVOKE_CANONICALISE_DIGITS", "TRUE"),
            ("PRIVOKE_CANONICALISE_EMAIL_WORDS", "On"),
        ]));
        assert_eq!(on, RobustnessOptions { strip_format_chars: true, canonicalise_digits: true, canonicalise_email_words: true });
        // Anything else, including " 1", is off: Python does not strip here.
        assert_eq!(
            RobustnessOptions::from_lookup(&env(&[("PRIVOKE_STRIP_FORMAT_CHARS", " 1"), ("PRIVOKE_CANONICALISE_DIGITS", "0")])),
            RobustnessOptions::default()
        );
    }

    #[test]
    fn default_view_is_lowercased_and_spaces_collapse() {
        let result = norm("  Hello   World\n\n\nA  [AT] b  ", true, RobustnessOptions::default());
        assert_eq!(result.text(), "hello world\na @ b");
        assert_eq!(result.origins().len(), result.chars().len());
    }

    #[test]
    fn digit_gaps_close_and_case_is_kept() {
        let result = norm("Ph 555  1234 and 1 2", false, RobustnessOptions::default());
        assert_eq!(result.text(), "Ph 5551234 and 12");
        assert_eq!(result.original_span((3, 10)), Some((3, 12)));
    }

    #[test]
    fn expansions_share_one_interval() {
        let result = norm("\u{fb01}x", true, RobustnessOptions::default());
        assert_eq!(result.text(), "fix");
        assert_eq!(result.origins(), &[(0, 1), (0, 1), (1, 2)]);
    }

    #[test]
    fn format_characters_are_dropped_only_on_request() {
        let on = RobustnessOptions { strip_format_chars: true, ..Default::default() };
        assert_eq!(norm("a\u{200b}b", false, on).text(), "ab");
        assert_eq!(norm("a\u{200b}b", false, RobustnessOptions::default()).text(), "a\u{200b}b");
        assert_eq!(norm("a\u{200b}b", false, on).origins(), &[(0, 2), (2, 3)]);
    }

    #[test]
    fn robustness_canonicalisations() {
        let both = RobustnessOptions { canonicalise_digits: true, canonicalise_email_words: true, ..Default::default() };
        assert_eq!(norm("john dot smith at gmail dot com", false, both).text(), "john.smith@gmail.com");
        assert_eq!(norm("five five five one two three four", false, both).text(), "5551234");
        assert_eq!(norm("5-5-5-1-2-3-4", false, both).text(), "5551234");
        assert_eq!(norm("one two three four five six seven", false, both).text(), "one two three four five six seven");
        assert!(matches!(
            normalize_with_offsets("s\u{131}x s\u{131}x s\u{131}x s\u{131}x s\u{131}x s\u{131}x s\u{131}x", false, Some(both)),
            Err(NormalizeError::UnknownDigitWord(_))
        ));
    }
}
