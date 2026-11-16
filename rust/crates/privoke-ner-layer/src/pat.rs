//! Python-`re` patterns for the NER code, on top of `privoke_rules::pyre`.
//!
//! `PyRegex` accepts only ASCII (plus a few preserved characters) in a pattern, and keeps those few characters
//! distinct in the text it matches. The NER patterns also name the en dash, the em dash and the bullet (`[:\-–]`,
//! `[–—\-]`, `[-*•]`). They are handled by a bijective relabelling that is exact:
//!
//! * a [`Subject`] (the text to search) chooses, per pattern, one sentinel ASCII punctuation character for each of
//!   those characters, such that the sentinel occurs neither in the text nor as a literal anywhere in the pattern;
//! * the pattern is compiled with each such character replaced by its sentinel, and the text is matched with each
//!   such character replaced by the same sentinel.
//!
//! A sentinel is punctuation, so it stays "other" (neither word, digit nor space) like the character it stands for.
//! A kind of character that the text does not hold needs no sentinel: its class member is dropped from the pattern. When
//! no sentinel is free (a text that holds a dash and every candidate) the search fails loudly rather than guess.
//!
//! `é` is not relabelled: the one pattern that names it is matched in two passes, see `pattern.rs`. A pattern that
//! names none of these characters is compiled once and matched on the shared shadow text unchanged.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use privoke_rules::pyre::{Haystack, PatternError, PyMatch, PyRegex};

const EN_DASH: char = '\u{2013}';
const EM_DASH: char = '\u{2014}';
const BULLET: char = '\u{2022}';
const OTHER: [char; 3] = [EN_DASH, EM_DASH, BULLET];
/// Sentinels for the dashes and the bullet: ASCII punctuation that is literal inside a character class.
const PUNCT_CANDIDATES: [char; 24] =
    ['`', '#', '%', '&', '@', ';', '<', '>', '!', '/', '"', '=', ',', ':', '~', '$', '+', '(', ')', '*', '.', '?', '{', '}'];

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Sentinels {
    other: [char; 3],
}

impl Sentinels {
    /// The pattern character for `c`: its sentinel, or `None` (dropped) when `c` is one of the dashes or the bullet and
    /// the text holds none of that kind (its sentinel is `'\0'`).
    fn relabel_pattern(self, c: char) -> Option<char> {
        match OTHER.iter().position(|&o| o == c) {
            Some(i) if self.other[i] == '\0' => None,
            Some(i) => Some(self.other[i]),
            None => Some(c),
        }
    }

    /// The text character for `c`: its sentinel, or `c` itself when no sentinel was chosen for its kind (the pattern does
    /// not name it, or the text holds none of it).
    fn relabel_text(self, c: char) -> char {
        match OTHER.iter().position(|&o| o == c) {
            Some(i) if self.other[i] != '\0' => self.other[i],
            _ => c,
        }
    }
}

/// The ASCII characters that a pattern uses as literals (outside operator and group syntax).
fn literal_chars(source: &str) -> [bool; 128] {
    let chars: Vec<char> = source.chars().collect();
    let mut literal = [false; 128];
    let mut mark = |c: char| {
        if c.is_ascii() {
            literal[c as usize] = true;
        }
    };
    let (mut i, mut in_class) = (0, false);
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' {
            if let Some(&next) = chars.get(i + 1) {
                mark(next);
            }
            i += 2;
        } else if in_class {
            if c == ']' {
                in_class = false;
            } else {
                mark(c);
            }
            i += 1;
        } else {
            match c {
                '[' => {
                    in_class = true;
                    i += 1;
                    if chars.get(i) == Some(&'^') {
                        i += 1;
                    }
                    if chars.get(i) == Some(&']') {
                        mark(']');
                        i += 1;
                    }
                }
                '(' => {
                    i += 1;
                    if chars.get(i) == Some(&'?') {
                        i += 1;
                        match chars.get(i) {
                            Some('P') => {
                                while i < chars.len() && chars[i] != '>' {
                                    i += 1;
                                }
                                i += 1;
                            }
                            Some('<') => {
                                i += 1;
                                if matches!(chars.get(i), Some('=' | '!')) {
                                    i += 1;
                                }
                            }
                            Some(':' | '=' | '!') => i += 1,
                            _ => {}
                        }
                    }
                }
                '{' => {
                    while i < chars.len() && chars[i] != '}' {
                        i += 1;
                    }
                    i += 1;
                }
                ')' | '?' | '*' | '+' | '|' | '.' | '^' | '$' | '}' => i += 1,
                other => {
                    mark(other);
                    i += 1;
                }
            }
        }
    }
    literal
}

/// A text prepared for matching: its characters, the shared shadow text and relabelled variants on demand.
#[derive(Debug)]
pub struct Subject {
    chars: Vec<char>,
    plain: Arc<Haystack>,
    present: [bool; 128],
    /// Which of the dashes and the bullet the text holds.
    has_other: [bool; 3],
    variants: Mutex<HashMap<Sentinels, Arc<Haystack>>>,
}

impl Subject {
    /// Prepare a text.
    pub fn new(chars: &[char]) -> Self {
        let mut present = [false; 128];
        for &c in chars {
            if c.is_ascii() {
                present[c as usize] = true;
            }
        }
        let has_other = OTHER.map(|o| chars.contains(&o));
        Self {
            chars: chars.to_vec(),
            plain: Arc::new(Haystack::from_chars(chars.to_vec())),
            present,
            has_other,
            variants: Mutex::new(HashMap::new()),
        }
    }

    /// The characters.
    pub fn chars(&self) -> &[char] {
        &self.chars
    }

    fn variant(&self, sentinels: Sentinels) -> Arc<Haystack> {
        let mut map = self.variants.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        map.entry(sentinels)
            .or_insert_with(|| Arc::new(Haystack::from_chars(self.chars.iter().map(|&c| sentinels.relabel_text(c)).collect())))
            .clone()
    }
}

/// A Python pattern, compiled on first use.
#[derive(Debug)]
pub struct Pattern {
    source: String,
    ignore_case: bool,
    needs_other: [bool; 3],
    literal: [bool; 128],
    plain: OnceLock<Result<Arc<PyRegex>, String>>,
    variants: Mutex<HashMap<Sentinels, Arc<PyRegex>>>,
}

impl Pattern {
    /// A pattern; `ignore_case` is `re.IGNORECASE`.
    pub fn new(source: &str, ignore_case: bool) -> Self {
        Self {
            source: source.to_owned(),
            ignore_case,
            needs_other: OTHER.map(|c| source.contains(c)),
            literal: literal_chars(source),
            plain: OnceLock::new(),
            variants: Mutex::new(HashMap::new()),
        }
    }

    fn pick(&self, subject: &Subject) -> Result<Sentinels, PatternError> {
        let none = || PatternError::Syntax("no free sentinel character for the pattern".to_owned());
        let free = |used: &[char]| {
            PUNCT_CANDIDATES.iter().copied().find(|&c| !self.literal[c as usize] && !subject.present[c as usize] && !used.contains(&c))
        };
        let mut other = ['\0'; 3];
        for index in 0..3 {
            if self.needs_other[index] && subject.has_other[index] {
                other[index] = free(&other).ok_or_else(none)?;
            }
        }
        Ok(Sentinels { other })
    }

    fn compiled(&self, sentinels: Option<Sentinels>) -> Result<Arc<PyRegex>, PatternError> {
        match sentinels {
            None => self
                .plain
                .get_or_init(|| PyRegex::new(&self.source, self.ignore_case).map(Arc::new).map_err(|e| e.to_string()))
                .clone()
                .map_err(PatternError::Syntax),
            Some(s) => {
                let mut map = self.variants.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(found) = map.get(&s) {
                    return Ok(found.clone());
                }
                let translated: String = self.source.chars().filter_map(|c| s.relabel_pattern(c)).collect();
                let regex = Arc::new(PyRegex::new(&translated, self.ignore_case)?);
                map.insert(s, regex.clone());
                Ok(regex)
            }
        }
    }

    fn resolve(&self, subject: &Subject) -> Result<(Arc<PyRegex>, Arc<Haystack>), PatternError> {
        if !self.needs_other.iter().any(|&n| n) {
            return Ok((self.compiled(None)?, subject.plain.clone()));
        }
        let sentinels = self.pick(subject)?;
        Ok((self.compiled(Some(sentinels))?, subject.variant(sentinels)))
    }

    /// The first match at or after character index `from` (`pattern.search(text, from)`).
    pub fn search_from(&self, subject: &Subject, from: usize) -> Result<Option<PyMatch>, PatternError> {
        let (regex, hay) = self.resolve(subject)?;
        regex.search_from(&hay, from)
    }

    /// `pattern.search(text)`.
    pub fn search(&self, subject: &Subject) -> Result<Option<PyMatch>, PatternError> {
        self.search_from(subject, 0)
    }

    /// `pattern.match(text, pos)`: a match that starts exactly at `pos`. The leftmost match from `pos` starts at
    /// `pos` whenever any match does, and is the one an anchored attempt would find.
    pub fn match_at(&self, subject: &Subject, pos: usize) -> Result<Option<PyMatch>, PatternError> {
        Ok(self.search_from(subject, pos)?.filter(|m| m.start == pos))
    }

    /// `pattern.finditer(text)`.
    pub fn find_iter(&self, subject: &Subject) -> Result<Vec<PyMatch>, PatternError> {
        let (regex, hay) = self.resolve(subject)?;
        regex.find_iter(&hay)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn subject(text: &str) -> Subject {
        Subject::new(&text.chars().collect::<Vec<_>>())
    }

    #[test]
    fn dashes_stay_distinct_from_hyphens_and_each_other() {
        let pattern = Pattern::new("name[:\\-\u{2013}]", true);
        for (text, hit) in
            [("name:", true), ("name-", true), ("name\u{2013}", true), ("name\u{2014}", false), ("name`", false), ("name#", false)]
        {
            assert_eq!(pattern.search(&subject(text)).expect("runs").is_some(), hit, "{text:?}");
        }
    }

    #[test]
    fn a_text_that_holds_the_first_sentinels_gets_others() {
        let tricky = Pattern::new("a[:\u{2013}]b", false);
        assert!(tricky.search(&subject("a`b a#b")).expect("runs").is_none());
        assert!(tricky.search(&subject("a\u{2013}b a`b")).expect("runs").is_some());
        let bullet = Pattern::new("(?:^|\\n)[ \\t]*(?:[-*\u{2022}]|\\d+[.)])$", false);
        assert!(bullet.search(&subject("x\n \u{2022}")).expect("runs").is_some());
        assert!(bullet.search(&subject("x\n `")).expect("runs").is_none());
        // A text that holds no dash needs no sentinel, however many candidates it holds.
        let every: String = PUNCT_CANDIDATES.iter().collect();
        assert!(tricky.search(&subject(&format!("a{every}b"))).expect("runs").is_none());
        // A dash and every candidate: the search fails instead of guessing.
        assert!(tricky.search(&subject(&format!("a\u{2013}b{every}"))).is_err());
    }

    #[test]
    fn a_dash_the_pattern_does_not_name_keeps_its_place() {
        // The text holds an em dash, the pattern names only the en dash: offsets must not move.
        let pattern = Pattern::new("to[ \\t]+[:\u{2013}]?x", false);
        let found = pattern.search(&subject("a\u{2014}to x")).expect("runs").map(|m| (m.start, m.end));
        assert_eq!(found, Some((2, 6)));
        // The text holds neither: the class member is dropped and a stray punctuation mark cannot match as a dash.
        assert!(pattern.search(&subject("to `x")).expect("runs").is_none());
    }

    #[test]
    fn literal_analysis_skips_syntax() {
        let literal = literal_chars(r"(?<![\w'’])(?P<n>a|b){1,2}[:=\-]\.x(?:y)?$");
        assert!(literal[b'\'' as usize] && literal[b':' as usize] && literal[b'=' as usize] && literal[b'.' as usize]);
        assert!(!literal[b'<' as usize] && !literal[b'!' as usize] && !literal[b'(' as usize] && !literal[b'$' as usize]);
        assert!(!literal[b',' as usize] && !literal[b'{' as usize]);
    }
}
