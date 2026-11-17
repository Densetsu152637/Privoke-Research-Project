//! A Python-`re` compatible matcher built on `regex` and `fancy-regex`.
//!
//! Python's `re` and Rust's engines disagree on Unicode class membership (`\w`, `\d`, `\s`),
//! on `$`, on `(?i)` equivalents and on pattern syntax. Instead of approximating, this module
//! makes the two agree by construction:
//!
//! 1. **Shadow text.** Before matching, every character outside printable ASCII is replaced by
//!    a stand-in with the same Python class (word, decimal digit, space or other), so any
//!    class test sees what Python would see. The haystack stays one-to-one with the original
//!    characters; offsets are converted back to character indexes.
//! 2. **Pattern translation.** A Python pattern is rewritten into Rust syntax. `\w`, `\d` and
//!    `\s` become small explicit classes over the stand-ins, so Rust's Unicode tables are never
//!    consulted, escapes follow Python's grammar and errors, `{,n}` and literal braces are
//!    normalised, `re.IGNORECASE` equivalents that Rust does not know (dotless and dotted `i`)
//!    are added, and `$` keeps Python's "end, or before a final newline" meaning.
//!
//! Patterns with look-around or back-references run on `fancy-regex`; everything else runs on
//! `regex`. Each such pattern records why ([`FancyReason`]).

use std::fmt;
use std::sync::OnceLock;

use fancy_regex as fancy;

use crate::pyunicode;

/// Non-ASCII characters left unchanged in the shadow text: the characters patterns mention and
/// the characters `re.IGNORECASE` equates with ASCII letters.
const PRESERVED: [char; 5] = ['\u{2019}', '\u{130}', '\u{131}', '\u{17f}', '\u{212a}'];
const STAND_IN_SPACE: char = '\u{2003}';
const STAND_IN_DIGIT: char = '\u{660}';
const STAND_IN_WORD: char = '\u{aa}';
const STAND_IN_OTHER: char = '\u{a7}';

const WORD_ITEMS: &str = r"0-9A-Za-z_\x{aa}\x{660}\x{130}\x{131}\x{17f}\x{212a}";
const DIGIT_ITEMS: &str = r"0-9\x{660}";
const SPACE_ITEMS: &str = r"\x09-\x0d \x{2003}";

/// Why a pattern needs the backtracking engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FancyReason {
    /// `(?=...)`
    Lookahead,
    /// `(?!...)`
    NegativeLookahead,
    /// `(?<=...)`
    Lookbehind,
    /// `(?<!...)`
    NegativeLookbehind,
    /// `\1` or `(?P=name)`
    BackReference,
}

impl FancyReason {
    /// Short name used in reports.
    pub fn label(self) -> &'static str {
        match self {
            Self::Lookahead => "lookahead",
            Self::NegativeLookahead => "negative lookahead",
            Self::Lookbehind => "lookbehind",
            Self::NegativeLookbehind => "negative lookbehind",
            Self::BackReference => "back-reference",
        }
    }
}

/// Errors from compiling or running a pattern.
#[derive(Debug, thiserror::Error)]
pub enum PatternError {
    /// Python would reject the pattern, or it uses a construct this matcher does not translate.
    #[error("pattern rejected: {0}")]
    Syntax(String),
    /// The Rust engine rejected the translated pattern.
    #[error("translated pattern rejected: {0}")]
    Engine(String),
    /// The backtracking engine gave up (only reachable with an explicit limit).
    #[error("match failed: {0}")]
    Match(String),
}

/// A haystack prepared once and shared by every pattern.
#[derive(Debug)]
pub struct Haystack {
    chars: Vec<char>,
    shadow: String,
    /// Byte offset of each character in `shadow`, plus the total length.
    starts: Vec<usize>,
    ends_with_newline: bool,
}

impl Haystack {
    /// Prepare a text.
    pub fn new(text: &str) -> Self {
        Self::from_chars(text.chars().collect())
    }

    /// Prepare a text given as characters.
    pub fn from_chars(chars: Vec<char>) -> Self {
        let mut shadow = String::with_capacity(chars.len());
        let mut starts = Vec::with_capacity(chars.len() + 1);
        for &c in &chars {
            starts.push(shadow.len());
            shadow.push(shadow_char(c));
        }
        starts.push(shadow.len());
        let ends_with_newline = chars.last() == Some(&'\n');
        Self { chars, shadow, starts, ends_with_newline }
    }

    /// The original characters.
    pub fn chars(&self) -> &[char] {
        &self.chars
    }

    /// Number of characters.
    pub fn len(&self) -> usize {
        self.chars.len()
    }

    /// True for the empty text.
    pub fn is_empty(&self) -> bool {
        self.chars.is_empty()
    }

    /// The characters `start..end` as a string.
    pub fn slice(&self, start: usize, end: usize) -> String {
        self.chars[start..end].iter().collect()
    }

    fn char_index(&self, byte: usize) -> usize {
        match self.starts.binary_search(&byte) {
            Ok(index) | Err(index) => index,
        }
    }
}

/// The stand-in for one character.
pub fn shadow_char(c: char) -> char {
    if matches!(c, ' '..='~' | '\t'..='\r') || PRESERVED.contains(&c) {
        c
    } else if pyunicode::is_space(c) {
        STAND_IN_SPACE
    } else if pyunicode::is_decimal(c) {
        STAND_IN_DIGIT
    } else if pyunicode::is_word(c) {
        STAND_IN_WORD
    } else {
        STAND_IN_OTHER
    }
}

/// One match, in character indexes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PyMatch {
    /// Start of the whole match.
    pub start: usize,
    /// End of the whole match.
    pub end: usize,
    /// Spans of the capture groups, index 0 being the whole match.
    pub groups: Vec<Option<(usize, usize)>>,
}

impl PyMatch {
    /// Span of a group, if it took part in the match.
    pub fn group(&self, index: usize) -> Option<(usize, usize)> {
        self.groups.get(index).copied().flatten()
    }
}

/// Capture group spans in bytes, group 0 first.
type GroupSpans = Vec<Option<(usize, usize)>>;

enum Engine {
    Fast(regex::Regex),
    Fancy(Box<fancy::Regex>),
}

impl fmt::Debug for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Fast(_) => "Engine::Fast",
            Self::Fancy(_) => "Engine::Fancy",
        })
    }
}

impl Engine {
    fn build(pattern: &str, fancy_needed: bool) -> Result<Self, PatternError> {
        if fancy_needed {
            fancy::RegexBuilder::new(pattern)
                .backtrack_limit(usize::MAX)
                .build()
                .map(|regex| Self::Fancy(Box::new(regex)))
                .map_err(|error| PatternError::Engine(error.to_string()))
        } else {
            regex::RegexBuilder::new(pattern)
                .size_limit(1 << 30)
                .dfa_size_limit(1 << 28)
                .build()
                .map(Self::Fast)
                .map_err(|error| PatternError::Engine(error.to_string()))
        }
    }

    /// Search the shadow text from a byte offset; groups are byte spans.
    fn search(&self, shadow: &str, at: usize, groups: usize) -> Result<Option<GroupSpans>, PatternError> {
        match self {
            Self::Fast(regex) => {
                if groups <= 1 {
                    Ok(regex.find_at(shadow, at).map(|m| vec![Some((m.start(), m.end()))]))
                } else {
                    Ok(regex.captures_at(shadow, at).map(|caps| (0..groups).map(|i| caps.get(i).map(|m| (m.start(), m.end()))).collect()))
                }
            }
            Self::Fancy(regex) => {
                let captures = regex.captures_from_pos(shadow, at).map_err(|error| PatternError::Match(error.to_string()))?;
                Ok(captures.map(|caps| (0..groups).map(|i| caps.get(i).map(|m| (m.start(), m.end()))).collect()))
            }
        }
    }
}

/// A compiled Python pattern.
#[derive(Debug)]
pub struct PyRegex {
    source: String,
    engine: Engine,
    /// Pattern text of the variant used instead of `engine` when the text ends with a newline and
    /// the pattern has `$`; compiled on first use.
    exact_pattern: Option<String>,
    exact: OnceLock<Result<Engine, String>>,
    reasons: Vec<FancyReason>,
    groups: usize,
    names: Vec<(String, usize)>,
}

impl PyRegex {
    /// Compile `pattern` as Python's `re.compile(pattern, re.IGNORECASE if ignore_case else 0)`.
    pub fn new(pattern: &str, ignore_case: bool) -> Result<Self, PatternError> {
        let plain = translate(pattern, ignore_case, DollarMode::EndOfText)?;
        let fancy_needed = !plain.reasons.is_empty();
        let engine = Engine::build(&plain.pattern, fancy_needed)?;
        let exact_pattern = if plain.uses_dollar { Some(translate(pattern, ignore_case, DollarMode::PythonDollar)?.pattern) } else { None };
        Ok(Self {
            source: pattern.to_owned(),
            engine,
            exact_pattern,
            exact: OnceLock::new(),
            reasons: plain.reasons,
            groups: plain.groups + 1,
            names: plain.names,
        })
    }

    /// The Python pattern text.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Why the pattern needs `fancy-regex`; empty for patterns on the `regex` crate.
    pub fn fancy_reasons(&self) -> &[FancyReason] {
        &self.reasons
    }

    /// True when the pattern has `$` and so keeps an exact `fancy-regex` variant for text that
    /// ends with a newline (the fast variant reads `$` as the end of the text).
    pub fn has_dollar_fallback(&self) -> bool {
        self.exact_pattern.is_some()
    }

    /// Index of a named group.
    pub fn group_index(&self, name: &str) -> Option<usize> {
        self.names.iter().find(|(n, _)| n == name).map(|&(_, index)| index)
    }

    fn engine_for(&self, hay: &Haystack) -> Result<&Engine, PatternError> {
        match (&self.exact_pattern, hay.ends_with_newline) {
            (Some(pattern), true) => self
                .exact
                .get_or_init(|| Engine::build(pattern, true).map_err(|error| error.to_string()))
                .as_ref()
                .map_err(|message| PatternError::Engine(message.clone())),
            _ => Ok(&self.engine),
        }
    }

    /// The first match at or after character index `from`.
    pub fn search_from(&self, hay: &Haystack, from: usize) -> Result<Option<PyMatch>, PatternError> {
        if from > hay.len() {
            return Ok(None);
        }
        let found = self.engine_for(hay)?.search(&hay.shadow, hay.starts[from], self.groups)?;
        Ok(found.map(|spans| {
            let groups: Vec<Option<(usize, usize)>> =
                spans.into_iter().map(|span| span.map(|(a, b)| (hay.char_index(a), hay.char_index(b)))).collect();
            let (start, end) = groups[0].unwrap_or((0, 0));
            PyMatch { start, end, groups }
        }))
    }

    /// `re.search`.
    pub fn search(&self, hay: &Haystack) -> Result<Option<PyMatch>, PatternError> {
        self.search_from(hay, 0)
    }

    /// `re.finditer`: successive non-overlapping matches. An empty match is followed by a
    /// search one character later (no shipped pattern can match the empty string).
    pub fn find_iter(&self, hay: &Haystack) -> Result<Vec<PyMatch>, PatternError> {
        let mut out = Vec::new();
        let mut from = 0;
        while let Some(found) = self.search_from(hay, from)? {
            from = if found.end == found.start { found.end + 1 } else { found.end };
            out.push(found);
            if from > hay.len() {
                break;
            }
        }
        Ok(out)
    }
}

// ---- translation ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum DollarMode {
    /// `$` becomes `\z`; exact when the text does not end with a newline.
    EndOfText,
    /// `$` becomes `(?=\n?\z)`, Python's meaning in every case.
    PythonDollar,
}

struct Translated {
    pattern: String,
    reasons: Vec<FancyReason>,
    uses_dollar: bool,
    groups: usize,
    names: Vec<(String, usize)>,
}

fn syntax<T>(message: impl Into<String>) -> Result<T, PatternError> {
    Err(PatternError::Syntax(message.into()))
}

fn shorthand_items(letter: char) -> &'static str {
    match letter {
        'd' => DIGIT_ITEMS,
        'w' => WORD_ITEMS,
        _ => SPACE_ITEMS,
    }
}

fn literal(c: char, out: &mut String) {
    if c.is_ascii_alphanumeric() {
        out.push(c);
    } else {
        out.push_str(&format!("\\x{{{:x}}}", c as u32));
    }
}

enum ClassItem {
    Char(char),
    Range(char, char),
    /// `\d`, `\w` or `\s`.
    Shorthand(char),
    /// `\D`, `\W` or `\S`, spelled as the lowercase letter.
    Negated(char),
}

struct Translator<'a> {
    chars: Vec<char>,
    index: usize,
    out: String,
    mode: DollarMode,
    scopes: Vec<bool>,
    reasons: Vec<FancyReason>,
    uses_dollar: bool,
    groups: usize,
    names: Vec<(String, usize)>,
    pattern: &'a str,
}

fn translate(pattern: &str, ignore_case: bool, mode: DollarMode) -> Result<Translated, PatternError> {
    for c in pattern.chars() {
        if !c.is_ascii() && !PRESERVED.contains(&c) {
            return syntax(format!("non-ASCII character {c:?} in pattern is not supported"));
        }
    }
    let mut translator = Translator {
        chars: pattern.chars().collect(),
        index: 0,
        out: String::new(),
        mode,
        scopes: vec![ignore_case],
        reasons: Vec::new(),
        uses_dollar: false,
        groups: 0,
        names: Vec::new(),
        pattern,
    };
    translator.run()?;
    let mut pattern_out = translator.out;
    if translator.scopes[0] {
        pattern_out.insert_str(0, "(?i)");
    }
    let mut reasons = translator.reasons;
    reasons.dedup();
    Ok(Translated {
        pattern: pattern_out,
        reasons,
        uses_dollar: translator.uses_dollar,
        groups: translator.groups,
        names: translator.names,
    })
}

impl Translator<'_> {
    fn ic(&self) -> bool {
        self.scopes.last().copied().unwrap_or(false)
    }

    fn peek(&self, offset: usize) -> Option<char> {
        self.chars.get(self.index + offset).copied()
    }

    fn eat(&mut self, expected: char) -> bool {
        if self.peek(0) == Some(expected) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn reason(&mut self, reason: FancyReason) {
        if !self.reasons.contains(&reason) {
            self.reasons.push(reason);
        }
    }

    fn run(&mut self) -> Result<(), PatternError> {
        while let Some(c) = self.peek(0) {
            let at = self.index;
            self.index += 1;
            match c {
                '\\' => self.escape_outside()?,
                '[' => self.class()?,
                '(' => self.group_open(at)?,
                ')' => {
                    if self.scopes.len() <= 1 {
                        return syntax(format!("unbalanced parenthesis in {:?}", self.pattern));
                    }
                    self.scopes.pop();
                    self.out.push(')');
                }
                '|' | '.' | '^' => self.out.push(c),
                '$' => {
                    self.uses_dollar = true;
                    self.out.push_str(match self.mode {
                        DollarMode::EndOfText => r"\z",
                        DollarMode::PythonDollar => r"(?=\n?\z)",
                    });
                }
                '*' | '+' | '?' => {
                    self.out.push(c);
                    self.after_quantifier()?;
                }
                '{' => self.brace()?,
                '}' | ']' => literal(c, &mut self.out),
                _ => self.emit_char(c),
            }
        }
        if self.scopes.len() != 1 {
            return syntax(format!("missing closing parenthesis in {:?}", self.pattern));
        }
        Ok(())
    }

    fn emit_char(&mut self, c: char) {
        if self.ic() && matches!(c, 'i' | 'I') {
            self.out.push_str(r"[iI\x{130}\x{131}]");
        } else {
            literal(c, &mut self.out);
        }
    }

    fn after_quantifier(&mut self) -> Result<(), PatternError> {
        if self.eat('?') {
            self.out.push('?');
        } else if self.peek(0) == Some('+') {
            return syntax("possessive quantifiers are not supported");
        }
        Ok(())
    }

    fn brace(&mut self) -> Result<(), PatternError> {
        // Python: `{`, optional digits, optional `,` and digits, then `}`; anything else is literal.
        let mut cursor = self.index;
        let digits = |cursor: &mut usize, chars: &[char]| {
            let start = *cursor;
            while chars.get(*cursor).is_some_and(char::is_ascii_digit) {
                *cursor += 1;
            }
            chars[start..*cursor].iter().collect::<String>()
        };
        if self.chars.get(cursor) == Some(&'}') {
            literal('{', &mut self.out);
            return Ok(());
        }
        let low = digits(&mut cursor, &self.chars);
        let (high, comma) = if self.chars.get(cursor) == Some(&',') {
            cursor += 1;
            (digits(&mut cursor, &self.chars), true)
        } else {
            (low.clone(), false)
        };
        if self.chars.get(cursor) != Some(&'}') {
            literal('{', &mut self.out);
            return Ok(());
        }
        cursor += 1;
        let low_value: u64 =
            if low.is_empty() { 0 } else { low.parse().map_err(|_| PatternError::Syntax("repeat count too large".into()))? };
        if !high.is_empty() {
            let high_value: u64 = high.parse().map_err(|_| PatternError::Syntax("repeat count too large".into()))?;
            if high_value < low_value {
                return syntax("min repeat greater than max repeat");
            }
        }
        self.index = cursor;
        self.out.push_str(&format!("{{{low_value}"));
        if comma {
            self.out.push(',');
            self.out.push_str(&high);
        }
        self.out.push('}');
        self.after_quantifier()
    }

    fn group_open(&mut self, at: usize) -> Result<(), PatternError> {
        let inherit = self.ic();
        if !self.eat('?') {
            self.groups += 1;
            self.scopes.push(inherit);
            self.out.push('(');
            return Ok(());
        }
        let Some(kind) = self.peek(0) else { return syntax("unterminated group") };
        match kind {
            ':' => {
                self.index += 1;
                self.scopes.push(inherit);
                self.out.push_str("(?:");
            }
            '=' | '!' => {
                self.index += 1;
                self.reason(if kind == '=' { FancyReason::Lookahead } else { FancyReason::NegativeLookahead });
                self.scopes.push(inherit);
                self.out.push_str(&format!("(?{kind}"));
            }
            '>' => return syntax("atomic groups are not supported"),
            '#' => {
                while let Some(c) = self.peek(0) {
                    self.index += 1;
                    if c == ')' {
                        return Ok(());
                    }
                }
                return syntax("missing ), unterminated comment");
            }
            '<' => {
                self.index += 1;
                let negative = match self.peek(0) {
                    Some('=') => false,
                    Some('!') => true,
                    _ => return syntax("unsupported group syntax (?<"),
                };
                self.index += 1;
                self.reason(if negative { FancyReason::NegativeLookbehind } else { FancyReason::Lookbehind });
                self.scopes.push(inherit);
                self.out.push_str(if negative { "(?<!" } else { "(?<=" });
            }
            'P' => {
                self.index += 1;
                if self.eat('<') {
                    let mut name = String::new();
                    loop {
                        match self.peek(0) {
                            Some('>') => {
                                self.index += 1;
                                break;
                            }
                            Some(c) if c.is_ascii_alphanumeric() || c == '_' => {
                                name.push(c);
                                self.index += 1;
                            }
                            _ => return syntax("bad group name"),
                        }
                    }
                    if name.is_empty() || name.starts_with(|c: char| c.is_ascii_digit()) {
                        return syntax("bad group name");
                    }
                    self.groups += 1;
                    self.names.push((name.clone(), self.groups));
                    self.scopes.push(inherit);
                    self.out.push_str(&format!("(?P<{name}>"));
                } else {
                    return syntax("unsupported group syntax (?P");
                }
            }
            _ => {
                // Inline flags: `(?i)` (pattern start only) or `(?i:...)`, `(?-i:...)`.
                let mut on = String::new();
                let mut off = String::new();
                let mut negative = false;
                loop {
                    let Some(c) = self.peek(0) else { return syntax("missing flag terminator") };
                    self.index += 1;
                    match c {
                        '-' if !negative => negative = true,
                        'i' => (if negative { &mut off } else { &mut on }).push('i'),
                        ')' => {
                            if negative {
                                return syntax("missing :");
                            }
                            if at != 0 {
                                return syntax("global flags not at the start of the expression");
                            }
                            if on != "i" {
                                return syntax("unsupported global flags");
                            }
                            self.scopes[0] = true;
                            return Ok(());
                        }
                        ':' => {
                            let scoped = if !off.is_empty() {
                                false
                            } else if !on.is_empty() {
                                true
                            } else {
                                return syntax("missing flag");
                            };
                            self.scopes.push(scoped);
                            self.out.push_str(if scoped { "(?i:" } else { "(?-i:" });
                            return Ok(());
                        }
                        _ => return syntax(format!("unsupported inline flag {c:?}")),
                    }
                }
            }
        }
        Ok(())
    }

    fn hex(&mut self, digits: usize) -> Result<char, PatternError> {
        let mut value = 0u32;
        for _ in 0..digits {
            let Some(d) = self.peek(0).and_then(|c| c.to_digit(16)) else { return syntax("incomplete escape") };
            value = value * 16 + d;
            self.index += 1;
        }
        char::from_u32(value).map_or_else(|| syntax("bad escape"), Ok)
    }

    /// Parse the escape after a backslash into a character, for escapes that denote one.
    fn char_escape(&mut self, c: char, in_class: bool) -> Result<char, PatternError> {
        Ok(match c {
            'a' => '\x07',
            'f' => '\x0c',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'v' => '\x0b',
            'x' => self.hex(2)?,
            'u' => self.hex(4)?,
            'U' => self.hex(8)?,
            '0' => {
                let mut value = 0u32;
                for _ in 0..2 {
                    match self.peek(0).and_then(|d| d.to_digit(8)) {
                        Some(d) => {
                            value = value * 8 + d;
                            self.index += 1;
                        }
                        None => break,
                    }
                }
                char::from_u32(value).map_or_else(|| syntax("bad escape"), Ok)?
            }
            '1'..='9' if in_class => {
                let mut value = c.to_digit(8).ok_or_else(|| PatternError::Syntax("bad escape in class".into()))?;
                for _ in 0..2 {
                    match self.peek(0).and_then(|d| d.to_digit(8)) {
                        Some(d) => {
                            value = value * 8 + d;
                            self.index += 1;
                        }
                        None => break,
                    }
                }
                char::from_u32(value).map_or_else(|| syntax("bad escape"), Ok)?
            }
            c if c.is_ascii_alphanumeric() => return syntax(format!("bad escape \\{c}")),
            c => c,
        })
    }

    fn escape_outside(&mut self) -> Result<(), PatternError> {
        let Some(c) = self.peek(0) else { return syntax("bad escape (end of pattern)") };
        self.index += 1;
        match c {
            'd' => self.out.push_str(&format!("[{DIGIT_ITEMS}]")),
            'D' => self.out.push_str(&format!("[^{DIGIT_ITEMS}]")),
            'w' => self.out.push_str(&format!("[{WORD_ITEMS}]")),
            'W' => self.out.push_str(&format!("[^{WORD_ITEMS}]")),
            's' => self.out.push_str(&format!("[{SPACE_ITEMS}]")),
            'S' => self.out.push_str(&format!("[^{SPACE_ITEMS}]")),
            'b' => self.out.push_str(r"\b"),
            'B' => self.out.push_str(r"\B"),
            'A' => self.out.push_str(r"\A"),
            'Z' => self.out.push_str(r"\z"),
            '1'..='9' => {
                // Three octal digits are an octal escape; otherwise a group reference.
                if c <= '7'
                    && self.peek(0).is_some_and(|d| ('0'..='7').contains(&d))
                    && self.peek(1).is_some_and(|d| ('0'..='7').contains(&d))
                {
                    let mut value = c.to_digit(8).unwrap_or(0);
                    for _ in 0..2 {
                        value = value * 8 + self.peek(0).and_then(|d| d.to_digit(8)).unwrap_or(0);
                        self.index += 1;
                    }
                    match char::from_u32(value) {
                        Some(ch) => literal(ch, &mut self.out),
                        None => return syntax("bad escape"),
                    }
                } else {
                    let mut number = c.to_digit(10).unwrap_or(0) as usize;
                    if let Some(d) = self.peek(0).and_then(|d| d.to_digit(10)) {
                        number = number * 10 + d as usize;
                        self.index += 1;
                    }
                    if number > self.groups {
                        return syntax(format!("invalid group reference {number}"));
                    }
                    self.reason(FancyReason::BackReference);
                    self.out.push_str(&format!(r"\{number}"));
                }
            }
            _ => {
                let ch = self.char_escape(c, false)?;
                self.emit_char(ch);
            }
        }
        Ok(())
    }

    fn class_char(&mut self) -> Result<Option<ClassItem>, PatternError> {
        let Some(c) = self.peek(0) else { return syntax("unterminated character set") };
        self.index += 1;
        if c != '\\' {
            return Ok(Some(ClassItem::Char(c)));
        }
        let Some(e) = self.peek(0) else { return syntax("bad escape (end of pattern)") };
        self.index += 1;
        Ok(Some(match e {
            'd' | 'w' | 's' => ClassItem::Shorthand(e),
            'D' => ClassItem::Negated('d'),
            'W' => ClassItem::Negated('w'),
            'S' => ClassItem::Negated('s'),
            'b' => ClassItem::Char('\x08'),
            _ => ClassItem::Char(self.char_escape(e, true)?),
        }))
    }

    fn class(&mut self) -> Result<(), PatternError> {
        let negate = self.eat('^');
        let mut items: Vec<ClassItem> = Vec::new();
        let mut first = true;
        loop {
            let Some(c) = self.peek(0) else { return syntax("unterminated character set") };
            if c == ']' && !first {
                self.index += 1;
                break;
            }
            first = false;
            let Some(item) = self.class_char()? else { return syntax("unterminated character set") };
            let is_range = self.peek(0) == Some('-') && self.peek(1).is_some_and(|d| d != ']');
            match item {
                ClassItem::Char(low) if is_range => {
                    self.index += 1;
                    let Some(high) = self.class_char()? else { return syntax("unterminated character set") };
                    match high {
                        ClassItem::Char(high) if high >= low => items.push(ClassItem::Range(low, high)),
                        ClassItem::Char(_) => return syntax("bad character range"),
                        _ => return syntax("bad character range"),
                    }
                }
                ClassItem::Shorthand(_) | ClassItem::Negated(_) if is_range => return syntax("bad character range"),
                other => items.push(other),
            }
        }
        let ic = self.ic();
        let holds_i = ic
            && items.iter().any(|item| match *item {
                ClassItem::Char(c) => matches!(c, 'i' | 'I'),
                ClassItem::Range(a, b) => (a <= 'i' && 'i' <= b) || (a <= 'I' && 'I' <= b),
                ClassItem::Shorthand(_) | ClassItem::Negated(_) => false,
            });
        self.out.push('[');
        if negate {
            self.out.push('^');
        }
        for item in &items {
            match *item {
                ClassItem::Char(c) => literal(c, &mut self.out),
                ClassItem::Range(a, b) => {
                    literal(a, &mut self.out);
                    self.out.push('-');
                    literal(b, &mut self.out);
                }
                ClassItem::Shorthand(letter) => self.out.push_str(shorthand_items(letter)),
                ClassItem::Negated(letter) => {
                    // A nested negated set is a union member in both engines.
                    self.out.push_str("[^");
                    self.out.push_str(shorthand_items(letter));
                    self.out.push(']');
                }
            }
        }
        if holds_i {
            self.out.push_str(r"\x{130}\x{131}");
        }
        self.out.push(']');
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn find_all(pattern: &str, text: &str) -> Vec<String> {
        let regex = PyRegex::new(pattern, true).expect("compiles");
        let hay = Haystack::new(text);
        regex.find_iter(&hay).expect("matches").iter().map(|m| hay.slice(m.start, m.end)).collect()
    }

    #[test]
    fn classes_follow_python_not_rust() {
        // Combining acute accent is not a Python word character; superscript two is.
        assert_eq!(find_all(r"\w+", "ab\u{301}c"), vec!["ab", "c"]);
        assert_eq!(find_all(r"\w+", "x\u{b2}"), vec!["x\u{b2}"]);
        assert_eq!(find_all(r"\d+", "a\u{663}\u{664}b"), vec!["\u{663}\u{664}"]);
        assert_eq!(find_all(r"a\sb", "a\u{1c}b"), vec!["a\u{1c}b"]);
        assert_eq!(find_all(r"\bfoo\b", "foo\u{301}"), vec!["foo"]);
    }

    #[test]
    fn ignorecase_extras_match_python() {
        assert_eq!(find_all("kelvin", "\u{212a}elvin"), vec!["\u{212a}elvin"]);
        assert_eq!(find_all("ill", "\u{130}ll \u{131}ll"), vec!["\u{130}ll", "\u{131}ll"]);
        assert_eq!(find_all("[a-z]+", "\u{131}\u{130}"), vec!["\u{131}\u{130}"]);
        assert!(find_all("[^a-z]+", "\u{131}").is_empty());
    }

    #[test]
    fn dollar_matches_before_a_final_newline() {
        assert_eq!(find_all(r"a$", "a\n"), vec!["a"]);
        assert_eq!(find_all(r"a$", "a"), vec!["a"]);
        assert!(find_all(r"a$", "a\nb").is_empty());
    }

    #[test]
    fn lookaround_and_references_use_the_backtracking_engine() {
        let regex = PyRegex::new(r"(?<!\w)@(?!x)\w+", true).expect("compiles");
        assert_eq!(regex.fancy_reasons(), &[FancyReason::NegativeLookbehind, FancyReason::NegativeLookahead]);
        let mac = PyRegex::new(r"\b[0-9a-f]{2}([:-])(?:[0-9a-f]{2}\1){4}[0-9a-f]{2}\b", true).expect("compiles");
        assert_eq!(mac.fancy_reasons(), &[FancyReason::BackReference]);
        let hay = Haystack::new("aa:bb:cc:dd:ee:ff aa:bb-cc:dd:ee:ff");
        assert_eq!(mac.find_iter(&hay).expect("matches").len(), 1);
    }

    #[test]
    fn python_syntax_rules_are_enforced() {
        assert!(PyRegex::new(r"abc\z", true).is_err());
        assert!(PyRegex::new(r"a(?i)b", true).is_err());
        assert!(PyRegex::new(r"\p{L}", true).is_err());
        assert!(PyRegex::new(r"[b-a]", true).is_err());
        assert_eq!(find_all(r"a{,2}b", "aab"), vec!["aab"]);
        assert_eq!(find_all(r"x{y", "x{y"), vec!["x{y"]);
    }
}
