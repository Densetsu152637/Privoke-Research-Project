//! A strict JSON value and parser that mirror what Python's `json.loads` accepts for the PriVoke contracts.
//!
//! Integers keep their exact decimal digits (Python integers are unbounded) and floats keep IEEE-754 bits, so the
//! canonical writer can reproduce `json.dumps`. `NaN`, `Infinity`, overflowing floats and lone surrogate escapes are
//! rejected: no contract output can contain them (`allow_nan=False`, strict UTF-8).

use std::collections::BTreeMap;

/// A parsed JSON value. Objects are ordered by Unicode code point, the order of Python's `sort_keys=True`.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `null`
    Null,
    /// `true` or `false`
    Bool(bool),
    /// An integer as its canonical decimal digits (`-` prefix allowed, no leading zeros, `-0` becomes `0`).
    Int(String),
    /// A float literal, parsed with correct rounding.
    Float(f64),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Value>),
    /// An object.
    Object(BTreeMap<String, Value>),
}

/// What to do with a repeated object key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Duplicates {
    /// Keep the last value, as `json.loads` does.
    LastWins,
    /// Fail, as the V3 contract `parse` does.
    Reject,
}

/// Parser limits and policies.
#[derive(Debug, Clone, Copy)]
pub struct ParseOptions {
    /// Repeated key policy.
    pub duplicates: Duplicates,
    /// Maximum nesting depth.
    pub max_depth: usize,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self { duplicates: Duplicates::LastWins, max_depth: 256 }
    }
}

/// Why a document was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JsonError {
    /// Malformed JSON at a byte offset.
    #[error("invalid JSON at byte {offset}: {reason}")]
    Syntax {
        /// Byte offset of the failure.
        offset: usize,
        /// Short reason.
        reason: &'static str,
    },
    /// `NaN`, `Infinity`, or a float literal that overflows to infinity.
    #[error("non-finite number at byte {0}")]
    NonFinite(usize),
    /// A `\uD800`-style escape that is not part of a valid pair.
    #[error("lone surrogate escape at byte {0}")]
    LoneSurrogate(usize),
    /// A repeated key under [`Duplicates::Reject`].
    #[error("duplicate object key {0:?}")]
    DuplicateKey(String),
    /// Nesting deeper than the limit.
    #[error("nesting deeper than {0}")]
    TooDeep(usize),
    /// An integer with more than 4300 digits, which Python also refuses.
    #[error("integer exceeds 4300 digits")]
    IntegerTooLong,
}

/// Parse a JSON document with the default options.
pub fn parse(input: &str) -> Result<Value, JsonError> {
    parse_with(input, ParseOptions::default())
}

/// Parse a JSON document.
pub fn parse_with(input: &str, options: ParseOptions) -> Result<Value, JsonError> {
    let mut parser = Parser { bytes: input.as_bytes(), position: 0, options };
    parser.skip_whitespace();
    let value = parser.value(0)?;
    parser.skip_whitespace();
    if parser.position != parser.bytes.len() {
        return Err(parser.syntax("extra data after document"));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    position: usize,
    options: ParseOptions,
}

impl Parser<'_> {
    fn syntax(&self, reason: &'static str) -> JsonError {
        JsonError::Syntax { offset: self.position, reason }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn starts_with(&self, literal: &str) -> bool {
        self.bytes[self.position..].starts_with(literal.as_bytes())
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.position += 1;
        }
    }

    fn literal(&mut self, text: &str, value: Value) -> Result<Value, JsonError> {
        if self.starts_with(text) {
            self.position += text.len();
            Ok(value)
        } else {
            Err(self.syntax("invalid literal"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, JsonError> {
        if depth > self.options.max_depth {
            return Err(JsonError::TooDeep(self.options.max_depth));
        }
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            Some(b'N') if self.starts_with("NaN") => Err(JsonError::NonFinite(self.position)),
            Some(b'I') if self.starts_with("Infinity") => Err(JsonError::NonFinite(self.position)),
            Some(b'-') if self.starts_with("-Infinity") => Err(JsonError::NonFinite(self.position)),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(self.syntax("expected a value")),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, JsonError> {
        self.position += 1;
        let mut map = BTreeMap::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.position += 1;
            return Ok(Value::Object(map));
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(self.syntax("expected a string key"));
            }
            let key = self.string()?;
            self.skip_whitespace();
            if self.peek() != Some(b':') {
                return Err(self.syntax("expected ':'"));
            }
            self.position += 1;
            self.skip_whitespace();
            let value = self.value(depth + 1)?;
            if map.insert(key.clone(), value).is_some() && self.options.duplicates == Duplicates::Reject {
                return Err(JsonError::DuplicateKey(key));
            }
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.position += 1,
                Some(b'}') => {
                    self.position += 1;
                    return Ok(Value::Object(map));
                }
                _ => return Err(self.syntax("expected ',' or '}'")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, JsonError> {
        self.position += 1;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.position += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_whitespace();
            items.push(self.value(depth + 1)?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.position += 1,
                Some(b']') => {
                    self.position += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.syntax("expected ',' or ']'")),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let slice = self.bytes.get(self.position..self.position + 4).ok_or_else(|| self.syntax("truncated \\u escape"))?;
        let mut value = 0u32;
        for byte in slice {
            let digit = char::from(*byte).to_digit(16).ok_or_else(|| self.syntax("invalid \\u escape"))?;
            value = value * 16 + digit;
        }
        self.position += 4;
        Ok(value)
    }

    fn unicode_escape(&mut self) -> Result<char, JsonError> {
        let start = self.position - 2;
        let first = self.hex4()?;
        let code = if (0xD800..0xDC00).contains(&first) {
            if !self.starts_with("\\u") {
                return Err(JsonError::LoneSurrogate(start));
            }
            self.position += 2;
            let second = self.hex4()?;
            if !(0xDC00..0xE000).contains(&second) {
                return Err(JsonError::LoneSurrogate(start));
            }
            0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
        } else if (0xDC00..0xE000).contains(&first) {
            return Err(JsonError::LoneSurrogate(start));
        } else {
            first
        };
        char::from_u32(code).ok_or(JsonError::LoneSurrogate(start))
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.position += 1;
        let mut out = String::new();
        loop {
            let Some(byte) = self.peek() else {
                return Err(self.syntax("unterminated string"));
            };
            match byte {
                b'"' => {
                    self.position += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.position += 1;
                    let Some(escape) = self.peek() else {
                        return Err(self.syntax("unterminated escape"));
                    };
                    self.position += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape()?),
                        _ => return Err(self.syntax("invalid escape")),
                    }
                }
                0x00..=0x1f => return Err(self.syntax("control character in string")),
                _ => {
                    // Copy one UTF-8 scalar; the input is a valid &str so boundaries are sound.
                    let rest = &self.bytes[self.position..];
                    let width = match byte {
                        0x00..=0x7f => 1,
                        0xc0..=0xdf => 2,
                        0xe0..=0xef => 3,
                        _ => 4,
                    };
                    let chunk = std::str::from_utf8(&rest[..width.min(rest.len())]).map_err(|_| self.syntax("invalid UTF-8"))?;
                    out.push_str(chunk);
                    self.position += width;
                }
            }
        }
    }

    fn number(&mut self) -> Result<Value, JsonError> {
        let start = self.position;
        if self.peek() == Some(b'-') {
            self.position += 1;
        }
        match self.peek() {
            Some(b'0') => self.position += 1,
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(self.syntax("expected a digit")),
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            self.position += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.syntax("expected a digit after '.'"));
            }
            self.digits();
            is_float = true;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.position += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.position += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.syntax("expected an exponent digit"));
            }
            self.digits();
            is_float = true;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.position]).map_err(|_| self.syntax("invalid number"))?;
        if is_float {
            let value: f64 = text.parse().map_err(|_| JsonError::NonFinite(start))?;
            if !value.is_finite() {
                return Err(JsonError::NonFinite(start));
            }
            Ok(Value::Float(value))
        } else {
            let digits = text.trim_start_matches('-');
            if digits.len() > 4300 {
                return Err(JsonError::IntegerTooLong);
            }
            Ok(Value::Int(if digits == "0" { "0".to_string() } else { text.to_string() }))
        }
    }

    fn digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.position += 1;
        }
    }
}
