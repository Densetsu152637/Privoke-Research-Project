//! Just enough of Python's `json.loads` and `json.dumps` for the native-messaging transcripts to replay.
//!
//! The Python host decided everything from one question: is the message an object whose `action` is the string
//! `ensure_supervisor`? So the parser accepts Python's whole grammar (including `NaN`, `Infinity`, lone surrogate
//! escapes, duplicate keys with the last one winning and arbitrarily long integers) and keeps only what that question
//! needs. `serde_json` is stricter than Python on every one of those, which would turn a reply into a crash.

/// The part of a JSON value the host looks at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Json {
    /// `null`: the Python loop treated a top-level `null` as end of input.
    Null,
    /// A string.
    String(String),
    /// An object, reduced to the value of its `action` key (the last duplicate wins).
    Object { action: Option<Box<Json>> },
    /// Any other value.
    Other,
}

const MAX_DEPTH: usize = 900;

/// Parse a complete document. The error text follows Python's wording where it is cheap to; the transcripts mark the
/// JSON error messages informational.
pub fn parse(text: &str) -> Result<Json, String> {
    let mut parser = Parser { bytes: text.as_bytes(), position: 0 };
    parser.skip_whitespace();
    let value = parser.value(0)?;
    parser.skip_whitespace();
    if parser.position != parser.bytes.len() {
        return Err(parser.error("Extra data"));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Parser<'_> {
    fn error(&self, message: &str) -> String {
        let before = &self.bytes[..self.position.min(self.bytes.len())];
        let line = before.iter().filter(|byte| **byte == b'\n').count() + 1;
        let column = before.iter().rposition(|byte| *byte == b'\n').map_or(self.position + 1, |index| self.position - index);
        format!("{message}: line {line} column {column} (char {})", self.position)
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.bytes.get(self.position), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.position += 1;
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, String> {
        if depth > MAX_DEPTH {
            return Err("maximum recursion depth exceeded".into());
        }
        match self.bytes.get(self.position) {
            Some(b'"') => Ok(Json::String(self.string()?)),
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'n') if self.keyword("null") => Ok(Json::Null),
            Some(b't') if self.keyword("true") => Ok(Json::Other),
            Some(b'f') if self.keyword("false") => Ok(Json::Other),
            Some(b'N') if self.keyword("NaN") => Ok(Json::Other),
            Some(b'I') if self.keyword("Infinity") => Ok(Json::Other),
            Some(b'-') if self.bytes[self.position..].starts_with(b"-Infinity") => {
                self.position += "-Infinity".len();
                Ok(Json::Other)
            }
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(self.error("Expecting value")),
        }
    }

    fn keyword(&mut self, word: &str) -> bool {
        if self.bytes[self.position..].starts_with(word.as_bytes()) {
            self.position += word.len();
            true
        } else {
            false
        }
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.position;
        if self.bytes.get(self.position) == Some(&b'-') {
            self.position += 1;
        }
        match self.bytes.get(self.position) {
            Some(b'0') => self.position += 1,
            Some(b'1'..=b'9') => self.digits(),
            _ => {
                self.position = start;
                return Err(self.error("Expecting value"));
            }
        }
        if self.bytes.get(self.position) == Some(&b'.') && self.bytes.get(self.position + 1).is_some_and(u8::is_ascii_digit) {
            self.position += 1;
            self.digits();
        }
        if matches!(self.bytes.get(self.position), Some(b'e' | b'E')) {
            let mut look = self.position + 1;
            if matches!(self.bytes.get(look), Some(b'+' | b'-')) {
                look += 1;
            }
            if self.bytes.get(look).is_some_and(u8::is_ascii_digit) {
                self.position = look;
                self.digits();
            }
        }
        Ok(Json::Other)
    }

    fn digits(&mut self) {
        while self.bytes.get(self.position).is_some_and(u8::is_ascii_digit) {
            self.position += 1;
        }
    }

    fn string(&mut self) -> Result<String, String> {
        let start = self.position;
        self.position += 1; // opening quote
        let mut text = String::new();
        let mut high_surrogate: Option<u32> = None;
        loop {
            let Some(&byte) = self.bytes.get(self.position) else {
                self.position = start;
                return Err(self.error("Unterminated string starting at"));
            };
            match byte {
                b'"' => {
                    self.position += 1;
                    if high_surrogate.is_some() {
                        text.push('\u{FFFD}');
                    }
                    return Ok(text);
                }
                b'\\' => {
                    self.position += 1;
                    let escape = self.bytes.get(self.position).copied();
                    self.position += 1;
                    let character = match escape {
                        Some(b'"') => '"',
                        Some(b'\\') => '\\',
                        Some(b'/') => '/',
                        Some(b'b') => '\u{8}',
                        Some(b'f') => '\u{c}',
                        Some(b'n') => '\n',
                        Some(b'r') => '\r',
                        Some(b't') => '\t',
                        Some(b'u') => {
                            let unit = self.hex4()?;
                            match (high_surrogate.take(), unit) {
                                (Some(high), 0xDC00..=0xDFFF) => {
                                    char::from_u32(0x10000 + ((high - 0xD800) << 10) + (unit - 0xDC00)).unwrap_or('\u{FFFD}')
                                }
                                (pending, _) => {
                                    if pending.is_some() {
                                        text.push('\u{FFFD}');
                                    }
                                    if (0xD800..=0xDBFF).contains(&unit) {
                                        high_surrogate = Some(unit);
                                        continue;
                                    }
                                    // A lone low surrogate is a valid Python str; Rust has no such char.
                                    char::from_u32(unit).unwrap_or('\u{FFFD}')
                                }
                            }
                        }
                        _ => {
                            self.position -= 1;
                            return Err(self.error("Invalid \\escape"));
                        }
                    };
                    if high_surrogate.take().is_some() {
                        text.push('\u{FFFD}');
                    }
                    text.push(character);
                }
                0..=0x1f => return Err(self.error("Invalid control character at")),
                _ => {
                    if high_surrogate.take().is_some() {
                        text.push('\u{FFFD}');
                    }
                    // The input is valid UTF-8 (the caller decoded it), so copy the whole scalar.
                    let rest = std::str::from_utf8(&self.bytes[self.position..]).map_err(|_| self.error("Invalid UTF-8"))?;
                    let Some(character) = rest.chars().next() else { return Err(self.error("Invalid UTF-8")) };
                    text.push(character);
                    self.position += character.len_utf8();
                }
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let digits = self.bytes.get(self.position..self.position + 4).filter(|slice| slice.iter().all(u8::is_ascii_hexdigit));
        let Some(digits) = digits else { return Err(self.error("Invalid \\uXXXX escape")) };
        self.position += 4;
        let text = std::str::from_utf8(digits).map_err(|_| "Invalid \\uXXXX escape".to_string())?;
        u32::from_str_radix(text, 16).map_err(|_| "Invalid \\uXXXX escape".to_string())
    }

    fn array(&mut self, depth: usize) -> Result<Json, String> {
        self.position += 1;
        self.skip_whitespace();
        if self.bytes.get(self.position) == Some(&b']') {
            self.position += 1;
            return Ok(Json::Other);
        }
        loop {
            self.skip_whitespace();
            self.value(depth + 1)?;
            self.skip_whitespace();
            match self.bytes.get(self.position) {
                Some(b',') => self.position += 1,
                Some(b']') => {
                    self.position += 1;
                    return Ok(Json::Other);
                }
                _ => return Err(self.error("Expecting ',' delimiter")),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, String> {
        self.position += 1;
        self.skip_whitespace();
        let mut action = None;
        if self.bytes.get(self.position) == Some(&b'}') {
            self.position += 1;
            return Ok(Json::Object { action });
        }
        loop {
            self.skip_whitespace();
            if self.bytes.get(self.position) != Some(&b'"') {
                return Err(self.error("Expecting property name enclosed in double quotes"));
            }
            let key = self.string()?;
            self.skip_whitespace();
            if self.bytes.get(self.position) != Some(&b':') {
                return Err(self.error("Expecting ':' delimiter"));
            }
            self.position += 1;
            self.skip_whitespace();
            let value = self.value(depth + 1)?;
            if key == "action" {
                action = Some(Box::new(value));
            }
            self.skip_whitespace();
            match self.bytes.get(self.position) {
                Some(b',') => self.position += 1,
                Some(b'}') => {
                    self.position += 1;
                    return Ok(Json::Object { action });
                }
                _ => return Err(self.error("Expecting ',' delimiter")),
            }
        }
    }
}

/// `json.dumps(value, separators=(",", ":"))` for a string: `ensure_ascii`, so every non-ASCII character becomes a
/// `\uXXXX` escape (a surrogate pair above the BMP) in lowercase hex.
pub fn dump_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(character),
            _ => {
                let mut units = [0u16; 2];
                for unit in character.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::bool_assert_comparison)]
mod tests {
    use super::*;

    fn action(text: &str) -> Option<Json> {
        match parse(text) {
            Ok(Json::Object { action }) => action.map(|boxed| *boxed),
            other => panic!("not an object: {other:?}"),
        }
    }

    #[test]
    fn accepts_what_python_accepts() {
        assert_eq!(action(r#"{"action":"ensure_supervisor"}"#), Some(Json::String("ensure_supervisor".into())));
        assert_eq!(action(r#"{"action":"a","action":"b"}"#), Some(Json::String("b".into())));
        assert_eq!(action(r#"{"x":NaN,"y":[Infinity,-Infinity,1e400,12345678901234567890123],"action":"\ud83d"}"#).is_some(), true);
        assert_eq!(parse("null"), Ok(Json::Null));
        assert_eq!(parse(" \t\r\n[1, 2, 3]\n"), Ok(Json::Other));
        assert_eq!(action("{\"action\":\"\\u00e9\\u4e2d\\ud83d\\ude00\"}"), Some(Json::String("é中😀".into())));
    }

    #[test]
    fn refuses_what_python_refuses() {
        for bad in ["", "{not json", "{", "[1,]", "{\"a\":1,}", "01", "\"a\nb\"", "[1] 2", "{\"a\" 1}", "nul", "tru"] {
            assert!(parse(bad).is_err(), "{bad:?} should fail");
        }
        assert_eq!(parse("").unwrap_err(), "Expecting value: line 1 column 1 (char 0)");
        assert_eq!(parse("{not json").unwrap_err(), "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)");
    }

    #[test]
    fn deep_nesting_is_an_error_not_a_crash() {
        let text = "[".repeat(5000);
        assert!(parse(&text).is_err());
    }

    #[test]
    fn dumps_like_ensure_ascii() {
        assert_eq!(dump_string("plain /\"\\\n\t\u{1}"), "\"plain /\\\"\\\\\\n\\t\\u0001\"");
        assert_eq!(dump_string("é中😀\u{7f}"), "\"\\u00e9\\u4e2d\\ud83d\\ude00\\u007f\"");
    }
}
