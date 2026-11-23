//! Process logging and small shared helpers.

use std::time::{SystemTime, UNIX_EPOCH};

/// One log line on stderr. Callers quote request-controlled values with `{:?}` so that a field cannot forge a line.
pub fn log(message: std::fmt::Arguments<'_>) {
    eprintln!("{message}");
}

/// Seconds since the Unix epoch, as Python's `time.time()`.
pub fn unix_seconds_f64() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0.0, |elapsed| elapsed.as_secs_f64())
}

/// Whole seconds since the Unix epoch, as Python's `int(time.time())`.
pub fn unix_seconds() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
}

/// Lowercase hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Decode lowercase or uppercase hexadecimal; `None` for odd length or a non-hex digit.
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let high = char::from(pair[0]).to_digit(16)?;
        let low = char::from(pair[1]).to_digit(16)?;
        out.push(u8::try_from(high * 16 + low).ok()?);
    }
    Some(out)
}

/// `validate_text`: bounded text before storage or interpolation into logs. Limits count characters.
pub fn validate_text(value: &str, field: &str, required: bool, limit: usize) -> Result<(), crate::error::Failure> {
    use crate::error::Failure;
    if required && value.is_empty() {
        return Err(Failure::invalid(format!("{field} is required.")));
    }
    if value.chars().count() > limit {
        return Err(Failure::invalid(format!("{field} exceeds {limit} characters.")));
    }
    if value.chars().any(|character| u32::from(character) < 32 || u32::from(character) == 127) {
        return Err(Failure::invalid(format!("{field} must not contain control characters.")));
    }
    Ok(())
}
