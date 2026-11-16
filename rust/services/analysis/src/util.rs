//! Small shared helpers.

/// One log line on stderr. Callers quote untrusted values with `{:?}` so that a request field cannot forge a line.
pub fn log(message: std::fmt::Arguments<'_>) {
    eprintln!("{message}");
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
