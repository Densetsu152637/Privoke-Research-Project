//! Small shared helpers.

/// Lowercase hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// One log line on stderr, as Go's `log.Printf` wrote. Values are quoted with `{:?}` by the callers so that a request
/// field cannot forge a log line.
pub fn log(message: std::fmt::Arguments<'_>) {
    eprintln!("{message}");
}
