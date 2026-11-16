//! Process logging.

/// One log line on stderr. Callers pass only fixed text and aggregate counts: never a peer address or identity.
pub fn log(message: std::fmt::Arguments<'_>) {
    eprintln!("{message}");
}
