//! The rows of the client lineage attack table (stage V3-R4a). When `PRIVOKE_LINEAGE_ROWS_OUT` names a file, every row a test
//! observes is appended to it as one JSON line; `evaluation/update_security.py --rust-service client-lineage` reads that file and
//! judges each row against its own table of expected outcomes.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::sync::Mutex;

static LOCK: Mutex<()> = Mutex::new(());

/// Record one observed row: `expected` and `observed` are `accepted` or `refused`, `reason` names the refusal (empty when accepted).
pub fn record(id: &str, name: &str, expected: &str, observed: &str, reason: &str) {
    let Some(path) = std::env::var_os("PRIVOKE_LINEAGE_ROWS_OUT").filter(|value| !value.is_empty()) else { return };
    let _guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let line = serde_json::json!({ "id": id, "name": name, "expected": expected, "observed": observed, "reason": reason });
    let mut file = std::fs::OpenOptions::new().create(true).append(true).open(path).expect("open the rows file");
    writeln!(file, "{line}").expect("write a row");
}
