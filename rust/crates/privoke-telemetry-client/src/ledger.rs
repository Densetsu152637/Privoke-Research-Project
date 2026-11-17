//! The installation-local, UTC-day epsilon ledger (`DailyPrivacyBudget` of `privacy.py`).
//!
//! One SQLite file, one row: the UTC day and the epsilon spent on it. A reservation is one `BEGIN IMMEDIATE`
//! transaction, so concurrent processes never overspend. Reservations are never refunded: a report that is later
//! dropped (a failed build, a full queue, a failed delivery) keeps its spend. Any fault fails closed with
//! [`PrivacyError::LedgerUnavailable`], and the caller sends nothing.
//!
//! The file layout is the Python one, so a ledger written by either implementation is read by the other.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, OptionalExtension};
use time::{OffsetDateTime, UtcOffset};

use crate::error::{LedgerFault, PrivacyError};
use crate::privacy::{EVENT_EPSILON_MAX, EVENT_EPSILON_MIN, has_six_decimals, validate_privacy_config};

/// Slack of the cap comparison, the oracle's `1e-12`.
const CAP_TOLERANCE: f64 = 1e-12;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const CREATE_TABLE: &str = "CREATE TABLE IF NOT EXISTS daily_budget (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), \
                            utc_day TEXT NOT NULL, epsilon_spent REAL NOT NULL)";
const FILE_NAME_WINDOWS: &str = "telemetry-budget.sqlite3";

/// The oracle's default ledger path, from an environment lookup, the platform and the home directory. Pure, so the
/// rules are testable without touching the process environment.
///
/// `TELEMETRY_PRIVACY_LEDGER_PATH` (with `~` expanded), else `%LOCALAPPDATA%\PriVoke` on Windows, else
/// `$XDG_STATE_HOME/privoke`, else `~/.local/state/privoke`.
pub fn default_ledger_path_with(
    lookup: &dyn Fn(&str) -> Option<String>,
    windows: bool,
    home: Option<PathBuf>,
) -> Result<PathBuf, PrivacyError> {
    let value = |name: &str| lookup(name).map(|text| text.trim().to_string()).filter(|text| !text.is_empty());
    let need_home = || home.clone().ok_or_else(|| PrivacyError::invalid("Could not determine the home directory."));
    if let Some(configured) = value("TELEMETRY_PRIVACY_LEDGER_PATH") {
        return expand_user(&configured, windows, &need_home);
    }
    if windows && let Some(root) = value("LOCALAPPDATA") {
        return Ok(PathBuf::from(root).join("PriVoke").join(FILE_NAME_WINDOWS));
    }
    if let Some(root) = value("XDG_STATE_HOME") {
        return Ok(PathBuf::from(root).join("privoke").join(FILE_NAME_WINDOWS));
    }
    Ok(need_home()?.join(".local").join("state").join("privoke").join(FILE_NAME_WINDOWS))
}

fn expand_user(configured: &str, windows: bool, home: &dyn Fn() -> Result<PathBuf, PrivacyError>) -> Result<PathBuf, PrivacyError> {
    if configured == "~" {
        return home();
    }
    let rest = configured.strip_prefix("~/").or_else(|| if windows { configured.strip_prefix("~\\") } else { None });
    match rest {
        Some(rest) => Ok(home()?.join(rest)),
        None => Ok(PathBuf::from(configured)),
    }
}

/// [`default_ledger_path_with`] over the real process environment.
pub fn default_ledger_path() -> Result<PathBuf, PrivacyError> {
    let windows = cfg!(windows);
    let home = if windows { std::env::var_os("USERPROFILE") } else { std::env::var_os("HOME") }.map(PathBuf::from);
    default_ledger_path_with(&|name| std::env::var(name).ok(), windows, home)
}

/// The UTC calendar day of `moment` as `YYYY-MM-DD` (Python's `date.isoformat()`).
fn utc_day(moment: OffsetDateTime) -> String {
    let utc = moment.to_offset(UtcOffset::UTC);
    format!("{:04}-{:02}-{:02}", utc.year(), u8::from(utc.month()), utc.day())
}

fn is_leap(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

/// Whether `text` is exactly what `date.fromisoformat(text).isoformat()` returns: `YYYY-MM-DD`, year 1 to 9999, a real
/// calendar day.
fn is_canonical_day(text: &str) -> bool {
    let bytes = text.as_bytes();
    let shape = bytes.len() == 10
        && bytes.iter().enumerate().all(|(index, byte)| if index == 4 || index == 7 { *byte == b'-' } else { byte.is_ascii_digit() });
    if !shape {
        return false;
    }
    let number = |range: std::ops::Range<usize>| text[range].parse::<u32>().unwrap_or(0);
    let (year, month, day) = (number(0..4), number(5..7), number(8..10));
    let length = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => return false,
    };
    year >= 1 && (1..=length).contains(&day)
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Atomic installation-local UTC-day epsilon ledger; reservations never refund.
#[derive(Debug, Clone)]
pub struct DailyPrivacyBudget {
    path: PathBuf,
    daily_epsilon: f64,
}

impl DailyPrivacyBudget {
    /// A ledger at `path` with a `daily_epsilon` cap. Nothing is created until the first reservation.
    pub fn new(path: impl Into<PathBuf>, daily_epsilon: f64) -> Result<Self, PrivacyError> {
        validate_privacy_config(EVENT_EPSILON_MIN, daily_epsilon)?;
        Ok(Self { path: path.into(), daily_epsilon })
    }

    /// The ledger file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The daily cap.
    pub fn daily_epsilon(&self) -> f64 {
        self.daily_epsilon
    }

    /// Try to spend `epsilon` on the UTC day of `now` (the current time when `None`). `Ok(true)` records the spend,
    /// `Ok(false)` means the cap would be exceeded and nothing changed. A fault of the file or its contents, or a
    /// clock that moved to an earlier UTC day, is `LedgerUnavailable`.
    pub fn reserve(&self, epsilon: f64, now: Option<OffsetDateTime>) -> Result<bool, PrivacyError> {
        if !epsilon.is_finite() || !(EVENT_EPSILON_MIN..=EVENT_EPSILON_MAX).contains(&epsilon) {
            return Err(PrivacyError::invalid("Reservation epsilon is outside the supported range."));
        }
        if !has_six_decimals(epsilon) {
            return Err(PrivacyError::invalid("Reservation epsilon must have at most six decimal places."));
        }
        if epsilon > self.daily_epsilon {
            return Ok(false);
        }
        let day = utc_day(now.unwrap_or_else(OffsetDateTime::now_utc));
        self.reserve_in_file(epsilon, &day).map_err(PrivacyError::LedgerUnavailable)
    }

    fn reserve_in_file(&self, epsilon: f64, day: &str) -> Result<bool, LedgerFault> {
        if let Some(parent) = self.path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            create_private_directory(parent)?;
        }
        let created = !self.path.exists();
        // No URI interpretation of the path, as `sqlite3.connect` without `uri=True`.
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let connection = Connection::open_with_flags(&self.path, flags)?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        if created {
            restrict_file(&self.path)?;
        }
        let integrity: Option<String> = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0)).optional()?;
        if integrity.as_deref() != Some("ok") {
            return Err(LedgerFault::Invalid("privacy budget ledger integrity check failed".to_string()));
        }
        connection.execute_batch(CREATE_TABLE)?;
        // From here an early return drops the connection, which rolls the transaction back.
        connection.execute_batch("BEGIN IMMEDIATE")?;
        connection.execute("INSERT OR IGNORE INTO daily_budget (singleton, utc_day, epsilon_spent) VALUES (1, ?, 0)", [day])?;
        let row: Option<(String, f64)> = connection
            .query_row("SELECT utc_day, epsilon_spent FROM daily_budget WHERE singleton = 1", [], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()?;
        let rows: i64 = connection.query_row("SELECT COUNT(*) FROM daily_budget", [], |row| row.get(0))?;
        if rows > 1 {
            return Err(LedgerFault::Invalid("privacy budget ledger has invalid rows".to_string()));
        }
        let Some((previous_day, mut spent)) = row else {
            return Err(LedgerFault::Invalid("privacy budget ledger contains invalid accounting data".to_string()));
        };
        if !spent.is_finite() || spent < 0.0 || spent > self.daily_epsilon {
            return Err(LedgerFault::Invalid("privacy budget ledger contains invalid accounting data".to_string()));
        }
        if !is_canonical_day(&previous_day) {
            return Err(LedgerFault::Invalid("privacy budget ledger contains an invalid UTC day".to_string()));
        }
        if day < previous_day.as_str() {
            return Err(LedgerFault::Invalid("system date moved backwards; budget ledger fails closed".to_string()));
        }
        if day > previous_day.as_str() {
            spent = 0.0;
        }
        if spent + epsilon > self.daily_epsilon + CAP_TOLERANCE {
            connection.execute_batch("ROLLBACK")?;
            return Ok(false);
        }
        connection.execute(
            "UPDATE daily_budget SET utc_day = ?, epsilon_spent = ? WHERE singleton = 1",
            rusqlite::params![day, spent + epsilon],
        )?;
        connection.execute_batch("COMMIT")?;
        Ok(true)
    }
}
