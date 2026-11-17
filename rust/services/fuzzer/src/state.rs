//! The durable curriculum state of `prompt_generation/curriculum.py`: a SQLite database with the Python tables
//! (`batches`, `cursors`), opened by the Python service's databases as they are.
//!
//! [`privoke_curriculum::curriculum::CursorState`] is infallible, so a write that fails is remembered and
//! [`SqliteState::finish`] rolls the whole reservation back instead of committing a partial one. Python wraps one
//! reservation in `BEGIN IMMEDIATE` and a commit; so does this type, one instance per reservation.

use std::path::Path;
use std::time::Duration;

use privoke_curriculum::curriculum::CursorState;
use privoke_curriculum::value::{self, Value};
use rusqlite::{Connection, OptionalExtension};

use crate::error::{Error, Result};

/// One open reservation transaction over the curriculum database.
#[derive(Debug)]
pub struct SqliteState {
    connection: Connection,
    failure: Option<String>,
}

impl SqliteState {
    /// Open (creating the tables) and take the write lock, as `BEGIN IMMEDIATE`.
    pub fn begin(path: &Path) -> Result<Self> {
        let connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(30))?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS batches (identity TEXT PRIMARY KEY, fingerprint TEXT, allocation TEXT);
             CREATE TABLE IF NOT EXISTS cursors (identity TEXT PRIMARY KEY, position INTEGER);
             BEGIN IMMEDIATE;",
        )?;
        Ok(Self { connection, failure: None })
    }

    /// Commit when the reservation succeeded and no write failed; roll back otherwise.
    pub fn finish(self, succeeded: bool) -> Result<()> {
        if succeeded && self.failure.is_none() {
            self.connection.execute_batch("COMMIT")?;
            return Ok(());
        }
        let _ = self.connection.execute_batch("ROLLBACK");
        match self.failure {
            Some(message) => Err(Error(message)),
            None => Ok(()),
        }
    }

    fn remember(&mut self, result: rusqlite::Result<usize>) {
        if let Err(error) = result
            && self.failure.is_none()
        {
            self.failure = Some(error.to_string());
        }
    }
}

impl CursorState for SqliteState {
    fn allocation(&self, identity: &str) -> Option<(String, Value)> {
        let row: Option<(Option<String>, Option<String>)> = self
            .connection
            .query_row("SELECT fingerprint, allocation FROM batches WHERE identity=?1", [identity], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()
            .ok()?;
        let (fingerprint, allocation) = row?;
        Some((fingerprint.unwrap_or_default(), value::parse_bytes(allocation?.as_bytes()).ok()?))
    }

    fn store_allocation(&mut self, identity: &str, fingerprint: &str, allocation: &Value) {
        match value::dumps(allocation) {
            Ok(text) => {
                let result = self.connection.execute("INSERT INTO batches VALUES (?1, ?2, ?3)", (identity, fingerprint, text));
                self.remember(result);
            }
            Err(error) => {
                if self.failure.is_none() {
                    self.failure = Some(error.to_string());
                }
            }
        }
    }

    fn cursor(&self, key: &str) -> Option<i64> {
        self.connection.query_row("SELECT position FROM cursors WHERE identity=?1", [key], |row| row.get::<_, i64>(0)).optional().ok()?
    }

    fn set_cursor(&mut self, key: &str, position: i64) {
        let result = self.connection.execute("INSERT OR REPLACE INTO cursors VALUES (?1, ?2)", (key, position));
        self.remember(result);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_committed_reservation_is_durable_and_a_rolled_back_one_is_not() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("curriculum.sqlite3");
        let allocation = value::object(vec![("train", value::strings(&["a"]))]);
        let mut state = SqliteState::begin(&path).unwrap();
        state.store_allocation("one", "fp", &allocation);
        state.set_cursor("key", 4);
        state.finish(true).unwrap();
        let state = SqliteState::begin(&path).unwrap();
        assert_eq!(state.allocation("one"), Some(("fp".to_string(), allocation.clone())));
        assert_eq!(state.cursor("key"), Some(4));
        assert_eq!(state.cursor("other"), None);
        state.finish(true).unwrap();

        let mut state = SqliteState::begin(&path).unwrap();
        state.set_cursor("key", 9);
        state.store_allocation("two", "fp2", &allocation);
        state.finish(false).unwrap();
        let state = SqliteState::begin(&path).unwrap();
        assert_eq!(state.cursor("key"), Some(4));
        assert_eq!(state.allocation("two"), None);
    }

    #[test]
    fn a_failed_write_prevents_the_commit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("curriculum.sqlite3");
        let allocation = value::object(vec![("train", value::strings(&["a"]))]);
        let mut state = SqliteState::begin(&path).unwrap();
        state.store_allocation("one", "fp", &allocation);
        state.store_allocation("one", "fp", &allocation);
        assert!(state.finish(true).is_err());
        let state = SqliteState::begin(&path).unwrap();
        assert_eq!(state.allocation("one"), None);
    }
}
