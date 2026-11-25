//! The durable `fits` table of `runtime_server.py`: one row per fit request identity, written (`started`) before the fit runs
//! and updated with `completed` and the candidate, or `failed` and the reason. A row that stays `started` means that the
//! outcome is unknown; the identity is never replayed (`ALREADY_EXISTS`).
//!
//! The database is the Python service's: `fits.sqlite` in the state directory, `synchronous=FULL`, autocommit, and the table
//! `fits(id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, status TEXT NOT NULL, candidate TEXT NOT NULL, reason TEXT NOT NULL)`.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension};

use crate::error::Result;

/// One row of the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The request identity.
    pub id: String,
    /// The fingerprint of the first request with this identity.
    pub fingerprint: String,
    /// `started`, `completed` or `failed`.
    pub status: String,
    /// The published candidate (empty until `completed`).
    pub candidate: String,
    /// The failure (empty unless `failed`).
    pub reason: String,
}

/// The open database.
#[derive(Debug)]
pub struct FitStore {
    connection: Connection,
}

impl FitStore {
    /// Open (creating the directory, the file and the table) the database under `directory`.
    pub fn open(directory: &Path) -> Result<Self> {
        std::fs::create_dir_all(directory)?;
        let connection = Connection::open(directory.join("fits.sqlite"))?;
        connection.execute_batch("PRAGMA synchronous=FULL")?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS fits(id TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,status TEXT NOT NULL,candidate TEXT NOT NULL,reason TEXT NOT NULL)",
        )?;
        Ok(Self { connection })
    }

    /// `SELECT fingerprint,status FROM fits WHERE id=?`.
    pub fn prior(&self, id: &str) -> Result<Option<(String, String)>> {
        Ok(self
            .connection
            .query_row("SELECT fingerprint,status FROM fits WHERE id=?1", [id], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()?)
    }

    /// `INSERT INTO fits VALUES (?,?, 'started','','')`: the identity is reserved before any work starts.
    pub fn start(&self, id: &str, fingerprint: &str) -> Result<()> {
        self.connection.execute("INSERT INTO fits VALUES (?1, ?2, 'started', '', '')", (id, fingerprint))?;
        Ok(())
    }

    /// `UPDATE fits SET status='completed',candidate=? WHERE id=?`.
    pub fn complete(&self, id: &str, candidate: &str) -> Result<()> {
        self.connection.execute("UPDATE fits SET status='completed',candidate=?1 WHERE id=?2", (candidate, id))?;
        Ok(())
    }

    /// `UPDATE fits SET status='failed',reason=? WHERE id=?`.
    pub fn fail(&self, id: &str, reason: &str) -> Result<()> {
        self.connection.execute("UPDATE fits SET status='failed',reason=?1 WHERE id=?2", (reason, id))?;
        Ok(())
    }

    /// `SELECT status,candidate,reason FROM fits WHERE id=?`.
    pub fn status(&self, id: &str) -> Result<Option<(String, String, String)>> {
        Ok(self
            .connection
            .query_row("SELECT status,candidate,reason FROM fits WHERE id=?1", [id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .optional()?)
    }

    /// Every row, ordered by identity (for the parity tests).
    pub fn rows(&self) -> Result<Vec<Row>> {
        let mut statement = self.connection.prepare("SELECT id,fingerprint,status,candidate,reason FROM fits ORDER BY id")?;
        let rows = statement.query_map([], |row| {
            Ok(Row { id: row.get(0)?, fingerprint: row.get(1)?, status: row.get(2)?, candidate: row.get(3)?, reason: row.get(4)? })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_fit_is_started_then_completed_or_failed_and_never_reserved_twice() {
        let directory = tempfile::tempdir().unwrap();
        let store = FitStore::open(directory.path()).unwrap();
        assert_eq!(store.prior("a").unwrap(), None);
        assert_eq!(store.status("a").unwrap(), None);
        store.start("a", "fp").unwrap();
        assert_eq!(store.prior("a").unwrap(), Some(("fp".into(), "started".into())));
        assert_eq!(store.status("a").unwrap(), Some(("started".into(), String::new(), String::new())));
        assert!(store.start("a", "other").is_err());
        store.complete("a", &"c".repeat(64)).unwrap();
        assert_eq!(store.status("a").unwrap(), Some(("completed".into(), "c".repeat(64), String::new())));
        store.start("b", "fp2").unwrap();
        store.fail("b", "ValueError: no").unwrap();
        assert_eq!(store.status("b").unwrap(), Some(("failed".into(), String::new(), "ValueError: no".into())));
        assert_eq!(store.rows().unwrap().iter().map(|row| row.id.as_str()).collect::<Vec<_>>(), vec!["a", "b"]);
    }

    #[test]
    fn the_rows_survive_a_restart() {
        let directory = tempfile::tempdir().unwrap();
        FitStore::open(directory.path()).unwrap().start("a", "fp").unwrap();
        let reopened = FitStore::open(directory.path()).unwrap();
        assert_eq!(reopened.prior("a").unwrap(), Some(("fp".into(), "started".into())));
    }
}
