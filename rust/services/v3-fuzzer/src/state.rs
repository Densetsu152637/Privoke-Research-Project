//! The durable `cycles` table of `fuzzer_server.py`: one row per request identity, written before the fit starts and updated
//! with the response once the cycle ends. A row whose response is still `NULL` means that the outcome of the cycle is
//! unknown, and the identity is never replayed.
//!
//! The database is the Python service's: `cycles.sqlite` in the state directory, `synchronous=FULL`, autocommit, and the table
//! `cycles(id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, response BLOB)`.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension};

use crate::error::Result;

/// A request identity seen before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prior {
    /// The fingerprint of the first request with this identity.
    pub fingerprint: String,
    /// Its response bytes, or `None` while the outcome is unknown.
    pub response: Option<Vec<u8>>,
}

/// One row of the table.
pub type Row = (String, String, Option<Vec<u8>>);

/// The open database.
#[derive(Debug)]
pub struct CycleStore {
    connection: Connection,
}

impl CycleStore {
    /// Open (creating the directory, the file and the table) the database under `directory`.
    pub fn open(directory: &Path) -> Result<Self> {
        std::fs::create_dir_all(directory)?;
        let connection = Connection::open(directory.join("cycles.sqlite"))?;
        connection.execute_batch("PRAGMA synchronous=FULL")?;
        connection.execute_batch("CREATE TABLE IF NOT EXISTS cycles(id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, response BLOB)")?;
        Ok(Self { connection })
    }

    /// `SELECT fingerprint,response FROM cycles WHERE id=?`.
    pub fn prior(&self, id: &str) -> Result<Option<Prior>> {
        let row = self
            .connection
            .query_row("SELECT fingerprint,response FROM cycles WHERE id=?1", [id], |row| {
                Ok(Prior { fingerprint: row.get(0)?, response: row.get(1)? })
            })
            .optional()?;
        Ok(row)
    }

    /// `INSERT INTO cycles VALUES (?,?,NULL)`: the identity is reserved before any work starts.
    pub fn reserve(&self, id: &str, fingerprint: &str) -> Result<()> {
        self.connection.execute("INSERT INTO cycles VALUES (?1, ?2, NULL)", (id, fingerprint))?;
        Ok(())
    }

    /// `UPDATE cycles SET response=? WHERE id=?`.
    pub fn record(&self, id: &str, response: &[u8]) -> Result<()> {
        self.connection.execute("UPDATE cycles SET response=?1 WHERE id=?2", (response, id))?;
        Ok(())
    }

    /// Every row, ordered by identity (for the parity tests).
    pub fn rows(&self) -> Result<Vec<Row>> {
        let mut statement = self.connection.prepare("SELECT id,fingerprint,response FROM cycles ORDER BY id")?;
        let rows =
            statement.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<Vec<u8>>>(2)?)))?;
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
    fn a_reserved_identity_has_no_response_until_the_cycle_ends() {
        let directory = tempfile::tempdir().unwrap();
        let store = CycleStore::open(directory.path()).unwrap();
        assert_eq!(store.prior("a").unwrap(), None);
        store.reserve("a", "fp").unwrap();
        assert_eq!(store.prior("a").unwrap(), Some(Prior { fingerprint: "fp".into(), response: None }));
        store.record("a", b"bytes").unwrap();
        assert_eq!(store.prior("a").unwrap(), Some(Prior { fingerprint: "fp".into(), response: Some(b"bytes".to_vec()) }));
        assert!(store.reserve("a", "other").is_err(), "an identity is reserved once");
        store.reserve("0", "x").unwrap();
        assert_eq!(store.rows().unwrap().iter().map(|row| row.0.as_str()).collect::<Vec<_>>(), vec!["0", "a"]);
    }

    #[test]
    fn the_rows_survive_a_restart() {
        let directory = tempfile::tempdir().unwrap();
        CycleStore::open(directory.path()).unwrap().reserve("a", "fp").unwrap();
        let reopened = CycleStore::open(directory.path()).unwrap();
        assert_eq!(reopened.prior("a").unwrap().unwrap().fingerprint, "fp");
    }
}
