use crate::Result;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct AuditLog {
    path: std::path::PathBuf,
}

impl AuditLog {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let log = Self { path };
        log.with_conn(|conn| {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    at TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    data TEXT NOT NULL
                );",
            )?;
            Ok(())
        })?;
        Ok(log)
    }

    pub fn record(&self, kind: &str, data: &Value) -> Result<()> {
        let at: DateTime<Utc> = Utc::now();
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO audit_events (at, kind, data) VALUES (?1, ?2, ?3)",
                params![at.to_rfc3339(), kind, serde_json::to_string(data)?],
            )?;
            Ok(())
        })
    }

    pub fn list(&self, limit: usize) -> Result<Vec<(String, String, Value)>> {
        self.with_conn(|conn| {
            let mut statement =
                conn.prepare("SELECT at, kind, data FROM audit_events ORDER BY id DESC LIMIT ?1")?;
            let rows = statement.query_map([limit as i64], |row| {
                let data: String = row.get(2)?;
                let parsed = serde_json::from_str(&data).unwrap_or(Value::Null);
                Ok((row.get(0)?, row.get(1)?, parsed))
            })?;

            let mut events = Vec::new();
            for row in rows {
                events.push(row?);
            }
            Ok(events)
        })
    }

    pub fn list_kind(&self, kind: &str, limit: usize) -> Result<Vec<(String, Value)>> {
        self.with_conn(|conn| {
            let mut statement = conn.prepare(
                "SELECT at, data FROM audit_events WHERE kind = ?1 ORDER BY id DESC LIMIT ?2",
            )?;
            let rows = statement.query_map(params![kind, limit as i64], |row| {
                let data: String = row.get(1)?;
                let parsed = serde_json::from_str(&data).unwrap_or(Value::Null);
                Ok((row.get(0)?, parsed))
            })?;

            let mut events = Vec::new();
            for row in rows {
                events.push(row?);
            }
            Ok(events)
        })
    }

    fn with_conn<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let conn = Connection::open(&self.path)?;
        f(&conn)
    }
}
