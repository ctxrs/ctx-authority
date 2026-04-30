use crate::Result;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde_json::Value;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
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
        tighten_audit_permissions(&log.path)?;
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
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;

            let mut events = Vec::new();
            for row in rows {
                let (at, kind, data) = row?;
                events.push((at, kind, serde_json::from_str(&data)?));
            }
            Ok(events)
        })
    }

    pub fn list_all(&self) -> Result<Vec<(String, String, Value)>> {
        self.with_conn(|conn| {
            let mut statement =
                conn.prepare("SELECT at, kind, data FROM audit_events ORDER BY id DESC")?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;

            let mut events = Vec::new();
            for row in rows {
                let (at, kind, data) = row?;
                events.push((at, kind, serde_json::from_str(&data)?));
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
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;

            let mut events = Vec::new();
            for row in rows {
                let (at, data) = row?;
                events.push((at, serde_json::from_str(&data)?));
            }
            Ok(events)
        })
    }

    pub fn list_all_kind(&self, kind: &str) -> Result<Vec<(String, Value)>> {
        self.with_conn(|conn| {
            let mut statement =
                conn.prepare("SELECT at, data FROM audit_events WHERE kind = ?1 ORDER BY id DESC")?;
            let rows = statement.query_map(params![kind], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;

            let mut events = Vec::new();
            for row in rows {
                let (at, data) = row?;
                events.push((at, serde_json::from_str(&data)?));
            }
            Ok(events)
        })
    }

    fn with_conn<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let conn = Connection::open(&self.path)?;
        f(&conn)
    }
}

#[cfg(unix)]
fn tighten_audit_permissions(path: &Path) -> Result<()> {
    let metadata = std::fs::metadata(path)?;
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        let mut permissions = metadata.permissions();
        permissions.set_mode(mode & !0o077);
        std::fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn tighten_audit_permissions(_path: &Path) -> Result<()> {
    Ok(())
}
