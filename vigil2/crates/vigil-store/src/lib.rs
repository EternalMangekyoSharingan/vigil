//! Vigil's history, in one SQLite file the daemon owns (`/var/lib/vigil/vigil.db`).
//!
//! - **Schema and migrations.** The schema version is SQLite's `user_version`. Before a
//!   migration runs, the current file is copied aside (`VACUUM INTO`), so a failed
//!   upgrade never loses history. Migrations are append-only: an old one is never edited.
//! - **First seen.** Every program, destination and connection keeps its first and last
//!   sighting: "this program has never connected out before" is one of the strongest
//!   single signals (docs/SPEC.md).
//! - **The time machine.** [`Store::connections_at`] answers "what was talking at 3 a.m.
//!   on Tuesday?" from the first/last sighting of each connection.
//! - **Retention.** Rows older than the retention window are deleted; freed pages are
//!   returned to the file system a little at a time (`incremental_vacuum`).
//! - **Events.** An append-only log of what Vigil itself did (sensors starting, Run mode
//!   runs, settings changes), with where each came from.
//!
//! WAL mode lets the daemon write while the store is read. Everything is local; nothing
//! here opens a network connection.

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use vigil_model::finding::Finding;
use vigil_model::host::{NetSnapshot, ProcessList, StoreStatus};
use vigil_model::netaddr::scope_of;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("{0}")]
    Json(#[from] serde_json::Error),
    #[error(
        "the database at {path} is from a newer Vigil (schema {found}, this version knows {known}); not touching it"
    )]
    TooNew { path: String, found: u32, known: u32 },
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// Append-only: add a new entry to change the schema, never edit an old one.
const MIGRATIONS: &[&str] = &[
    // 1: milestone 2.
    r#"
    CREATE TABLE programs (
        key TEXT PRIMARY KEY, name TEXT NOT NULL,
        first_seen REAL NOT NULL, last_seen REAL NOT NULL
    );
    CREATE TABLE destinations (
        ip TEXT PRIMARY KEY, scope TEXT NOT NULL,
        first_seen REAL NOT NULL, last_seen REAL NOT NULL
    );
    CREATE TABLE connections (
        id INTEGER PRIMARY KEY,
        proto TEXT NOT NULL, local_ip TEXT NOT NULL, local_port INTEGER NOT NULL,
        remote_ip TEXT NOT NULL, remote_port INTEGER NOT NULL, inode INTEGER NOT NULL,
        uid INTEGER NOT NULL, pid INTEGER, program TEXT, direction TEXT NOT NULL, kind TEXT NOT NULL,
        state TEXT NOT NULL, first_seen REAL NOT NULL, last_seen REAL NOT NULL,
        UNIQUE (proto, local_ip, local_port, remote_ip, remote_port, inode)
    );
    CREATE INDEX connections_last ON connections (last_seen);
    CREATE INDEX connections_first ON connections (first_seen);
    CREATE INDEX connections_program ON connections (program);
    CREATE TABLE processes (
        pid INTEGER NOT NULL, started REAL NOT NULL, key TEXT NOT NULL, name TEXT NOT NULL,
        exe TEXT, cmdline TEXT NOT NULL, uid INTEGER NOT NULL, ppid INTEGER NOT NULL,
        first_seen REAL NOT NULL, last_seen REAL NOT NULL,
        PRIMARY KEY (pid, started)
    );
    CREATE INDEX processes_last ON processes (last_seen);
    CREATE TABLE events (
        id INTEGER PRIMARY KEY, ts REAL NOT NULL, kind TEXT NOT NULL,
        summary TEXT NOT NULL, source TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '{}'
    );
    CREATE INDEX events_ts ON events (ts);
    CREATE TABLE findings (
        id TEXT PRIMARY KEY, tool TEXT NOT NULL, "check" TEXT NOT NULL, severity TEXT NOT NULL,
        title TEXT NOT NULL, body TEXT NOT NULL, first_seen REAL NOT NULL, last_seen REAL NOT NULL
    );
    "#,
];

pub const SCHEMA_VERSION: u32 = MIGRATIONS.len() as u32;

/// One connection as stored: when it was first and last seen open.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredConnection {
    pub proto: String,
    pub local_ip: String,
    pub local_port: u32,
    pub remote_ip: String,
    pub remote_port: u32,
    pub uid: u32,
    pub pid: Option<u32>,
    pub program: Option<String>,
    pub direction: String,
    pub kind: String,
    pub state: String,
    pub first_seen: f64,
    pub last_seen: f64,
}

/// What one recorded snapshot added.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Recorded {
    pub connections: usize,
    /// Programs seen holding a socket for the first time ever.
    pub new_programs: Vec<String>,
    /// Addresses beyond this machine contacted for the first time ever.
    pub new_destinations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub ts: f64,
    pub kind: String,
    pub summary: String,
    pub source: String,
    pub detail: serde_json::Value,
}

pub struct Store {
    conn: Connection,
    path: Option<PathBuf>,
}

impl Store {
    /// Open (creating if needed) and migrate. A newer schema than this version knows is
    /// refused rather than guessed at.
    pub fn open(path: &Path) -> Result<Store> {
        let conn = Connection::open(path)?;
        let mut s = Store { conn, path: Some(path.to_path_buf()) };
        s.setup()?;
        Ok(s)
    }

    /// An in-memory store, for tests and `--no-store`.
    pub fn memory() -> Result<Store> {
        let mut s = Store { conn: Connection::open_in_memory()?, path: None };
        s.setup()?;
        Ok(s)
    }

    fn setup(&mut self) -> Result<()> {
        // auto_vacuum must be chosen before the first table exists.
        self.conn.execute_batch("PRAGMA auto_vacuum = INCREMENTAL;")?;
        if self.path.is_some() {
            self.conn.query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()))?;
        }
        self.conn
            .execute_batch("PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 2000;")?;
        self.migrate()
    }

    pub fn schema_version(&self) -> Result<u32> {
        Ok(self.conn.query_row("PRAGMA user_version", [], |r| r.get(0))?)
    }

    fn migrate(&mut self) -> Result<()> {
        let found = self.schema_version()?;
        if found > SCHEMA_VERSION {
            let path = self.path.as_ref().map_or(":memory:".into(), |p| p.display().to_string());
            return Err(StoreError::TooNew { path, found, known: SCHEMA_VERSION });
        }
        if found == SCHEMA_VERSION {
            return Ok(());
        }
        if found > 0 {
            if let Some(p) = &self.path {
                let backup = p.with_extension(format!("db.bak-v{found}"));
                let _ = std::fs::remove_file(&backup);
                self.conn.execute("VACUUM INTO ?1", params![backup.to_string_lossy()])?;
            }
        }
        let tx = self.conn.transaction()?;
        for sql in &MIGRATIONS[found as usize..] {
            tx.execute_batch(sql)?;
        }
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.commit()?;
        Ok(())
    }

    /// Record one network snapshot: connections, programs and destinations, with their
    /// first and last sightings. One transaction per snapshot.
    pub fn record_net(&mut self, snap: &NetSnapshot) -> Result<Recorded> {
        let now = snap.taken_at;
        let tx = self.conn.transaction()?;
        let mut out = Recorded::default();
        {
            let mut conn_up = tx.prepare_cached(
                "INSERT INTO connections (proto, local_ip, local_port, remote_ip, remote_port, inode, uid, pid, program,
                                          direction, kind, state, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?13)
                 ON CONFLICT (proto, local_ip, local_port, remote_ip, remote_port, inode) DO UPDATE SET
                    last_seen = excluded.last_seen, state = excluded.state,
                    pid = COALESCE(excluded.pid, pid), program = COALESCE(excluded.program, program)",
            )?;
            let mut prog_new = tx.prepare_cached(
                "INSERT INTO programs (key, name, first_seen, last_seen) VALUES (?1, ?2, ?3, ?3)
                 ON CONFLICT (key) DO UPDATE SET last_seen = excluded.last_seen RETURNING first_seen",
            )?;
            let mut dest_new = tx.prepare_cached(
                "INSERT INTO destinations (ip, scope, first_seen, last_seen) VALUES (?1, ?2, ?3, ?3)
                 ON CONFLICT (ip) DO UPDATE SET last_seen = excluded.last_seen RETURNING first_seen",
            )?;
            for s in &snap.sockets {
                conn_up.execute(params![
                    s.proto,
                    s.local_ip,
                    s.local_port,
                    s.remote_ip,
                    s.remote_port,
                    s.inode as i64,
                    s.uid,
                    s.pid,
                    s.program,
                    s.direction,
                    s.kind,
                    s.state,
                    now
                ])?;
                out.connections += 1;
                if s.kind == "connection" {
                    // Anything a program reached beyond this machine and its link.
                    let scope = scope_of(&s.remote_ip);
                    if !matches!(scope, "loopback" | "unspecified" | "link-local" | "multicast") {
                        let first: f64 = dest_new.query_row(params![s.remote_ip, scope, now], |r| r.get(0))?;
                        if first == now && !out.new_destinations.contains(&s.remote_ip) {
                            out.new_destinations.push(s.remote_ip.clone());
                        }
                    }
                }
            }
            for p in snap.processes.values() {
                let first: f64 = prog_new.query_row(params![p.key, p.name, now], |r| r.get(0))?;
                if first == now {
                    out.new_programs.push(p.key.clone());
                }
            }
        }
        tx.commit()?;
        Ok(out)
    }

    /// Record every visible process (keyed by pid and start time, so a reused pid is a
    /// new process).
    pub fn record_processes(&mut self, list: &ProcessList) -> Result<usize> {
        self.record_processes_where(list, |_| true)
    }

    /// Record only the processes `keep` picks (the daemon writes new processes on every
    /// look and refreshes `last_seen` for all of them once a minute).
    pub fn record_processes_where(
        &mut self,
        list: &ProcessList,
        keep: impl Fn(&vigil_model::host::ProcessInfo) -> bool,
    ) -> Result<usize> {
        let tx = self.conn.transaction()?;
        let mut n = 0;
        {
            let mut up = tx.prepare_cached(
                "INSERT INTO processes (pid, started, key, name, exe, cmdline, uid, ppid, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
                 ON CONFLICT (pid, started) DO UPDATE SET last_seen = excluded.last_seen",
            )?;
            for p in list.processes.iter().filter(|p| keep(p)) {
                let Some(started) = p.started else { continue };
                up.execute(params![
                    p.pid,
                    started,
                    p.key,
                    p.name,
                    p.exe,
                    serde_json::to_string(&p.cmdline)?,
                    p.uid,
                    p.ppid,
                    list.taken_at
                ])?;
                n += 1;
            }
        }
        tx.commit()?;
        Ok(n)
    }

    /// Connections open at `t` (seconds since the epoch). `slack` covers the poll
    /// interval: a connection last seen 2 s before `t` was probably still open.
    pub fn connections_at(&self, t: f64, slack: f64) -> Result<Vec<StoredConnection>> {
        self.connections_where(
            "first_seen <= ?1 + ?2 AND last_seen >= ?1 - ?2 AND kind = 'connection'",
            params![t, slack],
        )
    }

    /// Connections that were open at any moment between `from` and `to`.
    pub fn connections_between(&self, from: f64, to: f64) -> Result<Vec<StoredConnection>> {
        self.connections_where("first_seen <= ?2 AND last_seen >= ?1 AND kind = 'connection'", params![from, to])
    }

    fn connections_where(&self, cond: &str, args: impl rusqlite::Params) -> Result<Vec<StoredConnection>> {
        let sql = format!(
            "SELECT proto, local_ip, local_port, remote_ip, remote_port, uid, pid, program, direction, kind, state,
                    first_seen, last_seen FROM connections WHERE {cond} ORDER BY first_seen"
        );
        let mut st = self.conn.prepare(&sql)?;
        let rows = st.query_map(args, |r| {
            Ok(StoredConnection {
                proto: r.get(0)?,
                local_ip: r.get(1)?,
                local_port: r.get(2)?,
                remote_ip: r.get(3)?,
                remote_port: r.get(4)?,
                uid: r.get(5)?,
                pid: r.get(6)?,
                program: r.get(7)?,
                direction: r.get(8)?,
                kind: r.get(9)?,
                state: r.get(10)?,
                first_seen: r.get(11)?,
                last_seen: r.get(12)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// When a program was first seen holding a socket, if ever.
    pub fn program_first_seen(&self, key: &str) -> Result<Option<f64>> {
        Ok(self
            .conn
            .query_row("SELECT first_seen FROM programs WHERE key = ?1", params![key], |r| r.get(0))
            .optional()?)
    }

    pub fn event(&self, ev: &Event) -> Result<()> {
        self.conn.execute(
            "INSERT INTO events (ts, kind, summary, source, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![ev.ts, ev.kind, ev.summary, ev.source, serde_json::to_string(&ev.detail)?],
        )?;
        Ok(())
    }

    pub fn events_since(&self, ts: f64, limit: usize) -> Result<Vec<Event>> {
        let mut st = self.conn.prepare(
            "SELECT ts, kind, summary, source, detail FROM events WHERE ts >= ?1 ORDER BY ts DESC, id DESC LIMIT ?2",
        )?;
        let rows = st.query_map(params![ts, limit as i64], |r| {
            let detail: String = r.get(4)?;
            Ok(Event {
                ts: r.get(0)?,
                kind: r.get(1)?,
                summary: r.get(2)?,
                source: r.get(3)?,
                detail: serde_json::from_str(&detail).unwrap_or(serde_json::Value::Null),
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Keep a finding, refreshing its last sighting if it is already known.
    pub fn put_finding(&self, f: &Finding, now: f64) -> Result<()> {
        self.conn.execute(
            r#"INSERT INTO findings (id, tool, "check", severity, title, body, first_seen, last_seen)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
               ON CONFLICT (id) DO UPDATE SET body = excluded.body, severity = excluded.severity,
                   title = excluded.title, last_seen = excluded.last_seen"#,
            params![f.id, f.tool, f.check, f.severity.as_str(), f.title, serde_json::to_string(f)?, now],
        )?;
        Ok(())
    }

    /// Findings seen at or after `ts` (the current ones, for a recent `ts`), newest first.
    pub fn findings_since(&self, ts: f64) -> Result<Vec<Finding>> {
        let mut st = self.conn.prepare("SELECT body FROM findings WHERE last_seen >= ?1 ORDER BY last_seen DESC")?;
        let rows = st.query_map(params![ts], |r| r.get::<_, String>(0))?;
        let mut out = vec![];
        for body in rows {
            out.push(serde_json::from_str(&body?)?);
        }
        Ok(out)
    }

    pub fn findings(&self) -> Result<Vec<Finding>> {
        let mut st = self.conn.prepare("SELECT body FROM findings ORDER BY last_seen DESC")?;
        let rows = st.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = vec![];
        for body in rows {
            out.push(serde_json::from_str(&body?)?);
        }
        Ok(out)
    }

    /// Delete history older than `days`; return how many rows went. Freed pages are
    /// handed back to the file system a little at a time.
    pub fn apply_retention(&mut self, now: f64, days: u32) -> Result<usize> {
        let cut = now - f64::from(days) * 86_400.0;
        let tx = self.conn.transaction()?;
        let mut n = 0;
        n += tx.execute("DELETE FROM connections WHERE last_seen < ?1", params![cut])?;
        n += tx.execute("DELETE FROM processes WHERE last_seen < ?1", params![cut])?;
        n += tx.execute("DELETE FROM events WHERE ts < ?1", params![cut])?;
        tx.commit()?;
        if n > 0 {
            self.conn.execute_batch("PRAGMA incremental_vacuum(2000);")?;
        }
        Ok(n)
    }

    fn count(&self, table: &str) -> u64 {
        self.conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get::<_, i64>(0)).unwrap_or(0) as u64
    }

    pub fn status(&self, retention_days: u32) -> StoreStatus {
        // The database plus its write-ahead log, which holds recent writes until a checkpoint.
        let len = |p: PathBuf| std::fs::metadata(p).map_or(0, |m| m.len());
        let size = self.path.as_ref().map_or(0, |p| len(p.clone()) + len(p.with_extension("db-wal")));
        StoreStatus {
            path: self.path.as_ref().map_or(":memory:".into(), |p| p.display().to_string()),
            schema: self.schema_version().unwrap_or(0),
            size_bytes: size,
            retention_days,
            programs_seen: self.count("programs"),
            destinations_seen: self.count("destinations"),
            events: self.count("events"),
        }
    }
}
