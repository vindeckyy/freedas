//! SQLite persistence for sessions, messages, parts, usage, and memory.
mod router_ops;
mod session_ops;

use rusqlite::{Connection, Error as SqlError, OptionalExtension, params};
use std::path::Path;
use std::sync::Mutex;

use freedas_core::Result;

pub struct Db {
    conn: Mutex<Connection>,
}

/// (scope, kind, text, confidence, project_id) columns of one memory row.
pub type MemoryRow = (String, String, String, String, Option<String>);

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db").finish_non_exhaustive()
    }
}

const SCHEMA_V1: &str = "
CREATE TABLE IF NOT EXISTS projects (id TEXT PRIMARY KEY, root TEXT NOT NULL, canonical TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, parent_id TEXT REFERENCES sessions(id) ON DELETE SET NULL, title TEXT NOT NULL, agent TEXT NOT NULL, model_provider TEXT, model_id TEXT, model_variant TEXT, workspace_id TEXT, status TEXT NOT NULL, archived INTEGER NOT NULL DEFAULT 0, metadata TEXT NOT NULL DEFAULT '{}', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS sessions_project_updated ON sessions(project_id, updated_at DESC);
CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, role TEXT NOT NULL, model TEXT, usage TEXT, error TEXT, metadata TEXT NOT NULL DEFAULT '{}', created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS messages_session_created ON messages(session_id, created_at);
CREATE TABLE IF NOT EXISTS parts (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE, idx INTEGER NOT NULL, kind TEXT NOT NULL, data TEXT NOT NULL, created_at INTEGER NOT NULL, UNIQUE(message_id, idx));
CREATE INDEX IF NOT EXISTS parts_session_kind ON parts(session_id, kind);
CREATE TABLE IF NOT EXISTS permissions (id TEXT PRIMARY KEY, session_id TEXT REFERENCES sessions(id) ON DELETE CASCADE, action TEXT NOT NULL, resource TEXT NOT NULL, effect TEXT NOT NULL, scope TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS todos (session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, id TEXT NOT NULL, content TEXT NOT NULL, status TEXT NOT NULL, priority TEXT NOT NULL, PRIMARY KEY(session_id, id));
CREATE TABLE IF NOT EXISTS snapshots (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, message_id TEXT NOT NULL, commit_sha TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS snapshots_session_message ON snapshots(session_id, message_id);
CREATE TABLE IF NOT EXISTS usage (id TEXT PRIMARY KEY, session_id TEXT REFERENCES sessions(id) ON DELETE SET NULL, workspace_id TEXT, provider TEXT NOT NULL, model TEXT NOT NULL, input_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0, cache_read_tokens INTEGER NOT NULL DEFAULT 0, cache_write_tokens INTEGER NOT NULL DEFAULT 0, cost_usd REAL NOT NULL DEFAULT 0, kind TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS usage_session ON usage(session_id);
CREATE TABLE IF NOT EXISTS tool_usage (id TEXT PRIMARY KEY, session_id TEXT REFERENCES sessions(id) ON DELETE SET NULL, tool TEXT NOT NULL, calls INTEGER NOT NULL DEFAULT 1, duration_ms INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS tool_usage_session_created ON tool_usage(session_id, created_at);
CREATE TABLE IF NOT EXISTS memories (id TEXT PRIMARY KEY, scope TEXT NOT NULL, project_id TEXT REFERENCES projects(id) ON DELETE CASCADE, kind TEXT NOT NULL, text TEXT NOT NULL, source_session TEXT, confidence REAL NOT NULL DEFAULT 0.8, embedding BLOB, created_at INTEGER NOT NULL, last_used_at INTEGER);
CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(text, content='memories', content_rowid='rowid');
CREATE TRIGGER IF NOT EXISTS memories_ai AFTER INSERT ON memories BEGIN INSERT INTO memories_fts(rowid, text) VALUES (new.rowid, new.text); END;
CREATE TRIGGER IF NOT EXISTS memories_ad AFTER DELETE ON memories BEGIN INSERT INTO memories_fts(memories_fts, rowid, text) VALUES('delete', old.rowid, old.text); END;
CREATE TRIGGER IF NOT EXISTS memories_au AFTER UPDATE ON memories BEGIN INSERT INTO memories_fts(memories_fts, rowid, text) VALUES('delete', old.rowid, old.text); INSERT INTO memories_fts(rowid, text) VALUES (new.rowid, new.text); END;
CREATE TABLE IF NOT EXISTS router_stats (task_class TEXT NOT NULL, model TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, successes INTEGER NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0, total_cost_usd REAL NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL, PRIMARY KEY(task_class, model));
CREATE TABLE IF NOT EXISTS redo_stack (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, message_id TEXT NOT NULL, commit_sha TEXT NOT NULL, messages_json TEXT NOT NULL DEFAULT '{}', created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS redo_stack_session ON redo_stack(session_id);
CREATE TABLE IF NOT EXISTS memory_tombstones (text_hash TEXT PRIMARY KEY, created_at INTEGER NOT NULL);
";

/// Backfills the four indexes added to `SCHEMA_V1` late; databases already
/// at version 1 lack them, and `IF NOT EXISTS` makes this a no-op for fresh
/// databases that applied `SCHEMA_V1` after the indexes were added.
const SCHEMA_V2: &str = "
CREATE INDEX IF NOT EXISTS parts_session_kind ON parts(session_id, kind);
CREATE INDEX IF NOT EXISTS snapshots_session_message ON snapshots(session_id, message_id);
CREATE INDEX IF NOT EXISTS tool_usage_session_created ON tool_usage(session_id, created_at);
CREATE INDEX IF NOT EXISTS redo_stack_session ON redo_stack(session_id);
 ";

/// Forgotten memories: their text hashes are tombstoned so a later distill
/// or import cannot silently re-learn a fact the operator deleted.
const SCHEMA_V3: &str = "
CREATE TABLE IF NOT EXISTS memory_tombstones (text_hash TEXT PRIMARY KEY, created_at INTEGER NOT NULL);
";

fn migrate(conn: &mut Connection) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version > 3 {
        return Err(freedas_core::FreedasError::Other(format!(
            "database schema version {version} is newer than this build (3)"
        )));
    }
    if version < 1 {
        let had_fts = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'memories_fts'",
                [],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);
        conn.execute_batch(SCHEMA_V1)?;
        conn.pragma_update(None, "user_version", 1)?;
        if !had_fts {
            // Rows that predate the FTS table are not indexed by the triggers.
            conn.execute(
                "INSERT INTO memories_fts(memories_fts) VALUES('rebuild')",
                [],
            )?;
        }
    }
    if version < 2 {
        conn.execute_batch(SCHEMA_V2)?;
        conn.pragma_update(None, "user_version", 2)?;
    }
    if version < 3 {
        conn.execute_batch(SCHEMA_V3)?;
        conn.pragma_update(None, "user_version", 3)?;
    }
    Ok(())
}

/// Clamp a caller-supplied row limit to the range SQLite can bind.
fn limit_i64(limit: usize) -> i64 {
    i64::try_from(limit).unwrap_or(i64::MAX)
}
/// Snapshot SHAs (`^[0-9a-f]{4,64}$`): short or full lowercase hex object names.
fn is_valid_commit_sha(s: &str) -> bool {
    (4..=64).contains(&s.len()) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Live write paths get the same SHA check as the import path: an empty
/// string stays allowed (it is the "no snapshot" sentinel), but anything
/// else must look like a git object name before it is stored and later fed
/// back to git commands.
fn check_commit_sha(s: &str) -> Result<()> {
    if !s.is_empty() && !is_valid_commit_sha(s) {
        return Err(freedas_core::FreedasError::Other(format!(
            "invalid commit sha `{s}`: expected 4-64 lowercase hex"
        )));
    }
    Ok(())
}

/// Clamp `days` to a non-negative millisecond window that cannot overflow.
fn days_ago(days: Option<i64>) -> i64 {
    let now = freedas_core::paths::now_ms();
    match days {
        Some(d) if d > 0 => now.saturating_sub(d.saturating_mul(86_400_000)).max(0),
        _ => 0,
    }
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let existed = path.exists();
        let mut conn = Connection::open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if existed
                && let Ok(md) = std::fs::metadata(path)
                && md.permissions().mode() & 0o077 != 0
            {
                static WARNED: std::sync::Once = std::sync::Once::new();
                WARNED.call_once(|| {
                    eprintln!(
                        "warning: database file {} had permissive mode; tightened to 0600",
                        path.display()
                    );
                });
            }
        }
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        migrate(&mut conn)?;
        #[cfg(unix)]
        {
            // Tighten the db file and WAL sidecars after WAL mode creates
            // them: transcripts are credentials-adjacent and must not sit
            // world-readable on multi-user hosts.
            use std::os::unix::fs::PermissionsExt;
            for suffix in ["", "-wal", "-shm"] {
                let p = if suffix.is_empty() {
                    path.to_path_buf()
                } else {
                    let mut os = path.as_os_str().to_os_string();
                    os.push(suffix);
                    std::path::PathBuf::from(os)
                };
                if p.exists() {
                    let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
                }
            }
        }
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn memory() -> Result<Self> {
        let mut conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        migrate(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().expect("db mutex")
    }

    pub fn ensure_project(&self, root: &Path) -> Result<String> {
        let root_str = root.to_string_lossy().to_string();
        let canonical = root
            .canonicalize()
            .unwrap_or_else(|_| root.to_path_buf())
            .to_string_lossy()
            .to_string();
        let now = freedas_core::paths::now_ms();
        let conn = self.lock();
        // `canonical` is UNIQUE, so a losing cross-process insert is a no-op and
        // the re-select returns the winner's id.
        conn.execute(
            "INSERT OR IGNORE INTO projects (id, root, canonical, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![format!("prj_{}", ulid::Ulid::new()), root_str, canonical, now],
        )?;
        Ok(conn.query_row(
            "SELECT id FROM projects WHERE canonical = ?1",
            params![canonical],
            |r| r.get(0),
        )?)
    }

    pub fn create_session(
        &self,
        project_id: &str,
        agent: &str,
        title: &str,
        workspace: Option<&str>,
    ) -> Result<String> {
        let id = format!("ses_{}", ulid::Ulid::new());
        let now = freedas_core::paths::now_ms();
        self.lock().execute(
            "INSERT INTO sessions (id, project_id, title, agent, workspace_id, status, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, 'idle', ?6, ?6)",
            params![id, project_id, title, agent, workspace, now])?;
        Ok(id)
    }

    /// Record the parent of a subagent session (no-op when the id is unknown).
    pub fn set_session_parent(&self, id: &str, parent_id: &str) -> Result<()> {
        self.lock().execute(
            "UPDATE sessions SET parent_id = ?1 WHERE id = ?2",
            params![parent_id, id],
        )?;
        Ok(())
    }

    /// Project root and agent for a stored session (`None` when unknown).
    pub fn session_context(&self, id: &str) -> Result<Option<(String, String)>> {
        let conn = self.lock();
        Ok(conn
            .query_row(
                "SELECT p.root, s.agent FROM sessions s JOIN projects p ON p.id = s.project_id WHERE s.id = ?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    pub fn list_sessions(&self, project_id: &str, limit: usize) -> Result<Vec<SessionRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, title, agent, status, created_at, updated_at FROM sessions WHERE project_id = ?1 ORDER BY updated_at DESC LIMIT ?2")?;
        let rows = stmt
            .query_map(params![project_id, limit_i64(limit)], |r| {
                Ok(SessionRow {
                    id: r.get(0)?,
                    title: r.get(1)?,
                    agent: r.get(2)?,
                    status: r.get(3)?,
                    created_at: r.get(4)?,
                    updated_at: r.get(5)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, SqlError>>()?;
        Ok(rows)
    }
    /// Remove a message and everything after it (used by revert), creating the
    /// redo entry in the same transaction. The redo row id is returned
    /// alongside the capture so callers thread it into `attach_redo_messages`
    /// instead of looking up the latest row.
    pub fn delete_messages_from(
        &self,
        session_id: &str,
        message_id: &str,
        commit_sha: &str,
    ) -> Result<(DeletedSet, i64)> {
        check_commit_sha(commit_sha)?;
        let mut conn = self.lock();
        ensure_redo_table(&conn)?;
        let tx = conn.transaction()?;
        let (removed, at) = capture_from(&tx, session_id, message_id)?;
        delete_captured(&tx, session_id, at, &removed)?;
        tx.execute(
            "INSERT INTO redo_stack (session_id, message_id, commit_sha, messages_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                session_id,
                message_id,
                commit_sha,
                serde_json::to_string(&removed)?,
                freedas_core::paths::now_ms()
            ],
        )?;
        let redo_id = tx.last_insert_rowid();
        tx.commit()?;
        Ok((removed, redo_id))
    }

    /// Undo in one transaction: capture the rows, delete them, and push the
    /// redo entry. Nothing is removed unless the redo entry is stored too.
    /// Returns the redo row id from the same transaction so callers thread
    /// it instead of looking up the latest redo row.
    pub fn undo_messages(
        &self,
        session_id: &str,
        message_id: &str,
        commit_sha: &str,
    ) -> Result<(DeletedSet, i64)> {
        check_commit_sha(commit_sha)?;
        let mut conn = self.lock();
        ensure_redo_table(&conn)?;
        let tx = conn.transaction()?;
        let (removed, at) = capture_from(&tx, session_id, message_id)?;
        delete_captured(&tx, session_id, at, &removed)?;
        tx.execute(
            "INSERT INTO redo_stack (session_id, message_id, commit_sha, messages_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                session_id,
                message_id,
                commit_sha,
                serde_json::to_string(&removed)?,
                freedas_core::paths::now_ms()
            ],
        )?;
        let redo_id = tx.last_insert_rowid();
        tx.commit()?;
        Ok((removed, redo_id))
    }

    /// Message-scoped writes take the owning session id so a confused caller
    /// cannot update another session's rows (message ids are unguessable but
    /// the check is cheap).
    pub fn set_message_model(
        &self,
        session_id: &str,
        message_id: &str,
        model: &serde_json::Value,
    ) -> Result<()> {
        self.lock().execute(
            "UPDATE messages SET model = ?3 WHERE id = ?2 AND session_id = ?1",
            params![session_id, message_id, model.to_string()],
        )?;
        Ok(())
    }

    pub fn set_message_usage(
        &self,
        session_id: &str,
        message_id: &str,
        usage: &serde_json::Value,
    ) -> Result<()> {
        self.lock().execute(
            "UPDATE messages SET usage = ?3 WHERE id = ?2 AND session_id = ?1",
            params![session_id, message_id, usage.to_string()],
        )?;
        Ok(())
    }

    /// Record the concrete model a session is using. Routed runs store
    /// `freedas`/`auto`; pinned runs store the provider and model ID.
    pub fn set_session_model(
        &self,
        session_id: &str,
        provider: &str,
        model_id: &str,
        variant: Option<&str>,
    ) -> Result<()> {
        self.lock().execute(
            "UPDATE sessions SET model_provider = ?2, model_id = ?3, model_variant = ?4, updated_at = ?5 WHERE id = ?1",
            params![
                session_id,
                provider,
                model_id,
                variant,
                freedas_core::paths::now_ms()
            ],
        )?;
        Ok(())
    }

    /// Token and cost totals for one session.
    pub fn session_usage(&self, session_id: &str) -> Result<(i64, i64, f64)> {
        let conn = self.lock();
        let row = conn.query_row(
            "SELECT COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0), COALESCE(SUM(cost_usd),0) FROM usage WHERE session_id = ?1",
            params![session_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        Ok(row)
    }

    /// Metadata of the most recent assistant message, which carries the
    /// router decision for that step.
    pub fn last_router_decision(&self, project_id: &str) -> Result<Option<String>> {
        let conn = self.lock();
        let row: Option<String> = conn
            .query_row(
                "SELECT m.metadata FROM messages m JOIN sessions s ON s.id = m.session_id WHERE s.project_id = ?1 AND m.role = 'assistant' ORDER BY m.created_at DESC, m.rowid DESC LIMIT 1",
                params![project_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(row)
    }

    /// Most recent compaction summary for a session, with the time it was made.
    pub fn latest_compaction(&self, session_id: &str) -> Result<Option<(i64, String)>> {
        let conn = self.lock();
        let row: Option<(i64, String)> = conn
            .query_row(
                "SELECT created_at, data FROM parts WHERE session_id = ?1 AND kind = 'compaction' ORDER BY created_at DESC, rowid DESC LIMIT 1",
                params![session_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(row.and_then(|(ts, data)| {
            serde_json::from_str::<serde_json::Value>(&data)
                .ok()
                .and_then(|v| v["summary"].as_str().map(|s| (ts, s.to_string())))
        }))
    }

    /// Move a session to another project. Snapshot rows follow the session
    /// (they are keyed by `session_id`), but the shadow-git repo lives under
    /// `snapshots/<project_id>/`; copy it so undo/redo keep working after `/move`.
    pub fn move_session(&self, id: &str, project_id: &str) -> Result<bool> {
        let old_project: Option<String> = self
            .lock()
            .query_row(
                "SELECT project_id FROM sessions WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .optional()?;
        let n = self.lock().execute(
            "UPDATE sessions SET project_id = ?2, updated_at = ?3 WHERE id = ?1",
            params![id, project_id, freedas_core::paths::now_ms()],
        )?;
        if n > 0
            && let Some(old) = old_project
            && old != project_id
        {
            Self::carry_snapshot_dir(&old, project_id);
        }
        Ok(n > 0)
    }

    /// Best-effort copy (fallback: symlink) of the shadow-git store to the new
    /// project id dir. Failures are ignored: the DB move already succeeded and
    /// a missing repo only disables undo/redo, it must not fail `/move`.
    fn carry_snapshot_dir(old_project: &str, new_project: &str) {
        let data_dir = freedas_core::paths::Paths::resolve(
            std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")),
        )
        .data_dir;
        let src = data_dir.join("snapshots").join(old_project);
        let dst = data_dir.join("snapshots").join(new_project);
        if src == dst || !src.exists() || dst.exists() {
            return;
        }
        if Self::copy_dir_recursive(&src, &dst).is_err() {
            #[cfg(unix)]
            let _ = std::os::unix::fs::symlink(&src, &dst);
        }
    }

    /// Recursive copy for the shadow-git store (`repo.git/`, `index`, `excludes`).
    fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dst)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let from = entry.path();
            let to = dst.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                Self::copy_dir_recursive(&from, &to)?;
            } else {
                std::fs::copy(&from, &to)?;
            }
        }
        Ok(())
    }

    pub fn delete_session(&self, id: &str) -> Result<bool> {
        let project_id: Option<String> = self
            .lock()
            .query_row(
                "SELECT project_id FROM sessions WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .optional()?;
        let mut conn = self.lock();
        // usage/tool_usage keep rows with session_id NULL on delete, which
        // would keep billing and stats counts for a deleted session.
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM usage WHERE session_id = ?1", params![id])?;
        tx.execute("DELETE FROM tool_usage WHERE session_id = ?1", params![id])?;
        let n = tx.execute("DELETE FROM sessions WHERE id = ?1", params![id])?;
        tx.commit()?;
        let deleted = n > 0;
        if deleted && let Some(pid) = project_id.as_deref() {
            self.prune_snapshot_repo_if_empty(pid);
        }
        Ok(deleted)
    }

    /// Best-effort removal of the shadow-git store (`snapshots/<pid>/repo.git`)
    /// once no sessions reference the project anymore. The repo is shared by
    /// all sessions of the project, so a still-referenced project is left
    /// alone. Failures are ignored: the DB delete already succeeded and a
    /// leftover directory only costs disk.
    fn prune_snapshot_repo_if_empty(&self, project_id: &str) {
        if project_id.is_empty()
            || !project_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return;
        }
        let remaining: i64 = self
            .lock()
            .query_row(
                "SELECT COUNT(*) FROM sessions WHERE project_id = ?1",
                params![project_id],
                |r| r.get(0),
            )
            .unwrap_or(1);
        if remaining > 0 {
            return;
        }
        let data_dir = freedas_core::paths::Paths::resolve(
            std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")),
        )
        .data_dir;
        let _ =
            std::fs::remove_dir_all(data_dir.join("snapshots").join(project_id).join("repo.git"));
    }

    pub fn add_message(
        &self,
        session_id: &str,
        role: &str,
        metadata: &serde_json::Value,
    ) -> Result<String> {
        let id = format!("msg_{}", ulid::Ulid::new());
        let now = freedas_core::paths::now_ms();
        self.lock().execute("INSERT INTO messages (id, session_id, role, metadata, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, session_id, role, metadata.to_string(), now])?;
        Ok(id)
    }

    pub fn add_part(
        &self,
        session_id: &str,
        message_id: &str,
        idx: i64,
        kind: &str,
        data: &serde_json::Value,
    ) -> Result<String> {
        let id = format!("prt_{}", ulid::Ulid::new());
        let now = freedas_core::paths::now_ms();
        self.lock().execute("INSERT INTO parts (id, session_id, message_id, idx, kind, data, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![id, session_id, message_id, idx, kind, data.to_string(), now])?;
        Ok(id)
    }

    pub fn list_messages(&self, session_id: &str) -> Result<Vec<MessageRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, role, model, usage, error, metadata, created_at FROM messages WHERE session_id = ?1 ORDER BY created_at, rowid",
        )?;
        let rows = stmt
            .query_map(params![session_id], |r| {
                Ok(MessageRow {
                    id: r.get(0)?,
                    role: r.get(1)?,
                    model: r.get(2)?,
                    usage: r.get(3)?,
                    error: r.get(4)?,
                    metadata: r.get(5)?,
                    created_at: r.get(6)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, SqlError>>()?;
        Ok(rows)
    }

    pub fn list_parts(&self, session_id: &str, message_id: &str) -> Result<Vec<PartRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, idx, kind, data, created_at FROM parts WHERE message_id = ?2 AND session_id = ?1 ORDER BY idx",
        )?;
        let rows = stmt
            .query_map(params![session_id, message_id], |r| {
                Ok(PartRow {
                    id: r.get(0)?,
                    idx: r.get(1)?,
                    kind: r.get(2)?,
                    data: r.get(3)?,
                    created_at: r.get(4)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, SqlError>>()?;
        Ok(rows)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_usage(
        &self,
        session_id: Option<&str>,
        provider: &str,
        model: &str,
        input: u64,
        output: u64,
        cache_read: u64,
        cache_write: u64,
        cost: f64,
        kind: &str,
    ) -> Result<()> {
        let id = format!("usg_{}", ulid::Ulid::new());
        let now = freedas_core::paths::now_ms();
        self.lock().execute(
            "INSERT INTO usage (id, session_id, provider, model, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, cost_usd, kind, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![id, session_id, provider, model, input as i64, output as i64, cache_read as i64, cache_write as i64, cost, kind, now])?;
        Ok(())
    }

    pub fn record_tool_usage(&self, session_id: &str, tool: &str, duration_ms: i64) -> Result<()> {
        let id = format!("tls_{}", ulid::Ulid::new());
        let now = freedas_core::paths::now_ms();
        self.lock().execute(
            "INSERT INTO tool_usage (id, session_id, tool, calls, duration_ms, created_at) VALUES (?1, ?2, ?3, 1, ?4, ?5)",
            params![id, session_id, tool, duration_ms, now])?;
        Ok(())
    }

    pub fn usage_totals(
        &self,
        days: Option<i64>,
        project_id: Option<&str>,
        model_filter: Option<&str>,
    ) -> Result<Vec<UsageTotal>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT provider, model, COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0), \
                    COALESCE(SUM(cache_read_tokens),0), COALESCE(SUM(cost_usd),0), COUNT(*) \
             FROM usage WHERE created_at >= ?1 \
               AND (?2 IS NULL OR session_id IN (SELECT id FROM sessions WHERE project_id = ?2)) \
               AND (?3 IS NULL OR model = ?3) \
             GROUP BY provider, model ORDER BY SUM(cost_usd) DESC",
        )?;
        let rows = stmt
            .query_map(params![days_ago(days), project_id, model_filter], |r| {
                Ok(UsageTotal {
                    provider: r.get(0)?,
                    model: r.get(1)?,
                    input: r.get(2)?,
                    output: r.get(3)?,
                    cache_read: r.get(4)?,
                    cost: r.get(5)?,
                    calls: r.get(6)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, SqlError>>()?;
        Ok(rows)
    }

    /// Tool call counts and time, honoring the same `--days`/`--project`
    /// filters as `usage_totals`.
    pub fn tool_usage_totals(
        &self,
        days: Option<i64>,
        project_id: Option<&str>,
    ) -> Result<Vec<ToolUsageTotal>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT tool, COALESCE(SUM(calls),0), COALESCE(SUM(duration_ms),0) FROM tool_usage \
             WHERE created_at >= ?1 \
               AND (?2 IS NULL OR session_id IN (SELECT id FROM sessions WHERE project_id = ?2)) \
             GROUP BY tool ORDER BY SUM(calls) DESC",
        )?;
        let rows = stmt
            .query_map(params![days_ago(days), project_id], |r| {
                Ok(ToolUsageTotal {
                    tool: r.get(0)?,
                    calls: r.get(1)?,
                    duration_ms: r.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, SqlError>>()?;
        Ok(rows)
    }

    pub fn add_memory(
        &self,
        scope: &str,
        project_id: Option<&str>,
        kind: &str,
        text: &str,
        confidence: f32,
    ) -> Result<String> {
        let id = format!("mem_{}", ulid::Ulid::new());
        let now = freedas_core::paths::now_ms();
        self.lock().execute("INSERT INTO memories (id, scope, project_id, kind, text, confidence, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![id, scope, project_id, kind, text, confidence, now])?;
        Ok(id)
    }

    /// Backdate an imported memory row to its source date.
    pub fn set_memory_created_at(&self, id: &str, created_at: i64) -> Result<bool> {
        let n = self.lock().execute(
            "UPDATE memories SET created_at = ?1 WHERE id = ?2",
            params![created_at, id],
        )?;
        Ok(n > 0)
    }

    pub fn recall_memory(&self, project_id: Option<&str>, limit: usize) -> Result<Vec<String>> {
        let conn = self.lock();
        let rows = if let Some(pid) = project_id {
            let mut stmt = conn.prepare("SELECT text FROM memories WHERE project_id = ?1 OR scope = 'user' ORDER BY confidence DESC, created_at DESC LIMIT ?2")?;
            stmt.query_map(params![pid, limit_i64(limit)], |r| r.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, SqlError>>()?
        } else {
            let mut stmt = conn.prepare(
                "SELECT text FROM memories ORDER BY confidence DESC, created_at DESC LIMIT ?1",
            )?;
            stmt.query_map(params![limit_i64(limit)], |r| r.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, SqlError>>()?
        };
        Ok(rows)
    }

    /// Relevance-ranked recall: FTS5 BM25 when a query is given, confidence
    /// order otherwise. Returns (kind, text) pairs for prompt labels.
    pub fn recall_memory_fts(
        &self,
        project_id: Option<&str>,
        query: &str,
        limit: usize,
    ) -> Result<Vec<(String, String)>> {
        let conn = self.lock();
        let (scope_clause, limit_param) = match project_id {
            Some(_) => ("AND (m.project_id = ?2 OR m.scope = 'user')", "?3"),
            None => ("", "?2"),
        };
        let tokens: Vec<String> = query
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| t.len() > 2)
            .take(8)
            .map(|t| {
                let esc = t.replace('"', "");
                ["\"", &esc, "\""].concat()
            })
            .collect();
        let fts = tokens.join(" OR ");
        if !fts.is_empty() {
            let sql = format!(
                "SELECT m.kind, m.text FROM memories m \
                 JOIN memories_fts f ON f.rowid = m.rowid \
                 WHERE memories_fts MATCH ?1 {scope_clause} \
                 ORDER BY bm25(memories_fts) - m.confidence * 2.0 \
                   - MAX(0.0, 1.0 - (julianday('now') * 86400000.0 - m.created_at) / 2592000000.0) \
                 LIMIT {limit_param}"
            );
            let mut stmt = conn.prepare(&sql)?;
            let lim = limit_i64(limit);
            let map = |r: &rusqlite::Row<'_>| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?));
            let rows = match project_id {
                Some(pid) => stmt
                    .query_map(params![fts, pid, lim], map)?
                    .collect::<std::result::Result<Vec<_>, SqlError>>()?,
                None => stmt
                    .query_map(params![fts, lim], map)?
                    .collect::<std::result::Result<Vec<_>, SqlError>>()?,
            };
            if !rows.is_empty() {
                return Ok(rows);
            }
        }
        // Fallback: most confident recent records.
        let lim = limit_i64(limit);
        let map = |r: &rusqlite::Row<'_>| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?));
        let rows = if let Some(pid) = project_id {
            let mut stmt = conn.prepare(
                "SELECT kind, text FROM memories m \
                 WHERE m.project_id = ?1 OR m.scope = 'user' \
                 ORDER BY confidence DESC, created_at DESC LIMIT ?2",
            )?;
            stmt.query_map(params![pid, lim], map)?
                .collect::<std::result::Result<Vec<_>, SqlError>>()?
        } else {
            let mut stmt = conn.prepare(
                "SELECT kind, text FROM memories m \
                 ORDER BY confidence DESC, created_at DESC LIMIT ?1",
            )?;
            stmt.query_map(params![lim], map)?
                .collect::<std::result::Result<Vec<_>, SqlError>>()?
        };
        Ok(rows)
    }

    /// Top user-scope records for the standing profile block.
    pub fn memory_profile(&self, limit: usize) -> Result<Vec<(String, String)>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT kind, text FROM memories WHERE scope = 'user'              ORDER BY confidence DESC, created_at DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit_i64(limit)], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, SqlError>>()?;
        Ok(rows)
    }

    /// (scope, kind, text, confidence, project_id) for one memory row.
    pub fn get_memory(&self, id: &str) -> Result<Option<MemoryRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT scope, kind, text, confidence, project_id FROM memories WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(params![id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, f64>(3)?.to_string(),
                r.get::<_, Option<String>>(4)?,
            ))
        })?;
        Ok(rows.next().transpose()?)
    }

    /// Hash used for forget tombstones: normalized text so trivial edits do
    /// not defeat the tombstone.
    fn memory_hash(text: &str) -> String {
        use sha2::Digest;
        let norm: String = text
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();
        sha2::Sha256::digest(norm.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// A forgotten text is permanently suppressed from distill/import.
    pub fn memory_tombstoned(&self, text: &str) -> bool {
        self.lock()
            .query_row(
                "SELECT 1 FROM memory_tombstones WHERE text_hash = ?1",
                params![Self::memory_hash(text)],
                |_| Ok(true),
            )
            .optional()
            .ok()
            .flatten()
            .unwrap_or(false)
    }

    /// Deletes the row and tombstones its text so distill cannot re-learn it.
    /// Forgetting does not scrub existing transcripts or exports.
    pub fn delete_memory(&self, id: &str) -> Result<bool> {
        let conn = self.lock();
        if let Ok(text) = conn.query_row(
            "SELECT text FROM memories WHERE id = ?1",
            params![id],
            |r| r.get::<_, String>(0),
        ) {
            conn.execute(
                "INSERT OR IGNORE INTO memory_tombstones (text_hash, created_at) VALUES (?1, ?2)",
                params![Self::memory_hash(&text), freedas_core::paths::now_ms()],
            )?;
        }
        Ok(conn.execute("DELETE FROM memories WHERE id = ?1", params![id])? > 0)
    }

    pub fn export_memory(&self) -> Result<String> {
        let conn = self.lock();
        let mut stmt =
            conn.prepare("SELECT kind, text, created_at FROM memories ORDER BY kind, created_at")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        let mut out = String::new();
        let mut cur = String::new();
        for row in rows.collect::<std::result::Result<Vec<_>, SqlError>>()? {
            if row.0 != cur {
                cur = row.0.clone();
                out.push_str(&format!("\n## {cur}\n"));
            }
            out.push_str(&format!("- {}\n", freedas_core::redact::redact(&row.1)));
        }
        Ok(out)
    }

    pub fn router_stats(&self) -> Result<Vec<RouterRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare("SELECT task_class, model, attempts, successes, failures, total_cost_usd FROM router_stats")?;
        let rows = stmt
            .query_map([], |r| {
                Ok(RouterRow {
                    task_class: r.get(0)?,
                    model: r.get(1)?,
                    attempts: r.get(2)?,
                    successes: r.get(3)?,
                    failures: r.get(4)?,
                    total_cost: r.get(5)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, SqlError>>()?;
        Ok(rows)
    }

    /// Push an undone (message_id → post-state sha, removed rows) entry,
    /// returning the new redo row id so callers thread it instead of
    /// looking up the latest row.
    pub fn push_redo(
        &self,
        session_id: &str,
        message_id: &str,
        commit_sha: &str,
        removed: &DeletedSet,
    ) -> Result<i64> {
        check_commit_sha(commit_sha)?;
        let conn = self.lock();
        ensure_redo_table(&conn)?;
        conn.execute(
            "INSERT INTO redo_stack (session_id, message_id, commit_sha, messages_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![session_id, message_id, commit_sha, serde_json::to_string(removed)?, freedas_core::paths::now_ms()],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Most recent redo entry for the session. Read-only: the entry is dropped
    /// by `apply_redo` only after the restore and re-insert succeed, so a
    /// failed redo can be retried.
    pub fn pop_redo(&self, session_id: &str) -> Result<Option<RedoRow>> {
        let conn = self.lock();
        ensure_redo_table(&conn)?;
        let raw: Option<(i64, String, String, String, String, i64)> = conn
            .query_row(
                "SELECT id, session_id, message_id, commit_sha, messages_json, created_at FROM redo_stack WHERE session_id = ?1 ORDER BY id DESC LIMIT 1",
                params![session_id],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((id, session_id, message_id, commit_sha, json, created_at)) = raw else {
            return Ok(None);
        };
        let removed = serde_json::from_str(&json).map_err(|e| {
            freedas_core::FreedasError::Other(format!("corrupt redo entry {id}: {e}"))
        })?;
        Ok(Some(RedoRow {
            id,
            session_id,
            message_id,
            commit_sha,
            removed,
            created_at,
        }))
    }

    /// Restore a popped redo set and drop its entry in one transaction.
    /// `session_id` is the caller's session: the redo row must belong to it
    /// and must exist, failing closed rather than letting payload rows pick
    /// the destination session.
    pub fn apply_redo(&self, session_id: &str, redo_id: i64, removed: &DeletedSet) -> Result<()> {
        let mut conn = self.lock();
        let owner: Option<String> = conn
            .query_row(
                "SELECT session_id FROM redo_stack WHERE id = ?1",
                params![redo_id],
                |r| r.get(0),
            )
            .optional()?;
        match owner {
            Some(o) if o == session_id => {}
            Some(_) => {
                return Err(freedas_core::FreedasError::Other(format!(
                    "redo entry {redo_id} belongs to a different session"
                )));
            }
            None => {
                return Err(freedas_core::FreedasError::Other(format!(
                    "redo entry {redo_id} no longer exists"
                )));
            }
        }
        let tx = conn.transaction()?;
        insert_set(&tx, session_id, removed)?;
        tx.execute("DELETE FROM redo_stack WHERE id = ?1", params![redo_id])?;
        tx.commit()?;
        Ok(())
    }

    /// Clear a session's redo stack (a fresh message invalidates redo).
    pub fn clear_redo(&self, session_id: &str) -> Result<()> {
        let conn = self.lock();
        ensure_redo_table(&conn)?;
        conn.execute(
            "DELETE FROM redo_stack WHERE session_id = ?1",
            params![session_id],
        )?;
        Ok(())
    }

    /// Attach the rows captured by `delete_messages_from` to the redo entry
    /// created in the same transaction. The caller threads the row id
    /// returned alongside the capture; never look up the latest row here.
    /// An empty capture is a no-op: a second delete in the revert path
    /// must not blank the payload the first one stored.
    pub fn attach_redo_messages(&self, redo_id: i64, removed: &DeletedSet) -> Result<()> {
        if removed.messages.is_empty() && removed.usage.is_empty() {
            return Ok(());
        }
        let conn = self.lock();
        ensure_redo_table(&conn)?;
        conn.execute(
            "UPDATE redo_stack SET messages_json = ?2 WHERE id = ?1",
            params![redo_id, serde_json::to_string(removed)?],
        )?;
        Ok(())
    }

    /// Re-insert captured messages, their parts, and usage rows with their
    /// original ids (redo / import) into the caller's session. Payload
    /// session values are overwritten with `session_id` so a stale or
    /// foreign payload cannot scatter rows into another session.
    pub fn insert_messages(&self, session_id: &str, removed: &DeletedSet) -> Result<()> {
        if session_id.is_empty() {
            return Err(freedas_core::FreedasError::Other(
                "insert_messages requires a session id".into(),
            ));
        }
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        insert_set(&tx, session_id, removed)?;
        tx.commit()?;
        Ok(())
    }

    /// Full session row for export (`None` when the id is unknown).
    pub fn session_full(&self, id: &str) -> Result<Option<SessionFull>> {
        let conn = self.lock();
        Ok(conn
            .query_row(
                "SELECT id, project_id, parent_id, title, agent, model_provider, model_id, model_variant, workspace_id, status, archived, metadata, created_at, updated_at FROM sessions WHERE id = ?1",
                params![id],
                |r| {
                    Ok(SessionFull {
                        id: r.get(0)?,
                        project_id: r.get(1)?,
                        parent_id: r.get(2)?,
                        title: r.get(3)?,
                        agent: r.get(4)?,
                        model_provider: r.get(5)?,
                        model_id: r.get(6)?,
                        model_variant: r.get(7)?,
                        workspace_id: r.get(8)?,
                        status: r.get(9)?,
                        archived: r.get::<_, i64>(10)? != 0,
                        metadata: r.get(11)?,
                        created_at: r.get(12)?,
                        updated_at: r.get(13)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn list_usage_rows(&self, session_id: &str) -> Result<Vec<UsageRecord>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, session_id, workspace_id, provider, model, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, cost_usd, kind, created_at FROM usage WHERE session_id = ?1 ORDER BY created_at, rowid",
        )?;
        let rows = stmt
            .query_map(params![session_id], |r| {
                Ok(UsageRecord {
                    id: r.get(0)?,
                    session_id: r.get(1)?,
                    workspace_id: r.get(2)?,
                    provider: r.get(3)?,
                    model: r.get(4)?,
                    input_tokens: r.get(5)?,
                    output_tokens: r.get(6)?,
                    cache_read_tokens: r.get(7)?,
                    cache_write_tokens: r.get(8)?,
                    cost_usd: r.get(9)?,
                    kind: r.get(10)?,
                    created_at: r.get(11)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, SqlError>>()?;
        Ok(rows)
    }

    pub fn list_snapshot_rows(&self, session_id: &str) -> Result<Vec<SnapshotRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, message_id, commit_sha, created_at FROM snapshots WHERE session_id = ?1 ORDER BY created_at, rowid",
        )?;
        let rows = stmt
            .query_map(params![session_id], |r| {
                Ok(SnapshotRow {
                    id: r.get(0)?,
                    message_id: r.get(1)?,
                    commit_sha: r.get(2)?,
                    created_at: r.get(3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, SqlError>>()?;
        Ok(rows)
    }

    pub fn list_todo_rows(&self, session_id: &str) -> Result<Vec<TodoRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, content, status, priority FROM todos WHERE session_id = ?1 ORDER BY id",
        )?;
        let rows = stmt
            .query_map(params![session_id], |r| {
                Ok(TodoRow {
                    id: r.get(0)?,
                    content: r.get(1)?,
                    status: r.get(2)?,
                    priority: r.get(3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, SqlError>>()?;
        Ok(rows)
    }

    pub fn list_permission_rows(&self, session_id: &str) -> Result<Vec<PermissionRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, action, resource, effect, scope, created_at FROM permissions WHERE session_id = ?1 ORDER BY created_at, rowid",
        )?;
        let rows = stmt
            .query_map(params![session_id], |r| {
                Ok(PermissionRow {
                    id: r.get(0)?,
                    action: r.get(1)?,
                    resource: r.get(2)?,
                    effect: r.get(3)?,
                    scope: r.get(4)?,
                    created_at: r.get(5)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, SqlError>>()?;
        Ok(rows)
    }

    /// Import a versioned export object: one transaction, remapping ids that
    /// collide with existing rows.
    pub fn import_session(&self, project_id: &str, v: &serde_json::Value) -> Result<ImportReport> {
        let version = v.get("version").and_then(|x| x.as_i64()).unwrap_or(0);
        if version != 1 {
            return Err(freedas_core::FreedasError::Other(format!(
                "unsupported export version {version} (expected 1)"
            )));
        }
        let session = v.get("session").cloned().unwrap_or_default();
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let now = freedas_core::paths::now_ms();
        let wanted = session.get("id").and_then(|x| x.as_str()).unwrap_or("");
        let session_exists: bool = if wanted.is_empty() {
            false
        } else {
            tx.query_row(
                "SELECT 1 FROM sessions WHERE id = ?1",
                params![wanted],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false)
        };
        let mut remapped = 0usize;
        let sid = if wanted.is_empty() || session_exists {
            if !wanted.is_empty() {
                remapped += 1;
            }
            format!("ses_{}", ulid::Ulid::new())
        } else {
            wanted.to_string()
        };
        let get = |key: &str| session.get(key).and_then(|x| x.as_str());
        // Keep the parent link only when that session exists in this database.
        let parent: Option<String> = match get("parentID") {
            Some(p)
                if tx
                    .query_row("SELECT 1 FROM sessions WHERE id = ?1", params![p], |_| {
                        Ok(true)
                    })
                    .optional()?
                    .unwrap_or(false) =>
            {
                Some(p.to_string())
            }
            _ => None,
        };
        tx.execute(
            "INSERT OR REPLACE INTO sessions (id, project_id, parent_id, title, agent, model_provider, model_id, model_variant, workspace_id, status, archived, metadata, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                sid,
                project_id,
                parent,
                get("title").unwrap_or("imported"),
                get("agent").unwrap_or("build"),
                get("modelProvider"),
                get("modelId"),
                get("modelVariant"),
                get("workspaceId").or_else(|| get("workspaceID")),
                get("status").unwrap_or("idle"),
                session.get("archived").and_then(|x| x.as_bool()).unwrap_or(false) as i64,
                session.pointer("/metadata").map(|m| m.to_string()).unwrap_or_else(|| "{}".into()),
                session.get("createdAt").and_then(|x| x.as_i64()).unwrap_or(now),
                session.get("updatedAt").and_then(|x| x.as_i64()).unwrap_or(now),
            ],
        )?;
        let (mut nmsg, mut nparts, mut nusage) = (0usize, 0usize, 0usize);
        // Export ids are opaque; map them so snapshot rows keep pointing at the
        // message that was imported under a possibly remapped id.
        let mut mid_map: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for m in v
            .get("messages")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default()
        {
            let wanted_mid = m.get("id").and_then(|x| x.as_str()).unwrap_or("");
            let mid_exists: bool = if wanted_mid.is_empty() {
                false
            } else {
                tx.query_row(
                    "SELECT 1 FROM messages WHERE id = ?1",
                    params![wanted_mid],
                    |_| Ok(true),
                )
                .optional()?
                .unwrap_or(false)
            };
            let mid = if wanted_mid.is_empty() || mid_exists {
                if !wanted_mid.is_empty() {
                    remapped += 1;
                }
                format!("msg_{}", ulid::Ulid::new())
            } else {
                wanted_mid.to_string()
            };
            if !wanted_mid.is_empty() {
                mid_map.insert(wanted_mid.to_string(), mid.clone());
            }
            tx.execute(
                "INSERT OR REPLACE INTO messages (id, session_id, role, model, usage, error, metadata, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    mid,
                    sid,
                    m.get("role").and_then(|x| x.as_str()).unwrap_or("user"),
                    m.get("model").map(|x| x.to_string()),
                    m.get("usage").map(|x| x.to_string()),
                    m.get("error").map(|x| x.to_string()),
                    m.pointer("/metadata").map(|x| x.to_string()).unwrap_or_else(|| "{}".into()),
                    m.get("createdAt").and_then(|x| x.as_i64()).unwrap_or(now),
                ],
            )?;
            nmsg += 1;
            for p in m
                .get("parts")
                .and_then(|x| x.as_array())
                .cloned()
                .unwrap_or_default()
            {
                let wanted_pid = p.get("id").and_then(|x| x.as_str()).unwrap_or("");
                let pid_exists: bool = if wanted_pid.is_empty() {
                    false
                } else {
                    tx.query_row(
                        "SELECT 1 FROM parts WHERE id = ?1",
                        params![wanted_pid],
                        |_| Ok(true),
                    )
                    .optional()?
                    .unwrap_or(false)
                };
                let pid = if wanted_pid.is_empty() || pid_exists {
                    if !wanted_pid.is_empty() {
                        remapped += 1;
                    }
                    format!("prt_{}", ulid::Ulid::new())
                } else {
                    wanted_pid.to_string()
                };
                tx.execute(
                    "INSERT OR REPLACE INTO parts (id, session_id, message_id, idx, kind, data, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        pid,
                        sid,
                        mid,
                        p.get("idx").and_then(|x| x.as_i64()).unwrap_or(0),
                        p.get("kind").and_then(|x| x.as_str()).unwrap_or("text"),
                        p.get("data").map(|x| x.to_string()).unwrap_or_else(|| "{}".into()),
                        p.get("createdAt").and_then(|x| x.as_i64()).unwrap_or(now),
                    ],
                )?;
                nparts += 1;
            }
        }
        for u in v
            .get("usage")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default()
        {
            let wanted = u.get("id").and_then(|x| x.as_str()).unwrap_or("");
            let exists: bool = if wanted.is_empty() {
                false
            } else {
                tx.query_row("SELECT 1 FROM usage WHERE id = ?1", params![wanted], |_| {
                    Ok(true)
                })
                .optional()?
                .unwrap_or(false)
            };
            let uid = if wanted.is_empty() || exists {
                if !wanted.is_empty() {
                    remapped += 1;
                }
                format!("usg_{}", ulid::Ulid::new())
            } else {
                wanted.to_string()
            };
            tx.execute(
                "INSERT OR REPLACE INTO usage (id, session_id, workspace_id, provider, model, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, cost_usd, kind, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    uid,
                    sid,
                    u.get("workspaceId").or_else(|| u.get("workspaceID")).and_then(|x| x.as_str()),
                    u.get("provider").and_then(|x| x.as_str()).unwrap_or("unknown"),
                    u.get("model").and_then(|x| x.as_str()).unwrap_or("unknown"),
                    u.get("inputTokens").and_then(|x| x.as_i64()).unwrap_or(0),
                    u.get("outputTokens").and_then(|x| x.as_i64()).unwrap_or(0),
                    u.get("cacheReadTokens").and_then(|x| x.as_i64()).unwrap_or(0),
                    u.get("cacheWriteTokens").and_then(|x| x.as_i64()).unwrap_or(0),
                    u.get("costUSD").and_then(|x| x.as_f64()).unwrap_or(0.0),
                    u.get("kind").and_then(|x| x.as_str()).unwrap_or("primary"),
                    u.get("createdAt").and_then(|x| x.as_i64()).unwrap_or(now),
                ],
            )?;
            nusage += 1;
        }
        for s in v
            .get("snapshots")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default()
        {
            let wanted = s.get("id").and_then(|x| x.as_str()).unwrap_or("");
            let exists: bool = if wanted.is_empty() {
                false
            } else {
                tx.query_row(
                    "SELECT 1 FROM snapshots WHERE id = ?1",
                    params![wanted],
                    |_| Ok(true),
                )
                .optional()?
                .unwrap_or(false)
            };
            let snapshot_id = if wanted.is_empty() || exists {
                if !wanted.is_empty() {
                    remapped += 1;
                }
                format!("snp_{}", ulid::Ulid::new())
            } else {
                wanted.to_string()
            };
            let message_id = s
                .get("messageID")
                .and_then(|x| x.as_str())
                .map(|m| mid_map.get(m).cloned().unwrap_or_else(|| m.to_string()))
                .unwrap_or_default();
            // Snapshot SHAs become `git` arguments during undo/redo; reject
            // anything that is not a short or full lowercase hex object name.
            let commit_sha = s.get("commitSha").and_then(|x| x.as_str()).unwrap_or("");
            if !is_valid_commit_sha(commit_sha) {
                return Err(freedas_core::FreedasError::Other(format!(
                    "invalid snapshots[].commitSha {commit_sha:?}: expected ^[0-9a-f]{{4,64}}$"
                )));
            }
            tx.execute(
                "INSERT OR REPLACE INTO snapshots (id, session_id, message_id, commit_sha, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    snapshot_id,
                    sid,
                    message_id,
                    commit_sha,
                    s.get("createdAt").and_then(|x| x.as_i64()).unwrap_or(now),
                ],
            )?;
        }
        for t in v
            .get("todos")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default()
        {
            let id = match t.get("id").and_then(|x| x.as_str()) {
                Some(id) if !id.is_empty() => id.to_string(),
                _ => format!("todo_{}", ulid::Ulid::new()),
            };
            tx.execute(
                "INSERT OR REPLACE INTO todos (session_id, id, content, status, priority) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    sid,
                    id,
                    t.get("content").and_then(|x| x.as_str()).unwrap_or(""),
                    t.get("status").and_then(|x| x.as_str()).unwrap_or("pending"),
                    t.get("priority").and_then(|x| x.as_str()).unwrap_or("medium"),
                ],
            )?;
        }
        for p in v
            .get("permissions")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default()
        {
            // Session-scoped rows are recreated under the new session id; global
            // rows (no session) are skipped because they are not part of the export.
            let scope = p.get("scope").and_then(|x| x.as_str()).unwrap_or("session");
            if scope != "session" {
                continue;
            }
            let wanted = p.get("id").and_then(|x| x.as_str()).unwrap_or("");
            let exists: bool = if wanted.is_empty() {
                false
            } else {
                tx.query_row(
                    "SELECT 1 FROM permissions WHERE id = ?1",
                    params![wanted],
                    |_| Ok(true),
                )
                .optional()?
                .unwrap_or(false)
            };
            let pid_out = if wanted.is_empty() || exists {
                if !wanted.is_empty() {
                    remapped += 1;
                }
                format!("prm_{}", ulid::Ulid::new())
            } else {
                wanted.to_string()
            };
            tx.execute(
                "INSERT OR REPLACE INTO permissions (id, session_id, action, resource, effect, scope, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    pid_out,
                    sid,
                    p.get("action").and_then(|x| x.as_str()).unwrap_or("read"),
                    p.get("resource").and_then(|x| x.as_str()).unwrap_or("*"),
                    p.get("effect").and_then(|x| x.as_str()).unwrap_or("allow"),
                    scope,
                    p.get("createdAt").and_then(|x| x.as_i64()).unwrap_or(now),
                ],
            )?;
        }
        tx.commit()?;
        Ok(ImportReport {
            session_id: sid,
            messages: nmsg,
            parts: nparts,
            usage: nusage,
            remapped,
        })
    }
}

/// Read the rows a revert removes, beginning at `message_id`. `created_at`
/// ties are broken by `rowid` so `delete_captured` removes exactly these rows.
fn capture_from(
    tx: &rusqlite::Transaction<'_>,
    session_id: &str,
    message_id: &str,
) -> Result<(DeletedSet, (i64, i64))> {
    let (at, rowid): (i64, i64) = tx.query_row(
        "SELECT created_at, rowid FROM messages WHERE id = ?1 AND session_id = ?2",
        params![message_id, session_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let mut messages: Vec<MessageRecord> = {
        let mut stmt = tx.prepare(
            "SELECT id, session_id, role, model, usage, error, metadata, created_at FROM messages \
             WHERE session_id = ?1 AND (created_at > ?2 OR (created_at = ?2 AND rowid >= ?3)) \
             ORDER BY created_at, rowid",
        )?;
        stmt.query_map(params![session_id, at, rowid], |r| {
            Ok(MessageRecord {
                id: r.get(0)?,
                session_id: r.get(1)?,
                role: r.get(2)?,
                model: r.get(3)?,
                usage: r.get(4)?,
                error: r.get(5)?,
                metadata: r.get(6)?,
                created_at: r.get(7)?,
                parts: Vec::new(),
            })
        })?
        .collect::<std::result::Result<Vec<_>, SqlError>>()?
    };
    for m in &mut messages {
        let mut stmt = tx.prepare(
            "SELECT id, session_id, message_id, idx, kind, data, created_at FROM parts WHERE message_id = ?1 ORDER BY idx",
        )?;
        m.parts = stmt
            .query_map(params![m.id], |r| {
                Ok(PartRecord {
                    id: r.get(0)?,
                    session_id: r.get(1)?,
                    message_id: r.get(2)?,
                    idx: r.get(3)?,
                    kind: r.get(4)?,
                    data: r.get(5)?,
                    created_at: r.get(6)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, SqlError>>()?;
    }
    let usage: Vec<UsageRecord> = {
        let mut stmt = tx.prepare(
            "SELECT id, session_id, workspace_id, provider, model, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, cost_usd, kind, created_at FROM usage WHERE session_id = ?1 AND (created_at > ?2 OR (created_at = ?2 AND rowid >= ?3)) ORDER BY created_at, rowid",
        )?;
        stmt.query_map(params![session_id, at, rowid], |r| {
            Ok(UsageRecord {
                id: r.get(0)?,
                session_id: r.get(1)?,
                workspace_id: r.get(2)?,
                provider: r.get(3)?,
                model: r.get(4)?,
                input_tokens: r.get(5)?,
                output_tokens: r.get(6)?,
                cache_read_tokens: r.get(7)?,
                cache_write_tokens: r.get(8)?,
                cost_usd: r.get(9)?,
                kind: r.get(10)?,
                created_at: r.get(11)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, SqlError>>()?
    };
    Ok((DeletedSet { messages, usage }, (at, rowid)))
}

fn delete_captured(
    tx: &rusqlite::Transaction<'_>,
    session_id: &str,
    (at, rowid): (i64, i64),
    removed: &DeletedSet,
) -> Result<()> {
    tx.execute(
        "DELETE FROM messages WHERE session_id = ?1 AND (created_at > ?2 OR (created_at = ?2 AND rowid >= ?3))",
        params![session_id, at, rowid],
    )?;
    // Usage rows carry no message id, so delete exactly the captured ids: a
    // timestamp-only window would also drop usage belonging to the last kept
    // message when timestamps tie.
    if !removed.usage.is_empty() {
        let placeholders = removed
            .usage
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("DELETE FROM usage WHERE id IN ({placeholders})");
        tx.execute(
            &sql,
            rusqlite::params_from_iter(removed.usage.iter().map(|u| u.id.as_str())),
        )?;
    }
    // Snapshots point at the removed messages; without this they dangle and a
    // later undo/redo would restore against a commit that no longer exists.
    if !removed.messages.is_empty() {
        let placeholders = removed
            .messages
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "DELETE FROM snapshots WHERE session_id = ?1 AND message_id IN ({placeholders})"
        );
        let mut p: Vec<&str> = vec![session_id];
        p.extend(removed.messages.iter().map(|m| m.id.as_str()));
        tx.execute(&sql, rusqlite::params_from_iter(p))?;
    }
    Ok(())
}

/// Re-insert a captured set inside an open transaction. The caller session wins:
/// payload `session_id` values are overwritten so a stale or cross-session
/// payload cannot scatter rows into another session.
fn insert_set(
    tx: &rusqlite::Transaction<'_>,
    session_id: &str,
    removed: &DeletedSet,
) -> Result<()> {
    for m in &removed.messages {
        debug_assert_eq!(
            m.session_id, session_id,
            "message payload session must match caller session"
        );
        tx.execute(
            "INSERT OR REPLACE INTO messages (id, session_id, role, model, usage, error, metadata, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![m.id, session_id, m.role, m.model, m.usage, m.error, m.metadata, m.created_at],
        )?;
        for p in &m.parts {
            debug_assert_eq!(
                p.session_id, session_id,
                "part payload session must match caller session"
            );
            debug_assert_eq!(
                p.message_id, m.id,
                "part payload message must match its message"
            );
            tx.execute(
                "INSERT OR REPLACE INTO parts (id, session_id, message_id, idx, kind, data, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![p.id, session_id, p.message_id, p.idx, p.kind, p.data, p.created_at],
            )?;
        }
    }
    for u in &removed.usage {
        debug_assert!(
            u.session_id.as_deref().unwrap_or(session_id) == session_id,
            "usage payload session must match caller session"
        );
        tx.execute(
            "INSERT OR REPLACE INTO usage (id, session_id, workspace_id, provider, model, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, cost_usd, kind, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![u.id, session_id, u.workspace_id, u.provider, u.model, u.input_tokens, u.output_tokens, u.cache_read_tokens, u.cache_write_tokens, u.cost_usd, u.kind, u.created_at],
        )?;
    }
    Ok(())
}

/// `redo_stack` predates the capture columns on some installs; recreate it
/// (a pending redo is transient) when the old shape is found.
fn ensure_redo_table(conn: &Connection) -> Result<()> {
    let mut cols: Vec<String> = Vec::new();
    if let Ok(mut stmt) = conn.prepare("PRAGMA table_info(redo_stack)")
        && let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(1))
    {
        cols = rows.flatten().collect();
    }
    if !cols.is_empty() && !cols.iter().any(|c| c == "messages_json") {
        conn.execute("DROP TABLE redo_stack", [])?;
    }
    conn.execute(
        "CREATE TABLE IF NOT EXISTS redo_stack (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, message_id TEXT NOT NULL, commit_sha TEXT NOT NULL, messages_json TEXT NOT NULL DEFAULT '{}', created_at INTEGER NOT NULL)",
        [],
    )?;
    // The legacy drop above also drops the index; recreate it.
    conn.execute(
        "CREATE INDEX IF NOT EXISTS redo_stack_session ON redo_stack(session_id)",
        [],
    )?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct SessionRow {
    pub id: String,
    pub title: String,
    pub agent: String,
    pub status: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct MessageRow {
    pub id: String,
    pub role: String,
    pub model: Option<String>,
    pub usage: Option<String>,
    pub error: Option<String>,
    pub metadata: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PartRecord {
    pub id: String,
    pub session_id: String,
    pub message_id: String,
    pub idx: i64,
    pub kind: String,
    pub data: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MessageRecord {
    pub id: String,
    pub session_id: String,
    pub role: String,
    pub model: Option<String>,
    pub usage: Option<String>,
    pub error: Option<String>,
    pub metadata: String,
    pub created_at: i64,
    pub parts: Vec<PartRecord>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UsageRecord {
    pub id: String,
    pub session_id: Option<String>,
    pub workspace_id: Option<String>,
    pub provider: String,
    pub model: String,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_read_tokens: i64,
    pub cache_write_tokens: i64,
    pub cost_usd: f64,
    pub kind: String,
    pub created_at: i64,
}

/// Rows removed by an undo: restored verbatim by redo.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DeletedSet {
    pub messages: Vec<MessageRecord>,
    #[serde(default)]
    pub usage: Vec<UsageRecord>,
}

#[derive(Debug, Clone)]
pub struct RedoRow {
    pub id: i64,
    pub session_id: String,
    pub message_id: String,
    pub commit_sha: String,
    pub removed: DeletedSet,
    pub created_at: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionFull {
    pub id: String,
    pub project_id: String,
    pub parent_id: Option<String>,
    pub title: String,
    pub agent: String,
    pub model_provider: Option<String>,
    pub model_id: Option<String>,
    pub model_variant: Option<String>,
    pub workspace_id: Option<String>,
    pub status: String,
    pub archived: bool,
    pub metadata: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotRow {
    pub id: String,
    pub message_id: String,
    pub commit_sha: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TodoRow {
    pub id: String,
    pub content: String,
    pub status: String,
    pub priority: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PermissionRow {
    pub id: String,
    pub action: String,
    pub resource: String,
    pub effect: String,
    pub scope: String,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct ImportReport {
    pub session_id: String,
    pub messages: usize,
    pub parts: usize,
    pub usage: usize,
    pub remapped: usize,
}

#[derive(Debug, Clone)]
pub struct PartRow {
    pub id: String,
    pub idx: i64,
    pub kind: String,
    pub data: String,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct UsageTotal {
    pub provider: String,
    pub model: String,
    pub input: i64,
    pub output: i64,
    pub cache_read: i64,
    pub cost: f64,
    pub calls: i64,
}

#[derive(Debug, Clone)]
pub struct ToolUsageTotal {
    pub tool: String,
    pub calls: i64,
    pub duration_ms: i64,
}

#[derive(Debug, Clone)]
pub struct RouterRow {
    pub task_class: String,
    pub model: String,
    pub attempts: i64,
    pub successes: i64,
    pub failures: i64,
    pub total_cost: f64,
}

// ── Session export ──────────────────────────────────────────────

pub fn export_session(
    d: &Db,
    paths: &freedas_core::paths::Paths,
    project_root: &std::path::Path,
    id: Option<&str>,
    sanitize: bool,
    format: &str,
) -> crate::Result<String> {
    let pid = d.ensure_project(project_root)?;
    let sid = match id {
        Some(v) if !v.is_empty() && v != "latest" => v.to_string(),
        _ => d
            .list_sessions(&pid, 1)?
            .first()
            .map(|s| s.id.clone())
            .unwrap_or_default(),
    };
    if sid.is_empty() {
        return Err(freedas_core::FreedasError::Other(
            "no sessions to export".into(),
        ));
    }
    let session = d
        .session_full(&sid)?
        .filter(|s| s.project_id == pid)
        .ok_or_else(|| freedas_core::FreedasError::Other(format!("session {sid} not found")))?;
    let messages = d.list_messages(&sid)?;
    let mut msgs = Vec::new();
    for m in &messages {
        let parts = d
            .list_parts(&sid, &m.id)?
            .into_iter()
            .map(|p| {
                serde_json::json!({
                    "id": p.id,
                    "idx": p.idx,
                    "kind": p.kind,
                    "data": serde_json::from_str::<serde_json::Value>(&p.data).unwrap_or_default(),
                    "createdAt": p.created_at,
                })
            })
            .collect::<Vec<_>>();
        msgs.push(serde_json::json!({
            "id": m.id,
            "role": m.role,
            "model": m.model.as_deref().and_then(|t| serde_json::from_str::<serde_json::Value>(t).ok()),
            "usage": m.usage.as_deref().and_then(|t| serde_json::from_str::<serde_json::Value>(t).ok()),
            "error": m.error.as_deref().and_then(|t| serde_json::from_str::<serde_json::Value>(t).ok()),
            "metadata": serde_json::from_str::<serde_json::Value>(&m.metadata).unwrap_or_default(),
            "createdAt": m.created_at,
            "parts": parts,
        }));
    }
    let usage = d.list_usage_rows(&sid)?;
    let snapshots = d.list_snapshot_rows(&sid)?;
    let todos = d.list_todo_rows(&sid)?;
    let permissions = d.list_permission_rows(&sid)?;
    if format == "markdown" {
        let mut md = format!(
            "# {}\n\n- id: {}\n- agent: {}\n- status: {}\n- created: {}\n\n",
            session.title, session.id, session.agent, session.status, session.created_at
        );
        for m in &messages {
            md.push_str(&format!("## {}\n\n", m.role));
            for p in d.list_parts(&sid, &m.id)? {
                let data: serde_json::Value = serde_json::from_str(&p.data).unwrap_or_default();
                match p.kind.as_str() {
                    "text" | "reasoning" => {
                        if let Some(t) = data["text"].as_str() {
                            md.push_str(t);
                            md.push_str("\n\n");
                        }
                    }
                    "tool" => {
                        md.push_str(&format!("```json\n{data}\n```\n\n"));
                    }
                    "compaction" => {
                        if let Some(s) = data["summary"].as_str() {
                            md.push_str(&format!("> compaction: {s}\n\n"));
                        }
                    }
                    _ => {}
                }
            }
        }
        if !usage.is_empty() {
            md.push_str("## Usage\n\n");
            for u in &usage {
                md.push_str(&format!(
                    "- {} / {}: in {} out {} cost ${:.4}\n",
                    u.provider, u.model, u.input_tokens, u.output_tokens, u.cost_usd
                ));
            }
        }
        if sanitize {
            let redacted = freedas_core::redact::redact(&md);
            return Ok(scrub_text(&redacted, &paths.home.to_string_lossy()));
        }
        return Ok(md);
    }
    let mut out = serde_json::json!({
        "version": 1,
        "session": {
            "id": session.id,
            "projectID": session.project_id,
            "parentID": session.parent_id,
            "title": session.title,
            "agent": session.agent,
            "modelProvider": session.model_provider,
            "modelId": session.model_id,
            "modelVariant": session.model_variant,
            "workspaceID": session.workspace_id,
            "status": session.status,
            "archived": session.archived,
            "metadata": serde_json::from_str::<serde_json::Value>(&session.metadata).unwrap_or_default(),
            "createdAt": session.created_at,
            "updatedAt": session.updated_at,
        },
        "messages": msgs,
        "usage": usage.iter().map(|u| serde_json::json!({
            "id": u.id,
            "workspaceID": u.workspace_id,
            "provider": u.provider,
            "model": u.model,
            "inputTokens": u.input_tokens,
            "outputTokens": u.output_tokens,
            "cacheReadTokens": u.cache_read_tokens,
            "cacheWriteTokens": u.cache_write_tokens,
            "costUSD": u.cost_usd,
            "kind": u.kind,
            "createdAt": u.created_at,
        })).collect::<Vec<_>>(),
        "snapshots": snapshots.iter().map(|s| serde_json::json!({
            "id": s.id, "messageID": s.message_id, "commitSha": s.commit_sha, "createdAt": s.created_at,
        })).collect::<Vec<_>>(),
        "todos": todos.iter().map(|t| serde_json::json!({
            "id": t.id, "content": t.content, "status": t.status, "priority": t.priority,
        })).collect::<Vec<_>>(),
        "permissions": permissions.iter().map(|p| serde_json::json!({
            "id": p.id, "action": p.action, "resource": p.resource,
            "effect": p.effect, "scope": p.scope, "createdAt": p.created_at,
        })).collect::<Vec<_>>(),
    });
    if sanitize {
        sanitize_value(&mut out, &paths.home);
    }
    Ok(serde_json::to_string_pretty(&out)?)
}

/// Redact secrets, the home prefix, and obvious `KEY=value` environment lines.
pub fn sanitize_value(value: &mut serde_json::Value, home: &std::path::Path) {
    *value = freedas_core::redact::redact_value(value);
    scrub_value(value, &home.to_string_lossy());
}

pub fn scrub_value(value: &mut serde_json::Value, home: &str) {
    match value {
        serde_json::Value::String(s) => *s = scrub_text(s, home),
        serde_json::Value::Array(a) => a.iter_mut().for_each(|v| scrub_value(v, home)),
        serde_json::Value::Object(o) => o.values_mut().for_each(|v| scrub_value(v, home)),
        _ => {}
    }
}

pub fn scrub_text(text: &str, home: &str) -> String {
    let replaced = if home.is_empty() {
        text.to_string()
    } else {
        text.replace(home, "~")
    };
    scrub_env_assignments(&replaced)
}

pub fn scrub_env_assignments(text: &str) -> String {
    text.split('\n')
        .map(|line| {
            let trimmed = line.trim_start();
            let Some(eq) = trimmed.find('=') else {
                return line.to_string();
            };
            let key = &trimmed[..eq];
            let value = &trimmed[eq + 1..];
            let env_like = !key.is_empty()
                && !value.is_empty()
                && !value.contains(char::is_whitespace)
                && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && key
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
            if env_like {
                let indent = &line[..line.len() - trimmed.len()];
                format!("{indent}{key}=[REDACTED]")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delete_and_reinsert_preserves_messages_parts_usage() {
        let db = Db::memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let pid = db.ensure_project(dir.path()).unwrap();
        let sid = db.create_session(&pid, "build", "t", None).unwrap();
        let mid = db
            .add_message(&sid, "assistant", &serde_json::json!({"router": {}}))
            .unwrap();
        db.add_part(&sid, &mid, 0, "text", &serde_json::json!({"text": "hi"}))
            .unwrap();
        db.record_usage(Some(&sid), "fake", "fake-1", 1, 2, 0, 0, 0.01, "primary")
            .unwrap();
        let (removed, _) = db.delete_messages_from(&sid, &mid, "abc123").unwrap();
        assert_eq!(removed.messages.len(), 1);
        assert_eq!(removed.messages[0].parts.len(), 1);
        assert_eq!(removed.usage.len(), 1);
        assert!(db.list_messages(&sid).unwrap().is_empty());
        assert!(db.list_usage_rows(&sid).unwrap().is_empty());
        db.insert_messages(&sid, &removed).unwrap();
        assert_eq!(db.list_messages(&sid).unwrap().len(), 1);
        assert_eq!(db.list_parts(&sid, &mid).unwrap().len(), 1);
        assert_eq!(db.list_usage_rows(&sid).unwrap().len(), 1);
    }

    #[test]
    fn redo_stack_roundtrip() {
        let db = Db::memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let pid = db.ensure_project(dir.path()).unwrap();
        let sid = db.create_session(&pid, "build", "t", None).unwrap();
        let mid = db
            .add_message(&sid, "assistant", &serde_json::json!({}))
            .unwrap();
        let (removed, redo_id) = db.delete_messages_from(&sid, &mid, "abc123").unwrap();
        // The redo entry is created in the delete transaction; the threaded id
        // points at the same row `pop_redo` returns.
        let row = db.pop_redo(&sid).unwrap().expect("redo row");
        assert_eq!(row.id, redo_id);
        assert_eq!(removed.messages.len(), 1);
        assert_eq!(row.commit_sha, "abc123");
        assert_eq!(row.removed.messages.len(), 1);
        // A pop is read-only so a failed redo can be retried.
        assert!(db.pop_redo(&sid).unwrap().is_some());
        db.apply_redo(&sid, row.id, &row.removed).unwrap();
        assert!(db.pop_redo(&sid).unwrap().is_none());
    }

    #[test]
    fn migration_and_session_roundtrip() {
        let db = Db::memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let pid = db.ensure_project(dir.path()).unwrap();
        let sid = db.create_session(&pid, "build", "t", None).unwrap();
        assert!(sid.starts_with("ses_"));
        let rows = db.list_sessions(&pid, 10).unwrap();
        assert_eq!(rows.len(), 1);
        let mid = db
            .add_message(&sid, "user", &serde_json::json!({}))
            .unwrap();
        db.add_part(&sid, &mid, 0, "text", &serde_json::json!({"text": "hi"}))
            .unwrap();
        let parts = db.list_parts(&sid, &mid).unwrap();
        assert_eq!(parts.len(), 1);
    }

    /// Build a session with one message, one part, and one usage row.
    fn seeded(db: &Db) -> (tempfile::TempDir, String, String, String) {
        let dir = tempfile::tempdir().unwrap();
        let pid = db.ensure_project(dir.path()).unwrap();
        let sid = db.create_session(&pid, "build", "t", None).unwrap();
        let mid = db
            .add_message(&sid, "assistant", &serde_json::json!({}))
            .unwrap();
        db.add_part(&sid, &mid, 0, "text", &serde_json::json!({"text": "hi"}))
            .unwrap();
        db.record_usage(Some(&sid), "fake", "fake-1", 1, 2, 0, 0, 0.01, "primary")
            .unwrap();
        (dir, pid, sid, mid)
    }

    #[test]
    fn undo_messages_moves_delete_and_redo_entry_together() {
        let db = Db::memory().unwrap();
        let (_dir, _pid, sid, mid) = seeded(&db);
        // An unknown boundary fails before anything is removed.
        assert!(db.undo_messages(&sid, "msg_missing", "abc123").is_err());
        // A malformed sha is rejected before anything is captured.
        assert!(db.undo_messages(&sid, &mid, "not a sha!").is_err());
        assert_eq!(db.list_messages(&sid).unwrap().len(), 1);
        let (removed, redo_id) = db.undo_messages(&sid, &mid, "abc123").unwrap();
        assert_eq!(removed.messages.len(), 1);
        assert_eq!(removed.messages[0].parts.len(), 1);
        assert!(db.list_messages(&sid).unwrap().is_empty());
        assert!(db.list_usage_rows(&sid).unwrap().is_empty());
        let row = db.pop_redo(&sid).unwrap().expect("redo entry");
        assert_eq!(row.id, redo_id);
        assert_eq!(row.commit_sha, "abc123");
    }

    #[test]
    fn attached_empty_capture_keeps_the_stored_redo_payload() {
        let db = Db::memory().unwrap();
        let (_dir, _pid, sid, mid) = seeded(&db);
        let (removed, redo_id) = db.delete_messages_from(&sid, &mid, "abc123").unwrap();
        assert_eq!(removed.messages.len(), 1);
        db.attach_redo_messages(redo_id, &DeletedSet::default())
            .unwrap();
        assert_eq!(
            db.pop_redo(&sid).unwrap().unwrap().removed.messages.len(),
            1
        );
    }

    #[test]
    fn corrupt_redo_payload_errors_and_keeps_the_entry() {
        let db = Db::memory().unwrap();
        let (_dir, _pid, sid, mid) = seeded(&db);
        let (_removed, _redo_id) = db.delete_messages_from(&sid, &mid, "abc123").unwrap();
        db.lock()
            .execute("UPDATE redo_stack SET messages_json = 'not json'", [])
            .unwrap();
        assert!(db.pop_redo(&sid).is_err());
        let count: i64 = db
            .lock()
            .query_row("SELECT COUNT(*) FROM redo_stack", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn message_boundary_breaks_created_at_ties_by_rowid() {
        let db = Db::memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let pid = db.ensure_project(dir.path()).unwrap();
        let sid = db.create_session(&pid, "build", "t", None).unwrap();
        let first = db
            .add_message(&sid, "user", &serde_json::json!({}))
            .unwrap();
        let second = db
            .add_message(&sid, "assistant", &serde_json::json!({}))
            .unwrap();
        db.lock()
            .execute("UPDATE messages SET created_at = 7", [])
            .unwrap();
        let (removed, _) = db.delete_messages_from(&sid, &second, "abc123").unwrap();
        assert_eq!(removed.messages.len(), 1);
        assert_eq!(removed.messages[0].id, second);
        let left = db.list_messages(&sid).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].id, first);
    }

    #[test]
    fn usage_filters_apply_independently() {
        let db = Db::memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let p1 = db.ensure_project(dir.path()).unwrap();
        let p2 = db.ensure_project(other.path()).unwrap();
        let s1 = db.create_session(&p1, "build", "a", None).unwrap();
        let s2 = db.create_session(&p2, "build", "b", None).unwrap();
        db.record_usage(Some(&s1), "fake", "m-a", 10, 1, 0, 0, 1.0, "primary")
            .unwrap();
        db.record_usage(Some(&s1), "fake", "m-a", 30, 3, 0, 0, 3.0, "primary")
            .unwrap();
        db.record_usage(Some(&s2), "fake", "m-b", 20, 2, 0, 0, 2.0, "primary")
            .unwrap();
        db.record_tool_usage(&s1, "bash", 5).unwrap();

        let all = db.usage_totals(None, None, None).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].model, "m-a");
        assert_eq!(all[0].cost, 4.0);
        let by_project = db.usage_totals(None, Some(&p1), None).unwrap();
        assert_eq!(by_project.len(), 1);
        assert_eq!(by_project[0].input, 40);
        let by_model = db.usage_totals(None, None, Some("m-b")).unwrap();
        assert_eq!(by_model.len(), 1);
        assert_eq!(by_model[0].input, 20);
        assert!(
            db.usage_totals(None, Some(&p1), Some("m-b"))
                .unwrap()
                .is_empty()
        );
        assert_eq!(db.tool_usage_totals(None, Some(&p1)).unwrap()[0].calls, 1);
        assert!(db.tool_usage_totals(None, Some(&p2)).unwrap().is_empty());

        let old = freedas_core::paths::now_ms() - 40 * 86_400_000;
        db.lock()
            .execute("UPDATE usage SET created_at = ?1", [old])
            .unwrap();
        assert!(db.usage_totals(Some(30), None, None).unwrap().is_empty());
        assert_eq!(db.usage_totals(Some(60), None, None).unwrap().len(), 2);
    }

    #[test]
    fn ensure_project_reuses_existing_rows() {
        let db = Db::memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let first = db.ensure_project(dir.path()).unwrap();
        assert_eq!(first, db.ensure_project(dir.path()).unwrap());
        // Another process already registered this root: its id wins.
        let other = tempfile::tempdir().unwrap();
        let canonical = other
            .path()
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .to_string();
        db.lock()
            .execute(
                "INSERT INTO projects (id, root, canonical, created_at) VALUES ('prj_other', ?1, ?2, 0)",
                params![other.path().to_string_lossy(), canonical],
            )
            .unwrap();
        assert_eq!("prj_other", db.ensure_project(other.path()).unwrap());
    }

    #[test]
    fn export_import_round_trips_snapshots_and_todos() {
        let db = Db::memory().unwrap();
        let (dir, pid, sid, mid) = seeded(&db);
        db.record_snapshot(&sid, &mid, "abc123").unwrap();
        db.lock()
            .execute(
                "INSERT INTO todos (session_id, id, content, status, priority) VALUES (?1, 't1', 'do it', 'pending', 'high')",
                params![sid],
            )
            .unwrap();
        let root = dir.path();
        let paths = freedas_core::paths::Paths::resolve(root.to_path_buf());
        let text = export_session(&db, &paths, root, Some(&sid), false, "json").unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let report = db.import_session(&pid, &v).unwrap();
        assert_ne!(report.session_id, sid);
        assert_eq!(report.messages, 1);
        let imported = db.list_messages(&report.session_id).unwrap();
        let snapshots = db.list_snapshot_rows(&report.session_id).unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].commit_sha, "abc123");
        // The snapshot follows the remapped message id.
        assert_eq!(snapshots[0].message_id, imported[0].id);
        let todos = db.list_todo_rows(&report.session_id).unwrap();
        assert_eq!(todos.len(), 1);
        assert_eq!(todos[0].id, "t1");
        assert_eq!(todos[0].priority, "high");
        assert_eq!(db.list_usage_rows(&report.session_id).unwrap().len(), 1);
    }

    #[test]
    fn recall_memory_fts_respects_scope_and_limit() {
        let db = Db::memory().unwrap();
        db.add_memory(
            "user",
            None,
            "preference",
            "always use pnpm for installs",
            0.9,
        )
        .unwrap();
        let rows = db.recall_memory_fts(None, "pnpm installs", 1).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "preference");
        // A project scope still reaches user-scope records with the ?2/?3 split.
        let rows = db
            .recall_memory_fts(Some("prj_x"), "pnpm installs", 5)
            .unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn newer_schema_version_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        {
            let conn = Connection::open(&path).unwrap();
            conn.pragma_update(None, "user_version", 4).unwrap();
        }
        assert!(Db::open(&path).is_err());
    }

    #[test]
    fn fork_copies_parts_with_timestamps_and_usage() {
        let db = Db::memory().unwrap();
        let (_dir, pid, sid, mid) = seeded(&db);
        let fork = db.fork_session(&pid, &sid, Some(&mid)).unwrap();
        let original_parts = db.list_parts(&sid, &mid).unwrap();
        let copied = db.list_messages(&fork).unwrap();
        assert_eq!(copied.len(), 1);
        let copied_parts = db.list_parts(&fork, &copied[0].id).unwrap();
        assert_eq!(copied_parts[0].created_at, original_parts[0].created_at);
        assert_eq!(db.list_usage_rows(&fork).unwrap().len(), 1);
        // The fork keeps the source id under a new session.
        assert_ne!(copied[0].id, mid);
    }

    #[test]
    fn import_rejects_non_hex_snapshot_sha() {
        let db = Db::memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let pid = db.ensure_project(dir.path()).unwrap();
        let v = serde_json::json!({
            "version": 1,
            "session": {"id": "ses_src", "title": "t", "agent": "build"},
            "messages": [],
            "usage": [],
            "snapshots": [
                {"id": "snp_1", "messageID": "msg_1", "commitSha": "not a sha!!", "createdAt": 1}
            ],
            "todos": [],
            "permissions": [],
        });
        assert!(db.import_session(&pid, &v).is_err());
        // Nothing is half-imported: the session row rolls back with the tx.
        assert!(db.session_full("ses_src").unwrap().is_none());
        let mut empty_sha = v.clone();
        empty_sha["snapshots"][0]["commitSha"] = serde_json::json!("zzzz");
        assert!(db.import_session(&pid, &empty_sha).is_err());
        let mut ok = v.clone();
        ok["snapshots"][0]["commitSha"] = serde_json::json!("abc123");
        let report = db.import_session(&pid, &ok).unwrap();
        assert_eq!(
            db.list_snapshot_rows(&report.session_id).unwrap()[0].commit_sha,
            "abc123"
        );
    }

    #[test]
    fn prune_snapshots_keeps_newest_n() {
        let db = Db::memory().unwrap();
        let (_dir, _pid, sid, mid) = seeded(&db);
        for i in 0..3 {
            db.record_snapshot(&sid, &format!("{mid}-{i}"), &format!("abc12{i}"))
                .unwrap();
        }
        assert_eq!(db.list_snapshot_rows(&sid).unwrap().len(), 3);
        assert_eq!(db.prune_snapshots(&sid, 2).unwrap(), 1);
        let rows = db.list_snapshot_rows(&sid).unwrap();
        assert_eq!(rows.len(), 2);
        // Ties in `created_at` break by `rowid`: the first capture is gone.
        assert!(!rows.iter().any(|r| r.message_id == format!("{mid}-0")));
        assert_eq!(db.prune_snapshots(&sid, 10).unwrap(), 0);
        assert_eq!(db.prune_snapshots(&sid, 0).unwrap(), 2);
        assert!(db.list_snapshot_rows(&sid).unwrap().is_empty());
    }
}
