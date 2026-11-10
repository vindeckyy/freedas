use crate::Db;
use freedas_core::Result;
use rusqlite::{OptionalExtension, params};
use std::collections::HashMap;

impl Db {
    pub fn record_snapshot(
        &self,
        session_id: &str,
        message_id: &str,
        commit_sha: &str,
    ) -> Result<String> {
        let id = format!("snp_{}", ulid::Ulid::new());
        let now = freedas_core::paths::now_ms();
        self.lock().execute(
            "INSERT INTO snapshots (id, session_id, message_id, commit_sha, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, session_id, message_id, commit_sha, now],
        )?;
        Ok(id)
    }

    pub fn last_snapshot(&self, session_id: &str, message_id: &str) -> Result<Option<String>> {
        Ok(self
            .lock()
            .query_row(
                "SELECT commit_sha FROM snapshots WHERE session_id = ?1 AND message_id = ?2 ORDER BY created_at DESC, rowid DESC LIMIT 1",
                params![session_id, message_id],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Delete snapshot rows beyond the newest `keep_latest` for the session
    /// (newest first by `created_at, rowid`), returning rows removed.
    /// Snapshot captures are capped per session by the caller, but without
    /// this the `snapshots` table grows forever. Object pruning (`git gc`)
    /// stays with the session owner, which owns the shadow repo on disk;
    /// this only trims the DB rows. Intended to run after each snapshot
    /// capture — currently unwired, safe to call standalone.
    pub fn prune_snapshots(&self, session_id: &str, keep_latest: usize) -> Result<u64> {
        let n = self.lock().execute(
            "DELETE FROM snapshots WHERE session_id = ?1 AND id NOT IN \
             (SELECT id FROM snapshots WHERE session_id = ?1 \
              ORDER BY created_at DESC, rowid DESC LIMIT ?2)",
            params![session_id, super::limit_i64(keep_latest)],
        )?;
        Ok(n as u64)
    }

    pub fn rename_session(&self, session_id: &str, title: &str) -> Result<()> {
        self.lock().execute(
            "UPDATE sessions SET title = ?1, updated_at = ?2 WHERE id = ?3",
            params![title, freedas_core::paths::now_ms(), session_id],
        )?;
        Ok(())
    }

    /// Copy a session and its transcript into a new session in one transaction.
    /// Parts keep their original timestamps; usage up to the fork point moves
    /// with the copied turns.
    pub fn fork_session(
        &self,
        project_id: &str,
        session_id: &str,
        up_to_message: Option<&str>,
    ) -> Result<String> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let (title, agent, workspace_id): (String, String, Option<String>) = tx.query_row(
            "SELECT title, agent, workspace_id FROM sessions WHERE id = ?1",
            params![session_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let new_id = format!("ses_{}", ulid::Ulid::new());
        let now = freedas_core::paths::now_ms();
        tx.execute(
            "INSERT INTO sessions (id, project_id, parent_id, title, agent, workspace_id, status, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'idle', ?7, ?7)",
            params![new_id, project_id, session_id, format!("{title} (fork)"), agent, workspace_id, now],
        )?;
        // (created_at, rowid) identifies the boundary; timestamps alone collide.
        let cutoff: Option<(i64, i64)> = match up_to_message {
            Some(upto) => Some(tx.query_row(
                "SELECT created_at, rowid FROM messages WHERE id = ?1 AND session_id = ?2",
                params![upto, session_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?),
            None => None,
        };
        type MessageRow = (
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            String,
            i64,
            i64,
        );
        let messages: Vec<MessageRow> = {
            let mut stmt = tx.prepare(
                "SELECT id, role, model, usage, error, metadata, created_at, rowid FROM messages WHERE session_id = ?1 ORDER BY created_at, rowid",
            )?;
            stmt.query_map(params![session_id], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
        };
        let mut msg_map: HashMap<String, String> = HashMap::new();
        for (old_id, role, model, usage, error, metadata, created_at, rowid) in messages {
            if let Some((at, boundary)) = cutoff
                && (created_at > at || (created_at == at && rowid > boundary))
            {
                continue;
            }
            let new_msg = format!("msg_{}", ulid::Ulid::new());
            msg_map.insert(old_id.clone(), new_msg.clone());
            tx.execute(
                "INSERT INTO messages (id, session_id, role, model, usage, error, metadata, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![new_msg, new_id, role, model, usage, error, metadata, created_at],
            )?;
            let parts: Vec<(i64, String, String, i64)> = {
                let mut stmt = tx.prepare(
                    "SELECT idx, kind, data, created_at FROM parts WHERE message_id = ?1 ORDER BY idx",
                )?;
                stmt.query_map(params![old_id], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?
            };
            for (idx, kind, data, part_at) in parts {
                let new_part = format!("prt_{}", ulid::Ulid::new());
                tx.execute(
                    "INSERT INTO parts (id, session_id, message_id, idx, kind, data, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![new_part, new_id, new_msg, idx, kind, data, part_at],
                )?;
            }
        }
        // Usage rows carry no message id and are written just after their
        // message, so the fork keeps everything before the *next* message.
        // `(created_at, rowid)` breaks timestamp ties the same way messages do.
        let usage_cutoff: (i64, i64) = match cutoff {
            Some((at, boundary)) => tx
                .query_row(
                    "SELECT created_at, rowid FROM messages WHERE session_id = ?1 AND (created_at > ?2 OR (created_at = ?2 AND rowid > ?3)) ORDER BY created_at, rowid LIMIT 1",
                    params![session_id, at, boundary],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .ok()
                .unwrap_or((i64::MAX, i64::MAX)),
            None => (i64::MAX, i64::MAX),
        };
        type UsageRow = (
            Option<String>,
            String,
            String,
            i64,
            i64,
            i64,
            i64,
            f64,
            String,
            i64,
        );
        let usage: Vec<UsageRow> = {
            let mut stmt = tx.prepare(
                "SELECT workspace_id, provider, model, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, cost_usd, kind, created_at FROM usage WHERE session_id = ?1 AND (created_at < ?2 OR (created_at = ?2 AND rowid < ?3)) ORDER BY created_at, rowid",
            )?;
            stmt.query_map(params![session_id, usage_cutoff.0, usage_cutoff.1], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
        };
        for (ws, provider, model, input, output, cache_read, cache_write, cost, kind, created_at) in
            usage
        {
            tx.execute(
                "INSERT INTO usage (id, session_id, workspace_id, provider, model, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, cost_usd, kind, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    format!("usg_{}", ulid::Ulid::new()),
                    new_id,
                    ws,
                    provider,
                    model,
                    input,
                    output,
                    cache_read,
                    cache_write,
                    cost,
                    kind,
                    created_at
                ],
            )?;
        }
        // Snapshots point at messages, so remap them onto the forked copies;
        // snapshots past the fork point have no mapped message and stay behind.
        let snaps: Vec<(String, String, i64)> = {
            let mut stmt = tx.prepare(
                "SELECT message_id, commit_sha, created_at FROM snapshots WHERE session_id = ?1 ORDER BY created_at, rowid",
            )?;
            stmt.query_map(params![session_id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
        };
        for (old_mid, commit_sha, created_at) in snaps {
            if let Some(new_mid) = msg_map.get(&old_mid) {
                tx.execute(
                    "INSERT INTO snapshots (id, session_id, message_id, commit_sha, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        format!("snp_{}", ulid::Ulid::new()),
                        new_id,
                        new_mid,
                        commit_sha,
                        created_at
                    ],
                )?;
            }
        }
        // Session-scoped permission rows follow the fork with a remapped session
        // id. `redo_stack` is transient and intentionally not copied.
        let perms: Vec<(String, String, String, i64)> = {
            let mut stmt = tx.prepare(
                "SELECT action, resource, effect, created_at FROM permissions WHERE session_id = ?1 AND scope = 'session' ORDER BY created_at, rowid",
            )?;
            stmt.query_map(params![session_id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
        };
        for (action, resource, effect, created_at) in perms {
            tx.execute(
                "INSERT INTO permissions (id, session_id, action, resource, effect, scope, created_at) VALUES (?1, ?2, ?3, ?4, ?5, 'session', ?6)",
                params![
                    format!("prm_{}", ulid::Ulid::new()),
                    new_id,
                    action,
                    resource,
                    effect,
                    created_at
                ],
            )?;
        }
        tx.commit()?;
        Ok(new_id)
    }
}
