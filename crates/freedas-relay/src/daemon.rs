//! Relay daemon: exposes local sessions outbound over one WSS connection.
//!
//! The daemon never opens a port. It polls the local session database for new
//! messages and parts, forwards them as `event` frames with a per-session
//! monotonic sequence, and executes `prompt`/`abort` frames from the dashboard
//! through the session runner.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use freedas_core::config::PermissionRule;
use freedas_core::paths::Paths;
use freedas_session::{ProgressSink, RunOpts, Runner};
use freedas_tools::{PermissionApprover, PermissionReply};
use rusqlite::{Connection, OpenFlags, params};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{RelayConnection, RelayFrame, connect_scoped, machine_id_in};

const POLL_INTERVAL: Duration = Duration::from_secs(2);
const MAX_BACKOFF_SECS: u64 = 30;
/// How long a tool call waits for the dashboard to answer a permission prompt.
const PERMISSION_TIMEOUT: Duration = Duration::from_secs(300);

pub struct DaemonOptions {
    pub url: String,
    pub token: String,
    pub paths: Paths,
}

/// Permission prompts in flight, plus their ids. Each entry records the
/// session that raised the prompt so a reply for another session is dropped.
#[derive(Debug, Default)]
struct ApprovalState {
    answers: Mutex<HashMap<String, (String, std::sync::mpsc::Sender<String>)>>,
}

/// Surfaces an `ask` to the dashboard as a `Permission` frame and blocks the
/// runner until the dashboard's `PermissionReply` arrives.
#[derive(Debug)]
struct RelayApprover {
    session_id: String,
    sender: mpsc::Sender<RelayFrame>,
    approvals: Arc<ApprovalState>,
}

impl PermissionApprover for RelayApprover {
    fn ask(&self, action: &str, resource: &str) -> PermissionReply {
        // Unguessable id: a dashboard holder cannot guess another prompt's id.
        let permission_id = format!("perm_{}", ulid::Ulid::new());
        let (tx, rx) = std::sync::mpsc::channel();
        self.approvals
            .answers
            .lock()
            .expect("answers")
            .insert(permission_id.clone(), (self.session_id.clone(), tx));
        let frame = RelayFrame::Permission {
            session_id: self.session_id.clone(),
            permission_id: permission_id.clone(),
            action: action.to_owned(),
            resource: resource.to_owned(),
        };
        if self.sender.try_send(frame).is_err() {
            self.approvals
                .answers
                .lock()
                .expect("answers")
                .remove(&permission_id);
            return PermissionReply::Reject;
        }
        match rx.recv_timeout(PERMISSION_TIMEOUT) {
            Ok(response) => match response.as_str() {
                "once" | "allow_once" => PermissionReply::Once,
                "always" | "allow_always" => PermissionReply::Always,
                _ => PermissionReply::Reject,
            },
            Err(_) => {
                self.approvals
                    .answers
                    .lock()
                    .expect("answers")
                    .remove(&permission_id);
                PermissionReply::Reject
            }
        }
    }
}

/// State that outlives a socket reconnect so events are not replayed and
/// sequence numbers keep increasing.
#[derive(Default)]
struct DaemonState {
    seqs: Arc<Mutex<HashMap<String, u64>>>,
    cancels: Arc<Mutex<HashMap<String, CancellationToken>>>,
    approvals: Arc<ApprovalState>,
    rules: Arc<Mutex<Vec<PermissionRule>>>,
    cursors: HashMap<String, Cursor>,
    usage_totals: HashMap<String, UsageTotals>,
}

/// What `relay.json` says about what this machine exposes.
struct ShareState {
    /// `machine` exposes every session; `session` exposes only `shared`.
    scope: String,
    shared: HashSet<String>,
    mtime: Option<SystemTime>,
}

fn read_share(paths: &Paths) -> ShareState {
    let file = paths.state_dir.join("relay.json");
    let mtime = std::fs::metadata(&file)
        .and_then(|meta| meta.modified())
        .ok();
    let parsed = std::fs::read_to_string(&file)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok());
    let scope = match parsed.as_ref().and_then(|value| value["scope"].as_str()) {
        // Only `machine` and `session` are valid; anything else would be
        // rejected at hello, so fall back to exposing everything.
        Some("session") => "session".to_owned(),
        _ => "machine".to_owned(),
    };
    let shared = parsed
        .as_ref()
        .and_then(|value| value["shared"].as_array())
        .map(|ids| {
            ids.iter()
                .filter_map(|id| id.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    ShareState {
        scope,
        shared,
        mtime,
    }
}

/// Run the relay daemon until `relay stop` (SIGTERM) or an unrecoverable error.
///
/// Writes `<state>/relay.pid`, reconnects with exponential backoff, and
/// re-reads `relay.json` so `relay share`/`unshare` take effect live.
pub async fn start(opts: DaemonOptions) -> Result<(), String> {
    let paths = opts.paths;
    std::fs::create_dir_all(&paths.state_dir).map_err(|e| format!("state dir: {e}"))?;
    let pid_path = paths.state_dir.join("relay.pid");
    std::fs::write(&pid_path, std::process::id().to_string())
        .map_err(|e| format!("pid file: {e}"))?;
    let machine = machine_id_in(&paths.state_dir);

    let shutdown = CancellationToken::new();
    {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            if let Ok(mut term) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                term.recv().await;
            }
            shutdown.cancel();
        });
    }

    let mut backoff = 1u64;
    // Reconnects keep cursors, sequence numbers, and remembered rules.
    let mut state = DaemonState::default();
    while !shutdown.is_cancelled() {
        let share = read_share(&paths);
        let connected = tokio::select! {
            _ = shutdown.cancelled() => break,
            result = connect_scoped(&opts.url, &opts.token, &machine, &share.scope) => result,
        };
        match connected {
            Ok(conn) => {
                backoff = 1;
                if let Err(error) = pump(conn, &paths, &share, &shutdown, &mut state).await {
                    eprintln!("relay: {error}");
                }
            }
            Err(error) => eprintln!("relay: {error}"),
        }
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(Duration::from_secs(backoff)) => {}
        }
        backoff = (backoff * 2).min(MAX_BACKOFF_SECS);
    }
    let _ = std::fs::remove_file(&pid_path);
    Ok(())
}

/// Stop a running daemon: SIGTERM its pid, then drop `relay.json` and the pid file.
pub fn stop(paths: &Paths) -> Result<(), String> {
    let pid_path = paths.state_dir.join("relay.pid");
    if let Ok(text) = std::fs::read_to_string(&pid_path) {
        if let Ok(pid) = text.trim().parse::<u32>() {
            let _ = std::process::Command::new("kill")
                .arg("-TERM")
                .arg(pid.to_string())
                .status();
        }
        let _ = std::fs::remove_file(&pid_path);
    }
    let _ = std::fs::remove_file(paths.state_dir.join("relay.json"));
    Ok(())
}

async fn pump(
    mut conn: RelayConnection,
    paths: &Paths,
    share: &ShareState,
    shutdown: &CancellationToken,
    state: &mut DaemonState,
) -> Result<(), String> {
    let sender = conn.sender();
    let db = Connection::open_with_flags(paths.db_path(), OpenFlags::SQLITE_OPEN_READ_ONLY).ok();
    let mut tick = tokio::time::interval(POLL_INTERVAL);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            frame = conn.next() => match frame {
                Some(RelayFrame::Prompt { session_id, text }) => {
                    // Defense in depth: the server also enforces scope, but the
                    // daemon never runs a prompt for an unshared session.
                    if share.scope == "session" && !share.shared.contains(&session_id) {
                        continue;
                    }
                    spawn_prompt(
                        paths,
                        sender.clone(),
                        &state.seqs,
                        &state.cancels,
                        &state.approvals,
                        &state.rules,
                        session_id,
                        text,
                    );
                }
                Some(RelayFrame::Abort { session_id }) => {
                    if share.scope == "session" && !share.shared.contains(&session_id) {
                        continue;
                    }
                    if let Some(token) = state.cancels.lock().expect("cancels").remove(&session_id) {
                        token.cancel();
                    }
                }
                Some(RelayFrame::PermissionReply { session_id, permission_id, response }) => {
                    let answer = state
                        .approvals
                        .answers
                        .lock()
                        .expect("answers")
                        .remove(&permission_id);
                    // Drop replies whose session does not match the prompt that
                    // raised them; otherwise one session could answer another's.
                    if let Some((expected, answer)) = answer
                        && expected == session_id
                    {
                        let _ = answer.send(response);
                    }
                }
                Some(RelayFrame::Error { message }) => eprintln!("relay: {message}"),
                Some(_) => {}
                None => return Err("connection closed".into()),
            },
            _ = tick.tick() => {
                if read_share(paths).mtime != share.mtime {
                    // share/unshare changed the scope: reconnect with it.
                    return Ok(());
                }
                if let Some(db) = &db {
                    poll_db(
                        db,
                        share,
                        &mut state.cursors,
                        &mut state.usage_totals,
                        &state.seqs,
                        &sender,
                    );
                }
            }
        }
    }
}

#[derive(Default, Clone, Copy)]
struct Cursor {
    message: u64,
    part: u64,
}

impl Cursor {
    /// Start after the history that already exists, so a fresh connection is
    /// not flooded with the whole transcript.
    fn seed(db: &Connection, session_id: &str) -> Self {
        Self {
            message: max_rowid(db, "messages", session_id),
            part: max_rowid(db, "parts", session_id),
        }
    }
}

fn max_rowid(db: &Connection, table: &str, session_id: &str) -> u64 {
    db.query_row(
        &format!("SELECT COALESCE(MAX(rowid), 0) FROM {table} WHERE session_id = ?1"),
        params![session_id],
        |row| row.get::<_, i64>(0),
    )
    .unwrap_or(0)
    .max(0) as u64
}

fn next_seq(seqs: &Mutex<HashMap<String, u64>>, session_id: &str) -> u64 {
    let mut seqs = seqs.lock().expect("seqs");
    let seq = seqs.entry(session_id.to_owned()).or_insert(0);
    *seq += 1;
    *seq
}

/// Returns false when the frame was dropped, so the caller can retry it.
fn send_event(
    sender: &mpsc::Sender<RelayFrame>,
    seqs: &Mutex<HashMap<String, u64>>,
    session_id: &str,
    event: Value,
) -> bool {
    let frame = RelayFrame::Event {
        session_id: session_id.to_owned(),
        seq: next_seq(seqs, session_id),
        event,
    };
    // The socket is a realtime view; a full queue drops rather than blocks the run.
    sender.try_send(frame).is_ok()
}

fn advance(cursor: &mut u64, rowid: u64, sent: bool) {
    if sent {
        *cursor = rowid;
    }
}

#[derive(Default, Clone, Copy, PartialEq)]
struct UsageTotals {
    input_tokens: i64,
    output_tokens: i64,
    cost_usd: f64,
}

/// The `usage` event for a session, only when its totals moved since the last
/// tick. The first observation seeds the baseline without emitting.
fn usage_event(
    last: &mut HashMap<String, UsageTotals>,
    session_id: &str,
    totals: UsageTotals,
) -> Option<Value> {
    // Emit on the first observation too, so a session that ran before the
    // daemon started still shows its cost and tokens in the dashboard.
    let changed = last
        .get(session_id)
        .is_none_or(|current| *current != totals);
    if !changed {
        return None;
    }
    last.insert(session_id.to_owned(), totals);
    if totals.input_tokens == 0 && totals.output_tokens == 0 && totals.cost_usd == 0.0 {
        return None;
    }
    Some(json!({
        "type": "usage",
        "sessionID": session_id,
        "inputTokens": totals.input_tokens,
        "outputTokens": totals.output_tokens,
        "costUsd": totals.cost_usd,
    }))
}

fn query_usage(db: &Connection, session_id: &str) -> UsageTotals {
    db.query_row(
        "SELECT COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0), COALESCE(SUM(cost_usd),0) FROM usage WHERE session_id = ?1",
        params![session_id],
        |row| {
            Ok(UsageTotals {
                input_tokens: row.get(0)?,
                output_tokens: row.get(1)?,
                cost_usd: row.get(2)?,
            })
        },
    )
    .unwrap_or_default()
}

/// Forward new messages and parts for every exposed session.
fn poll_db(
    db: &Connection,
    share: &ShareState,
    cursors: &mut HashMap<String, Cursor>,
    usage_totals: &mut HashMap<String, UsageTotals>,
    seqs: &Mutex<HashMap<String, u64>>,
    sender: &mpsc::Sender<RelayFrame>,
) {
    let mut session_ids: Vec<String> = match db.prepare("SELECT id FROM sessions") {
        Ok(mut stmt) => stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map(|rows| rows.flatten().collect())
            .unwrap_or_default(),
        Err(_) => return,
    };
    if share.scope == "session" {
        session_ids.retain(|id| share.shared.contains(id));
    }
    cursors.retain(|id, _| session_ids.contains(id));
    usage_totals.retain(|id, _| session_ids.contains(id));
    // Sequence numbers live as long as the cursor/usage entries they belong to;
    // otherwise unshared sessions leak map entries forever.
    seqs.lock()
        .expect("seqs")
        .retain(|id, _| session_ids.contains(id));

    for session_id in session_ids {
        if let Some(event) = usage_event(usage_totals, &session_id, query_usage(db, &session_id)) {
            let _ = send_event(sender, seqs, &session_id, event);
        }
        let cursor = match cursors.entry(session_id.clone()) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                // Announce the session once so the dashboard lists it even
                // though historical rows are not replayed.
                let _ = sender.try_send(RelayFrame::Share {
                    session_id: session_id.clone(),
                });
                entry.insert(Cursor::seed(db, &session_id))
            }
        };
        let messages = query_rows(
            db,
            "SELECT rowid, id, role, CAST(created_at AS TEXT) FROM messages WHERE session_id = ?1 AND rowid > ?2 ORDER BY rowid",
            &session_id,
            cursor.message,
        );
        for (rowid, values) in messages {
            let sent = send_event(
                sender,
                seqs,
                &session_id,
                json!({
                    "type": "message.updated",
                    "sessionID": session_id,
                    "messageID": values[0],
                    "role": values[1],
                    "timestamp": values[2].parse::<i64>().unwrap_or_default(),
                }),
            );
            advance(&mut cursor.message, rowid, sent);
        }
        let parts = query_rows(
            db,
            "SELECT rowid, message_id, kind, data FROM parts WHERE session_id = ?1 AND rowid > ?2 ORDER BY rowid",
            &session_id,
            cursor.part,
        );
        for (rowid, values) in parts {
            let data: Value = serde_json::from_str(&values[2])
                .unwrap_or_else(|_| Value::String(values[2].clone()));
            let sent = send_event(
                sender,
                seqs,
                &session_id,
                json!({
                    "type": "message.part.updated",
                    "sessionID": session_id,
                    "messageID": values[0],
                    "part": { "kind": values[1], "data": data },
                }),
            );
            advance(&mut cursor.part, rowid, sent);
        }
    }
}

/// `(rowid, columns as strings)` for rows past `after`.
fn query_rows(db: &Connection, sql: &str, session_id: &str, after: u64) -> Vec<(u64, Vec<String>)> {
    let Ok(mut stmt) = db.prepare(sql) else {
        return Vec::new();
    };
    let Ok(rows) = stmt.query_map(params![session_id, after as i64], |row| {
        let rowid: i64 = row.get(0)?;
        let mut values = Vec::new();
        let mut index = 1;
        while let Ok(value) = row.get::<_, String>(index) {
            values.push(value);
            index += 1;
        }
        Ok((rowid.max(0) as u64, values))
    }) else {
        return Vec::new();
    };
    rows.flatten().collect()
}

#[allow(clippy::too_many_arguments)]
fn spawn_prompt(
    paths: &Paths,
    sender: mpsc::Sender<RelayFrame>,
    seqs: &Arc<Mutex<HashMap<String, u64>>>,
    cancels: &Arc<Mutex<HashMap<String, CancellationToken>>>,
    approvals: &Arc<ApprovalState>,
    rules: &Arc<Mutex<Vec<PermissionRule>>>,
    session_id: String,
    text: String,
) {
    let project_root =
        session_root(&paths.db_path(), &session_id).unwrap_or_else(|| paths.project_root.clone());
    let cancel = CancellationToken::new();
    cancels
        .lock()
        .expect("cancels")
        .insert(session_id.clone(), cancel.clone());
    let _ = send_event(
        &sender,
        seqs,
        &session_id,
        json!({ "type": "relay.prompt", "sessionID": session_id, "text": text }),
    );

    let paths = paths.clone();
    let seqs = seqs.clone();
    let cancels = cancels.clone();
    let rules = rules.clone();
    let approver: Arc<dyn PermissionApprover> = Arc::new(RelayApprover {
        session_id: session_id.clone(),
        sender: sender.clone(),
        approvals: approvals.clone(),
    });
    // A dedicated thread keeps the blocking approver off the relay runtime.
    std::thread::spawn(move || {
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return;
        };
        runtime.block_on(async move {
            let Ok(db) = freedas_db::Db::open(&paths.db_path()) else {
                return;
            };
            let config = freedas_core::config::load(&paths, false).unwrap_or_default();
            let runner = Runner::new(
                Arc::new(db),
                paths.clone(),
                config,
                freedas_catalog::builtin_catalog(),
            );
            let progress: ProgressSink = {
                let sender = sender.clone();
                let seqs = seqs.clone();
                let session_id = session_id.clone();
                Arc::new(move |chunk: String| {
                    let event = if let Some(marker) = chunk.strip_prefix('\u{1}') {
                        json!({
                            "type": "relay.marker",
                            "sessionID": session_id,
                            "marker": marker,
                        })
                    } else if let Some(json) = chunk.strip_prefix('\u{2}') {
                        // Tool results must not arrive as assistant text.
                        serde_json::from_str::<serde_json::Value>(json)
                            .map(|mut v| {
                                v["type"] = "tool.result".into();
                                v["sessionID"] = session_id.clone().into();
                                v
                            })
                            .unwrap_or_else(|_| {
                                json!({
                                    "type": "message.part.updated",
                                    "sessionID": session_id,
                                    "part": { "kind": "text", "data": { "text": chunk } },
                                })
                            })
                    } else {
                        json!({
                            "type": "message.part.updated",
                            "sessionID": session_id,
                            "part": { "kind": "text", "data": { "text": chunk } },
                        })
                    };
                    let _ = send_event(&sender, &seqs, &session_id, event);
                })
            };
            let opts = RunOpts {
                project_root,
                agent: "build".into(),
                model: None,
                prompt: text,
                auto: false,
                manual: false,
                workspace: None,
                session_id: Some(session_id.clone()),
                title: None,
                variant: None,
                depth: 0,
                parent_id: None,
                review_mode: false,
                progress: Some(progress),
                headless: false,
                mcp_disabled: Vec::new(),
                approver: Some(approver),
                session_rules: rules,
            };
            let event = match runner.run_task_opts(opts, cancel).await {
                Ok(result) => json!({
                    "type": "session.completed",
                    "sessionID": session_id,
                    "completed": result.completed,
                    "text": result.text,
                }),
                Err(error) => json!({
                    "type": "session.error",
                    "sessionID": session_id,
                    "error": error.to_string(),
                }),
            };
            let _ = send_event(&sender, &seqs, &session_id, event);
            cancels.lock().expect("cancels").remove(&session_id);
        });
    });
}

fn session_root(db_path: &Path, session_id: &str) -> Option<std::path::PathBuf> {
    let db = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
    db.query_row(
        "SELECT p.root FROM sessions s JOIN projects p ON p.id = s.project_id WHERE s.id = ?1",
        params![session_id],
        |row| row.get::<_, String>(0),
    )
    .ok()
    .map(std::path::PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_events_only_when_totals_move() {
        let mut last = HashMap::new();
        let first = UsageTotals {
            input_tokens: 10,
            output_tokens: 5,
            cost_usd: 0.25,
        };
        let seeded = usage_event(&mut last, "ses_1", first).expect("first observation emits");
        assert_eq!(seeded["inputTokens"], 10);
        assert!(usage_event(&mut last, "ses_1", first).is_none());

        let second = UsageTotals {
            input_tokens: 20,
            output_tokens: 9,
            cost_usd: 0.5,
        };
        let event = usage_event(&mut last, "ses_1", second).expect("changed totals emit");
        assert_eq!(
            event,
            json!({
                "type": "usage",
                "sessionID": "ses_1",
                "inputTokens": 20,
                "outputTokens": 9,
                "costUsd": 0.5,
            })
        );
        assert!(usage_event(&mut last, "ses_1", second).is_none());
        // A different session seeds and emits its own totals.
        assert!(usage_event(&mut last, "ses_2", second).is_some());
    }

    #[test]
    fn cursors_only_advance_for_delivered_frames() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("relay-test.db");
        let db = freedas_db::Db::open(&db_path).unwrap();
        let project_id = db.ensure_project(dir.path()).unwrap();
        let session_id = db
            .create_session(&project_id, "build", "cursor test", None)
            .unwrap();
        let message_id = db.add_message(&session_id, "user", &json!({})).unwrap();
        db.add_part(
            &session_id,
            &message_id,
            0,
            "text",
            &json!({ "text": "hi" }),
        )
        .unwrap();
        drop(db);

        let conn = Connection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        // A receiver that is already gone forces every `try_send` to fail.
        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);
        let share = ShareState {
            scope: "machine".into(),
            shared: HashSet::new(),
            mtime: None,
        };
        let mut cursors = HashMap::new();
        // Pretend a previous poll saw nothing, so the queued rows are retried.
        cursors.insert(session_id.clone(), Cursor::default());
        let mut usage = HashMap::new();
        let seqs = Mutex::new(HashMap::new());
        poll_db(&conn, &share, &mut cursors, &mut usage, &seqs, &sender);

        let cursor = cursors[&session_id];
        assert_eq!(cursor.message, 0);
        assert_eq!(cursor.part, 0);
    }
}
