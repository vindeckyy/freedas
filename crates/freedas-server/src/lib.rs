//! Local HTTP server: session API, SSE events, OpenAPI.

pub mod client;
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path as AxumPath, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Sse},
    routing::{get, post, put},
};
use base64::Engine as _;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::broadcast;

use freedas_core::paths::Paths;
use freedas_db::Db;
use freedas_tools::Tool as _;

/// Type of every API error body: status plus `{"error": ...}`.
type ApiError = (StatusCode, Json<Value>);
type ApiResult = Result<Json<Value>, ApiError>;

fn internal(error: impl std::fmt::Display) -> ApiError {
    eprintln!("freedas server: {error}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": error.to_string()})),
    )
}

fn missing(message: impl Into<String>) -> ApiError {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"error": message.into()})),
    )
}

fn bad_request(message: impl Into<String>) -> ApiError {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": message.into()})),
    )
}

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Db>,
    pub paths: Paths,
    pub bus: broadcast::Sender<Value>,
    /// Cancellation tokens for runs started from the API.
    pub aborts: Arc<
        std::sync::Mutex<
            std::collections::HashMap<String, Arc<tokio_util::sync::CancellationToken>>,
        >,
    >,
    /// Permission requests waiting on a client reply; the key is a generated
    /// permission id.
    pub pending_perms: Arc<std::sync::Mutex<std::collections::HashMap<String, PendingPerm>>>,
    /// Monotonic ids plus a bounded replay buffer for SSE `Last-Event-ID`.
    events: EventLog,
    /// Serializes config read-modify-write cycles.
    config_lock: Arc<tokio::sync::Mutex<()>>,
}

impl AppState {
    pub fn new(db: Arc<Db>, paths: Paths) -> Self {
        let (bus, _) = broadcast::channel(1024);
        Self {
            db,
            paths,
            bus,
            aborts: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            pending_perms: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            events: EventLog::default(),
            config_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    fn emit(&self, value: Value) {
        emit(&self.bus, &self.events, value);
    }
}

fn emit(bus: &broadcast::Sender<Value>, events: &EventLog, value: Value) {
    let _ = bus.send(events.push(value));
}

/// Bounded ring of recent events tagged with monotonic ids, so an SSE client
/// that reconnects with `Last-Event-ID` can replay what it missed. Holds the
/// last 10,000 events in memory only; there is no DB-backed replay for older
/// events. When `since` predates the retained window, `replay_since` prepends
/// a `server.gap` marker so the client knows it missed history.
#[derive(Clone, Default, Debug)]
struct EventLog {
    inner: Arc<std::sync::Mutex<EventLogInner>>,
}

#[derive(Default, Debug)]
struct EventLogInner {
    next: u64,
    entries: std::collections::VecDeque<(u64, Value)>,
}

impl EventLog {
    fn push(&self, mut value: Value) -> Value {
        let mut inner = self.inner.lock().expect("event log");
        inner.next += 1;
        let id = inner.next;
        if let Value::Object(map) = &mut value {
            map.insert("id".into(), json!(id));
        }
        inner.entries.push_back((id, value.clone()));
        if inner.entries.len() > 10_000 {
            inner.entries.pop_front();
        }
        value
    }

    fn replay_since(&self, id: u64) -> Vec<Value> {
        let inner = self.inner.lock().expect("event log");
        let mut out = Vec::new();
        if let Some((oldest, _)) = inner.entries.front()
            && id != 0
            && id < *oldest
        {
            out.push(json!({"type": "server.gap", "since": id, "next": *oldest}));
        }
        out.extend(
            inner
                .entries
                .iter()
                .filter(|(entry_id, _)| *entry_id > id)
                .map(|(_, value)| value.clone()),
        );
        out
    }
}

/// Server authentication. Auth is enforced when a token or password is
/// configured; the CLI never binds a non-loopback address without a token.
#[derive(Clone, Debug, Default)]
pub struct Auth {
    token: Option<String>,
    password: Option<String>,
    username: String,
    /// Bound to loopback: reject foreign `Host` headers (DNS rebinding).
    loopback_only: bool,
}

impl Auth {
    pub fn new(token: Option<String>, password: Option<String>) -> Self {
        Self {
            token,
            password,
            username: "freedas".into(),
            loopback_only: false,
        }
    }

    pub fn loopback_only(mut self) -> Self {
        self.loopback_only = true;
        self
    }

    fn from_env(loopback_only: bool) -> Self {
        Self {
            token: env_nonempty("FREEDAS_SERVER_TOKEN"),
            password: env_nonempty("FREEDAS_SERVER_PASSWORD"),
            username: env_nonempty("FREEDAS_SERVER_USERNAME").unwrap_or_else(|| "freedas".into()),
            loopback_only,
        }
    }

    fn enabled(&self) -> bool {
        self.token.is_some() || self.password.is_some()
    }

    fn authorized(&self, headers: &HeaderMap) -> bool {
        let value = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        if let (Some(expected), Some(value)) = (&self.token, value)
            && let Some(got) = value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
            && ct_eq(got.trim(), expected)
        {
            return true;
        }
        if let (Some(expected), Some(value)) = (&self.password, value)
            && let Some(encoded) = value
                .strip_prefix("Basic ")
                .or_else(|| value.strip_prefix("basic "))
            && let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(encoded.trim())
            && let Ok(pair) = String::from_utf8(raw)
            && let Some((user, pass)) = pair.split_once(':')
        {
            // Evaluate both halves so the comparison cost does not depend on
            // which one fails.
            return ct_eq(user, &self.username) & ct_eq(pass, expected);
        }
        false
    }
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// Length-checked constant-time string compare.
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn is_loopback_host(host: &str) -> bool {
    matches!(
        host.trim_start_matches('[').trim_end_matches(']'),
        "127.0.0.1" | "localhost" | "::1"
    )
}

/// Reject a `Host` header that does not name loopback while the server is
/// bound to loopback. A missing header (HTTP/1.0, tests) is allowed.
fn host_allowed(headers: &HeaderMap) -> bool {
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return true;
    };
    let host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    is_loopback_host(host)
}

async fn authorize(
    auth: Auth,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if req.uri().path() != "/global/health" {
        if auth.loopback_only && !host_allowed(req.headers()) {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "host not allowed"})),
            )
                .into_response();
        }
        if auth.enabled() && !auth.authorized(req.headers()) {
            let mut response = (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "unauthorized"})),
            )
                .into_response();
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Bearer"),
            );
            return response;
        }
    }
    next.run(req).await
}

/// A permission request parked until a client answers: the session id and the
/// channel that unblocks the tool call.
pub type PendingPerm = (
    String,
    std::sync::mpsc::Sender<freedas_tools::PermissionReply>,
);

/// Answers pending permissions for a session with `Reject`; used when a run is
/// aborted or its session deleted so a parked tool never waits forever.
fn drain_pending(
    pending: &Arc<std::sync::Mutex<std::collections::HashMap<String, PendingPerm>>>,
    session_id: &str,
) {
    let mut pending = pending.lock().expect("pending_perms");
    let ids: Vec<String> = pending
        .iter()
        .filter(|(_, (sid, _))| sid == session_id)
        .map(|(id, _)| id.clone())
        .collect();
    for id in ids {
        if let Some((_, tx)) = pending.remove(&id) {
            let _ = tx.send(freedas_tools::PermissionReply::Reject);
        }
    }
}

/// Approver that surfaces asks as `permission.asked` SSE events and parks the
/// tool call until a client posts a reply, the run is aborted, or it times out.
#[derive(Debug)]
struct SseApprover {
    session_id: String,
    bus: broadcast::Sender<Value>,
    events: EventLog,
    pending: AppStatePendingPerms,
    paths: Paths,
}
type AppStatePendingPerms = Arc<std::sync::Mutex<std::collections::HashMap<String, PendingPerm>>>;

const PERMISSION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

impl freedas_tools::PermissionApprover for SseApprover {
    fn ask(&self, action: &str, resource: &str) -> freedas_tools::PermissionReply {
        let perm_id = format!("perm_{}", ulid::Ulid::new());
        let (tx, rx) = std::sync::mpsc::channel();
        self.pending
            .lock()
            .expect("pending_perms")
            .insert(perm_id.clone(), (self.session_id.clone(), tx));
        emit(
            &self.bus,
            &self.events,
            json!({
                "type": "permission.asked",
                "sessionID": self.session_id,
                "permissionID": perm_id,
                "action": action,
                "resource": resource,
            }),
        );
        // The reply arrives on a plain channel from another task. `block_in_place`
        // keeps the async worker from stalling; on a single-threaded runtime
        // there is no worker to hand off to, so wait directly.
        let wait = || {
            rx.recv_timeout(PERMISSION_TIMEOUT)
                .unwrap_or(freedas_tools::PermissionReply::Reject)
        };
        let multi_thread = tokio::runtime::Handle::try_current()
            .map(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
            .unwrap_or(false);
        let reply = if multi_thread {
            tokio::task::block_in_place(wait)
        } else {
            wait()
        };
        // Timeouts and stray replies must not leave an entry behind; an abort
        // may already have drained it.
        if let Ok(mut pending) = self.pending.lock()
            && pending
                .get(&perm_id)
                .map(|(sid, _)| sid == &self.session_id)
                .unwrap_or(false)
        {
            pending.remove(&perm_id);
        }
        emit(
            &self.bus,
            &self.events,
            json!({
                "type": "permission.replied",
                "sessionID": self.session_id,
                "permissionID": perm_id,
                "response": format!("{reply:?}").to_lowercase(),
            }),
        );
        reply
    }
    fn remember(&self, action: &str, resource: &str) {
        let _ = freedas_core::config::remember_rule(&self.paths, action, resource);
    }
}

pub fn app(db: Arc<Db>, paths: Paths) -> Router {
    app_with_auth(db, paths, Auth::from_env(false))
}

pub fn app_with_auth(db: Arc<Db>, paths: Paths, auth: Auth) -> Router {
    let state = AppState::new(db, paths);
    Router::new()
        .route(
            "/",
            get(|| async { axum::response::Html(freedas_web::INDEX_HTML) }),
        )
        .route("/global/health", get(health))
        .route("/doc", get(openapi_doc))
        .route("/project", get(list_projects))
        .route("/project/current", get(current_project))
        .route("/path", get(paths_info))
        .route("/vcs", get(vcs_info))
        .route("/session", get(list_sessions).post(create_session))
        .route("/session/status", get(sessions_status))
        .route(
            "/session/{id}",
            get(get_session)
                .delete(delete_session)
                .patch(rename_session),
        )
        .route(
            "/session/{id}/message",
            get(list_messages).post(post_message),
        )
        .route("/session/{id}/prompt_async", post(prompt_async))
        .route("/session/{id}/children", get(list_children))
        .route("/session/{id}/todo", get(list_todos))
        .route("/session/{id}/summarize", post(summarize_session))
        .route("/session/{id}/init", post(init_agents_md))
        .route("/session/{id}/shell", post(shell_session))
        .route("/session/{id}/fork", post(fork_session))
        .route("/session/{id}/abort", post(abort_session))
        .route("/session/{id}/usage", get(session_usage))
        .route("/session/{id}/revert", post(revert_session))
        .route("/session/{id}/permissions/{perm}", post(reply_permission))
        .route("/session/{id}/status", get(session_status))
        .route("/session/{id}/unrevert", post(unrevert_session))
        .route("/session/{id}/diff", get(session_diff))
        .route("/config", get(get_config).patch(patch_config))
        .route("/agent", get(list_agents))
        .route("/event", get(sse_events))
        .route("/global/event", get(sse_events))
        .route("/command", get(list_commands))
        .route("/session/{id}/command", post(post_command))
        .route("/find", get(find_text))
        .route("/find/file", get(find_file))
        .route("/find/symbol", get(find_symbol))
        .route("/file", get(list_files))
        .route("/file/content", get(file_content))
        .route("/file/status", get(file_status))
        .route("/lsp", get(lsp_status))
        .route("/formatter", get(formatter_status))
        .route("/provider", get(list_providers))
        .route("/provider/auth", get(provider_auth))
        .route("/auth/{id}", put(set_auth))
        .route("/mcp", get(list_mcp).post(add_mcp))
        .with_state(state)
        .layer(axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| {
                let auth = auth.clone();
                async move { authorize(auth, req, next).await }
            },
        ))
}

/// `FREEDAS_DISABLE_PROJECT_CONFIG` skips project-layer config for server/ACP
/// just as the CLI does.
fn project_config_disabled() -> bool {
    std::env::var("FREEDAS_DISABLE_PROJECT_CONFIG")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

async fn health() -> Json<Value> {
    Json(json!({"healthy": true, "version": env!("CARGO_PKG_VERSION")}))
}

#[derive(Deserialize)]
struct PageQuery {
    #[serde(default)]
    limit: Option<usize>,
}

async fn list_sessions(State(s): State<AppState>, Query(q): Query<PageQuery>) -> ApiResult {
    let pid =
        s.db.ensure_project(&s.paths.project_root)
            .map_err(internal)?;
    let rows =
        s.db.list_sessions(&pid, q.limit.unwrap_or(50))
            .map_err(internal)?;
    let aborts = s.aborts.lock().expect("aborts");
    Ok(Json(json!(
        rows.iter()
            .map(|r| {
                let status = if aborts.contains_key(&r.id) {
                    "busy"
                } else {
                    r.status.as_str()
                };
                json!({
                "id": r.id, "title": r.title, "agent": r.agent, "status": status,
                "createdAt": r.created_at, "updatedAt": r.updated_at
                })
            })
            .collect::<Vec<_>>()
    )))
}

#[derive(Deserialize)]
struct CreateSession {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    agent: Option<String>,
}

async fn create_session(State(s): State<AppState>, Json(body): Json<CreateSession>) -> ApiResult {
    let pid =
        s.db.ensure_project(&s.paths.project_root)
            .map_err(internal)?;
    let id =
        s.db.create_session(
            &pid,
            body.agent.as_deref().unwrap_or("build"),
            body.title.as_deref().unwrap_or("New session"),
            None,
        )
        .map_err(internal)?;
    s.emit(json!({"type": "session.created", "sessionID": id}));
    Ok(Json(json!({"id": id})))
}

async fn get_session(State(s): State<AppState>, AxumPath(id): AxumPath<String>) -> ApiResult {
    let messages = s.db.list_messages(&id).map_err(internal)?;
    let Some(full) = s.db.session_full(&id).map_err(internal)? else {
        return Err(missing(format!("session {id} not found")));
    };
    Ok(Json(json!({
        "id": full.id,
        "projectID": full.project_id,
        "parentID": full.parent_id,
        "title": full.title,
        "agent": full.agent,
        "model": {
            "provider": full.model_provider,
            "id": full.model_id,
            "variant": full.model_variant,
        },
        "workspaceID": full.workspace_id,
        "status": full.status,
        "archived": full.archived,
        "metadata": serde_json::from_str::<Value>(&full.metadata).unwrap_or_default(),
        "createdAt": full.created_at,
        "updatedAt": full.updated_at,
        "messageCount": messages.len(),
    })))
}

async fn delete_session(State(s): State<AppState>, AxumPath(id): AxumPath<String>) -> ApiResult {
    let deleted = s.db.delete_session(&id).map_err(internal)?;
    drain_pending(&s.pending_perms, &id);
    s.emit(json!({"type": "session.deleted", "sessionID": id}));
    Ok(Json(json!({"deleted": deleted})))
}

#[derive(Deserialize)]
struct RenameBody {
    #[serde(default)]
    title: Option<String>,
}

async fn rename_session(
    State(s): State<AppState>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<RenameBody>,
) -> ApiResult {
    let title = body.title.unwrap_or_default();
    if s.db.session_full(&id).map_err(internal)?.is_none() {
        return Err(missing(format!("session {id} not found")));
    }
    s.db.rename_session(&id, &title).map_err(internal)?;
    Ok(Json(json!({"id": id, "title": title})))
}

async fn list_messages(State(s): State<AppState>, AxumPath(id): AxumPath<String>) -> ApiResult {
    let mut out = Vec::new();
    for m in s.db.list_messages(&id).map_err(internal)? {
        let parts = s.db.list_parts(&m.id).map_err(internal)?;
        let metadata: Value = serde_json::from_str(&m.metadata).unwrap_or(Value::Null);
        out.push(json!({
            "info": {
                "id": m.id,
                "role": m.role,
                "createdAt": m.created_at,
                "model": m.model.as_deref().and_then(|t| serde_json::from_str::<Value>(t).ok()),
                "router": metadata.get("router").cloned(),
            },
            "parts": parts.iter().map(|p| json!({"id": p.id, "type": p.kind, "data": serde_json::from_str::<Value>(&p.data).unwrap_or_default()})).collect::<Vec<_>>()
        }));
    }
    Ok(Json(json!(out)))
}

#[derive(Deserialize)]
struct PostMessage {
    #[serde(default)]
    text: Option<String>,
    /// Auto-approve actions that are not explicitly denied.
    #[serde(default)]
    auto: bool,
    /// Ask even for actions an allow rule covers (mutually exclusive with
    /// `auto` in the CLI).
    #[serde(default)]
    manual: bool,
    /// Pin a model for this run only.
    #[serde(default)]
    model: Option<String>,
    /// Reasoning variant for the pinned model.
    #[serde(default)]
    variant: Option<String>,
}

/// Options for one prompt run. Grouped so the spawn sites stay readable.
struct RunRequest {
    text: String,
    auto: bool,
    manual: bool,
    agent: Option<String>,
    model: Option<String>,
    variant: Option<String>,
}

/// Spawn the agent run for a prompt. Returns `409` when the session already
/// has a live run, so two prompts cannot interleave in one transcript. Shared
/// by the prompt endpoints so they stream the same events on the bus.
fn spawn_run(s: &AppState, id: String, request: RunRequest) -> Result<(), ApiError> {
    let RunRequest {
        text,
        auto,
        manual,
        agent,
        model,
        variant,
    } = request;
    if auto && manual {
        return Err(bad_request("auto and manual are mutually exclusive"));
    }
    let cancel = Arc::new(tokio_util::sync::CancellationToken::new());
    {
        let mut aborts = s.aborts.lock().expect("aborts");
        if aborts.contains_key(&id) {
            return Err((
                StatusCode::CONFLICT,
                Json(json!({"error": "session already running", "sessionID": id})),
            ));
        }
        aborts.insert(id.clone(), cancel.clone());
    }
    // Name the session from its first prompt, like the CLI does.
    if let Ok(pid) = s.db.ensure_project(&s.paths.project_root)
        && let Ok(rows) = s.db.list_sessions(&pid, 200)
        && let Some(row) = rows.iter().find(|r| r.id == id)
        && row.title == "New session"
    {
        let title: String = text.chars().take(80).collect();
        if !title.is_empty() {
            let _ = s.db.rename_session(&id, &title);
        }
    }
    // The runner records the user message itself; the reply streams on the bus.
    s.emit(json!({"type": "message.updated", "sessionID": id}));

    // Run the agent for this session and stream events on the bus.
    let db = s.db.clone();
    let paths = s.paths.clone();
    let bus = s.bus.clone();
    let events = s.events.clone();
    let session_id = id.clone();
    let aborts = s.aborts.clone();
    let pending = s.pending_perms.clone();
    tokio::spawn(async move {
        let cfg =
            freedas_core::config::load(&paths, project_config_disabled()).unwrap_or_else(|e| {
                eprintln!("config: {e}");
                Default::default()
            });
        let agent = agent
            .or_else(|| {
                db.ensure_project(&paths.project_root)
                    .ok()
                    .and_then(|pid| db.list_sessions(&pid, 50).ok())
                    .and_then(|rows| rows.into_iter().find(|r| r.id == session_id))
                    .map(|r| r.agent)
            })
            .unwrap_or_else(|| cfg.default_agent.clone());
        let runner = freedas_session::Runner::new(
            db,
            paths.clone(),
            cfg.clone(),
            freedas_catalog::builtin_catalog(),
        );
        emit(
            &bus,
            &events,
            json!({"type": "session.status", "sessionID": session_id, "status": "busy"}),
        );
        let result = runner
            .run_task_opts(
                freedas_session::RunOpts {
                    project_root: paths.project_root.clone(),
                    agent,
                    model,
                    prompt: text,
                    auto,
                    manual,
                    workspace: cfg.workspace.clone(),
                    session_id: Some(session_id.clone()),
                    title: None,
                    variant,
                    depth: 0,
                    parent_id: None,
                    review_mode: false,
                    progress: Some({
                        let bus = bus.clone();
                        let events = events.clone();
                        let session_id = session_id.clone();
                        std::sync::Arc::new(move |chunk: String| {
                            if chunk.starts_with('\u{1}') {
                                emit(
                                    &bus,
                                    &events,
                                    json!({
                                        "type": "session.marker",
                                        "sessionID": session_id,
                                        "marker": chunk.trim_start_matches('\u{1}'),
                                    }),
                                );
                            } else {
                                emit(
                                    &bus,
                                    &events,
                                    json!({
                                        "type": "message.part.delta",
                                        "sessionID": session_id,
                                        "text": chunk,
                                    }),
                                );
                            }
                        })
                    }),
                    headless: false,
                    mcp_disabled: Vec::new(),
                    approver: Some(Arc::new(SseApprover {
                        session_id: session_id.clone(),
                        bus: bus.clone(),
                        events: events.clone(),
                        pending: pending.clone(),
                        paths: paths.clone(),
                    })),
                    session_rules: Default::default(),
                },
                (*cancel).clone(),
            )
            .await;
        {
            let mut aborts = aborts.lock().expect("aborts");
            // Only the run that inserted this token may remove it, so a later
            // run's token is never cleared by a finishing predecessor.
            if aborts
                .get(&session_id)
                .map(|token| Arc::ptr_eq(token, &cancel))
                .unwrap_or(false)
            {
                aborts.remove(&session_id);
            }
        }
        match result {
            Ok(r) => {
                emit(
                    &bus,
                    &events,
                    json!({
                        "type": "message.part.updated",
                        "sessionID": session_id,
                        "text": r.text,
                        "completed": r.completed,
                        "blocked": r.blocked,
                    }),
                );
            }
            Err(freedas_core::FreedasError::Cancelled) => {
                emit(
                    &bus,
                    &events,
                    json!({
                        "type": "session.stopped",
                        "sessionID": session_id,
                    }),
                );
            }
            Err(e) => {
                emit(
                    &bus,
                    &events,
                    json!({
                        "type": "session.error",
                        "sessionID": session_id,
                        "error": e.to_string(),
                    }),
                );
            }
        }
        emit(
            &bus,
            &events,
            json!({"type": "session.idle", "sessionID": session_id}),
        );
    });
    Ok(())
}

/// Admit a prompt and return immediately; the run streams on `/event`. The
/// user message is written by the runner, so this response cannot carry its id
/// - watch `message.updated` for it.
async fn post_message(
    State(s): State<AppState>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<PostMessage>,
) -> ApiResult {
    if s.db.session_full(&id).map_err(internal)?.is_none() {
        return Err(missing(format!("session {id} not found")));
    }
    spawn_run(
        &s,
        id.clone(),
        RunRequest {
            text: body.text.unwrap_or_default(),
            auto: body.auto,
            manual: body.manual,
            agent: None,
            model: body.model,
            variant: body.variant,
        },
    )?;
    Ok(Json(json!({
        "info": {"role": "user", "sessionID": id},
        "accepted": true,
        "async": true,
    })))
}

/// Same run as `post_message`; the response returns as soon as the task is
/// spawned, so a client can watch the bus instead of holding the request.
async fn prompt_async(
    State(s): State<AppState>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<PostMessage>,
) -> ApiResult {
    if s.db.session_full(&id).map_err(internal)?.is_none() {
        return Err(missing(format!("session {id} not found")));
    }
    spawn_run(
        &s,
        id.clone(),
        RunRequest {
            text: body.text.unwrap_or_default(),
            auto: body.auto,
            manual: body.manual,
            agent: None,
            model: body.model,
            variant: body.variant,
        },
    )?;
    Ok(Json(json!({"ok": true, "accepted": true, "sessionID": id})))
}

/// Build a runner with the server's effective config, shared by the
/// session-maintenance endpoints.
fn runner_for(s: &AppState) -> freedas_session::Runner {
    let cfg = freedas_core::config::load(&s.paths, project_config_disabled()).unwrap_or_else(|e| {
        eprintln!("config: {e}");
        Default::default()
    });
    freedas_session::Runner::new(
        s.db.clone(),
        s.paths.clone(),
        cfg,
        freedas_catalog::builtin_catalog(),
    )
}

async fn abort_session(State(s): State<AppState>, AxumPath(id): AxumPath<String>) -> Json<Value> {
    let cancelled = s
        .aborts
        .lock()
        .expect("aborts")
        .get(&id)
        .map(|token| {
            token.cancel();
            true
        })
        .unwrap_or(false);
    // Unblock a tool parked on a permission prompt; the run is going away.
    drain_pending(&s.pending_perms, &id);
    Json(json!({"aborted": cancelled}))
}

async fn revert_session(State(s): State<AppState>, AxumPath(id): AxumPath<String>) -> ApiResult {
    let messages = s.db.list_messages(&id).map_err(internal)?;
    let index = messages.iter().rposition(|message| message.role == "user");
    let Some(index) = index else {
        return Err(bad_request("nothing to revert"));
    };
    // `Runner::undo` deletes from this message on and pushes the redo rows
    // itself; the server must not repeat either step.
    let removed = messages.len() - index;
    let runner = runner_for(&s);
    match runner
        .undo(&s.paths.project_root, &id, &messages[index].id)
        .await
    {
        Ok(sha) => {
            s.emit(json!({
                "type": "session.reverted",
                "sessionID": id,
                "restored": sha,
                "removedMessages": removed,
            }));
            Ok(Json(json!({"restored": sha, "removedMessages": removed})))
        }
        Err(e) => Err(internal(e)),
    }
}

async fn unrevert_session(State(s): State<AppState>, AxumPath(id): AxumPath<String>) -> ApiResult {
    let runner = runner_for(&s);
    match runner.redo(&s.paths.project_root, &id).await {
        Ok(sha) => Ok(Json(json!({"restored": sha}))),
        Err(e) => Err(internal(e)),
    }
}

/// Diff between this session's first and last snapshots. Scoping to the
/// session's shadow-git commits keeps unrelated working-tree changes out.
async fn session_diff(State(s): State<AppState>, AxumPath(id): AxumPath<String>) -> ApiResult {
    let Some(full) = s.db.session_full(&id).map_err(internal)? else {
        return Err(missing(format!("session {id} not found")));
    };
    let snapshots = s.db.list_snapshot_rows(&id).map_err(internal)?;
    let mut diff = String::new();
    if snapshots.len() >= 2 {
        let repo = s
            .paths
            .snapshot_dir(&full.project_id)
            .join("repo.git")
            .to_string_lossy()
            .to_string();
        let first = snapshots[0].commit_sha.clone();
        let last = snapshots[snapshots.len() - 1].commit_sha.clone();
        diff = freedas_git::git_text(
            &[
                "--git-dir",
                repo.as_str(),
                "diff",
                "--no-color",
                "--no-ext-diff",
                first.as_str(),
                last.as_str(),
            ],
            &s.paths.project_root,
        )
        .await
        .unwrap_or_default();
    }
    let mut files = Vec::new();
    let mut current: Option<(String, u32, u32)> = None;
    for line in diff.lines() {
        if let Some(rest) = line.strip_prefix("+++ b/") {
            if let Some(done) = current.take() {
                files.push(done);
            }
            current = Some((rest.to_string(), 0, 0));
        } else if let Some(file) = current.as_mut() {
            if line.starts_with('+') && !line.starts_with("+++") {
                file.1 += 1;
            } else if line.starts_with('-') && !line.starts_with("---") {
                file.2 += 1;
            }
        }
    }
    if let Some(done) = current {
        files.push(done);
    }
    Ok(Json(json!({
        "diff": diff,
        "files": files.iter().map(|(p, a, d)| json!({"path": p, "added": a, "removed": d})).collect::<Vec<_>>(),
        // Snapshot diffs already include new files; kept for API shape.
        "untracked": [],
    })))
}

async fn session_usage(State(s): State<AppState>, AxumPath(id): AxumPath<String>) -> ApiResult {
    if s.db.session_full(&id).map_err(internal)?.is_none() {
        return Err(missing(format!("session {id} not found")));
    }
    let (input, output, cost) = s.db.session_usage(&id).map_err(internal)?;
    Ok(Json(json!({
        "sessionID": id,
        "inputTokens": input,
        "outputTokens": output,
        "costUsd": cost,
    })))
}

#[derive(Deserialize)]
struct ForkBody {
    #[serde(default)]
    message_id: Option<String>,
}

async fn fork_session(
    State(s): State<AppState>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<ForkBody>,
) -> ApiResult {
    if s.db.session_full(&id).map_err(internal)?.is_none() {
        return Err(missing(format!("session {id} not found")));
    }
    if let Some(mid) = body.message_id.as_deref() {
        let messages = s.db.list_messages(&id).map_err(internal)?;
        if !messages.iter().any(|m| m.id == mid) {
            return Err(bad_request(format!("unknown message {mid}")));
        }
    }
    let pid =
        s.db.ensure_project(&s.paths.project_root)
            .map_err(internal)?;
    let new_id =
        s.db.fork_session(&pid, &id, body.message_id.as_deref())
            .map_err(internal)?;
    Ok(Json(json!({"id": new_id})))
}

async fn get_config(State(s): State<AppState>) -> ApiResult {
    let cfg = freedas_core::config::load(&s.paths, project_config_disabled()).unwrap_or_else(|e| {
        eprintln!("config: {e}");
        Default::default()
    });
    let value = serde_json::to_value(cfg).map_err(internal)?;
    Ok(Json(redact_config(value)))
}

/// Mask credentials before the effective config leaves the process. Values
/// under secret-looking keys and every MCP header/environment entry are
/// replaced; non-secret settings stay readable.
fn redact_config(mut value: Value) -> Value {
    fn secret_key(key: &str) -> bool {
        let key = key.to_ascii_lowercase();
        key.contains("api_key")
            || key.contains("apikey")
            || key.contains("token")
            || key.contains("secret")
            || key.contains("password")
            || key.contains("credential")
    }
    fn walk(value: &mut Value) {
        match value {
            Value::Object(map) => {
                for (key, entry) in map.iter_mut() {
                    if (key == "environment" || key == "headers" || key == "env")
                        && let Value::Object(entries) = entry
                    {
                        for entry in entries.values_mut() {
                            if entry.is_string() {
                                *entry = json!("[redacted]");
                            }
                        }
                        continue;
                    }
                    if secret_key(key) && entry.is_string() {
                        *entry = json!("[redacted]");
                        continue;
                    }
                    walk(entry);
                }
            }
            Value::Array(items) => {
                for item in items {
                    walk(item);
                }
            }
            _ => {}
        }
    }
    walk(&mut value);
    value
}

/// JSON Merge Patch (RFC 7386): objects merge recursively, `null` removes a
/// key, anything else replaces. Unlike the config *layer* merge, a PATCH does
/// not concatenate arrays - the caller sent the value it wants.
fn merge_patch(base: &mut Value, patch: Value) {
    match (base, patch) {
        (Value::Object(b), Value::Object(p)) => {
            for (k, v) in p {
                if v.is_null() {
                    b.remove(&k);
                } else if let Some(existing) = b.get_mut(&k) {
                    merge_patch(existing, v);
                } else {
                    b.insert(k, v);
                }
            }
        }
        (b, p) => *b = p,
    }
}

/// Persist a config patch into the global config file, atomically, then
/// return the redacted effective config. JSONC comments are not preserved
/// (same documented tradeoff as `remember_rule`).
async fn patch_config(State(s): State<AppState>, Json(body): Json<Value>) -> ApiResult {
    if !body.is_object() {
        return Err(bad_request("body must be a JSON object"));
    }
    // Serialize read-modify-write so concurrent PATCHes cannot lose keys.
    let _guard = s.config_lock.lock().await;
    let path = s.paths.global_config();
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(internal)?;
    }
    let mut root: Value = match tokio::fs::read_to_string(&path).await {
        Ok(text) => {
            jsonc_parser::parse_to_serde_value(&text, &jsonc_parser::ParseOptions::default())
                .ok()
                .flatten()
                .filter(Value::is_object)
                .ok_or_else(|| bad_request("existing config file is not a JSON object"))?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => json!({}),
        Err(error) => return Err(internal(error)),
    };
    merge_patch(&mut root, body);
    // Reject a patch that would leave a document the loader cannot read.
    let config: freedas_core::config::Config = serde_json::from_value(root.clone())
        .map_err(|error| bad_request(format!("invalid config: {error}")))?;
    for (key, model) in [
        ("model", &config.model),
        ("small_model", &config.small_model),
    ] {
        if let Some(model) = model.as_deref()
            && let Err(error) = freedas_core::config::check_model(model)
        {
            return Err(bad_request(format!("invalid `{key}`: {error}")));
        }
    }
    let tmp = path.with_extension("jsonc.tmp");
    let write = async {
        tokio::fs::write(&tmp, serde_json::to_vec_pretty(&root)?).await?;
        tokio::fs::rename(&tmp, &path).await
    };
    write.await.map_err(internal)?;
    drop(_guard);
    get_config(State(s)).await
}

async fn list_agents() -> Json<Value> {
    let agents = freedas_agent::builtin_agents();
    Json(json!(
        agents
            .iter()
            .map(|a| json!({"id": a.id, "mode": a.mode, "description": a.description}))
            .collect::<Vec<_>>()
    ))
}

async fn list_commands(State(s): State<AppState>) -> Json<Value> {
    let mut out = Vec::new();
    let dirs = [
        s.paths.project_root.join(".freedas").join("commands"),
        s.paths.config_dir.join("commands"),
    ];
    for dir in dirs {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                let p = e.path();
                if p.extension().map(|x| x == "md").unwrap_or(false) {
                    let text = std::fs::read_to_string(&p).unwrap_or_default();
                    let (front, body) = freedas_agent::parse_frontmatter(&text)
                        .unwrap_or((json!({}), text.clone()));
                    out.push(json!({
                        "name": p.file_stem().map(|x| x.to_string_lossy().to_string()).unwrap_or_default(),
                        "description": front["description"].as_str().unwrap_or(""),
                        "agent": front["agent"].as_str(),
                        "body": body,
                    }));
                }
            }
        }
    }
    for skill in freedas_skill::discover(&s.paths.project_root) {
        out.push(json!({
            "name": skill.id,
            "description": skill.description,
            "body": skill.body,
        }));
    }
    // MCP prompts become `/<server>:<prompt>` commands; a short connect budget
    // keeps /command responsive when a server is down.
    let cfg = freedas_core::config::load(&s.paths, project_config_disabled()).unwrap_or_else(|e| {
        eprintln!("config: {e}");
        Default::default()
    });
    if let Ok(prompts) = tokio::time::timeout(
        std::time::Duration::from_secs(4),
        freedas_mcp::discover_slash_commands(&cfg.mcp),
    )
    .await
    {
        for p in prompts {
            out.push(json!({
                "name": p.name,
                "description": p.description,
                "body": null,
                "mcp": true,
                "arguments": p.arguments.iter().map(|a| json!({
                    "name": a.name, "required": a.required,
                })).collect::<Vec<_>>(),
            }));
        }
    }
    Json(json!(out))
}

/// Run a custom command/skill/MCP prompt against a session: expands the body
/// into the session's next prompt. Built-in commands stay TUI-local.
#[derive(Deserialize)]
pub struct CommandBody {
    pub name: String,
    #[serde(default)]
    pub args: String,
}

/// A resolved custom command: body plus the frontmatter fields that change how
/// it runs.
struct ResolvedCommand {
    body: String,
    agent: Option<String>,
    model: Option<String>,
    subtask: bool,
}

async fn post_command(
    State(s): State<AppState>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<CommandBody>,
) -> ApiResult {
    // Resolve the named command the same way /command lists it.
    let mut resolved: Option<ResolvedCommand> = None;
    for dir in [
        s.paths.project_root.join(".freedas").join("commands"),
        s.paths.config_dir.join("commands"),
    ] {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                let p = e.path();
                if p.extension().map(|x| x == "md").unwrap_or(false)
                    && p.file_stem()
                        .map(|x| x.to_string_lossy() == body.name)
                        .unwrap_or(false)
                {
                    let text = std::fs::read_to_string(&p).unwrap_or_default();
                    let (front, cmd_body) =
                        freedas_agent::parse_frontmatter(&text).unwrap_or((json!({}), text));
                    let field = |key| {
                        front
                            .get(key)
                            .and_then(Value::as_str)
                            .map(str::trim)
                            .filter(|v| !v.is_empty())
                            .map(str::to_string)
                    };
                    resolved = Some(ResolvedCommand {
                        body: cmd_body,
                        agent: field("agent"),
                        model: field("model"),
                        subtask: front
                            .get("subtask")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                    });
                }
            }
        }
    }
    if resolved.is_none()
        && let Some(skill) = freedas_skill::discover(&s.paths.project_root)
            .into_iter()
            .find(|sk| sk.id == body.name)
    {
        resolved = Some(ResolvedCommand {
            body: skill.body,
            agent: None,
            model: None,
            subtask: false,
        });
    }
    let Some(command) = resolved else {
        return Err(missing(format!("unknown command {}", body.name)));
    };
    if s.db.session_full(&id).map_err(internal)?.is_none() {
        return Err(missing(format!("session {id} not found")));
    }
    let text = freedas_skill::expand_args(&command.body, &body.args);
    // `subtask: true` runs in a child session, like the TUI does.
    let target = if command.subtask {
        let pid =
            s.db.ensure_project(&s.paths.project_root)
                .map_err(internal)?;
        s.db.fork_session(&pid, &id, None).map_err(internal)?
    } else {
        id.clone()
    };
    spawn_run(
        &s,
        target.clone(),
        RunRequest {
            text,
            auto: false,
            manual: false,
            agent: command.agent,
            model: command.model,
            variant: None,
        },
    )?;
    Ok(Json(json!({
        "ok": true,
        "sessionID": target,
        "accepted": true,
        "async": true,
    })))
}

async fn list_mcp(State(s): State<AppState>) -> Json<Value> {
    let cfg = freedas_core::config::load(&s.paths, project_config_disabled()).unwrap_or_else(|e| {
        eprintln!("config: {e}");
        Default::default()
    });
    let servers = freedas_mcp::status_from_config(&cfg);
    Json(json!(
        servers
            .iter()
            .map(|x| json!({
                "name": x.name,
                "state": x.state,
                "tools": x.tools,
                "prompts": x.prompts,
                "error": x.error,
            }))
            .collect::<Vec<_>>()
    ))
}

fn sse_event(value: &Value) -> axum::response::sse::Event {
    let mut event = axum::response::sse::Event::default().data(value.to_string());
    if let Some(id) = value.get("id").and_then(Value::as_u64) {
        event = event.id(id.to_string());
    }
    event
}

async fn sse_events(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Sse<impl futures::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>>
{
    let last = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    // Subscribe before snapshotting so nothing that happens in between is lost;
    // duplicate live ids are skipped below.
    let mut rx = s.bus.subscribe();
    let replay = match last {
        Some(id) => s.events.replay_since(id),
        None => Vec::new(),
    };
    let stream = async_stream::stream! {
        yield Ok(axum::response::sse::Event::default().data(
            serde_json::to_string(&json!({"type": "server.connected"})).unwrap_or_default(),
        ));
        let mut sent = last.unwrap_or(0);
        for event in replay {
            sent = sent.max(event.get("id").and_then(Value::as_u64).unwrap_or(0));
            yield Ok(sse_event(&event));
        }
        loop {
            match rx.recv().await {
                Ok(event) => {
                    let id = event.get("id").and_then(Value::as_u64).unwrap_or(0);
                    if id <= sent {
                        continue;
                    }
                    sent = id;
                    yield Ok(sse_event(&event));
                }
                Err(broadcast::error::RecvError::Lagged(dropped)) => {
                    // Stream-only marker: never enters the EventLog and never
                    // moves `sent`, so the client resumes from what it has.
                    yield Ok(sse_event(&json!({
                        "type": "server.lagged",
                        "dropped": dropped,
                    })));
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };
    Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default())
}

/// Serve with CORS for the given origins (empty = no CORS headers).
pub async fn serve_with_cors(host: &str, port: u16, origins: Vec<String>) -> std::io::Result<()> {
    let paths = Paths::resolve(std::env::current_dir().unwrap_or_default());
    let db = Arc::new(Db::open(&paths.db_path()).expect("open db"));
    let listener = tokio::net::TcpListener::bind((host, port)).await?;
    let addr = listener.local_addr()?;
    let auth = Auth::from_env(is_loopback_host(host));
    let app = app_with_auth(db, paths, auth).layer(axum::middleware::from_fn(
        move |req: axum::extract::Request, next: axum::middleware::Next| {
            let origins = origins.clone();
            async move {
                use axum::http::{Method, header};
                let allow = req
                    .headers()
                    .get(header::ORIGIN)
                    .and_then(|v| v.to_str().ok())
                    .filter(|o| origins.iter().any(|x| x == o))
                    .map(str::to_string);
                let mut resp = if req.method() == Method::OPTIONS {
                    axum::response::Response::new(axum::body::Body::empty())
                } else {
                    next.run(req).await
                };
                if let Some(origin) = allow {
                    let h = resp.headers_mut();
                    if let Ok(value) = axum::http::HeaderValue::from_str(&origin) {
                        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
                    }
                    h.insert(
                        header::ACCESS_CONTROL_ALLOW_METHODS,
                        axum::http::HeaderValue::from_static("GET,POST,PUT,PATCH,DELETE,OPTIONS"),
                    );
                    h.insert(
                        header::ACCESS_CONTROL_ALLOW_HEADERS,
                        axum::http::HeaderValue::from_static("content-type,authorization"),
                    );
                    h.insert(header::VARY, axum::http::HeaderValue::from_static("origin"));
                }
                resp
            }
        },
    ));
    println!("freedas server on http://{addr}");
    axum::serve(listener, app).await
}

pub async fn serve(host: &str, port: u16) -> std::io::Result<()> {
    let paths = Paths::resolve(std::env::current_dir().unwrap_or_default());
    let db = Arc::new(Db::open(&paths.db_path()).expect("open db"));
    let listener = tokio::net::TcpListener::bind((host, port)).await?;
    let addr = listener.local_addr()?;
    let app = app_with_auth(db, paths, Auth::from_env(is_loopback_host(host)));
    println!("freedas server on http://{addr}");
    axum::serve(listener, app).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use tower::ServiceExt;

    fn setup() -> (tempfile::TempDir, Arc<Db>, Paths) {
        let dir = tempfile::tempdir().expect("tempdir");
        let project_root = dir.path().join("project");
        std::fs::create_dir_all(&project_root).expect("project");
        let paths = Paths {
            home: dir.path().join("home"),
            config_dir: dir.path().join("config"),
            data_dir: dir.path().join("data"),
            state_dir: dir.path().join("state"),
            cache_dir: dir.path().join("cache"),
            bin_dir: dir.path().join("bin"),
            project_root,
        };
        let db = Arc::new(Db::open(&paths.db_path()).expect("db"));
        (dir, db, paths)
    }

    async fn send(
        server: &Router,
        method: &str,
        uri: &str,
        body: Option<&str>,
        headers: &[(&str, &str)],
    ) -> (StatusCode, Value) {
        let mut builder = axum::http::Request::builder().method(method).uri(uri);
        for (key, value) in headers {
            builder = builder.header(*key, *value);
        }
        let body = body
            .map(|body| Body::from(body.to_string()))
            .unwrap_or_else(Body::empty);
        let response = server
            .clone()
            .oneshot(builder.body(body).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    #[tokio::test]
    async fn session_api_roundtrip() {
        let (_dir, db, paths) = setup();
        let server = app_with_auth(db, paths, Auth::default());
        let (status, _) = send(&server, "GET", "/session", None, &[]).await;
        assert_eq!(status, StatusCode::OK);
        let (status, body) = send(
            &server,
            "POST",
            "/session",
            Some(r#"{"title":"t","agent":"build"}"#),
            &[("content-type", "application/json")],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["id"].as_str().unwrap().starts_with("ses_"));
    }

    #[tokio::test]
    async fn auth_requires_the_configured_token() {
        let (_dir, db, paths) = setup();
        let server = app_with_auth(db, paths, Auth::new(Some("secret".into()), None));
        assert_eq!(
            send(&server, "GET", "/session", None, &[]).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            send(
                &server,
                "GET",
                "/session",
                None,
                &[("authorization", "Bearer wrong")],
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            send(
                &server,
                "GET",
                "/session",
                None,
                &[("authorization", "Bearer secret")],
            )
            .await
            .0,
            StatusCode::OK
        );
        // Health stays reachable without credentials.
        assert_eq!(
            send(&server, "GET", "/global/health", None, &[]).await.0,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn foreign_host_is_rejected_on_a_loopback_bind() {
        let (_dir, db, paths) = setup();
        let server = app_with_auth(db, paths, Auth::default().loopback_only());
        assert_eq!(
            send(
                &server,
                "GET",
                "/session",
                None,
                &[("host", "evil.example:4096")],
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            send(
                &server,
                "GET",
                "/session",
                None,
                &[("host", "127.0.0.1:4096")],
            )
            .await
            .0,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn config_patch_rejects_unparseable_or_invalid_files() {
        let (_dir, db, paths) = setup();
        std::fs::create_dir_all(&paths.config_dir).expect("config dir");
        let server = app_with_auth(db, paths.clone(), Auth::default());
        let header = [("content-type", "application/json")];

        std::fs::write(paths.global_config(), "{ not json").expect("write");
        let (status, _) = send(
            &server,
            "PATCH",
            "/config",
            Some(r#"{"model":"freedas/auto"}"#),
            &header,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        std::fs::write(paths.global_config(), r#"{"default_agent":42}"#).expect("write");
        let (status, _) = send(
            &server,
            "PATCH",
            "/config",
            Some(r#"{"model":"freedas/auto"}"#),
            &header,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        std::fs::remove_file(paths.global_config()).expect("remove");
        let (status, body) = send(
            &server,
            "PATCH",
            "/config",
            Some(r#"{"model":"openai/gpt-5"}"#),
            &header,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["model"], "openai/gpt-5");
    }

    #[tokio::test]
    async fn second_prompt_on_a_running_session_conflicts() {
        let (_dir, db, paths) = setup();
        let state = AppState::new(db.clone(), paths.clone());
        let project = db.ensure_project(&paths.project_root).expect("project");
        let session = db
            .create_session(&project, "build", "t", None)
            .expect("session");
        state.aborts.lock().expect("aborts").insert(
            session.clone(),
            Arc::new(tokio_util::sync::CancellationToken::new()),
        );
        let (status, _) = spawn_run(
            &state,
            session,
            RunRequest {
                text: "hi".into(),
                auto: false,
                manual: false,
                agent: None,
                model: None,
                variant: None,
            },
        )
        .expect_err("second run must conflict");
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(state.aborts.lock().expect("aborts").len(), 1);
    }

    #[test]
    fn config_redaction_masks_credentials() {
        let redacted = redact_config(json!({
            "model": "freedas/auto",
            "extra_provider": {"api_key": "sk-live"},
            "mcp": {"linear": {
                "url": "https://mcp.linear.app/mcp",
                "headers": {"Authorization": "Bearer t"},
                "environment": {"ACME_TOKEN": "abc"},
            }},
        }));
        assert_eq!(redacted["model"], "freedas/auto");
        assert_eq!(redacted["extra_provider"]["api_key"], "[redacted]");
        assert_eq!(
            redacted["mcp"]["linear"]["headers"]["Authorization"],
            "[redacted]"
        );
        assert_eq!(
            redacted["mcp"]["linear"]["environment"]["ACME_TOKEN"],
            "[redacted]"
        );
        assert_eq!(
            redacted["mcp"]["linear"]["url"],
            "https://mcp.linear.app/mcp"
        );
    }

    #[cfg(unix)]
    #[test]
    fn walk_files_skips_symlinks_and_loops() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("root");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(root.join("sub")).expect("dirs");
        std::fs::create_dir_all(&outside).expect("outside");
        std::fs::write(root.join("real.txt"), "x").expect("write");
        std::fs::write(root.join("sub/nested.txt"), "x").expect("write");
        std::fs::write(outside.join("secret.txt"), "x").expect("write");
        std::os::unix::fs::symlink(outside.join("secret.txt"), root.join("link.txt"))
            .expect("file symlink");
        std::os::unix::fs::symlink(&root, root.join("loop")).expect("dir symlink");

        let files = walk_files(&root, 100);
        let names: Vec<String> = files
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(names.contains(&"real.txt".to_string()));
        assert!(names.contains(&"nested.txt".to_string()));
        assert!(!names.iter().any(|name| name == "link.txt"));
        assert!(!names.iter().any(|name| name == "secret.txt"));
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn init_markers_must_balance() {
        let section = "<!-- freedas:init:begin -->\nnew\n<!-- freedas:init:end -->\n";
        let prose = "keep me\n<!-- freedas:init:begin -->\nold\n<!-- freedas:init:end -->\n";
        let merged = merge_init_section(prose, section).expect("balanced");
        assert!(merged.starts_with("keep me"));
        assert!(merged.contains("new"));
        assert!(!merged.contains("old"));
        assert!(merge_init_section("user prose\n<!-- freedas:init:begin -->\n", section).is_err());
        assert!(merge_init_section("user prose\n", section).is_ok());
    }
}

#[derive(serde::Deserialize)]
pub struct PermissionReplyBody {
    pub response: Option<String>,
}

async fn reply_permission(
    State(s): State<AppState>,
    AxumPath((session_id, perm)): AxumPath<(String, String)>,
    Json(body): Json<PermissionReplyBody>,
) -> ApiResult {
    let reply = match body.response.as_deref() {
        Some("always") => freedas_tools::PermissionReply::Always,
        Some("once") => freedas_tools::PermissionReply::Once,
        _ => freedas_tools::PermissionReply::Reject,
    };
    let mut pending = s.pending_perms.lock().expect("pending_perms");
    match pending.get(&perm) {
        Some((sid, _)) if sid == &session_id => {}
        Some(_) => {
            return Err((
                StatusCode::CONFLICT,
                Json(json!({"error": "permission belongs to another session"})),
            ));
        }
        None => return Err(missing("unknown or answered permission")),
    }
    let (_, tx) = pending.remove(&perm).expect("checked above");
    let _ = tx.send(reply);
    Ok(Json(json!({"ok": true})))
}

async fn session_status(State(s): State<AppState>, AxumPath(id): AxumPath<String>) -> ApiResult {
    if s.db.session_full(&id).map_err(internal)?.is_none() {
        return Err(missing(format!("session {id} not found")));
    }
    let busy = s.aborts.lock().expect("aborts").contains_key(&id);
    Ok(Json(
        json!({"sessionID": id, "status": if busy { "busy" } else { "idle" }}),
    ))
}

async fn openapi_doc() -> Json<Value> {
    let routes: [(&str, &[&str]); 42] = [
        ("/global/health", &["get"]),
        ("/global/event", &["get"]),
        ("/event", &["get"]),
        ("/doc", &["get"]),
        ("/project", &["get"]),
        ("/project/current", &["get"]),
        ("/path", &["get"]),
        ("/vcs", &["get"]),
        ("/config", &["get", "patch"]),
        ("/provider", &["get"]),
        ("/provider/auth", &["get"]),
        ("/auth/{id}", &["put"]),
        ("/session", &["get", "post"]),
        ("/session/status", &["get"]),
        ("/session/{id}", &["get", "delete", "patch"]),
        ("/session/{id}/message", &["get", "post"]),
        ("/session/{id}/prompt_async", &["post"]),
        ("/session/{id}/command", &["post"]),
        ("/session/{id}/shell", &["post"]),
        ("/session/{id}/children", &["get"]),
        ("/session/{id}/todo", &["get"]),
        ("/session/{id}/fork", &["post"]),
        ("/session/{id}/abort", &["post"]),
        ("/session/{id}/summarize", &["post"]),
        ("/session/{id}/init", &["post"]),
        ("/session/{id}/revert", &["post"]),
        ("/session/{id}/unrevert", &["post"]),
        ("/session/{id}/diff", &["get"]),
        ("/session/{id}/usage", &["get"]),
        ("/session/{id}/status", &["get"]),
        ("/session/{id}/permissions/{perm}", &["post"]),
        ("/find", &["get"]),
        ("/find/file", &["get"]),
        ("/find/symbol", &["get"]),
        ("/file", &["get"]),
        ("/file/content", &["get"]),
        ("/file/status", &["get"]),
        ("/lsp", &["get"]),
        ("/formatter", &["get"]),
        ("/mcp", &["get", "post"]),
        ("/agent", &["get"]),
        ("/command", &["get"]),
    ];
    let mut paths = serde_json::Map::new();
    for (path, methods) in routes {
        let mut ops = serde_json::Map::new();
        for method in methods {
            ops.insert(
                (*method).to_string(),
                json!({"responses": {"200": {"description": "ok"}}}),
            );
        }
        paths.insert(path.to_string(), Value::Object(ops));
    }
    Json(json!({
        "openapi": "3.0.0",
        "info": {"title": "Freedas local API", "version": env!("CARGO_PKG_VERSION")},
        "paths": paths,
    }))
}

async fn list_projects(State(s): State<AppState>) -> ApiResult {
    let id =
        s.db.ensure_project(&s.paths.project_root)
            .map_err(internal)?;
    Ok(Json(json!([{"id": id, "root": s.paths.project_root}])))
}

async fn current_project(State(s): State<AppState>) -> ApiResult {
    let id =
        s.db.ensure_project(&s.paths.project_root)
            .map_err(internal)?;
    Ok(Json(json!({"id": id, "root": s.paths.project_root})))
}

async fn paths_info(State(s): State<AppState>) -> Json<Value> {
    Json(json!({
        "cwd": std::env::current_dir().unwrap_or_default(),
        "root": s.paths.project_root,
        "dataDir": s.paths.data_dir,
        "configDir": s.paths.config_dir,
        "stateDir": s.paths.state_dir,
        "cacheDir": s.paths.cache_dir,
        "binDir": s.paths.bin_dir,
    }))
}

/// `git status --porcelain` as `{path,status}` entries; empty outside a repo.
async fn git_status_entries(root: &std::path::Path) -> Vec<Value> {
    let text = freedas_git::git_text(&["status", "--porcelain"], root)
        .await
        .unwrap_or_default();
    text.lines()
        .filter(|line| line.len() > 3)
        .map(|line| {
            json!({
                "status": line.get(..2).unwrap_or("").trim(),
                "path": line.get(3..).unwrap_or(""),
            })
        })
        .collect()
}

async fn vcs_info(State(s): State<AppState>) -> Json<Value> {
    let root = &s.paths.project_root;
    let inside = freedas_git::git_text(&["rev-parse", "--is-inside-work-tree"], root)
        .await
        .map(|t| t.trim() == "true")
        .unwrap_or(false);
    if !inside {
        return Json(json!({"branch": null, "defaultBranch": null, "status": [], "clean": true}));
    }
    let branch = freedas_git::git_text(&["rev-parse", "--abbrev-ref", "HEAD"], root)
        .await
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|b| !b.is_empty() && b != "HEAD");
    let default_branch = freedas_git::git_text(
        &["symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
        root,
    )
    .await
    .ok()
    .map(|t| t.trim().trim_start_matches("origin/").to_string())
    .filter(|b| !b.is_empty());
    let status = git_status_entries(root).await;
    Json(json!({
        "branch": branch,
        "defaultBranch": default_branch,
        "status": status,
        "clean": status.is_empty(),
    }))
}

/// Map every known session to `busy` (a run token exists) or `idle`.
async fn sessions_status(State(s): State<AppState>) -> ApiResult {
    let mut map = serde_json::Map::new();
    let pid =
        s.db.ensure_project(&s.paths.project_root)
            .map_err(internal)?;
    for row in s.db.list_sessions(&pid, 200).map_err(internal)? {
        map.insert(row.id, json!("idle"));
    }
    for id in s.aborts.lock().expect("aborts").keys() {
        map.insert(id.clone(), json!("busy"));
    }
    Ok(Json(Value::Object(map)))
}

async fn list_children(State(s): State<AppState>, AxumPath(id): AxumPath<String>) -> ApiResult {
    let Some(full) = s.db.session_full(&id).map_err(internal)? else {
        return Err(missing(format!("session {id} not found")));
    };
    let mut out = Vec::new();
    for row in
        s.db.list_sessions(&full.project_id, 200)
            .map_err(internal)?
    {
        if let Some(child) = s.db.session_full(&row.id).map_err(internal)?
            && child.parent_id.as_deref() == Some(id.as_str())
        {
            out.push(json!({
                "id": child.id,
                "parentID": child.parent_id,
                "title": child.title,
                "agent": child.agent,
                "status": child.status,
                "createdAt": child.created_at,
                "updatedAt": child.updated_at,
            }));
        }
    }
    Ok(Json(json!(out)))
}

async fn list_todos(State(s): State<AppState>, AxumPath(id): AxumPath<String>) -> ApiResult {
    Ok(Json(json!(
        s.db.list_todo_rows(&id)
            .map_err(internal)?
            .iter()
            .map(|t| json!({
                "id": t.id,
                "content": t.content,
                "status": t.status,
                "priority": t.priority,
            }))
            .collect::<Vec<_>>()
    )))
}

async fn summarize_session(State(s): State<AppState>, AxumPath(id): AxumPath<String>) -> ApiResult {
    let summary = runner_for(&s).compact(&id).await.map_err(internal)?;
    Ok(Json(json!({"sessionID": id, "summary": summary})))
}

async fn init_agents_md(State(s): State<AppState>, AxumPath(id): AxumPath<String>) -> ApiResult {
    if s.db.session_full(&id).map_err(internal)?.is_none() {
        return Err(missing(format!("session {id} not found")));
    }
    let path = s.paths.project_root.join("AGENTS.md");
    let section = agents_md_section(&s.paths.project_root);
    let existing = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(internal(error)),
    };
    let merged = merge_init_section(&existing, &section).map_err(bad_request)?;
    // Never write in place: a failed write must not truncate the user's file.
    let tmp = path.with_extension("md.tmp");
    std::fs::write(&tmp, &merged).map_err(internal)?;
    std::fs::rename(&tmp, &path).map_err(internal)?;
    Ok(Json(json!({
        "ok": true,
        "sessionID": id,
        "path": path,
        "lines": merged.lines().count(),
        "content": section,
    })))
}

#[derive(Deserialize)]
struct ShellBody {
    #[serde(default)]
    command: Option<String>,
}

/// Server-side shell for the web UI. Runs through the `bash` tool so the
/// permission scanner and OS sandbox apply exactly as they do to the agent.
async fn shell_session(
    State(s): State<AppState>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<ShellBody>,
) -> ApiResult {
    let command = body.command.unwrap_or_default();
    if command.trim().is_empty() {
        return Err(bad_request("command required"));
    }
    let Some(session) = s.db.session_full(&id).map_err(internal)? else {
        return Err(missing(format!("session {id} not found")));
    };
    let cfg = freedas_core::config::load(&s.paths, project_config_disabled()).unwrap_or_else(|e| {
        eprintln!("config: {e}");
        Default::default()
    });
    let ctx = freedas_tools::ToolContext {
        session_id: id.clone(),
        project_root: s.paths.project_root.clone(),
        cwd: s.paths.project_root.clone(),
        config: cfg.clone(),
        agent_rules: Vec::new(),
        session_rules: Default::default(),
        auto: false,
        manual: false,
        read_hashes: Default::default(),
        sandbox: cfg.sandbox.mode != "off",
        bypass: false,
        plans_dir: Some(s.paths.plans_dir()),
        approver: Some(Arc::new(SseApprover {
            session_id: id.clone(),
            bus: s.bus.clone(),
            events: s.events.clone(),
            pending: s.pending_perms.clone(),
            paths: s.paths.clone(),
        })),
        db: Some(s.db.clone()),
        project_id: Some(session.project_id),
    };
    let input = json!({"command": command, "timeout_ms": 30_000});
    match freedas_tools::Bash.execute(&input, &ctx).await {
        Ok(output) => Ok(Json(json!({
            "sessionID": id,
            "content": output.content,
            "truncated": output.truncated,
            "exit": output.metadata.get("exit"),
        }))),
        Err(freedas_core::FreedasError::PermissionDenied { action, resource }) => Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": format!("permission denied: {action} {resource}")})),
        )),
        Err(error) => Err(internal(error)),
    }
}

#[derive(Deserialize)]
struct FindQuery {
    #[serde(default)]
    pattern: Option<String>,
}

#[derive(Deserialize)]
struct FileFindQuery {
    #[serde(default)]
    query: Option<String>,
}

#[derive(Deserialize)]
struct PathQuery {
    #[serde(default)]
    path: Option<String>,
}

/// Regular files under `root`, skipping hidden entries, build directories,
/// symlinks, and already-visited directories. Symlinks are never followed, so
/// a link cannot pull in files outside the project or create a walk loop.
fn walk_files(root: &std::path::Path, max: usize) -> Vec<std::path::PathBuf> {
    use std::collections::HashSet;
    let Ok(canon_root) = root.canonicalize() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut stack = vec![canon_root.clone()];
    while let Some(dir) = stack.pop() {
        if !seen.insert(dir.clone()) {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') || matches!(name.as_str(), "target" | "node_modules" | "dist")
            {
                continue;
            }
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            let path = entry.path();
            if file_type.is_dir() {
                // Canonical containment also rejects a directory swapped for a
                // traversal after the walk started.
                match path.canonicalize() {
                    Ok(canon) if canon.starts_with(&canon_root) => stack.push(canon),
                    _ => continue,
                }
            } else if file_type.is_file() {
                out.push(path);
                if out.len() >= max {
                    return out;
                }
            }
        }
    }
    out
}

fn relative(root: &std::path::Path, path: &std::path::Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

async fn find_text(State(s): State<AppState>, Query(q): Query<FindQuery>) -> Json<Value> {
    let pattern = q.pattern.unwrap_or_default().to_lowercase();
    if pattern.is_empty() {
        return Json(json!([]));
    }
    let root = &s.paths.project_root;
    let mut hits = Vec::new();
    for path in walk_files(root, 5000) {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if text.len() > 1024 * 1024 {
            continue;
        }
        for (idx, line) in text.lines().enumerate() {
            if line.to_lowercase().contains(&pattern) {
                hits.push(json!({
                    "path": relative(root, &path),
                    "line": idx + 1,
                    "text": line.chars().take(240).collect::<String>(),
                }));
                if hits.len() >= 100 {
                    return Json(json!(hits));
                }
            }
        }
    }
    Json(json!(hits))
}

async fn find_file(State(s): State<AppState>, Query(q): Query<FileFindQuery>) -> Json<Value> {
    let query = q.query.unwrap_or_default().to_lowercase();
    if query.is_empty() {
        return Json(json!([]));
    }
    let root = &s.paths.project_root;
    let mut hits = Vec::new();
    for path in walk_files(root, 20000) {
        let rel = relative(root, &path);
        if rel.to_lowercase().contains(&query) {
            hits.push(json!({
                "path": rel,
                "name": path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
            }));
            if hits.len() >= 200 {
                break;
            }
        }
    }
    Json(json!(hits))
}

async fn find_symbol() -> Json<Value> {
    // No symbol index is wired into the local server yet; report an empty set
    // rather than failing the caller.
    let _ = freedas_lsp::servers_available();
    Json(json!([]))
}

/// Canonicalize `rel` under the project root; `None` when it escapes.
fn resolve_in_project(root: &std::path::Path, rel: &str) -> Option<std::path::PathBuf> {
    let canon_root = root.canonicalize().ok()?;
    let joined = if rel.is_empty() {
        canon_root.clone()
    } else {
        canon_root.join(rel)
    };
    let canon = joined.canonicalize().ok()?;
    canon.starts_with(&canon_root).then_some(canon)
}

fn not_found(error: &str) -> axum::response::Response {
    (StatusCode::NOT_FOUND, Json(json!({"error": error}))).into_response()
}

async fn list_files(
    State(s): State<AppState>,
    Query(q): Query<PathQuery>,
) -> axum::response::Response {
    let Some(dir) = resolve_in_project(&s.paths.project_root, q.path.as_deref().unwrap_or(""))
    else {
        return not_found("path outside project");
    };
    if !dir.is_dir() {
        return not_found("not a directory");
    }
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return not_found("unreadable directory");
    };
    let mut out = entries
        .flatten()
        .map(|e| {
            json!({
                "name": e.file_name().to_string_lossy(),
                "isDir": e.path().is_dir(),
            })
        })
        .collect::<Vec<_>>();
    out.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Json(json!(out)).into_response()
}

async fn file_content(
    State(s): State<AppState>,
    Query(q): Query<PathQuery>,
) -> axum::response::Response {
    let Some(path) = resolve_in_project(&s.paths.project_root, q.path.as_deref().unwrap_or(""))
    else {
        return not_found("path outside project");
    };
    let Ok(meta) = std::fs::metadata(&path) else {
        return not_found("file not found");
    };
    if meta.len() > 1024 * 1024 {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({"error": "file exceeds 1 MiB"})),
        )
            .into_response();
    }
    match std::fs::read_to_string(&path) {
        Ok(content) => Json(json!({
            "path": relative(&s.paths.project_root, &path),
            "content": content,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn file_status(State(s): State<AppState>) -> Json<Value> {
    Json(json!(git_status_entries(&s.paths.project_root).await))
}

async fn lsp_status() -> Json<Value> {
    let servers = freedas_lsp::servers_available();
    Json(json!({
        "servers": servers,
        "status": if servers.is_empty() { "unavailable" } else { "available" },
    }))
}

async fn formatter_status() -> Json<Value> {
    Json(json!({"status": "none"}))
}

const PROVIDER_IDS: [&str; 7] = [
    "anthropic",
    "openai",
    "google",
    "openrouter",
    "opencode-go",
    "opencode-zen",
    "fake",
];

async fn list_providers(State(s): State<AppState>) -> Json<Value> {
    Json(json!(
        PROVIDER_IDS
            .iter()
            .map(|id| json!({
                "id": id,
                "connected": freedas_provider::credentials::api_key_for(&s.paths.data_dir, id).is_some(),
            }))
            .collect::<Vec<_>>()
    ))
}

async fn provider_auth() -> Json<Value> {
    let mut out = serde_json::Map::new();
    for id in PROVIDER_IDS {
        out.insert(id.to_string(), json!({"api_key": ["api_key"], "oauth": []}));
    }
    Json(Value::Object(out))
}

#[derive(Deserialize)]
struct AuthBody {
    #[serde(default)]
    api_key: Option<String>,
}

async fn set_auth(
    State(s): State<AppState>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<AuthBody>,
) -> ApiResult {
    let Some(key) = body.api_key.filter(|k| !k.is_empty()) else {
        return Err(bad_request("api_key required"));
    };
    freedas_provider::credentials::store(&s.paths.data_dir, &id, &key).map_err(internal)?;
    Ok(Json(json!({"ok": true, "id": id})))
}

#[derive(Deserialize)]
struct AddMcp {
    name: String,
    #[serde(default)]
    config: Value,
}

/// Merge one server into the project config's `mcp` map. JSONC is parsed with
/// comments intact and rewritten as plain JSON (same tradeoff as permissions).
async fn add_mcp(State(s): State<AppState>, Json(body): Json<AddMcp>) -> ApiResult {
    if body.name.trim().is_empty() {
        return Err(bad_request("name required"));
    }
    let _guard = s.config_lock.lock().await;
    let root = &s.paths.project_root;
    let candidates = [
        root.join(".freedas").join("freedas.jsonc"),
        root.join(".freedas").join("freedas.json"),
        root.join("freedas.jsonc"),
        root.join("freedas.json"),
    ];
    let path = candidates
        .iter()
        .find(|p| p.exists())
        .cloned()
        .unwrap_or_else(|| root.join(".freedas").join("freedas.jsonc"));
    let mut config: Value = match std::fs::read_to_string(&path) {
        Ok(text) => {
            jsonc_parser::parse_to_serde_value(&text, &jsonc_parser::ParseOptions::default())
                .ok()
                .flatten()
                .filter(Value::is_object)
                .ok_or_else(|| bad_request("existing config file is not a JSON object"))?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => json!({}),
        Err(error) => return Err(internal(error)),
    };
    let Some(root) = config.as_object_mut() else {
        return Err(bad_request("existing config file is not a JSON object"));
    };
    let mcp = root.entry("mcp").or_insert_with(|| json!({}));
    let Some(mcp) = mcp.as_object_mut() else {
        return Err(bad_request("`mcp` is not an object"));
    };
    mcp.insert(
        body.name.clone(),
        if body.config.is_null() {
            json!({})
        } else {
            body.config
        },
    );
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(internal)?;
    }
    let tmp = path.with_extension("jsonc.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&config).map_err(internal)?)
        .map_err(internal)?;
    std::fs::rename(&tmp, &path).map_err(internal)?;
    Ok(Json(json!({"ok": true, "path": path})))
}

/// Static AGENTS.md block for `/session/{id}/init`.
fn agents_md_section(root: &std::path::Path) -> String {
    let has = |f: &str| root.join(f).exists();
    let mut commands = Vec::new();
    if has("Cargo.toml") {
        commands.extend([
            "cargo build",
            "cargo test",
            "cargo fmt --all --check",
            "cargo clippy --workspace --all-targets -- -D warnings",
        ]);
    }
    if has("package.json") {
        commands.extend(["npm install", "npm test"]);
    }
    if has("pyproject.toml") || has("setup.py") {
        commands.push("pytest");
    }
    if has("go.mod") {
        commands.extend(["go build ./...", "go test ./..."]);
    }
    if has("Makefile") {
        commands.push("make");
    }
    let mut layout = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }
            let suffix = if entry.path().is_dir() { "/" } else { "" };
            layout.push(format!("{name}{suffix}"));
        }
    }
    layout.sort();
    let mut out = String::from("<!-- freedas:init:begin -->\n");
    out.push_str("## Project\n\n");
    out.push_str(&format!("Root: {}\n\n", root.display()));
    if !layout.is_empty() {
        out.push_str("Layout: ");
        out.push_str(&layout.join(", "));
        out.push_str("\n\n");
    }
    if !commands.is_empty() {
        out.push_str("Commands:\n");
        for command in commands {
            out.push_str(&format!("- `{command}`\n"));
        }
        out.push('\n');
    }
    out.push_str("Run the narrowest check that covers a change, and do not claim a result you did not observe.\n");
    out.push_str("<!-- freedas:init:end -->\n");
    out
}

fn merge_init_section(existing: &str, section: &str) -> Result<String, String> {
    const BEGIN: &str = "<!-- freedas:init:begin -->";
    const END: &str = "<!-- freedas:init:end -->";
    let begins = existing.matches(BEGIN).count();
    let ends = existing.matches(END).count();
    match (begins, ends) {
        (0, 0) if existing.is_empty() => Ok(section.to_string()),
        (0, 0) => Ok(format!("{existing}\n\n{section}")),
        (1, 1) => {
            let start = existing.find(BEGIN).expect("counted above");
            let end = existing.find(END).expect("counted above");
            if start > end {
                return Err("AGENTS.md has freedas:init markers in the wrong order".into());
            }
            let end = end + END.len();
            Ok(format!(
                "{}{}{}",
                &existing[..start],
                section,
                &existing[end..]
            ))
        }
        _ => Err(
            "AGENTS.md has unbalanced freedas:init markers; refusing to overwrite user prose"
                .into(),
        ),
    }
}
