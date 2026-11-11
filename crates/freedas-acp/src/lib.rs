//! Agent Client Protocol server over stdio.

/// `FREEDAS_DISABLE_PROJECT_CONFIG` skips project-layer config for server/ACP
/// just as the CLI does.
fn project_config_disabled() -> bool {
    std::env::var("FREEDAS_DISABLE_PROJECT_CONFIG")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use freedas_core::config;
use freedas_core::config::PermissionRule;
use freedas_core::paths::Paths;
use freedas_db::Db;
use freedas_session::{RunOpts, Runner};
use freedas_tools::{PermissionApprover, PermissionReply, ToolContext};
use serde_json::{Value, json};

const OUTPUT_CAP: usize = 1024 * 1024;
/// How long a tool call waits for the ACP client to answer a permission prompt.
const PERMISSION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// Largest stdio frame accepted before the peer is cut off.
const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
/// Largest file read served to a client.
const MAX_READ_BYTES: u64 = 5 * 1024 * 1024;
/// Largest file write accepted from a client.
const MAX_WRITE_BYTES: usize = 5 * 1024 * 1024;
/// Open sessions, in-flight prompts, live terminals.
const MAX_SESSIONS: usize = 64;
const MAX_PROMPTS: usize = 8;
const MAX_TERMINALS: usize = 32;

#[derive(Clone)]
struct Session {
    cwd: PathBuf,
    agent: String,
    model: Option<String>,
    /// Rules granted with "allow always" for the rest of the session.
    rules: Arc<Mutex<Vec<PermissionRule>>>,
    /// Rules granted with "allow once": consumed by the next permission check.
    once: Arc<Mutex<Vec<PermissionRule>>>,
}

impl Session {
    fn fallback() -> Self {
        Self {
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            agent: "build".into(),
            model: None,
            rules: Arc::new(Mutex::new(Vec::new())),
            once: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[derive(Clone, Debug)]
struct PendingPermission {
    session_id: String,
    action: String,
    resource: String,
}

type ApprovalAnswers =
    Arc<Mutex<HashMap<String, (std::sync::mpsc::Sender<PermissionReply>, PendingPermission)>>>;

/// Blocks the runner thread while the ACP client answers `session/request_permission`.
#[derive(Debug)]
struct AcpApprover {
    session_id: String,
    next_perm: Arc<AtomicU64>,
    answers: ApprovalAnswers,
    pending: Arc<std::sync::Mutex<Vec<String>>>,
}

impl PermissionApprover for AcpApprover {
    fn ask(&self, action: &str, resource: &str) -> PermissionReply {
        let permission_id = format!(
            "perm_{}",
            self.next_perm.fetch_add(1, Ordering::Relaxed) + 1
        );
        let (tx, rx) = std::sync::mpsc::channel();
        self.answers.lock().expect("answers").insert(
            permission_id.clone(),
            (
                tx,
                PendingPermission {
                    session_id: self.session_id.clone(),
                    action: action.to_owned(),
                    resource: resource.to_owned(),
                },
            ),
        );
        self.pending
            .lock()
            .expect("pending")
            .push(permission_request(
                &permission_id,
                &self.session_id,
                action,
                resource,
            ));
        match rx.recv_timeout(PERMISSION_TIMEOUT) {
            Ok(reply) => reply,
            Err(_) => {
                self.answers.lock().expect("answers").remove(&permission_id);
                PermissionReply::Reject
            }
        }
    }
}

struct Terminal {
    session_id: String,
    child: Arc<Mutex<tokio::process::Child>>,
    output: Arc<Mutex<Vec<u8>>>,
    readers: Vec<tokio::task::JoinHandle<()>>,
    exit: Arc<Mutex<Option<i32>>>,
}

/// JSON-RPC 2.0 server that speaks newline-delimited JSON on stdio.
/// A permission request raised inside a spawned prompt task:
/// `(request id, session id, action, resource)`.
type RaisedRequest = (String, String, String, String);

/// Frees a prompt's cancels entry when its worker thread exits on any path;
/// without it finished prompts accumulate toward MAX_PROMPTS forever.
struct CancelSlot {
    cancels: Arc<Mutex<HashMap<String, tokio_util::sync::CancellationToken>>>,
    session_id: String,
}

impl Drop for CancelSlot {
    fn drop(&mut self) {
        if let Ok(mut cancels) = self.cancels.lock() {
            cancels.remove(&self.session_id);
        }
    }
}

pub struct AcpServer {
    db: Arc<Db>,
    sessions: HashMap<String, Session>,
    cancels: Arc<Mutex<HashMap<String, tokio_util::sync::CancellationToken>>>,
    pending: Arc<std::sync::Mutex<Vec<String>>>,
    /// Permission requests awaiting a client answer, keyed by request ID.
    permissions: HashMap<String, PendingPermission>,
    /// Requests raised inside a spawned prompt task, adopted on the next line.
    raised: Arc<Mutex<Vec<RaisedRequest>>>,
    /// Permission prompts raised by a running prompt, keyed by request id.
    answers: ApprovalAnswers,
    next_perm: Arc<AtomicU64>,
    terminals: HashMap<String, Terminal>,
    next_terminal: u64,
    /// Roots a `session/new` cwd may live under; the launch directory plus
    /// anything the host opts into.
    allowed_roots: Vec<PathBuf>,
}

impl AcpServer {
    pub fn new(db: Arc<Db>) -> Self {
        let launch = std::env::current_dir()
            .and_then(|d| d.canonicalize())
            .unwrap_or_else(|_| PathBuf::from("/"));
        Self {
            db,
            allowed_roots: vec![launch],
            sessions: HashMap::new(),
            cancels: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(std::sync::Mutex::new(Vec::new())),
            permissions: HashMap::new(),
            raised: Arc::new(Mutex::new(Vec::new())),
            answers: Arc::new(Mutex::new(HashMap::new())),
            next_perm: Arc::new(AtomicU64::new(0)),
            terminals: HashMap::new(),
            next_terminal: 0,
        }
    }

    /// Handle one JSON-RPC line, returning the lines to write back.
    ///
    /// Malformed input is logged to stderr and yields no output.
    pub async fn handle_line(&mut self, line: &str) -> Vec<String> {
        let line = line.trim();
        if line.is_empty() {
            return Vec::new();
        }
        let request: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("acp: malformed line: {error}");
                return vec![rpc_error(
                    Value::Null,
                    -32700,
                    format!("parse error: {error}"),
                )];
            }
        };
        self.adopt_raised_permissions();
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let Some(method) = request.get("method").and_then(Value::as_str) else {
            // A response to an agent-initiated request, e.g. a permission answer.
            return self.apply_client_response(&id, &request);
        };
        let params = request.get("params").cloned().unwrap_or(Value::Null);
        match method {
            "initialize" => vec![response(
                id,
                json!({
                    "protocolVersion": 1,
                    "agentInfo": { "name": "Freedas", "version": "0.1.0" },
                    "capabilities": {
                        "sessions": true,
                        "prompts": true,
                        "cancellation": true,
                        "modes": true,
                        "filesystem": { "readTextFile": true, "writeTextFile": true },
                        "terminal": true,
                    },
                }),
            )],
            "session/new" => self.new_session(id, &params),
            "session/load" => self.load_session(id, &params),
            "session/prompt" => self.prompt(id, &params).await,
            "session/set_mode" => self.set_mode(id, &params),
            "session/set_model" => self.set_model(id, &params),
            "session/cancel" => {
                let session_id = params
                    .get("sessionId")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if let Some(token) = self.cancels.lock().expect("cancels").remove(session_id) {
                    token.cancel();
                }
                vec![response(id, json!({ "ok": true }))]
            }
            "fs/read_text_file" => self.read_text_file(id, &params),
            "fs/write_text_file" => self.write_text_file(id, &params),
            "terminal/create" => self.terminal_create(id, &params),
            "terminal/output" => self.terminal_output(id, &params),
            "terminal/wait_for_exit" => self.terminal_wait(id, &params).await,
            "terminal/kill" => self.terminal_kill(id, &params).await,
            "terminal/release" => self.terminal_release(id, &params),
            _ => vec![rpc_error(id, -32601, format!("method not found: {method}"))],
        }
    }

    fn session(&self, params: &Value) -> Option<(String, Session)> {
        let session_id = params.get("sessionId").and_then(Value::as_str)?;
        let session = self.sessions.get(session_id)?.clone();
        Some((session_id.to_owned(), session))
    }

    fn new_session(&mut self, id: Value, params: &Value) -> Vec<String> {
        if self.sessions.len() >= MAX_SESSIONS {
            return vec![rpc_error(id, -32000, "too many sessions".into())];
        }
        let cwd = params
            .get("cwd")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .unwrap_or_else(|| Session::fallback().cwd);
        // The client must not pivot the agent into a tree the launcher did
        // not grant: the session root stays inside an allowed root.
        let cwd = match cwd.canonicalize() {
            Ok(abs) => abs,
            Err(error) => return vec![rpc_error(id, -32602, format!("cwd: {error}"))],
        };
        let any_cwd = std::env::var("FREEDAS_ACP_ALLOW_ANY_CWD").is_ok_and(|v| v == "1");
        if !any_cwd && !self.allowed_roots.iter().any(|r| cwd.starts_with(r)) {
            return vec![rpc_error(
                id,
                -32602,
                "cwd is outside the allowed workspace roots".to_string(),
            )];
        }
        let agent = params
            .get("agent")
            .and_then(Value::as_str)
            .unwrap_or("build")
            .to_string();
        // Same check session/set_mode performs: an arbitrary agent string
        // silently falls back to the default agent and widens tool access.
        let trust =
            freedas_core::config::load(&freedas_core::paths::Paths::resolve(cwd.clone()), false)
                .map(|c| c.trust_project_code)
                .unwrap_or(false);
        if !freedas_agent::merged_agents(&cwd, trust)
            .iter()
            .any(|a| a.id == agent)
        {
            return vec![rpc_error(id, -32602, format!("unknown agent: {agent}"))];
        }
        let model = params
            .get("model")
            .and_then(Value::as_str)
            .map(str::to_string);
        let project_id = match self.db.ensure_project(&cwd) {
            Ok(project_id) => project_id,
            Err(error) => return vec![rpc_error(id, -32603, error.to_string())],
        };
        let session_id = match self
            .db
            .create_session(&project_id, &agent, "ACP session", None)
        {
            Ok(session_id) => session_id,
            Err(error) => return vec![rpc_error(id, -32603, error.to_string())],
        };
        self.sessions.insert(
            session_id.clone(),
            Session {
                cwd,
                agent,
                model,
                ..Session::fallback()
            },
        );
        vec![response(id, json!({ "sessionId": session_id }))]
    }

    fn load_session(&mut self, id: Value, params: &Value) -> Vec<String> {
        let Some(session_id) = params.get("sessionId").and_then(Value::as_str) else {
            return vec![rpc_error(id, -32602, "missing sessionId".into())];
        };
        if !self.sessions.contains_key(session_id) {
            match self.db.session_context(session_id) {
                Ok(Some((root, agent))) => {
                    // The stored root came from a previous session/new check,
                    // but sessions also exist from the local CLI in other
                    // projects - re-validate so load cannot escape the
                    // workspace roots session/new enforces.
                    let cwd = match PathBuf::from(root).canonicalize() {
                        Ok(cwd) => cwd,
                        Err(error) => {
                            return vec![rpc_error(id, -32602, format!("session cwd: {error}"))];
                        }
                    };
                    let any_cwd =
                        std::env::var("FREEDAS_ACP_ALLOW_ANY_CWD").is_ok_and(|v| v == "1");
                    if !any_cwd && !self.allowed_roots.iter().any(|r| cwd.starts_with(r)) {
                        return vec![rpc_error(
                            id,
                            -32602,
                            "session cwd is outside the allowed workspace roots".to_string(),
                        )];
                    }
                    // The stored agent may predate this process's trust state
                    // or a custom-agent removal; re-check like session/new.
                    let trust = freedas_core::config::load(
                        &freedas_core::paths::Paths::resolve(cwd.clone()),
                        false,
                    )
                    .map(|c| c.trust_project_code)
                    .unwrap_or(false);
                    if !freedas_agent::merged_agents(&cwd, trust)
                        .iter()
                        .any(|a| a.id == agent)
                    {
                        return vec![rpc_error(id, -32602, format!("unknown agent: {agent}"))];
                    }
                    self.sessions.insert(
                        session_id.to_string(),
                        Session {
                            cwd,
                            agent,
                            ..Session::fallback()
                        },
                    );
                }
                Ok(None) => return vec![rpc_error(id, -32602, "unknown session".into())],
                Err(error) => return vec![rpc_error(id, -32603, error.to_string())],
            }
        }
        vec![response(id, json!({ "sessionId": session_id }))]
    }

    /// `session/set_mode`: switch the agent a session runs with.
    fn set_mode(&mut self, id: Value, params: &Value) -> Vec<String> {
        let Some(session_id) = params.get("sessionId").and_then(Value::as_str) else {
            return vec![rpc_error(id, -32602, "missing sessionId".into())];
        };
        let agent = ["modeId", "agent", "mode"]
            .iter()
            .find_map(|key| params.get(*key).and_then(Value::as_str));
        let Some(agent) = agent else {
            return vec![rpc_error(id, -32602, "missing modeId".into())];
        };
        let Some(cwd) = self.sessions.get(session_id).map(|s| s.cwd.clone()) else {
            return vec![rpc_error(id, -32602, "unknown session".into())];
        };
        // Only advertised agents may be selected; an arbitrary string here
        // would widen tool access for later prompts.
        let trust =
            freedas_core::config::load(&freedas_core::paths::Paths::resolve(cwd.clone()), false)
                .map(|c| c.trust_project_code)
                .unwrap_or(false);
        let known = freedas_agent::merged_agents(&cwd, trust)
            .iter()
            .any(|a| a.id == agent);
        if !known {
            return vec![rpc_error(id, -32602, format!("unknown mode: {agent}"))];
        }
        match self.sessions.get_mut(session_id) {
            Some(session) => {
                session.agent = agent.to_owned();
                vec![response(id, json!({ "modeId": agent }))]
            }
            None => vec![rpc_error(id, -32602, "unknown session".into())],
        }
    }

    /// `session/set_model`: pin a model, or `auto` for router selection.
    fn set_model(&mut self, id: Value, params: &Value) -> Vec<String> {
        let Some(session_id) = params.get("sessionId").and_then(Value::as_str) else {
            return vec![rpc_error(id, -32602, "missing sessionId".into())];
        };
        let Some(model_id) = params.get("modelId").and_then(Value::as_str) else {
            return vec![rpc_error(id, -32602, "missing modelId".into())];
        };
        let model = (!model_id.is_empty() && model_id != "auto").then(|| model_id.to_owned());
        match self.sessions.get_mut(session_id) {
            Some(session) => {
                session.model = model;
                vec![response(id, json!({ "modelId": model_id }))]
            }
            None => vec![rpc_error(id, -32602, "unknown session".into())],
        }
    }

    async fn prompt(&mut self, id: Value, params: &Value) -> Vec<String> {
        let Some(session_id) = params.get("sessionId").and_then(Value::as_str) else {
            return vec![rpc_error(id, -32602, "missing sessionId".into())];
        };
        // ACP sends content blocks (`[{type:"text",text}]`); a bare string is
        // accepted too so scripts and older clients keep working.
        let prompt = match params.get("prompt") {
            Some(Value::String(text)) => text.clone(),
            Some(Value::Array(blocks)) => blocks
                .iter()
                .filter_map(|block| block.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n"),
            _ => return vec![rpc_error(id, -32602, "missing prompt".into())],
        };
        let Some(session) = self.sessions.get(session_id).cloned() else {
            return vec![rpc_error(id, -32602, "unknown session".into())];
        };
        let response_id = id.clone();
        // Two prompts on one session would interleave in one transcript, and
        // the first run's cancel token would be overwritten.
        let token = {
            let mut cancels = self.cancels.lock().expect("cancels");
            if cancels.contains_key(session_id) {
                return vec![rpc_error(
                    id,
                    -32000,
                    "session has a prompt in flight".into(),
                )];
            }
            if cancels.len() >= MAX_PROMPTS {
                return vec![rpc_error(id, -32000, "too many prompts in flight".into())];
            }
            let token = tokio_util::sync::CancellationToken::new();
            cancels.insert(session_id.to_string(), token.clone());
            token
        };
        let cancels = self.cancels.clone();
        let db = self.db.clone();
        let pending = self.pending.clone();
        let raised = self.raised.clone();
        let answers = self.answers.clone();
        let rules = session.rules.clone();
        let next_perm = self.next_perm.clone();
        let session_id = session_id.to_string();
        let prompt = prompt.to_string();
        // Keep the runner off the stdio runtime: a permission prompt blocks the
        // runner thread until this loop forwards the client's answer.
        std::thread::spawn(move || {
            // Frees the cancels entry on every exit - result, bail, or panic.
            let _slot = CancelSlot {
                cancels,
                session_id: session_id.clone(),
            };
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    pending.lock().expect("pending").push(rpc_error(
                        response_id,
                        -32603,
                        error.to_string(),
                    ));
                    return;
                }
            };
            let paths = Paths::resolve(session.cwd.clone());
            let config = config::load(&paths, project_config_disabled()).unwrap_or_else(|e| {
                eprintln!("config: {e}");
                Default::default()
            });
            let runner = Runner::new(db, paths, config, freedas_catalog::builtin_catalog());
            let approver: Arc<dyn PermissionApprover> = Arc::new(AcpApprover {
                session_id: session_id.clone(),
                next_perm: next_perm.clone(),
                answers,
                pending: pending.clone(),
            });
            let opts = RunOpts {
                project_root: session.cwd.clone(),
                agent: session.agent.clone(),
                model: session.model.clone(),
                prompt,
                auto: false,
                manual: false,
                workspace: None,
                session_id: Some(session_id.clone()),
                title: None,
                variant: None,
                depth: 0,
                parent_id: None,
                review_mode: false,
                progress: None,
                headless: false,
                mcp_disabled: Vec::new(),
                approver: Some(approver),
                session_rules: rules,
            };
            let result = runtime.block_on(runner.run_task_opts(opts, token));
            let lines = match result {
                Ok(result) => {
                    let mut out = Vec::new();
                    for blocked in &result.blocked {
                        out.push(update(&session_id, "tool", blocked));
                    }
                    out.push(update(&session_id, "message", &result.text));
                    out.push(response(
                        response_id.clone(),
                        json!({ "finishReason": "complete" }),
                    ));
                    out
                }
                Err(freedas_core::FreedasError::PermissionAsked { action, resource }) => {
                    let perm_id = format!("perm_{}", next_perm.fetch_add(1, Ordering::Relaxed) + 1);
                    raised.lock().expect("raised").push((
                        perm_id.clone(),
                        session_id.clone(),
                        action.clone(),
                        resource.clone(),
                    ));
                    vec![
                        permission_request(&perm_id, &session_id, &action, &resource),
                        response(response_id.clone(), json!({ "finishReason": "permission" })),
                    ]
                }
                // Cancel is a normal outcome, not a fault: answer the prompt
                // with a finishReason so the client does not report failure.
                Err(freedas_core::FreedasError::Cancelled) => {
                    vec![response(
                        response_id.clone(),
                        json!({ "finishReason": "cancelled" }),
                    )]
                }
                Err(error) => {
                    vec![rpc_error(response_id.clone(), -32000, error.to_string())]
                }
            };
            pending.lock().expect("pending").extend(lines);
        });
        Vec::new()
    }

    /// Move permission requests raised by a prompt task into the answer map.
    fn adopt_raised_permissions(&mut self) {
        let raised = std::mem::take(&mut *self.raised.lock().expect("raised"));
        for (perm_id, session_id, action, resource) in raised {
            self.permissions.insert(
                perm_id,
                PendingPermission {
                    session_id,
                    action,
                    resource,
                },
            );
        }
    }

    /// Apply a client's answer to a `session/request_permission` request.
    fn apply_client_response(&mut self, id: &Value, request: &Value) -> Vec<String> {
        let Some(perm_id) = id.as_str() else {
            return Vec::new();
        };
        let option = request
            .get("result")
            .and_then(|result| result.get("optionId"))
            .and_then(Value::as_str)
            .unwrap_or("reject");
        let reply = match option {
            "allow_once" => PermissionReply::Once,
            "allow_always" => PermissionReply::Always,
            _ => PermissionReply::Reject,
        };
        if let Some((answer, meta)) = self.answers.lock().expect("answers").remove(perm_id) {
            // A prompt-task `allow_always` must persist like the fs/terminal path;
            // otherwise the grant is one-shot and the next check re-prompts.
            if option == "allow_always"
                && let Some(session) = self.sessions.get(&meta.session_id)
            {
                session
                    .rules
                    .lock()
                    .expect("rules")
                    .push(PermissionRule::new(&meta.action, &meta.resource, "allow"));
            }
            let _ = answer.send(reply);
            return Vec::new();
        }
        let Some(pending) = self.permissions.remove(perm_id) else {
            return Vec::new();
        };
        let rule = PermissionRule::new(&pending.action, &pending.resource, "allow");
        match (option, self.sessions.get(&pending.session_id)) {
            ("allow_always", Some(session)) => {
                session.rules.lock().expect("rules").push(rule);
            }
            ("allow_once", Some(session)) => {
                session.once.lock().expect("rules").push(rule);
            }
            _ => {}
        }
        Vec::new()
    }

    /// Permission context for a session. A one-shot grant is used only by the
    /// check that matches its action and resource, then removed.
    fn permission_ctx(
        &self,
        session_id: &str,
        session: &Session,
        action: &str,
        resource: &str,
    ) -> ToolContext {
        let paths = Paths::resolve(session.cwd.clone());
        let config = config::load(&paths, project_config_disabled()).unwrap_or_else(|e| {
            eprintln!("config: {e}");
            Default::default()
        });
        let mut rules = session.rules.lock().expect("rules").clone();
        let mut once = session.once.lock().expect("rules");
        if let Some(index) = once
            .iter()
            .position(|rule| rule.action == action && rule.resource == resource)
        {
            rules.push(once.remove(index));
        }
        drop(once);
        ToolContext {
            session_id: session_id.to_owned(),
            project_root: session.cwd.clone(),
            cwd: session.cwd.clone(),
            config,
            agent_rules: Vec::new(),
            session_rules: Arc::new(Mutex::new(rules)),
            auto: false,
            manual: false,
            read_hashes: Default::default(),
            sandbox: false,
            bypass: false,
            plans_dir: None,
            approver: None,
            db: Some(self.db.clone()),
            project_id: self.db.ensure_project(&session.cwd).ok(),
            prefetch: None,
        }
    }

    /// Turn a blocked permission into `session/request_permission`, or report
    /// any other error as a JSON-RPC failure.
    fn perm_error(
        &mut self,
        id: Value,
        session_id: &str,
        error: freedas_core::FreedasError,
    ) -> Vec<String> {
        match error {
            freedas_core::FreedasError::PermissionAsked { action, resource } => {
                let perm_id = format!(
                    "perm_{}",
                    self.next_perm.fetch_add(1, Ordering::Relaxed) + 1
                );
                self.permissions.insert(
                    perm_id.clone(),
                    PendingPermission {
                        session_id: session_id.to_owned(),
                        action: action.clone(),
                        resource: resource.clone(),
                    },
                );
                vec![
                    response(id, json!({ "status": "permission_requested" })),
                    permission_request(&perm_id, session_id, &action, &resource),
                ]
            }
            other => vec![rpc_error(id, -32000, other.to_string())],
        }
    }

    fn read_text_file(&mut self, id: Value, params: &Value) -> Vec<String> {
        let Some((session_id, session)) = self.session(params) else {
            return vec![rpc_error(id, -32602, "unknown session".into())];
        };
        let Some(path) = params.get("path").and_then(Value::as_str) else {
            return vec![rpc_error(id, -32602, "missing path".into())];
        };
        let ctx = self.permission_ctx(&session_id, &session, "read", path);
        if let Err(error) = freedas_tools::check_perm(&ctx, "read", Some(path)) {
            return self.perm_error(id, &session_id, error);
        }
        let file = match rooted(&session.cwd, path) {
            Ok(file) => file,
            Err(error) => return vec![rpc_error(id, -32602, error)],
        };
        let bytes = match std::fs::File::open(&file) {
            Ok(f) => {
                let mut buf = Vec::new();
                let mut take = std::io::Read::take(f, MAX_READ_BYTES + 1);
                match std::io::Read::read_to_end(&mut take, &mut buf) {
                    Ok(_) => buf,
                    Err(error) => return vec![rpc_error(id, -32000, error.to_string())],
                }
            }
            Err(error) => return vec![rpc_error(id, -32000, error.to_string())],
        };
        if bytes.len() as u64 > MAX_READ_BYTES {
            return vec![rpc_error(id, -32000, "file too large (>5 MiB)".into())];
        }
        vec![response(
            id,
            json!({ "content": String::from_utf8_lossy(&bytes) }),
        )]
    }

    fn write_text_file(&mut self, id: Value, params: &Value) -> Vec<String> {
        let Some((session_id, session)) = self.session(params) else {
            return vec![rpc_error(id, -32602, "unknown session".into())];
        };
        let Some(path) = params.get("path").and_then(Value::as_str) else {
            return vec![rpc_error(id, -32602, "missing path".into())];
        };
        let Some(content) = params.get("content").and_then(Value::as_str) else {
            return vec![rpc_error(id, -32602, "missing content".into())];
        };
        if content.len() > MAX_WRITE_BYTES {
            return vec![rpc_error(id, -32000, "content too large (>5 MiB)".into())];
        }
        let ctx = self.permission_ctx(&session_id, &session, "edit", path);
        if let Err(error) = freedas_tools::check_perm(&ctx, "edit", Some(path)) {
            return self.perm_error(id, &session_id, error);
        }
        let file = match rooted(&session.cwd, path) {
            Ok(file) => file,
            Err(error) => return vec![rpc_error(id, -32602, error)],
        };
        if let Some(parent) = file.parent()
            && let Err(error) = std::fs::create_dir_all(parent)
        {
            return vec![rpc_error(id, -32000, error.to_string())];
        }
        match std::fs::write(&file, content) {
            Ok(()) => vec![response(id, json!({}))],
            Err(error) => vec![rpc_error(id, -32000, error.to_string())],
        }
    }

    fn terminal_create(&mut self, id: Value, params: &Value) -> Vec<String> {
        if self.terminals.len() >= MAX_TERMINALS {
            return vec![rpc_error(id, -32000, "too many terminals".into())];
        }
        let Some((session_id, session)) = self.session(params) else {
            return vec![rpc_error(id, -32602, "unknown session".into())];
        };
        let (command, direct) = match params.get("command") {
            Some(Value::String(command)) => (command.clone(), None),
            Some(Value::Array(parts)) => {
                let parts: Vec<String> = parts
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect();
                if parts.is_empty() {
                    return vec![rpc_error(id, -32602, "missing command".into())];
                }
                (parts.join(" "), Some(parts))
            }
            _ => return vec![rpc_error(id, -32602, "missing command".into())],
        };
        let mut ctx = self.permission_ctx(&session_id, &session, "bash", &command);
        // Mirror the Bash tool gates (tools/lib.rs:916,993): catastrophic deny,
        // shell-scan write/read expansion, sandboxed containment. Only the
        // spawn stays argv-direct for the array form below.
        ctx.sandbox = true;
        if let Some(hit) = acp_catastrophic_hit(&command)
            && !acp_explicit_bash_allow(&ctx, &command)
        {
            return self.perm_error(
                id,
                &session_id,
                freedas_core::FreedasError::PermissionDenied {
                    action: "bash".into(),
                    resource: hit,
                },
            );
        }
        let scan = acp_scan_shell(&command);
        // Dynamic constructs cannot be resolved statically; the sandbox cannot
        // vouch for them, so keep the prompt instead of absorbing the ask.
        if scan.needs_ask {
            ctx.sandbox = false;
        }
        if scan.commands.is_empty()
            && let Err(error) = freedas_tools::check_perm(&ctx, "bash", Some(&command))
        {
            return self.perm_error(id, &session_id, error);
        }
        for sub in &scan.commands {
            if let Err(error) = freedas_tools::check_perm(&ctx, "bash", Some(sub)) {
                return self.perm_error(id, &session_id, error);
            }
        }
        for target in &scan.writes {
            let (action, resource) = if rooted(&session.cwd, target).is_ok() {
                ("edit", target.as_str())
            } else {
                ("external_directory", target.as_str())
            };
            if let Err(error) = freedas_tools::check_perm(&ctx, action, Some(resource)) {
                return self.perm_error(id, &session_id, error);
            }
        }
        for target in &scan.reads {
            let (action, resource) = if rooted(&session.cwd, target).is_ok() {
                ("read", target.as_str())
            } else {
                ("external_directory", target.as_str())
            };
            if let Err(error) = freedas_tools::check_perm(&ctx, action, Some(resource)) {
                return self.perm_error(id, &session_id, error);
            }
        }
        // An array command is argv: spawn it directly so shell metachars in an
        // argument cannot execute. Only the string form runs via `bash -c`.
        let mut spawn_cmd = match direct {
            Some(parts) => {
                let mut cmd = tokio::process::Command::new(&parts[0]);
                cmd.args(&parts[1..]);
                cmd
            }
            None => {
                let mut cmd = tokio::process::Command::new("/bin/bash");
                cmd.arg("-c").arg(&command);
                cmd
            }
        };
        let mut child = match spawn_cmd
            .current_dir(&session.cwd)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(error) => return vec![rpc_error(id, -32000, error.to_string())],
        };
        let output = Arc::new(Mutex::new(Vec::new()));
        let mut readers = Vec::new();
        if let Some(stdout) = child.stdout.take() {
            readers.push(pump(stdout, output.clone()));
        }
        if let Some(stderr) = child.stderr.take() {
            readers.push(pump(stderr, output.clone()));
        }
        self.next_terminal += 1;
        let terminal_id = format!("term_{}", self.next_terminal);
        self.terminals.insert(
            terminal_id.clone(),
            Terminal {
                session_id: session_id.clone(),
                child: Arc::new(Mutex::new(child)),
                output,
                readers,
                exit: Arc::new(Mutex::new(None)),
            },
        );
        vec![response(id, json!({ "terminalId": terminal_id }))]
    }

    fn terminal_output(&mut self, id: Value, params: &Value) -> Vec<String> {
        let Some(terminal_id) = params.get("terminalId").and_then(Value::as_str) else {
            return vec![rpc_error(id, -32602, "missing terminalId".into())];
        };
        let Some(session_id) = params.get("sessionId").and_then(Value::as_str) else {
            return vec![rpc_error(id, -32602, "missing sessionId".into())];
        };
        let Some(terminal) = self.terminals.get(terminal_id) else {
            return vec![rpc_error(id, -32602, "unknown terminal".into())];
        };
        if terminal.session_id != session_id {
            return vec![rpc_error(id, -32602, "unknown terminal".into())];
        };
        let bytes = terminal.output.lock().expect("output").clone();
        vec![response(
            id,
            json!({
                "output": String::from_utf8_lossy(&bytes),
                "truncated": bytes.len() >= OUTPUT_CAP,
                "exitStatus": terminal.exit.lock().expect("exit").map(|code| json!({ "exitCode": code })),
            }),
        )]
    }

    async fn terminal_wait(&mut self, id: Value, params: &Value) -> Vec<String> {
        let Some(terminal_id) = params.get("terminalId").and_then(Value::as_str) else {
            return vec![rpc_error(id, -32602, "missing terminalId".into())];
        };
        let Some(session_id) = params.get("sessionId").and_then(Value::as_str) else {
            return vec![rpc_error(id, -32602, "missing sessionId".into())];
        };
        let Some(terminal) = self.terminals.get_mut(terminal_id) else {
            return vec![rpc_error(id, -32602, "unknown terminal".into())];
        };
        if terminal.session_id != session_id {
            return vec![rpc_error(id, -32602, "unknown terminal".into())];
        };
        if let Some(code) = *terminal.exit.lock().expect("exit") {
            return vec![response(
                id,
                json!({ "exitCode": code, "signal": Value::Null }),
            )];
        }
        // Poll off the stdio loop so other requests stay responsive.
        let child = terminal.child.clone();
        let exit = terminal.exit.clone();
        let readers = std::mem::take(&mut terminal.readers);
        let pending = self.pending.clone();
        let rid = id.clone();
        tokio::spawn(async move {
            let code = loop {
                let status = {
                    let mut child = child.lock().expect("child");
                    child.try_wait()
                };
                match status {
                    Ok(Some(status)) => break Ok(status.code()),
                    Ok(None) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
                    Err(error) => break Err(error),
                }
            };
            for reader in readers {
                let _ = reader.await;
            }
            let line = match code {
                Ok(code) => {
                    *exit.lock().expect("exit") = code;
                    response(rid, json!({ "exitCode": code, "signal": Value::Null }))
                }
                Err(error) => rpc_error(rid, -32000, error.to_string()),
            };
            pending.lock().expect("pending").push(line);
        });
        Vec::new()
    }

    async fn terminal_kill(&mut self, id: Value, params: &Value) -> Vec<String> {
        let Some(terminal_id) = params.get("terminalId").and_then(Value::as_str) else {
            return vec![rpc_error(id, -32602, "missing terminalId".into())];
        };
        let Some(session_id) = params.get("sessionId").and_then(Value::as_str) else {
            return vec![rpc_error(id, -32602, "missing sessionId".into())];
        };
        let Some(terminal) = self.terminals.get_mut(terminal_id) else {
            return vec![rpc_error(id, -32602, "unknown terminal".into())];
        };
        if terminal.session_id != session_id {
            return vec![rpc_error(id, -32602, "unknown terminal".into())];
        };
        let running = terminal.exit.lock().expect("exit").is_none();
        if running && let Ok(mut child) = terminal.child.lock() {
            let _ = child.start_kill();
        }
        vec![response(id, json!({}))]
    }

    fn terminal_release(&mut self, id: Value, params: &Value) -> Vec<String> {
        let Some(terminal_id) = params.get("terminalId").and_then(Value::as_str) else {
            return vec![rpc_error(id, -32602, "missing terminalId".into())];
        };
        let Some(session_id) = params.get("sessionId").and_then(Value::as_str) else {
            return vec![rpc_error(id, -32602, "missing sessionId".into())];
        };
        let owned = self
            .terminals
            .get(terminal_id)
            .is_some_and(|terminal| terminal.session_id == session_id);
        if !owned {
            return vec![rpc_error(id, -32602, "unknown terminal".into())];
        }
        self.terminals.remove(terminal_id);
        vec![response(id, json!({}))]
    }
}

/// Drain a child pipe into the shared buffer, capped at [`OUTPUT_CAP`].
fn pump(
    mut pipe: impl tokio::io::AsyncRead + Unpin + Send + 'static,
    output: Arc<Mutex<Vec<u8>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut chunk = [0u8; 8192];
        loop {
            match pipe.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    let mut buffer = output.lock().expect("output");
                    let room = OUTPUT_CAP.saturating_sub(buffer.len());
                    buffer.extend_from_slice(&chunk[..read.min(room)]);
                }
            }
        }
    })
}

/// Project-rooted path: relative paths resolve against the session root and
/// anything that escapes it is rejected.
fn rooted(root: &Path, path: &str) -> Result<PathBuf, String> {
    let candidate = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else {
        root.join(path)
    };
    let normalized = match candidate.canonicalize() {
        Ok(path) => path,
        Err(_) => match (candidate.parent(), candidate.file_name()) {
            (Some(parent), Some(name)) => parent
                .canonicalize()
                .map_err(|_| format!("invalid path: {path}"))?
                .join(name),
            _ => return Err(format!("invalid path: {path}")),
        },
    };
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    if !normalized.starts_with(&root) {
        return Err(format!("outside project: {path}"));
    }
    Ok(normalized)
}

/// Whole-string glob with `*` and `?`, mirroring the permission rule engine.
fn acp_glob_match(pattern: &str, value: &str) -> bool {
    fn inner(p: &[char], v: &[char]) -> bool {
        if p.is_empty() {
            return v.is_empty();
        }
        match p[0] {
            '*' => {
                for i in 0..=v.len() {
                    if inner(&p[1..], &v[i..]) {
                        return true;
                    }
                }
                false
            }
            '?' => !v.is_empty() && inner(&p[1..], &v[1..]),
            c => {
                if v.is_empty() {
                    return false;
                }
                c == v[0] && inner(&p[1..], &v[1..])
            }
        }
    }
    let p: Vec<char> = pattern.chars().collect();
    let v: Vec<char> = value.chars().collect();
    inner(&p, &v)
}

/// Catastrophic deny list mirror (tools `catastrophic_hit` plus the shared
/// parser list): `rm -rf /`, `mkfs*`, `dd of=/dev/*`, fork bombs, and the
/// `rm -rf ~` form the shared parser misses.
fn acp_catastrophic_hit(command: &str) -> Option<String> {
    let compact: String = command.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains(":(){:|:&};:") {
        return Some(":(){ :|:& };:".into());
    }
    for segment in command.split([';', '|', '&', '\n']) {
        let mut words: Vec<&str> = segment.split_whitespace().collect();
        loop {
            match words.first().copied() {
                Some("sudo" | "env" | "nice" | "nohup" | "command" | "time" | "exec") => {
                    words.remove(0);
                }
                Some(w) if w.contains('=') && !w.starts_with('/') => {
                    words.remove(0);
                }
                Some("bash" | "sh" | "zsh") if words.get(1) == Some(&"-c") => {
                    words.drain(..2);
                }
                _ => break,
            }
        }
        let Some(prog) = words
            .first()
            .copied()
            .map(|s| s.rsplit('/').next().unwrap_or(s))
        else {
            continue;
        };
        let args = &words[1..];
        let recursive = args.iter().any(|a| {
            *a == "--recursive"
                || (a.starts_with('-') && !a.starts_with("--") && a.contains(['r', 'R']))
        });
        let force = args
            .iter()
            .any(|a| *a == "--force" || (a.starts_with('-') && a.contains('f')));
        let target_root = args.iter().any(|a| *a == "/" || *a == "/*");
        let target_home = args.iter().any(|a| *a == "~" || *a == "~/");
        match prog {
            "rm" if recursive && force && (target_root || target_home) => {
                return Some(if target_home {
                    "rm -rf ~".into()
                } else {
                    "rm -rf /".into()
                });
            }
            p if p.starts_with("mkfs") => return Some("mkfs".into()),
            "dd" if args.iter().any(|a| a.starts_with("of=/dev/")) => {
                return Some("dd of=/dev/".into());
            }
            "chmod"
                if recursive
                    && target_root
                    && args
                        .iter()
                        .any(|a| !a.starts_with('-') && a.contains("777")) =>
            {
                return Some("chmod -R 777 /".into());
            }
            "shutdown" | "reboot" | "halt" | "poweroff" => return Some(prog.to_string()),
            _ => {}
        }
    }
    None
}

/// Only an explicit non-`*` `bash` allow rule overrides a catastrophic hit.
fn acp_explicit_bash_allow(ctx: &ToolContext, command: &str) -> bool {
    let session = ctx.session_rules.lock().expect("rules").clone();
    ctx.config
        .permission
        .rules
        .iter()
        .chain(session.iter())
        .any(|rule| {
            rule.action == "bash"
                && rule.resource != "*"
                && rule.effect == "allow"
                && acp_glob_match(&rule.resource, command)
        })
}

struct AcpShellScan {
    commands: Vec<String>,
    reads: Vec<String>,
    writes: Vec<String>,
    needs_ask: bool,
}

/// Lightweight `scan_shell` mirror: subcommands plus read/write targets.
/// Fails closed — dynamic constructs set `needs_ask`.
fn acp_scan_shell(command: &str) -> AcpShellScan {
    const DYNAMIC: &[&str] = &[
        "$(",
        "`",
        "$[",
        "<(",
        ">(",
        "<<<",
        "eval ",
        "sh -c",
        "bash -c",
        "env ",
        "xargs",
        "find -exec",
        "git -c",
        "rg --pre",
        "sed -e",
        "python -c",
        "node -e",
        "perl -e",
        "ruby -e",
    ];
    const WRITES: &[&str] = &[
        "tee", "cp", "mv", "rm", "mkdir", "touch", "chmod", "chown", "dd", "ln",
    ];
    const READS: &[&str] = &[
        "cat", "bat", "grep", "egrep", "fgrep", "rg", "head", "tail", "less", "more", "wc", "sort",
        "uniq", "cut", "strings", "file", "diff", "cmp",
    ];
    let mut scan = AcpShellScan {
        commands: Vec::new(),
        reads: Vec::new(),
        writes: Vec::new(),
        needs_ask: DYNAMIC.iter().any(|marker| command.contains(marker)),
    };
    for part in acp_split_commands(command) {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        scan.commands.push(trimmed.to_string());
        let tokens = acp_shell_tokens(trimmed);
        // `> file` / `>> file` write targets.
        let mut index = 0;
        while index < tokens.len() {
            let token = tokens[index].as_str();
            if token == ">" || token == ">>" {
                if let Some(target) = tokens.get(index + 1) {
                    if target.contains('$') {
                        scan.needs_ask = true;
                    } else {
                        scan.writes.push(target.clone());
                    }
                }
                index += 2;
                continue;
            }
            if (token.starts_with('>') && token.len() > 1)
                || (token.starts_with("2>") && token.len() > 2)
            {
                scan.needs_ask = true;
                index += 1;
                continue;
            }
            index += 1;
        }
        let Some(first) = tokens.first().map(String::as_str) else {
            continue;
        };
        let operands: Vec<&String> = tokens[1..].iter().filter(|w| !w.starts_with('-')).collect();
        if WRITES.contains(&first) {
            for target in operands {
                if target.contains('$') {
                    scan.needs_ask = true;
                } else {
                    scan.writes.push(target.clone());
                }
            }
        } else if READS.contains(&first) {
            let mut operands = operands.into_iter();
            if matches!(first, "grep" | "egrep" | "fgrep" | "rg") {
                operands.next();
            }
            for target in operands {
                if target.contains('$') {
                    scan.needs_ask = true;
                } else {
                    scan.reads.push(target.clone());
                }
            }
        }
    }
    scan
}

/// Split on top-level `;`, `&&`, `||`, `|`, `&`, and newlines, respecting quotes.
fn acp_split_commands(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut single = false;
    let mut double = false;
    for ch in command.chars() {
        match ch {
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            ';' | '\n' | '&' | '|' if !single && !double => {
                if !current.trim().is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        out.push(current);
    }
    out
}

/// Whitespace-split respecting single/double quotes; quotes are stripped.
fn acp_shell_tokens(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut single = false;
    let mut double = false;
    let mut chars = command.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '\\' if !single => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            c if c.is_whitespace() && !single && !double => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// `session/request_permission` for allow-once / allow-always / reject.
fn permission_request(perm_id: &str, session_id: &str, action: &str, resource: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": perm_id,
        "method": "session/request_permission",
        "params": {
            "sessionId": session_id,
            "toolCall": { "title": format!("{action}: {resource}") },
            "options": [
                { "optionId": "allow_once", "name": "Allow once", "kind": "allow_once" },
                { "optionId": "allow_always", "name": "Allow always", "kind": "allow_always" },
                { "optionId": "reject", "name": "Reject", "kind": "reject_once" },
            ],
        },
    })
    .to_string()
}

/// Serve ACP over stdin/stdout until stdin closes.
pub async fn run_stdio() -> io::Result<()> {
    let paths = Paths::resolve(std::env::current_dir()?);
    paths.ensure_dirs()?;
    let db = Arc::new(Db::open(&paths.db_path()).map_err(io::Error::other)?);
    let mut server = AcpServer::new(db);
    let mut stdout = io::stdout().lock();
    // Read stdin on a blocking thread so a prompt that is still running can
    // stream `session/update` notifications while the client waits.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(64);
    tokio::task::spawn_blocking(move || {
        use std::io::BufRead;
        let stdin = io::stdin();
        let mut lines = stdin.lock();
        // Byte-counted line read: a peer that never stops writing one "line"
        // is drained and dropped instead of OOMing the process.
        loop {
            let mut over = false;
            let mut bytes: Vec<u8> = Vec::new();
            loop {
                let buf = match lines.fill_buf() {
                    Ok(b) if !b.is_empty() => b,
                    _ => break, // EOF
                };
                let take = buf
                    .iter()
                    .position(|b| *b == b'\n')
                    .map(|p| p + 1)
                    .unwrap_or(buf.len());
                if bytes.len() + take > MAX_FRAME_BYTES {
                    over = true;
                } else if !over {
                    bytes.extend_from_slice(&buf[..take]);
                }
                let nl = buf[..take].contains(&b'\n');
                lines.consume(take);
                if nl {
                    break;
                }
            }
            if bytes.is_empty() && !over {
                break;
            }
            let line = if over {
                "{\"jsonrpc\":\"2.0\",\"method\":\"__oversize\"}\n".to_string()
            } else {
                String::from_utf8_lossy(&bytes).into_owned()
            };
            if tx.blocking_send(line).is_err() {
                break;
            }
        }
    });
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(25));
    loop {
        tokio::select! {
            incoming = rx.recv() => match incoming {
                Some(text) => {
                    for message in server.handle_line(&text).await {
                        writeln!(stdout, "{message}")?;
                        stdout.flush()?;
                    }
                }
                None => break,
            },
            _ = tick.tick() => {}
        }
        // Drain completed prompt output.
        let drained = std::mem::take(&mut *server.pending.lock().expect("pending"));
        for message in drained {
            writeln!(stdout, "{message}")?;
            stdout.flush()?;
        }
    }
    Ok(())
}

/// Blocking entry point kept for the CLI dispatcher.
pub fn run() -> io::Result<()> {
    std::thread::spawn(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(run_stdio())
    })
    .join()
    .unwrap_or_else(|_| Err(io::Error::other("acp thread panicked")))
}

fn response(id: Value, result: Value) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string()
}

fn rpc_error(id: Value, code: i64, message: String) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }).to_string()
}

fn update(session_id: &str, kind: &str, text: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": { "sessionId": session_id, "kind": kind, "text": text },
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> AcpServer {
        let mut s = AcpServer::new(Arc::new(Db::memory().unwrap()));
        if let Ok(t) = std::env::temp_dir().canonicalize() {
            s.allowed_roots.push(t);
        }
        s
    }

    async fn call(server: &mut AcpServer, method: &str, params: Value) -> Vec<Value> {
        let line = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        server
            .handle_line(&line.to_string())
            .await
            .iter()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn initialize_response_shape() {
        let mut server = server();
        let out = call(&mut server, "initialize", json!({})).await;
        assert_eq!(out.len(), 1);
        let result = &out[0]["result"];
        assert_eq!(result["protocolVersion"], 1);
        assert_eq!(result["agentInfo"]["name"], "Freedas");
        assert_eq!(result["agentInfo"]["version"], "0.1.0");
        assert_eq!(result["capabilities"]["sessions"], true);
        assert_eq!(result["capabilities"]["prompts"], true);
        assert_eq!(result["capabilities"]["cancellation"], true);
    }

    #[tokio::test]
    async fn unknown_method_returns_method_not_found() {
        let mut server = server();
        let line = json!({ "jsonrpc": "2.0", "id": "abc", "method": "nope/method" });
        let out = server.handle_line(&line.to_string()).await;
        assert_eq!(out.len(), 1);
        let response: Value = serde_json::from_str(&out[0]).unwrap();
        assert_eq!(response["id"], "abc");
        assert_eq!(response["error"]["code"], -32601);
    }

    #[tokio::test]
    async fn session_new_returns_session_id() {
        let mut server = server();
        let cwd = std::env::temp_dir();
        let out = call(
            &mut server,
            "session/new",
            json!({ "cwd": cwd, "agent": "build", "model": "fake/fake-1" }),
        )
        .await;
        let session_id = out[0]["result"]["sessionId"].as_str().unwrap();
        assert!(session_id.starts_with("ses_"), "{session_id}");
    }

    #[tokio::test]
    async fn malformed_line_returns_parse_error() {
        let mut server = server();
        let out = server.handle_line("{not json").await;
        assert_eq!(out.len(), 1);
        let response: Value = serde_json::from_str(&out[0]).unwrap();
        assert_eq!(response["error"]["code"], -32700);
        assert!(server.handle_line("   ").await.is_empty());
    }

    #[tokio::test]
    async fn prompt_streams_update_and_completes() {
        let dir = std::env::temp_dir().join(format!("freedas-acp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Keep snapshots and config out of the real home directory.
        unsafe {
            std::env::set_var("FREEDAS_DATA", dir.join("data"));
            std::env::set_var("FREEDAS_CONFIG", dir.join("config"));
        }
        let mut server = server();
        let out = call(
            &mut server,
            "session/new",
            json!({ "cwd": dir, "agent": "build", "model": "fake/fake-1" }),
        )
        .await;
        let session_id = out[0]["result"]["sessionId"].as_str().unwrap().to_string();

        let out = call(
            &mut server,
            "session/prompt",
            json!({ "sessionId": session_id, "prompt": "hello" }),
        )
        .await;
        // The prompt runs asynchronously and answers exactly once, at the end.
        assert!(out.is_empty());
        let pending = wait_for_response(&mut server, 1).await;
        let responses: Vec<&Value> = pending
            .iter()
            .filter(|v| v["id"] == 1 && v.get("result").is_some())
            .collect();
        assert_eq!(responses.len(), 1, "prompt answered twice: {pending:?}");
        assert_eq!(responses[0]["result"]["finishReason"], "complete");
        let updates: Vec<&Value> = pending
            .iter()
            .filter(|v| v["method"] == "session/update")
            .collect();
        assert!(!updates.is_empty());
        assert_eq!(updates[0]["params"]["sessionId"], session_id.as_str());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Poll the pending queue until a response with `id` shows up, then drain it.
    async fn wait_for_response(server: &mut AcpServer, id: i64) -> Vec<Value> {
        for _ in 0..200 {
            let pending: Vec<Value> = {
                let queued = server.pending.lock().expect("pending");
                queued
                    .iter()
                    .map(|line| serde_json::from_str::<Value>(line).unwrap_or_default())
                    .collect()
            };
            if pending.iter().any(|value| value["id"] == id) {
                let drained = std::mem::take(&mut *server.pending.lock().expect("pending"));
                return drained
                    .iter()
                    .map(|line| serde_json::from_str::<Value>(line).unwrap_or_default())
                    .collect();
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("no response with id {id}");
    }

    async fn session_in(server: &mut AcpServer, cwd: &std::path::Path) -> String {
        let out = call(
            server,
            "session/new",
            json!({ "cwd": cwd, "agent": "build" }),
        )
        .await;
        out[0]["result"]["sessionId"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn set_mode_and_model_update_the_session() {
        let mut server = server();
        let dir = std::env::temp_dir();
        let session_id = session_in(&mut server, &dir).await;

        let out = call(
            &mut server,
            "session/set_mode",
            json!({ "sessionId": session_id, "modeId": "plan" }),
        )
        .await;
        assert_eq!(out[0]["result"]["modeId"], "plan");
        assert_eq!(server.sessions[&session_id].agent, "plan");

        let out = call(
            &mut server,
            "session/set_model",
            json!({ "sessionId": session_id, "modelId": "openai/gpt-4o" }),
        )
        .await;
        assert_eq!(out[0]["result"]["modelId"], "openai/gpt-4o");
        assert_eq!(
            server.sessions[&session_id].model.as_deref(),
            Some("openai/gpt-4o")
        );

        call(
            &mut server,
            "session/set_model",
            json!({ "sessionId": session_id, "modelId": "auto" }),
        )
        .await;
        assert!(server.sessions[&session_id].model.is_none());
    }

    #[tokio::test]
    async fn filesystem_methods_are_project_rooted() {
        let dir = std::env::temp_dir().join(format!("freedas-acp-fs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut server = server();
        let session_id = session_in(&mut server, &dir).await;

        let out = call(
            &mut server,
            "fs/write_text_file",
            json!({ "sessionId": session_id, "path": "note.txt", "content": "hello acp" }),
        )
        .await;
        assert_eq!(out[0]["result"], json!({}));
        assert_eq!(
            std::fs::read_to_string(dir.join("note.txt")).unwrap(),
            "hello acp"
        );

        let out = call(
            &mut server,
            "fs/read_text_file",
            json!({ "sessionId": session_id, "path": "note.txt" }),
        )
        .await;
        assert_eq!(out[0]["result"]["content"], "hello acp");

        let out = call(
            &mut server,
            "fs/read_text_file",
            json!({ "sessionId": session_id, "path": "../escape.txt" }),
        )
        .await;
        let message = out[0]["error"]["message"].as_str().unwrap_or_default();
        assert!(message.contains("outside project"), "got {message}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn terminal_runs_bash_and_reports_output() {
        let dir = std::env::temp_dir().join(format!("freedas-acp-term-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut server = server();
        let session_id = session_in(&mut server, &dir).await;

        let out = call(
            &mut server,
            "terminal/create",
            json!({ "sessionId": session_id, "command": "echo hi && pwd" }),
        )
        .await;
        let terminal_id = out[0]["result"]["terminalId"].as_str().unwrap().to_string();

        let out = call(
            &mut server,
            "terminal/wait_for_exit",
            json!({ "sessionId": session_id, "terminalId": terminal_id }),
        )
        .await;
        assert!(out.is_empty(), "wait must not block the loop");
        let pending = wait_for_response(&mut server, 1).await;
        let exit = pending
            .iter()
            .find(|value| value["id"] == 1)
            .expect("exit response");
        assert_eq!(exit["result"]["exitCode"], 0);

        let out = call(
            &mut server,
            "terminal/output",
            json!({ "sessionId": session_id, "terminalId": terminal_id }),
        )
        .await;
        let output = out[0]["result"]["output"].as_str().unwrap();
        assert!(output.contains("hi"), "got {output}");
        assert!(
            output.contains(dir.file_name().unwrap().to_str().unwrap()),
            "command must run in the session cwd: {output}"
        );

        call(
            &mut server,
            "terminal/release",
            json!({ "sessionId": session_id, "terminalId": terminal_id }),
        )
        .await;
        assert!(!server.terminals.contains_key(&terminal_id));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn permission_requests_map_options_to_rules() {
        let mut server = server();
        let dir = std::env::temp_dir();
        let session_id = session_in(&mut server, &dir).await;
        server.permissions.insert(
            "perm_1".into(),
            PendingPermission {
                session_id: session_id.clone(),
                action: "bash".into(),
                resource: "git push".into(),
            },
        );
        let frame: Value = serde_json::from_str(&permission_request(
            "perm_1",
            &session_id,
            "bash",
            "git push",
        ))
        .unwrap();
        assert_eq!(frame["method"], "session/request_permission");
        assert_eq!(frame["params"]["options"][0]["optionId"], "allow_once");
        assert_eq!(frame["params"]["options"][2]["optionId"], "reject");

        let answer = json!({
            "jsonrpc": "2.0",
            "id": "perm_1",
            "result": { "optionId": "allow_always" },
        });
        assert!(server.handle_line(&answer.to_string()).await.is_empty());
        let rules = server.sessions[&session_id].rules.lock().unwrap().clone();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].action, "bash");
        assert_eq!(rules[0].resource, "git push");
        assert_eq!(rules[0].effect, "allow");
        assert!(server.permissions.is_empty());

        // A one-shot grant is consumed by the next permission context.
        server.permissions.insert(
            "perm_2".into(),
            PendingPermission {
                session_id: session_id.clone(),
                action: "edit".into(),
                resource: "src/lib.rs".into(),
            },
        );
        let answer = json!({
            "jsonrpc": "2.0",
            "id": "perm_2",
            "result": { "optionId": "allow_once" },
        });
        server.handle_line(&answer.to_string()).await;
        let session = server.sessions[&session_id].clone();
        // An unrelated check must not consume the one-shot grant.
        let ctx = server.permission_ctx(&session_id, &session, "read", "other.rs");
        assert_eq!(ctx.session_rules.lock().unwrap().len(), 1);
        assert_eq!(server.sessions[&session_id].once.lock().unwrap().len(), 1);
        // The matching check consumes it.
        let ctx = server.permission_ctx(&session_id, &session, "edit", "src/lib.rs");
        assert_eq!(ctx.session_rules.lock().unwrap().len(), 2);
        assert!(server.sessions[&session_id].once.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn load_session_uses_the_stored_project_root() {
        let dir = std::env::temp_dir().join(format!("freedas-acp-load-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = Arc::new(Db::memory().unwrap());
        let project_id = db.ensure_project(&dir).unwrap();
        let session_id = db
            .create_session(&project_id, "plan", "stored", None)
            .unwrap();
        let mut server = AcpServer::new(db);
        // session/load re-validates cwd against allowed_roots like session/new.
        server.allowed_roots.push(dir.canonicalize().unwrap());
        let out = call(
            &mut server,
            "session/load",
            json!({ "sessionId": session_id }),
        )
        .await;
        assert_eq!(out[0]["result"]["sessionId"], session_id.as_str());
        let loaded = &server.sessions[&session_id];
        assert_eq!(
            loaded.cwd.canonicalize().unwrap(),
            dir.canonicalize().unwrap()
        );
        assert_eq!(loaded.agent, "plan");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn approver_waits_for_the_client_answer() {
        let answers: ApprovalAnswers = Arc::new(Mutex::new(HashMap::new()));
        let pending = Arc::new(Mutex::new(Vec::new()));
        let approver = AcpApprover {
            session_id: "ses_1".into(),
            next_perm: Arc::new(AtomicU64::new(0)),
            answers: answers.clone(),
            pending: pending.clone(),
        };
        let handle = std::thread::spawn(move || approver.ask("bash", "git push"));
        let mut permission_id = None;
        for _ in 0..100 {
            if let Some(line) = pending.lock().unwrap().first() {
                let frame: Value = serde_json::from_str(line).unwrap();
                permission_id = frame["id"].as_str().map(str::to_owned);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let permission_id = permission_id.expect("permission request emitted");
        let (answer, _meta) = answers.lock().unwrap().remove(&permission_id).unwrap();
        answer.send(PermissionReply::Always).unwrap();
        assert_eq!(handle.join().unwrap(), PermissionReply::Always);
    }
}
