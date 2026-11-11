//! Self-hosted relay server.
//!
//! Machines connect outbound over `/ws`, authenticate with the first `hello`
//! frame, and exchange relay frames. Events are fanned out to every connected
//! machine through a broadcast channel; presence is tracked per machine.

use axum::{
    Json, Router,
    extract::{
        Path, Query, Request, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::StatusCode,
    middleware::{self, Next},
    response::{
        IntoResponse, Response,
        sse::{Event as SseEvent, KeepAlive, Sse},
    },
    routing::{get, post},
};
use freedas_relay::{MAX_FRAME, RelayFrame};
use futures::{SinkExt, Stream};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::convert::Infallible;
use std::io;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc};

/// A machine drops off the dashboard after this much silence.
const PRESENCE_TTL: Duration = Duration::from_secs(60);
/// First `hello` must arrive within this long or the socket is closed.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Bounded per-session replay so a reconnecting dashboard can resume.
const MAX_HISTORY_PER_SESSION: usize = 1000;
/// Bounds for client-supplied session ids; anything else is ignored.
const MAX_SESSIONS_PER_MACHINE: usize = 512;
const MAX_SESSION_ID_LEN: usize = 128;
/// Sessions tracked in the replay-dedup ring.
const MAX_SESSIONS_TRACKED: usize = 4096;
/// One-time SSE tickets live this long before being refused.
const TICKET_TTL: std::time::Duration = std::time::Duration::from_secs(30);
/// How long `forward` waits for a slow machine before reporting 504.
const FORWARD_TIMEOUT: Duration = Duration::from_millis(500);

struct Machine {
    /// Identifies the socket that registered this entry so a stale socket
    /// cannot evict its replacement.
    conn: u64,
    last_seen: Instant,
    scope: String,
    sessions: BTreeSet<String>,
    /// Sessions the user explicitly shared with the dashboard.
    shared: BTreeSet<String>,
    /// Frames from the dashboard bound for this machine's socket.
    outbound: mpsc::Sender<RelayFrame>,
    /// Latest usage totals reported by the machine, per session.
    usage: HashMap<String, UsageSummary>,
}

#[derive(Clone, Copy, Default, PartialEq)]
struct UsageSummary {
    input_tokens: i64,
    output_tokens: i64,
    cost_usd: f64,
}

/// Per-session replay ring: session id -> (seq, frame), oldest first.
type SessionHistory = HashMap<String, VecDeque<(u64, RelayFrame)>>;

#[derive(Clone)]
struct RelayState {
    token: String,
    /// Per-machine credentials/scopes configured by the operator
    /// (`RELAY_MACHINE_TOKENS` / `RELAY_MACHINE_SCOPES` as
    /// `id=value,id2=value2`). When present, a hello must match its entry —
    /// self-asserted machine_id and scope stop being enough.
    machine_tokens: Arc<HashMap<String, String>>,
    machine_scopes: Arc<HashMap<String, String>>,
    /// One-time SSE tickets minted by `POST /events/ticket`; consumed on use
    /// and expired after `TICKET_TTL`, so the bearer stays out of URLs.
    tickets: Arc<Mutex<HashMap<String, Instant>>>,
    /// Recent event hashes per session for exact-replay drops.
    seen: Arc<Mutex<HashMap<String, VecDeque<u64>>>>,
    events: broadcast::Sender<RelayFrame>,
    machines: Arc<Mutex<HashMap<String, Machine>>>,
    next_conn: Arc<AtomicU64>,
    /// Per-session ring buffer (cap `MAX_HISTORY_PER_SESSION`) for `since_seq`
    /// and `Last-Event-ID` resume on `GET /events`.
    history: Arc<Mutex<SessionHistory>>,
    /// Per-session server sequence authority: last assigned `seq` per session.
    /// History entries are stored under `next_seq`, never the client `seq`,
    /// so replay never drops or reorders on client seq games. The counter
    /// survives unshare purges so a re-shared session keeps increasing.
    seqs: Arc<Mutex<HashMap<String, u64>>>,
}

impl RelayState {
    /// Mint a one-time ticket for `GET /events?ticket=`; the SSE handshake
    /// consumes it so tickets cannot be replayed.
    fn mint_ticket(&self) -> String {
        let ticket = ulid::Ulid::new().to_string();
        let mut tickets = self.tickets.lock().expect("tickets lock poisoned");
        tickets.retain(|_, at| at.elapsed() < TICKET_TTL);
        tickets.insert(ticket.clone(), Instant::now());
        ticket
    }

    /// Consume a ticket once; expired or unknown tickets are refused.
    fn take_ticket(&self, ticket: &str) -> bool {
        let mut tickets = self.tickets.lock().expect("tickets lock poisoned");
        tickets
            .remove(ticket)
            .is_some_and(|at| at.elapsed() < TICKET_TTL)
    }
}

/// Client-supplied ids are untrusted: ignore empty, overlong, or odd ids so
/// one machine cannot grow server memory with junk keys.
/// Cheap payload fingerprint for replay dedup — std-only, no secrets, the
/// map key never leaves the server.
fn fingerprint(event: &serde_json::Value) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    event.to_string().hash(&mut hasher);
    hasher.finish()
}

fn valid_session_id(id: &str) -> bool {
    if id.is_empty() || id.len() > MAX_SESSION_ID_LEN {
        return false;
    }
    id.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
}

impl RelayState {
    fn machines(&self) -> std::sync::MutexGuard<'_, HashMap<String, Machine>> {
        self.machines.lock().expect("presence lock poisoned")
    }

    fn touch(&self, machine_id: &str) {
        if let Some(machine) = self.machines().get_mut(machine_id) {
            machine.last_seen = Instant::now();
        }
    }

    /// Register a socket and return its connection id, or `None` when a live
    /// socket already owns this machine. Like `forget`, the entry is keyed by
    /// connection: a new socket never replaces a live machine's outbound or
    /// scope. Presence survives a reconnect so the dashboard keeps the
    /// sessions the machine exposed.
    fn register(
        &self,
        machine_id: &str,
        scope: &str,
        outbound: mpsc::Sender<RelayFrame>,
    ) -> Option<u64> {
        let mut machines = self.machines();
        if let Some(existing) = machines.get(machine_id) {
            let fresh = Instant::now().duration_since(existing.last_seen) < PRESENCE_TTL;
            if fresh && !existing.outbound.is_closed() {
                return None;
            }
        }
        let conn = self.next_conn.fetch_add(1, Ordering::Relaxed) + 1;
        let previous = machines.remove(machine_id);
        if let Some(prev) = &previous {
            // A live socket never reaches here, but a stale-TTL takeover is
            // exactly how a forged hello impersonates a machine: make noise.
            eprintln!(
                "relay: machine {machine_id} re-registered (previous scope {}, new {scope})",
                prev.scope
            );
        }
        let (sessions, shared, usage) = previous
            .map(|machine| (machine.sessions, machine.shared, machine.usage))
            .unwrap_or_default();
        machines.insert(
            machine_id.to_owned(),
            Machine {
                conn,
                last_seen: Instant::now(),
                scope: scope.to_owned(),
                sessions,
                shared,
                outbound,
                usage,
            },
        );
        Some(conn)
    }

    /// Remove a machine only when the entry still belongs to this socket.
    fn forget(&self, machine_id: &str, conn: u64) {
        let mut machines = self.machines();
        if machines
            .get(machine_id)
            .is_some_and(|machine| machine.conn == conn)
        {
            machines.remove(machine_id);
        }
    }

    /// The live machine that already owns a session, if any. "Owned" means
    /// recorded or shared while the machine is fresh — a second machine
    /// cannot squat a victim's session id.
    fn session_owner(&self, session_id: &str, exclude: &str) -> Option<String> {
        let now = Instant::now();
        self.machines()
            .iter()
            .find(|(id, machine)| {
                id.as_str() != exclude
                    && now.duration_since(machine.last_seen) < PRESENCE_TTL
                    && (machine.sessions.contains(session_id)
                        || machine.shared.contains(session_id))
            })
            .map(|(id, _)| id.clone())
    }

    fn record_event(&self, machine_id: &str, session_id: &str) {
        if !valid_session_id(session_id) {
            return;
        }
        if let Some(owner) = self.session_owner(session_id, machine_id) {
            eprintln!("relay: {machine_id} tried to squat session owned by {owner}");
            return;
        }
        if let Some(machine) = self.machines().get_mut(machine_id) {
            machine.last_seen = Instant::now();
            // Cap per-machine entries so one client cannot grow memory unbounded.
            if !machine.sessions.contains(session_id)
                && machine.sessions.len() + machine.shared.len() >= MAX_SESSIONS_PER_MACHINE
            {
                return;
            }
            machine.sessions.insert(session_id.to_owned());
        }
    }

    /// Keep the latest usage totals when an event says so.
    fn record_usage(&self, machine_id: &str, session_id: &str, event: &serde_json::Value) {
        if event.get("type").and_then(|kind| kind.as_str()) != Some("usage") {
            return;
        }
        if !valid_session_id(session_id) {
            return;
        }
        let mut machines = self.machines();
        let Some(machine) = machines.get_mut(machine_id) else {
            return;
        };
        machine.last_seen = Instant::now();
        if !machine.usage.contains_key(session_id)
            && machine.usage.len() >= MAX_SESSIONS_PER_MACHINE
        {
            return;
        }
        machine.usage.insert(
            session_id.to_owned(),
            UsageSummary {
                input_tokens: event["inputTokens"].as_i64().unwrap_or(0),
                output_tokens: event["outputTokens"].as_i64().unwrap_or(0),
                cost_usd: event["costUsd"].as_f64().unwrap_or(0.0),
            },
        );
    }

    /// Latest usage for a session a connected machine is exposing. Stale
    /// (presence-TTL expired) machines never serve summaries.
    fn usage_for_session(&self, session_id: &str) -> Option<UsageSummary> {
        let now = Instant::now();
        self.machines().values().find_map(|machine| {
            if now.duration_since(machine.last_seen) >= PRESENCE_TTL {
                return None;
            }
            let exposed = if machine.scope == "session" {
                machine.shared.contains(session_id)
            } else {
                machine.sessions.contains(session_id)
            };
            exposed
                .then(|| machine.usage.get(session_id).copied())
                .flatten()
        })
    }

    /// Next server `seq` for a session; the server is the seq authority.
    fn next_seq(&self, session_id: &str) -> u64 {
        let mut seqs = self.seqs.lock().expect("seq lock poisoned");
        let entry = seqs.entry(session_id.to_owned()).or_insert(0);
        *entry = entry.saturating_add(1).max(1);
        *entry
    }

    /// Append a frame to the per-session ring for `since_seq` resume. The
    /// client `seq` is ignored: the frame is stored under the server `seq`
    /// so duplicate, out-of-order, or huge client seqs never drop history.
    /// Returns the server-assigned seq for stamping on the live broadcast.
    fn push_history(&self, frame: &RelayFrame) -> Option<u64> {
        let RelayFrame::Event {
            session_id, event, ..
        } = frame
        else {
            return None;
        };
        if !valid_session_id(session_id) {
            return None;
        }
        let seq = self.next_seq(session_id);
        self.record_seen(session_id, &fingerprint(event));
        let stored = RelayFrame::Event {
            session_id: session_id.clone(),
            seq,
            event: event.clone(),
        };
        let mut history = self.history.lock().expect("history lock poisoned");
        let entry = history.entry(session_id.clone()).or_default();
        entry.push_back((seq, stored));
        while entry.len() > MAX_HISTORY_PER_SESSION {
            entry.pop_front();
        }
        Some(seq)
    }

    /// Whether this exact event payload was already recorded for the
    /// session: replayed frames append history and rebroadcast as "new"
    /// otherwise. A short ring of payload fingerprints is enough.
    fn is_replay(&self, session_id: &str, hash: u64) -> bool {
        self.seen
            .lock()
            .expect("seen lock poisoned")
            .get(session_id)
            .is_some_and(|ring| ring.contains(&hash))
    }

    fn record_seen(&self, session_id: &str, hash: &u64) {
        let mut seen = self.seen.lock().expect("seen lock poisoned");
        let ring = seen.entry(session_id.to_owned()).or_default();
        ring.push_back(*hash);
        while ring.len() > 64 {
            ring.pop_front();
        }
        while seen.len() > MAX_SESSIONS_TRACKED {
            if let Some(key) = seen.keys().next().cloned() {
                seen.remove(&key);
            } else {
                break;
            }
        }
    }

    /// Buffered frames for `session_id` after `since_seq`, oldest first.
    fn history_since(&self, session_id: &str, since_seq: u64) -> Vec<(u64, RelayFrame)> {
        self.history
            .lock()
            .expect("history lock poisoned")
            .get(session_id)
            .map(|entry| {
                entry
                    .iter()
                    .filter(|(seq, _)| *seq > since_seq)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    fn set_shared(&self, machine_id: &str, session_id: &str, shared: bool) {
        if !valid_session_id(session_id) {
            return;
        }
        if shared && self.session_owner(session_id, machine_id).is_some() {
            eprintln!("relay: {machine_id} tried to share an owned session {session_id}");
            return;
        }
        if let Some(machine) = self.machines().get_mut(machine_id) {
            machine.last_seen = Instant::now();
            if shared {
                if !machine.sessions.contains(session_id)
                    && machine.sessions.len() + machine.shared.len() >= MAX_SESSIONS_PER_MACHINE
                {
                    return;
                }
                machine.shared.insert(session_id.to_owned());
                machine.sessions.insert(session_id.to_owned());
            } else {
                machine.shared.remove(session_id);
            }
        }
        if !shared && !self.exposes(session_id) {
            // Stop serving replay for a session nobody exposes anymore.
            self.history
                .lock()
                .expect("history lock poisoned")
                .remove(session_id);
        }
    }

    /// Live machines, newest presence only.
    fn live(&self) -> Vec<(String, String, Vec<String>)> {
        let now = Instant::now();
        self.machines()
            .iter()
            .filter(|(_, machine)| now.duration_since(machine.last_seen) < PRESENCE_TTL)
            .map(|(id, machine)| {
                let exposed: Vec<String> = if machine.scope == "session" {
                    machine.shared.iter().cloned().collect()
                } else {
                    machine.sessions.iter().cloned().collect()
                };
                (id.clone(), machine.scope.clone(), exposed)
            })
            .collect()
    }

    fn machine_for_session(&self, session_id: &str) -> Option<mpsc::Sender<RelayFrame>> {
        let now = Instant::now();
        self.machines()
            .values()
            .filter(|machine| now.duration_since(machine.last_seen) < PRESENCE_TTL)
            .find(|machine| {
                if machine.scope == "session" {
                    machine.shared.contains(session_id)
                } else {
                    machine.sessions.contains(session_id)
                }
            })
            .map(|machine| machine.outbound.clone())
    }

    /// Whether a live machine exposes this session at all.
    fn exposes(&self, session_id: &str) -> bool {
        let now = Instant::now();
        self.machines().values().any(|machine| {
            now.duration_since(machine.last_seen) < PRESENCE_TTL
                && if machine.scope == "session" {
                    machine.shared.contains(session_id)
                } else {
                    machine.sessions.contains(session_id)
                }
        })
    }
}

/// Build the relay router. An empty `token` falls back to `RELAY_TOKEN`; if
/// that is unset too, every connection and dashboard request is refused.
pub fn app(token: String) -> Router {
    let token = if token.is_empty() {
        std::env::var("RELAY_TOKEN").unwrap_or_default()
    } else {
        token
    };
    if token.is_empty() {
        eprintln!("relay: no token configured; refusing all authentication");
    }
    let (events, _) = broadcast::channel(1000);
    let state = RelayState {
        token,
        machine_tokens: Arc::new(env_id_map("RELAY_MACHINE_TOKENS")),
        machine_scopes: Arc::new(env_id_map("RELAY_MACHINE_SCOPES")),
        tickets: Arc::new(Mutex::new(HashMap::new())),
        seen: Arc::new(Mutex::new(HashMap::new())),
        events,
        machines: Arc::new(Mutex::new(HashMap::new())),
        next_conn: Arc::new(AtomicU64::new(0)),
        history: Arc::new(Mutex::new(HashMap::new())),
        seqs: Arc::new(Mutex::new(HashMap::new())),
    };
    build(state)
}

fn build(state: RelayState) -> Router {
    let dashboard = Router::new()
        .route("/events", get(events))
        .route("/events/ticket", post(events_ticket))
        .route("/machines", get(list_machines))
        .route("/sessions", get(list_sessions))
        .route("/sessions/{id}/summary", get(session_summary))
        .route("/sessions/{id}/prompt", post(prompt_session))
        .route("/sessions/{id}/abort", post(abort_session))
        .route("/sessions/{id}/permission", post(permission_session))
        .layer(middleware::from_fn_with_state(state.clone(), require_token));
    Router::new()
        .route("/health", get(health))
        .route("/ws", get(ws_upgrade))
        .merge(dashboard)
        .with_state(state)
}

/// Parse `id=value,id2=value2` env maps; empty entries and `=`s in values
/// are dropped so a typo fails closed rather than silently widening.
fn env_id_map(name: &str) -> HashMap<String, String> {
    std::env::var(name)
        .unwrap_or_default()
        .split(',')
        .filter_map(|pair| {
            let (id, value) = pair.split_once('=')?;
            let (id, value) = (id.trim(), value.trim());
            (!id.is_empty() && !value.is_empty()).then(|| (id.to_owned(), value.to_owned()))
        })
        .collect()
}

/// Bearer-token gate for the dashboard API. Only `GET /events` accepts
/// `?token=` because `EventSource` cannot set headers; every other route
/// requires `Authorization: Bearer` so tokens stay out of logs and history.
async fn require_token(State(state): State<RelayState>, request: Request, next: Next) -> Response {
    let header = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    // Query tokens are only honored on `GET /events`.
    let is_events =
        request.method() == axum::http::Method::GET && request.uri().path() == "/events";
    let query = is_events
        .then(|| {
            request
                .uri()
                .query()
                .and_then(|query| {
                    query
                        .split('&')
                        .find_map(|pair| pair.strip_prefix("token="))
                })
                .map(percent_decode)
        })
        .flatten();
    // `/events` also accepts a one-time `?ticket=` minted by
    // `POST /events/ticket`; consumed on use and short-lived, so no bearer
    // ever has to sit in a URL.
    let ticket_ok = is_events
        && request
            .uri()
            .query()
            .and_then(|query| {
                query
                    .split('&')
                    .find_map(|pair| pair.strip_prefix("ticket="))
            })
            .is_some_and(|ticket| state.take_ticket(ticket));
    let allowed = ticket_ok
        || header.is_some_and(|presented| token_matches(&state.token, presented))
        || query
            .as_deref()
            .is_some_and(|presented| token_matches(&state.token, presented));
    if allowed {
        next.run(request).await
    } else {
        auth_failure_backoff().await;
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        )
            .into_response()
    }
}

static AUTH_FAILS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Bounded brute-force defense on hello/bearer guesses: exponential delay
/// (100ms → 3.2s cap) plus a log line that never echoes the credential.
async fn auth_failure_backoff() {
    let n = AUTH_FAILS.fetch_add(1, Ordering::Relaxed).min(5);
    eprintln!("relay: auth failure #{}", n + 1);
    tokio::time::sleep(std::time::Duration::from_millis(100u64 << n)).await;
}

/// Minimal percent-decoding for the `EventSource` query token.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len()
                && let (Some(high), Some(low)) =
                    (hex_value(bytes[index + 1]), hex_value(bytes[index + 2])) =>
            {
                out.push(high * 16 + low);
                index += 3;
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub async fn serve(host: &str, port: u16, token: &str) -> io::Result<()> {
    let listener = tokio::net::TcpListener::bind((host, port)).await?;
    axum::serve(listener, app(token.to_owned()))
        .with_graceful_shutdown(shutdown_signal())
        .await
}

/// Resolves on Ctrl-C or SIGTERM so the listener stops accepting and the
/// process exits 0 under a supervisor.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true }))
}

/// `POST /events/ticket`: mint a short-lived, single-use SSE ticket so
/// `EventSource` clients need not place the bearer in `?token=`.
async fn events_ticket(State(state): State<RelayState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ticket": state.mint_ticket() }))
}

/// `GET /events`: server-sent stream of every session event machines report.
/// Supports resume: `?since_seq=N` (optionally `&session_id=`) and the
/// `Last-Event-ID` header (emitted as `<session_id>:<seq>`) replay buffered
/// per-session ring entries before live frames.
async fn events(
    State(state): State<RelayState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let since_seq: u64 = params
        .get("since_seq")
        .and_then(|value| value.parse().ok())
        .or_else(|| {
            headers
                .get("last-event-id")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.rsplit(':').next())
                .and_then(|value| value.parse().ok())
        })
        .unwrap_or(0);
    let session_filter = params
        .get("session_id")
        .or_else(|| params.get("sessionID"))
        .cloned();
    // Snapshot the per-session ring for replay, oldest first.
    let replay: Vec<(String, u64, RelayFrame)> = {
        let sessions: Vec<String> = match &session_filter {
            Some(filter) => vec![filter.clone()],
            None => state
                .history
                .lock()
                .expect("history lock poisoned")
                .keys()
                .cloned()
                .collect(),
        };
        let mut out = Vec::new();
        for session_id in &sessions {
            // Only replay sessions a live machine still exposes; unshared or
            // disconnected sessions stay out of resume.
            if !state.exposes(session_id) {
                continue;
            }
            for (seq, frame) in state.history_since(session_id, since_seq) {
                out.push((session_id.clone(), seq, frame));
            }
        }
        out.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        out
    };
    let mut last: HashMap<String, u64> = HashMap::new();
    for (session_id, seq, _) in &replay {
        last.entry(session_id.clone())
            .and_modify(|entry| *entry = (*entry).max(*seq))
            .or_insert(*seq);
    }
    let queue: std::collections::VecDeque<Result<SseEvent, Infallible>> = replay
        .into_iter()
        .map(|(session_id, seq, frame)| {
            let data = match &frame {
                RelayFrame::Event { event, .. } => serde_json::json!({
                    "sessionID": session_id,
                    "seq": seq,
                    "event": event,
                })
                .to_string(),
                other => other.to_json(),
            };
            Ok(SseEvent::default()
                .id(format!("{session_id}:{seq}"))
                .data(data))
        })
        .collect();
    let stream = futures::stream::unfold(
        (
            state.events.subscribe(),
            queue,
            last,
            session_filter,
            state.clone(),
        ),
        |(mut rx, mut queue, mut last, filter, state)| async move {
            loop {
                if let Some(item) = queue.pop_front() {
                    return Some((item, (rx, queue, last, filter, state)));
                }
                match rx.recv().await {
                    Ok(RelayFrame::Event {
                        session_id,
                        seq,
                        event,
                    }) => {
                        // Drop events for sessions nobody exposes anymore, even
                        // if a stale broadcast is still in flight.
                        if !state.exposes(&session_id) {
                            continue;
                        }
                        last.entry(session_id.clone())
                            .and_modify(|entry| *entry = (*entry).max(seq))
                            .or_insert(seq);
                        if let Some(filter) = &filter
                            && &session_id != filter
                        {
                            continue;
                        }
                        let data = serde_json::json!({
                            "sessionID": session_id,
                            "seq": seq,
                            "event": event,
                        })
                        .to_string();
                        let item = Ok(SseEvent::default()
                            .id(format!("{session_id}:{seq}"))
                            .data(data));
                        return Some((item, (rx, queue, last, filter, state)));
                    }
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Re-fill from the per-session ring instead of dropping.
                        let pending: Vec<(String, u64)> = {
                            let history = state.history.lock().expect("history lock poisoned");
                            history
                                .keys()
                                .filter(|session_id| {
                                    filter.as_ref().is_none_or(|f| *session_id == f)
                                        && state.exposes(session_id)
                                })
                                .map(|session_id| {
                                    (
                                        session_id.clone(),
                                        last.get(session_id).copied().unwrap_or(0),
                                    )
                                })
                                .collect()
                        };
                        let mut missed: Vec<(String, u64, RelayFrame)> = Vec::new();
                        for (session_id, since) in &pending {
                            for (seq, frame) in state.history_since(session_id, *since) {
                                missed.push((session_id.clone(), seq, frame));
                            }
                        }
                        missed.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
                        for (session_id, seq, frame) in missed {
                            last.entry(session_id.clone())
                                .and_modify(|entry| *entry = (*entry).max(seq))
                                .or_insert(seq);
                            let data = match &frame {
                                RelayFrame::Event { event, .. } => serde_json::json!({
                                    "sessionID": session_id,
                                    "seq": seq,
                                    "event": event,
                                })
                                .to_string(),
                                other => other.to_json(),
                            };
                            queue.push_back(Ok(SseEvent::default()
                                .id(format!("{session_id}:{seq}"))
                                .data(data)));
                        }
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        },
    );
    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// `GET /machines`: connected machines and how many sessions each exposes.
async fn list_machines(State(state): State<RelayState>) -> Json<serde_json::Value> {
    let machines: Vec<serde_json::Value> = state
        .live()
        .into_iter()
        .map(|(machine_id, scope, sessions)| {
            serde_json::json!({
                "machineID": machine_id,
                "scope": scope,
                "sessions": sessions.len(),
            })
        })
        .collect();
    Json(serde_json::json!(machines))
}

/// `GET /sessions`: every session a connected machine is exposing.
async fn list_sessions(State(state): State<RelayState>) -> Json<serde_json::Value> {
    let mut sessions = Vec::new();
    for (machine_id, _scope, ids) in state.live() {
        for session_id in ids {
            sessions.push(serde_json::json!({
                "sessionID": session_id,
                "machineID": machine_id,
            }));
        }
    }
    Json(serde_json::json!(sessions))
}

/// `GET /sessions/{id}/summary`: the latest usage totals for a session.
async fn session_summary(
    State(state): State<RelayState>,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    let known = state.exposes(&session_id);
    match state.usage_for_session(&session_id) {
        Some(usage) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "sessionID": session_id,
                "inputTokens": usage.input_tokens,
                "outputTokens": usage.output_tokens,
                "costUsd": usage.cost_usd,
            })),
        ),
        None if known => (
            StatusCode::OK,
            Json(serde_json::json!({
                "sessionID": session_id,
                "inputTokens": 0,
                "outputTokens": 0,
                "costUsd": 0.0,
            })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "unknown session" })),
        ),
    }
}

/// `POST /sessions/{id}/prompt` forwards a prompt to the owning machine.
async fn prompt_session(
    State(state): State<RelayState>,
    Path(session_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let Some(text) = body.get("text").and_then(|text| text.as_str()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "missing text" })),
        );
    };
    forward(&state, session_id, |session_id| RelayFrame::Prompt {
        session_id,
        text: text.to_owned(),
    })
    .await
}

/// `POST /sessions/{id}/abort` interrupts the run owning the session.
async fn abort_session(
    State(state): State<RelayState>,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    forward(&state, session_id, |session_id| RelayFrame::Abort {
        session_id,
    })
    .await
}

/// `POST /sessions/{id}/permission` forwards a dashboard permission answer.
async fn permission_session(
    State(state): State<RelayState>,
    Path(session_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let Some(permission_id) = body
        .get("permissionID")
        .and_then(|value| value.as_str())
        .map(str::to_owned)
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "missing permissionID" })),
        );
    };
    let response = body
        .get("response")
        .and_then(|value| value.as_str())
        .unwrap_or("reject")
        .to_owned();
    forward(&state, session_id, move |session| {
        RelayFrame::PermissionReply {
            session_id: session,
            permission_id,
            response,
        }
    })
    .await
}

async fn forward(
    state: &RelayState,
    session_id: String,
    frame: impl FnOnce(String) -> RelayFrame,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(outbound) = state.machine_for_session(&session_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "unknown session" })),
        );
    };
    // Never block the dashboard on a slow/dead machine: try a nonblocking
    // send first, then wait briefly before reporting 504.
    match outbound.try_send(frame(session_id.clone())) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "sessionID": session_id })),
        ),
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => (
            StatusCode::GONE,
            Json(serde_json::json!({ "error": "machine disconnected" })),
        ),
        Err(tokio::sync::mpsc::error::TrySendError::Full(frame)) => {
            match tokio::time::timeout(FORWARD_TIMEOUT, outbound.send(frame)).await {
                Ok(Ok(())) => (
                    StatusCode::OK,
                    Json(serde_json::json!({ "ok": true, "sessionID": session_id })),
                ),
                Ok(Err(_)) => (
                    StatusCode::GONE,
                    Json(serde_json::json!({ "error": "machine disconnected" })),
                ),
                Err(_) => (
                    StatusCode::GATEWAY_TIMEOUT,
                    Json(serde_json::json!({ "error": "machine busy" })),
                ),
            }
        }
    }
}

async fn ws_upgrade(ws: WebSocketUpgrade, State(state): State<RelayState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle(socket, state))
}

async fn handle(mut socket: WebSocket, state: RelayState) {
    // Idle sockets must not accumulate: the first frame has 10s to arrive.
    let hello = match tokio::time::timeout(HELLO_TIMEOUT, socket.recv()).await {
        Ok(Some(Ok(Message::Text(text)))) => hello_machine(&state, &text),
        Ok(Some(Ok(Message::Binary(bytes)))) => std::str::from_utf8(&bytes)
            .ok()
            .and_then(|text| hello_machine(&state, text)),
        _ => None,
    };
    let Some((machine_id, scope)) = hello else {
        auth_failure_backoff().await;
        let _ = socket
            .send(Message::Text(
                RelayFrame::Error {
                    message: "forbidden".to_owned(),
                }
                .to_json()
                .into(),
            ))
            .await;
        let _ = socket.close().await;
        return;
    };

    let (outbound, mut outbound_rx) = mpsc::channel::<RelayFrame>(64);
    let Some(conn) = state.register(&machine_id, &scope, outbound) else {
        let _ = socket
            .send(Message::Text(
                RelayFrame::Error {
                    message: "conflict".to_owned(),
                }
                .to_json()
                .into(),
            ))
            .await;
        let _ = socket.close().await;
        return;
    };
    let mut events = state.events.subscribe();
    loop {
        tokio::select! {
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Text(text))) => process(&state, &machine_id, &text, &mut socket).await,
                Some(Ok(Message::Binary(bytes))) => {
                    if let Ok(text) = std::str::from_utf8(&bytes) {
                        process(&state, &machine_id, text, &mut socket).await;
                    }
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => {}
            },
            Some(frame) = outbound_rx.recv() => {
                if !send_frame(&mut socket, frame).await {
                    break;
                }
            }
            // Machines are publishers, not subscribers: the broadcast is for
            // the dashboard only. Forwarding it to peers leaked every other
            // machine's session events and permission prompts.
            _ = events.recv() => {}
        }
    }
    state.forget(&machine_id, conn);
}

/// Send one frame, replacing anything over the cap with an error frame.
async fn send_frame(socket: &mut WebSocket, frame: RelayFrame) -> bool {
    let text = frame.to_json();
    let text = if text.len() > MAX_FRAME {
        RelayFrame::Error {
            message: format!("frame truncated: {} bytes", text.len()),
        }
        .to_json()
    } else {
        text
    };
    socket.send(Message::Text(text.into())).await.is_ok()
}

fn hello_machine(state: &RelayState, text: &str) -> Option<(String, String)> {
    let Some(RelayFrame::Hello {
        machine_id,
        scope,
        token,
        ..
    }) = RelayFrame::from_json(text)
    else {
        return None;
    };
    if machine_id.is_empty() || (scope != "machine" && scope != "session") {
        return None;
    }
    // Per-machine credential when the operator configured one; the shared
    // token alone is no longer enough to impersonate that id.
    let expected = state
        .machine_tokens
        .get(&machine_id)
        .unwrap_or(&state.token);
    if !token_matches(expected, &token) {
        return None;
    }
    // Scope must match the server-side allowlist when one exists — the
    // client no longer picks "machine" by assertion.
    if !state.machine_scopes.is_empty()
        && state.machine_scopes.get(&machine_id).map(String::as_str) != Some(scope.as_str())
    {
        return None;
    }
    Some((machine_id, scope))
}

async fn process(state: &RelayState, machine_id: &str, text: &str, socket: &mut WebSocket) {
    if text.len() > MAX_FRAME {
        send_frame(
            socket,
            RelayFrame::Error {
                message: "frame too large".to_owned(),
            },
        )
        .await;
        return;
    }
    let Some(frame) = RelayFrame::from_json(text) else {
        return;
    };
    match frame {
        RelayFrame::Event {
            session_id, event, ..
        } => {
            // Replay dedup first: an exact copy must not append history or
            // rebroadcast as "new". Server seq is stamped on the live frame
            // too so dashboards never see client-chosen ordering.
            let hash = fingerprint(&event);
            if state.is_replay(&session_id, hash) {
                return;
            }
            state.record_event(machine_id, &session_id);
            state.record_usage(machine_id, &session_id, &event);
            let Some(seq) = state.push_history(&RelayFrame::Event {
                session_id: session_id.clone(),
                seq: 0,
                event: event.clone(),
            }) else {
                return;
            };
            let _ = state.events.send(RelayFrame::Event {
                session_id,
                seq,
                event,
            });
        }
        RelayFrame::Permission { ref session_id, .. } => {
            // Bind the prompt to its session: only the machine exposing the
            // session may ask for it, so one machine cannot spoof another's
            // permission prompt.
            if !valid_session_id(session_id) {
                return;
            }
            let allowed = state.machines().get(machine_id).is_some_and(|machine| {
                if machine.scope == "session" {
                    machine.shared.contains(session_id)
                } else {
                    machine.sessions.contains(session_id)
                }
            });
            if !allowed {
                return;
            }
            let _ = state.events.send(frame);
        }
        RelayFrame::Share { ref session_id } => state.set_shared(machine_id, session_id, true),
        RelayFrame::Unshare { ref session_id } => {
            state.set_shared(machine_id, session_id, false);
        }
        RelayFrame::Heartbeat { .. } => state.touch(machine_id),
        _ => {}
    }
}

/// Constant-time comparison so token validation does not leak matching bytes.
fn token_matches(expected: &str, presented: &str) -> bool {
    if presented.is_empty() || expected.is_empty() {
        return false;
    }
    expected.len() == presented.len()
        && expected
            .bytes()
            .zip(presented.bytes())
            .fold(0, |diff, (a, b)| diff | (a ^ b))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use futures::{SinkExt, StreamExt};
    use tokio::time::{Duration, timeout};
    use tokio_tungstenite::tungstenite::Message as WsMessage;
    use tower::ServiceExt;

    #[test]
    fn parses_hello_frame() {
        let frame = RelayFrame::from_json(
            r#"{"type":"hello","machine_id":"m1","version":"0.1.0","scope":"machine","token":"t"}"#,
        );
        assert!(
            matches!(frame, Some(RelayFrame::Hello { .. })),
            "got {frame:?}"
        );
        assert!(RelayFrame::from_json(r#"{"type":"heartbeat"}"#).is_none());
    }

    #[tokio::test]
    async fn health_reports_ok() {
        let response = app("secret".to_owned())
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json, serde_json::json!({ "ok": true }));
    }

    #[tokio::test]
    async fn events_streams_relayed_frames() {
        let (events, _) = broadcast::channel(8);
        let state = RelayState {
            token: "secret".to_owned(),
            machine_tokens: Arc::new(HashMap::new()),
            machine_scopes: Arc::new(HashMap::new()),
            tickets: Arc::new(Mutex::new(HashMap::new())),
            seen: Arc::new(Mutex::new(HashMap::new())),
            events,
            machines: Arc::new(Mutex::new(HashMap::new())),
            next_conn: Arc::new(AtomicU64::new(0)),
            history: Arc::new(Mutex::new(HashMap::new())),
            seqs: Arc::new(Mutex::new(HashMap::new())),
        };
        let (outbound, _outbound_rx) = mpsc::channel(4);
        state
            .register("machine-a", "machine", outbound)
            .expect("first register");
        state.record_event("machine-a", "ses_1");
        let response = build(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/events")
                    .header("authorization", "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        assert!(
            content_type.starts_with("text/event-stream"),
            "got {content_type}"
        );
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-cache")
        );
        let mut body = response.into_body().into_data_stream();

        // Non-event frames stay off the dashboard stream.
        let _ = state.events.send(RelayFrame::Heartbeat { ts: 1 });
        state
            .events
            .send(RelayFrame::Event {
                session_id: "ses_1".to_owned(),
                seq: 4,
                event: serde_json::json!({ "type": "message.part.updated" }),
            })
            .unwrap();

        let chunk = timeout(Duration::from_secs(2), body.next())
            .await
            .expect("no SSE frame arrived")
            .expect("stream ended")
            .expect("stream failed");
        let text = String::from_utf8(chunk.to_vec()).unwrap();
        let data = text
            .lines()
            .find_map(|l| l.strip_prefix("data: "))
            .expect("SSE frame without a data line");
        let json: serde_json::Value = serde_json::from_str(data.trim_end()).unwrap();
        assert_eq!(json["sessionID"], "ses_1");
        assert_eq!(json["seq"], 4);
        assert_eq!(json["event"]["type"], "message.part.updated");
    }

    #[tokio::test]
    async fn summary_reports_latest_usage() {
        let (events, _) = broadcast::channel(8);
        let state = RelayState {
            token: "secret".to_owned(),
            machine_tokens: Arc::new(HashMap::new()),
            machine_scopes: Arc::new(HashMap::new()),
            tickets: Arc::new(Mutex::new(HashMap::new())),
            seen: Arc::new(Mutex::new(HashMap::new())),
            events,
            machines: Arc::new(Mutex::new(HashMap::new())),
            next_conn: Arc::new(AtomicU64::new(0)),
            history: Arc::new(Mutex::new(HashMap::new())),
            seqs: Arc::new(Mutex::new(HashMap::new())),
        };
        let (outbound, _outbound_rx) = mpsc::channel(4);
        state
            .register("machine-a", "machine", outbound)
            .expect("first register");
        state.record_event("machine-a", "ses_1");
        // A non-usage event is not a summary.
        state.record_usage(
            "machine-a",
            "ses_1",
            &serde_json::json!({ "type": "session.status" }),
        );

        let router = build(state.clone());
        let request = || {
            Request::builder()
                .uri("/sessions/ses_1/summary")
                .header("authorization", "Bearer secret")
                .body(Body::empty())
                .unwrap()
        };
        // The session is exposed but has no usage yet: report zeros.
        let response = router.clone().oneshot(request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["inputTokens"], 0);

        state.record_usage(
            "machine-a",
            "ses_1",
            &serde_json::json!({
                "type": "usage",
                "sessionID": "ses_1",
                "inputTokens": 120,
                "outputTokens": 45,
                "costUsd": 0.125,
            }),
        );
        state.record_usage(
            "machine-a",
            "ses_1",
            &serde_json::json!({ "type": "session.completed" }),
        );
        let response = router.clone().oneshot(request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "sessionID": "ses_1",
                "inputTokens": 120,
                "outputTokens": 45,
                "costUsd": 0.125,
            })
        );

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/sessions/ses_missing/summary")
                    .header("authorization", "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    async fn ws_url() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app("secret".to_owned()))
                .await
                .unwrap();
        });
        format!("ws://{addr}/ws")
    }

    fn hello(machine_id: &str, token: &str) -> WsMessage {
        let frame = RelayFrame::Hello {
            machine_id: machine_id.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            scope: "machine".to_owned(),
            token: token.to_owned(),
        };
        WsMessage::Text(frame.to_json().into())
    }

    #[tokio::test]
    async fn events_broadcast_between_machines() {
        let url = ws_url().await;
        let (mut a, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        let (mut b, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        a.send(hello("machine-a", "secret")).await.unwrap();
        b.send(hello("machine-b", "secret")).await.unwrap();

        let event = RelayFrame::Event {
            session_id: "ses_1".to_owned(),
            seq: 7,
            event: serde_json::json!({ "type": "message.part.updated" }),
        };
        // Machines are publishers, not subscribers: machine-origin frames
        // must never reach a peer socket (cross-session leak).
        a.send(WsMessage::Text(event.to_json().into()))
            .await
            .unwrap();
        let leaked = match timeout(Duration::from_millis(300), b.next()).await {
            Ok(Some(Ok(WsMessage::Text(text)))) => RelayFrame::from_json(text.as_str()),
            _ => None,
        };
        assert!(
            !matches!(leaked, Some(RelayFrame::Event { .. })),
            "peer received machine event: {leaked:?}"
        );
    }

    #[tokio::test]
    async fn permission_reply_reaches_machine() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app("secret".to_owned()))
                .await
                .unwrap();
        });
        let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
            .await
            .unwrap();
        socket.send(hello("machine-a", "secret")).await.unwrap();
        let event = RelayFrame::Event {
            session_id: "ses_1".to_owned(),
            seq: 1,
            event: serde_json::json!({ "type": "session.status" }),
        };
        socket
            .send(WsMessage::Text(event.to_json().into()))
            .await
            .unwrap();

        let client = reqwest::Client::new();
        let mut routed = false;
        // Retry until the server has processed the event that registers ses_1.
        for _ in 0..50 {
            let response = client
                .post(format!("http://{addr}/sessions/ses_1/permission"))
                .bearer_auth("secret")
                .json(&serde_json::json!({"permissionID": "perm_1", "response": "once"}))
                .send()
                .await
                .unwrap();
            if response.status().is_success() {
                routed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(routed, "permission route never found the machine");

        let mut reply = None;
        for _ in 0..50 {
            match timeout(Duration::from_millis(100), socket.next()).await {
                Ok(Some(Ok(WsMessage::Text(text)))) => {
                    if let Some(frame @ RelayFrame::PermissionReply { .. }) =
                        RelayFrame::from_json(text.as_str())
                    {
                        reply = Some(frame);
                        break;
                    }
                }
                Ok(Some(Ok(_))) => continue,
                _ => continue,
            }
        }
        assert_eq!(
            reply,
            Some(RelayFrame::PermissionReply {
                session_id: "ses_1".to_owned(),
                permission_id: "perm_1".to_owned(),
                response: "once".to_owned(),
            })
        );
    }

    #[tokio::test]
    async fn share_frames_track_dashboard_sessions() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app("secret".to_owned()))
                .await
                .unwrap();
        });
        let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
            .await
            .unwrap();
        let hello = RelayFrame::Hello {
            machine_id: "machine-a".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            scope: "session".to_owned(),
            token: "secret".to_owned(),
        };
        socket
            .send(WsMessage::Text(hello.to_json().into()))
            .await
            .unwrap();
        socket
            .send(WsMessage::Text(
                RelayFrame::Share {
                    session_id: "ses_1".to_owned(),
                }
                .to_json()
                .into(),
            ))
            .await
            .unwrap();

        let client = reqwest::Client::new();
        let mut shared = false;
        for _ in 0..50 {
            let sessions: serde_json::Value = client
                .get(format!("http://{addr}/sessions"))
                .bearer_auth("secret")
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            if sessions
                .as_array()
                .is_some_and(|list| list.iter().any(|entry| entry["sessionID"] == "ses_1"))
            {
                shared = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(shared, "shared session never appeared in /sessions");

        socket
            .send(WsMessage::Text(
                RelayFrame::Unshare {
                    session_id: "ses_1".to_owned(),
                }
                .to_json()
                .into(),
            ))
            .await
            .unwrap();
        let mut unshared = false;
        for _ in 0..50 {
            let sessions: serde_json::Value = client
                .get(format!("http://{addr}/sessions"))
                .bearer_auth("secret")
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            if sessions
                .as_array()
                .is_some_and(|list| !list.iter().any(|entry| entry["sessionID"] == "ses_1"))
            {
                unshared = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(unshared, "unshared session still listed");
    }

    #[test]
    fn empty_expected_token_fails_closed() {
        assert!(!token_matches("", "anything"));
        assert!(!token_matches("", ""));
        assert!(token_matches("secret", "secret"));
        assert!(!token_matches("secret", "wrong"));
    }

    #[test]
    fn decodes_query_tokens() {
        assert_eq!(percent_decode("a%20b+c"), "a b c");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("%E2%9C%93"), "✓");
    }

    #[tokio::test]
    async fn dashboard_requires_a_token() {
        let (events, _) = broadcast::channel(8);
        let state = RelayState {
            token: "secret".to_owned(),
            machine_tokens: Arc::new(HashMap::new()),
            machine_scopes: Arc::new(HashMap::new()),
            tickets: Arc::new(Mutex::new(HashMap::new())),
            seen: Arc::new(Mutex::new(HashMap::new())),
            events,
            machines: Arc::new(Mutex::new(HashMap::new())),
            next_conn: Arc::new(AtomicU64::new(0)),
            history: Arc::new(Mutex::new(HashMap::new())),
            seqs: Arc::new(Mutex::new(HashMap::new())),
        };
        let router = build(state);
        let denied = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/sessions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        let allowed = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/events?token=secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
        // Query tokens never authorize mutating or listing routes.
        let denied_query = router
            .oneshot(
                Request::builder()
                    .uri("/sessions?token=secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied_query.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn stale_socket_cannot_evict_a_reconnected_machine() {
        let (events, _) = broadcast::channel(8);
        let state = RelayState {
            token: "secret".to_owned(),
            machine_tokens: Arc::new(HashMap::new()),
            machine_scopes: Arc::new(HashMap::new()),
            tickets: Arc::new(Mutex::new(HashMap::new())),
            seen: Arc::new(Mutex::new(HashMap::new())),
            events,
            machines: Arc::new(Mutex::new(HashMap::new())),
            next_conn: Arc::new(AtomicU64::new(0)),
            history: Arc::new(Mutex::new(HashMap::new())),
            seqs: Arc::new(Mutex::new(HashMap::new())),
        };
        let (first, first_rx) = mpsc::channel(4);
        let old = state
            .register("machine-a", "machine", first)
            .expect("first register");
        // A live machine blocks a second socket from stealing its entry.
        let (second, _second_rx) = mpsc::channel(4);
        assert!(state.register("machine-a", "machine", second).is_none());
        // Once the first socket disconnects, a reconnect takes over.
        drop(first_rx);
        let (second, _second_rx) = mpsc::channel(4);
        let new = state
            .register("machine-a", "machine", second)
            .expect("reconnect");
        assert_ne!(old, new);
        state.forget("machine-a", old);
        assert!(state.machines().contains_key("machine-a"));
        state.forget("machine-a", new);
        assert!(!state.machines().contains_key("machine-a"));
    }

    #[tokio::test]
    async fn rejects_bad_token() {
        let url = ws_url().await;
        let (mut socket, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        socket.send(hello("machine-a", "wrong")).await.unwrap();
        let message = timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let WsMessage::Text(text) = message else {
            panic!("expected an error frame, got {message:?}");
        };
        assert_eq!(
            RelayFrame::from_json(text.as_str()),
            Some(RelayFrame::Error {
                message: "forbidden".to_owned()
            })
        );
    }

    #[tokio::test]
    async fn requires_hello_first() {
        let url = ws_url().await;
        let (mut socket, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        socket
            .send(WsMessage::Text(
                RelayFrame::Heartbeat { ts: 1 }.to_json().into(),
            ))
            .await
            .unwrap();
        let message = timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let WsMessage::Text(text) = message else {
            panic!("expected an error frame, got {message:?}");
        };
        assert_eq!(
            RelayFrame::from_json(text.as_str()),
            Some(RelayFrame::Error {
                message: "forbidden".to_owned()
            })
        );
    }
}
