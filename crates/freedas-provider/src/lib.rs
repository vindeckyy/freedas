//! Provider abstraction: normalized chat streaming across providers.

use async_trait::async_trait;
use freedas_core::FreedasError;
use futures::Stream;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::pin::Pin;
use std::time::Duration;

pub type BoxStream = Pin<Box<dyn Stream<Item = Result<ChatEvent, ProviderError>> + Send>>;

#[derive(Debug, Clone)]
pub struct ProviderError {
    pub kind: String,
    pub status: Option<u16>,
    pub message: String,
    pub retryable: bool,
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}
impl std::error::Error for ProviderError {}

impl From<ProviderError> for freedas_core::FreedasError {
    fn from(e: ProviderError) -> Self {
        FreedasError::Provider(format!("{}: {}", e.kind, e.message))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelRef {
    pub provider: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
    /// Assistant tool calls, in the OpenAI shape.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCallRef>,
    /// Set on a tool result so OpenAI-compatible APIs can pair it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallRef {
    pub id: String,
    pub name: String,
    pub arguments: String,
}

impl ChatMessage {
    pub fn new(role: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: role.into(),
            content: content.into(),
            tool_calls: Vec::new(),
            tool_call_id: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSchema {
    pub name: String,
    pub description: String,
    pub schema: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct ChatRequest {
    pub model: ModelRef,
    pub system: Vec<String>,
    pub messages: Vec<ChatMessage>,
    pub tools: Vec<ToolSchema>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    pub metadata: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub enum ChatEvent {
    Start,
    TextDelta(String),
    ReasoningDelta(String),
    ToolCallStart {
        id: String,
        name: String,
    },
    ToolCallArgsDelta {
        id: String,
        delta: String,
    },
    ToolCallEnd {
        id: String,
        args: serde_json::Value,
    },
    Usage {
        input: u64,
        output: u64,
        cache_read: u64,
        cache_write: u64,
        cost: f64,
        estimated: bool,
    },
    Finish {
        reason: String,
    },
    Error(ProviderError),
}

#[derive(Debug, Clone)]
pub enum AuthMethod {
    ApiKey,
    OAuthDevice,
    OAuthBrowser,
    Command,
    Env,
}

#[async_trait]
pub trait Provider: Send + Sync {
    fn id(&self) -> &str;
    async fn models(&self) -> Result<Vec<String>, ProviderError>;
    async fn stream(
        &self,
        request: ChatRequest,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<BoxStream, ProviderError>;
}

/// Build a provider from an already-resolved key. Extracted from session
/// `provider_for` so callers can refresh once on auth failure and rebuild
/// without duplicating the match: resolve with `oauth::credential_key_for`,
/// on `auth` error call `oauth::access_token_for` once, then rebuild here
/// and retry the stream once.
pub fn provider_with_key(
    provider_id: &str,
    key: Option<String>,
    gateway_base: &str,
) -> Option<std::sync::Arc<dyn Provider>> {
    match provider_id {
        "anthropic" => Some(std::sync::Arc::new(anthropic::Anthropic::new(key))),
        "google" | "gemini" => Some(std::sync::Arc::new(gemini::Gemini::new(key))),
        "fake" => Some(std::sync::Arc::new(fake::FakeProvider)),
        "opencode-go" => Some(std::sync::Arc::new(
            openai_compatible::OpenAiCompatible::opencode(
                "https://opencode.ai/inference/go/v1",
                key,
            ),
        )),
        "opencode-zen" => Some(std::sync::Arc::new(
            openai_compatible::OpenAiCompatible::opencode("https://opencode.ai/zen/v1", key),
        )),
        "openrouter" => Some(std::sync::Arc::new(
            openai_compatible::OpenAiCompatible::new("https://openrouter.ai/api/v1", key),
        )),
        "openai" => Some(std::sync::Arc::new(
            openai_compatible::OpenAiCompatible::new("https://api.openai.com/v1", key),
        )),
        "freedas" => Some(std::sync::Arc::new(
            openai_compatible::OpenAiCompatible::new(gateway_base, key),
        )),
        _ => None,
    }
}
/// Shared client: connect and idle timeouts keep a stalled provider from
/// hanging a step forever.
pub fn http_client() -> reqwest::Client {
    static CLIENT: std::sync::LazyLock<reqwest::Client> = std::sync::LazyLock::new(|| {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(120))
            .read_timeout(Duration::from_secs(300))
            .build()
            .expect("build reqwest client")
    });
    CLIENT.clone()
}

const MAX_ERROR_BODY: usize = 2048;

/// Raw provider bodies land in user-visible errors; cap them.
pub fn truncate_body(body: &str) -> String {
    if body.len() <= MAX_ERROR_BODY {
        return body.to_string();
    }
    let mut end = MAX_ERROR_BODY;
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… [truncated {} bytes]", &body[..end], body.len())
}

/// Statuses worth another attempt. Auth and context overflow never are.
pub fn retryable_status(status: u16) -> bool {
    matches!(status, 408 | 429 | 500 | 502 | 503 | 504 | 529)
}

pub fn http_error(status: u16, body: &str) -> ProviderError {
    let lower = body.to_ascii_lowercase();
    let kind = if lower.contains("context_length_exceeded")
        || lower.contains("maximum context length")
        || lower.contains("prompt is too long")
        || lower.contains("input is too long")
    {
        "context_overflow"
    } else if status == 401
        || status == 403
        || lower.contains("api key not valid")
        || lower.contains("api_key_invalid")
    {
        "auth"
    } else if status == 429 {
        "rate_limit"
    } else {
        "http"
    };
    ProviderError {
        kind: kind.into(),
        status: Some(status),
        message: truncate_body(body),
        retryable: kind != "context_overflow" && kind != "auth" && retryable_status(status),
    }
}

fn cancelled_error() -> ProviderError {
    ProviderError {
        kind: "cancelled".into(),
        status: None,
        message: "request cancelled".into(),
        retryable: false,
    }
}

fn network_error(e: &reqwest::Error) -> ProviderError {
    let mut message = e.to_string();
    if let Some(url) = e.url() {
        let mut sanitized = url.clone();
        sanitized.set_query(None);
        message = message.replace(url.as_str(), sanitized.as_str());
    }
    ProviderError {
        kind: "network".into(),
        status: None,
        message: truncate_body(&message),
        retryable: true,
    }
}

fn retry_after(resp: &reqwest::Response) -> Option<Duration> {
    let value = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?;
    let trimmed = value.trim();
    if let Ok(secs) = trimmed.parse::<f64>() {
        if !secs.is_finite() {
            return None;
        }
        return Some(Duration::from_secs_f64(secs.clamp(0.0, 60.0)));
    }
    // HTTP-date form (IMF-fixdate, e.g. `Wed, 21 Oct 2015 07:28:00 GMT`).
    parse_http_date_delay(trimmed)
}

fn parse_http_date_delay(value: &str) -> Option<Duration> {
    // Minimal IMF-fixdate parser; no new deps. Returns clamped delay.
    let s = value.strip_suffix("GMT")?.trim();
    let s = s.split_once(',')?.1.trim();
    let mut it = s.split_whitespace();
    let day: i64 = it.next()?.parse().ok()?;
    let mon = match it.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: i64 = it.next()?.parse().ok()?;
    let hms = it.next()?;
    if it.next().is_some() {
        return None;
    }
    let mut hms_it = hms.split(':');
    let hh: i64 = hms_it.next()?.parse().ok()?;
    let mm: i64 = hms_it.next()?.parse().ok()?;
    let ss: i64 = hms_it.next()?.parse().ok()?;
    if hms_it.next().is_some() {
        return None;
    }
    let days = days_from_civil(year, mon, day)?;
    let target = days * 86_400 + hh * 3600 + mm * 60 + ss;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(target);
    let delay = (target - now).clamp(0, 60);
    Some(Duration::from_secs(delay as u64))
}

fn days_from_civil(y: i64, m: i64, d: i64) -> Option<i64> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9).rem_euclid(12);
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146097 + doe - 719468)
}

/// Full-jitter backoff: uniform in `[0, min(8s, 500ms * 2^attempt)]`.
fn jitter_delay(attempt: u32) -> Duration {
    let cap = 500u64
        .saturating_mul(1u64 << (attempt.saturating_sub(1)).min(4))
        .min(8_000);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    // Mix attempt + pid so concurrent retries do not correlate.
    let pid = std::process::id() as u64;
    let mut x = nanos
        .wrapping_add((attempt as u64).wrapping_mul(0x9E3779B97F4A7C15))
        .wrapping_add(pid.wrapping_mul(0xBF58476D1CE4E5B9))
        .wrapping_add(0x9E3779B97F4A7C15);
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58476D1CE4E5B9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94D049BB133111EB);
    x ^= x >> 31;
    Duration::from_millis(x % (cap + 1))
}

/// Send one request with bounded retries: 5 attempts, full jitter, honoring
/// `Retry-After`. `ContextOverflow` and auth failures are returned at once.
pub(crate) async fn send_with_retry(
    cancel: &tokio_util::sync::CancellationToken,
    build: impl Fn() -> reqwest::RequestBuilder,
) -> Result<reqwest::Response, ProviderError> {
    const MAX_ATTEMPTS: u32 = 5;
    let mut attempt = 0;
    loop {
        attempt += 1;
        if cancel.is_cancelled() {
            return Err(cancelled_error());
        }
        let mut retry_at = None;
        let error = match build().send().await {
            Ok(resp) if resp.status().is_success() => return Ok(resp),
            Ok(resp) => {
                retry_at = retry_after(&resp);
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                http_error(status, &body)
            }
            Err(e) => network_error(&e),
        };
        if !error.retryable || attempt >= MAX_ATTEMPTS {
            return Err(error);
        }
        let delay = retry_at.unwrap_or_else(|| jitter_delay(attempt));
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = cancel.cancelled() => return Err(cancelled_error()),
        }
    }
}

fn estimate_input_tokens(request: &ChatRequest) -> u64 {
    let chars: usize = request.system.iter().map(|s| s.len()).sum::<usize>()
        + request
            .messages
            .iter()
            .map(|m| {
                m.content.len()
                    + m.tool_calls
                        .iter()
                        .map(|c| c.arguments.len())
                        .sum::<usize>()
            })
            .sum::<usize>();
    (chars as u64).div_ceil(4)
}

/// Cost from the bundled catalog; unknown models report zero rather than a
/// fabricated number.
pub(crate) fn usage_cost(model: &ModelRef, input: u64, output: u64, cache_read: u64) -> f64 {
    let catalog = freedas_catalog::builtin_catalog();
    let full = format!("{}/{}", model.provider, model.id);
    let Some(info) = freedas_catalog::get_model(&catalog, &full)
        .or_else(|| catalog.iter().find(|m| m.id == model.id))
    else {
        return 0.0;
    };
    let cached = cache_read.min(input);
    let fresh = input.saturating_sub(cached);
    (fresh as f64 * info.cost_input
        + cached as f64 * info.cost_cache_read
        + output as f64 * info.cost_output)
        / 1e6
}

/// Normalize a gateway base so `FREEDAS_GATEWAY_URL=https://host` and
/// `.../v1` both reach the same endpoints.
pub fn normalize_v1_base(url: &str) -> String {
    let url = url.trim_end_matches('/');
    if url.ends_with("/v1") || url.contains("/v1/") {
        url.to_string()
    } else {
        format!("{url}/v1")
    }
}

/// Incremental SSE parser for one provider stream.
pub(crate) trait SseHandler: Send {
    fn event(&mut self, data: &str) -> Vec<Result<ChatEvent, ProviderError>>;
    fn end(&mut self) -> Vec<Result<ChatEvent, ProviderError>> {
        Vec::new()
    }
}

/// Stream provider SSE through `handler`, emitting normalized events and
/// stopping when the caller cancels.
pub(crate) fn sse_stream(
    resp: reqwest::Response,
    cancel: tokio_util::sync::CancellationToken,
    handler: impl SseHandler + 'static,
) -> BoxStream {
    use futures::StreamExt;
    use futures::future::Either;

    let events = eventsource_stream::EventStream::new(resp.bytes_stream());
    let state = (
        Box::pin(events),
        std::collections::VecDeque::<Result<ChatEvent, ProviderError>>::new(),
        cancel,
        Box::new(handler) as Box<dyn SseHandler>,
        false,
    );
    let stream = futures::stream::unfold(
        state,
        |(mut events, mut queue, cancel, mut handler, mut ended)| async move {
            loop {
                if let Some(item) = queue.pop_front() {
                    return Some((item, (events, queue, cancel, handler, ended)));
                }
                if ended || cancel.is_cancelled() {
                    return None;
                }
                let next = futures::future::select(
                    Box::pin(events.next()),
                    Box::pin(cancel.clone().cancelled_owned()),
                )
                .await;
                match next {
                    Either::Left((Some(Ok(event)), _)) => queue.extend(handler.event(&event.data)),
                    Either::Left((Some(Err(e)), _)) => queue.push_back(Err(ProviderError {
                        kind: "stream".into(),
                        status: None,
                        message: truncate_body(&e.to_string()),
                        retryable: true,
                    })),
                    Either::Left((None, _)) => {
                        ended = true;
                        queue.extend(handler.end());
                    }
                    Either::Right(_) => ended = true,
                }
            }
        },
    );
    Box::pin(stream)
}

pub mod fake {
    use super::*;
    use futures::stream;

    pub struct FakeProvider;

    /// True when an assistant turn already issued this call. The fake provider
    /// has no real progress signal, so it replays a call only once.
    fn already_called(messages: &[ChatMessage], name: &str, args: &serde_json::Value) -> bool {
        messages
            .iter()
            .flat_map(|m| m.tool_calls.iter())
            .any(|call| {
                call.name == name
                    && serde_json::from_str::<serde_json::Value>(&call.arguments)
                        .map(|existing| existing == *args)
                        .unwrap_or(false)
            })
    }

    #[async_trait]
    impl Provider for FakeProvider {
        fn id(&self) -> &str {
            "fake"
        }
        async fn models(&self) -> Result<Vec<String>, ProviderError> {
            Ok(vec!["fake-1".into()])
        }
        async fn stream(
            &self,
            request: ChatRequest,
            _cancel: tokio_util::sync::CancellationToken,
        ) -> Result<BoxStream, ProviderError> {
            let mut events = Vec::new();
            events.push(Ok(ChatEvent::Start));
            // Only a user turn is a prompt: tool results are transcript, not
            // instructions, and a `WRITE:`/`READ:` inside one must not run.
            let last = request
                .messages
                .iter()
                .rev()
                .find(|m| m.role == "user" && m.tool_call_id.is_none())
                .map(|m| m.content.as_str())
                .unwrap_or("");
            let trigger: Option<(&str, serde_json::Value)> = if let Some(idx) = last.find("WRITE:")
            {
                // Format: WRITE:<path>:<content>, parsed from the marker offset
                // so a colon earlier in the prompt cannot shift the path.
                let rest = &last[idx + "WRITE:".len()..];
                rest.split_once(':').map(|(path, content)| {
                    (
                        "write",
                        serde_json::json!({"path": path, "content": content}),
                    )
                })
            } else if let Some(path) = last.split("READ:").nth(1) {
                Some(("read", serde_json::json!({"path": path.trim()})))
            } else if let Some(cmd) = last.split("RUN:").nth(1) {
                Some(("bash", serde_json::json!({"command": cmd.trim()})))
            } else if last.contains("TEST:") {
                Some(("bash", serde_json::json!({"command": "echo ok"})))
            } else {
                None
            };
            if let Some((name, args)) = trigger {
                // Each tool call fires once per transcript: the prompt that
                // triggered it stays in `messages` for every later step.
                if already_called(&request.messages, name, &args) {
                    events.push(Ok(ChatEvent::TextDelta("Fake response.".into())));
                } else {
                    let id = "call_fake_1".to_string();
                    events.push(Ok(ChatEvent::ToolCallStart {
                        id: id.clone(),
                        name: name.to_string(),
                    }));
                    events.push(Ok(ChatEvent::ToolCallEnd { id, args }));
                }
            } else if let Some(rest) = last.trim().strip_prefix("THINK:") {
                // Test-only: stream reasoning so the TUI's thinking block can be
                // exercised without a reasoning model.
                events.push(Ok(ChatEvent::ReasoningDelta(rest.to_string())));
                events.push(Ok(ChatEvent::TextDelta("done".into())));
            } else if last.trim() == "SYSTEM:" {
                // Test-only: echo the assembled system prompt so recall,
                // instructions, and environment blocks are observable.
                events.push(Ok(ChatEvent::TextDelta(request.system.join("\n"))));
            } else if let Some(rest) = last.strip_prefix("ECHO:") {
                events.push(Ok(ChatEvent::TextDelta(rest.to_string())));
            } else {
                events.push(Ok(ChatEvent::TextDelta("Fake response.".into())));
            }
            events.push(Ok(ChatEvent::Usage {
                input: 10,
                output: 5,
                cache_read: 0,
                cache_write: 0,
                cost: 0.0,
                estimated: false,
            }));
            events.push(Ok(ChatEvent::Finish {
                reason: "stop".into(),
            }));
            Ok(Box::pin(stream::iter(events)))
        }
    }
}

pub mod openai_compatible {
    use super::*;
    use tokio_util::sync::CancellationToken;

    pub struct OpenAiCompatible {
        pub base_url: String,
        pub api_key: Option<String>,
        pub client: reqwest::Client,
        /// Extra headers some gateways require (for example OpenCode's
        /// `User-Agent` and `x-opencode-session`).
        pub headers: Vec<(String, String)>,
        /// OpenCode encodes a thinking level after `:` in its selectors; the
        /// API model id stops at the colon.
        pub strip_variant_suffix: bool,
    }

    impl OpenAiCompatible {
        pub fn new(base_url: &str, api_key: Option<String>) -> Self {
            Self {
                base_url: base_url.trim_end_matches('/').to_string(),
                api_key,
                client: http_client(),
                headers: Vec::new(),
                strip_variant_suffix: false,
            }
        }

        /// OpenCode Go/Zen: separate providers, same key, extra gateway headers.
        pub fn opencode(base_url: &str, api_key: Option<String>) -> Self {
            let mut client = Self::new(base_url, api_key);
            client.headers = vec![
                ("user-agent".into(), "opencode/1.0".into()),
                (
                    "x-opencode-session".into(),
                    uuid::Uuid::new_v4().to_string(),
                ),
            ];
            client.strip_variant_suffix = true;
            client
        }

        fn model_id<'a>(&'a self, id: &'a str) -> &'a str {
            if self.strip_variant_suffix {
                id.split(':').next().unwrap_or(id)
            } else {
                id
            }
        }

        fn with_headers(&self, mut req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
            if let Some(k) = &self.api_key {
                req = req.bearer_auth(k);
            }
            for (name, value) in &self.headers {
                req = req.header(name.as_str(), value.as_str());
            }
            if let Some(id) = sandbox_header() {
                req = req.header("x-freedas-sandbox", id);
            }
            req
        }
    }

    /// `FREEDAS_SANDBOX_ID` names the sandbox a gateway token is scoped to; the
    /// sandbox runner sets it in the container, nothing else does.
    fn sandbox_header() -> Option<String> {
        sandbox_id(std::env::var("FREEDAS_SANDBOX_ID").ok())
    }

    pub(crate) fn sandbox_id(value: Option<String>) -> Option<String> {
        value
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    }

    struct CallAcc {
        id: String,
        name: String,
        args: String,
    }

    struct OpenAiHandler {
        model: ModelRef,
        estimated_input: u64,
        calls: BTreeMap<u64, CallAcc>,
        output_bytes: u64,
        usage_emitted: bool,
        finished: bool,
    }

    impl OpenAiHandler {
        fn flush_calls(&mut self, out: &mut Vec<Result<ChatEvent, ProviderError>>) {
            for (_, call) in std::mem::take(&mut self.calls) {
                if call.name.is_empty() {
                    continue;
                }
                let trimmed = call.args.trim();
                if trimmed.is_empty() {
                    out.push(Ok(ChatEvent::ToolCallEnd {
                        id: call.id,
                        args: serde_json::json!({}),
                    }));
                    continue;
                }
                match serde_json::from_str(trimmed) {
                    Ok(args) => out.push(Ok(ChatEvent::ToolCallEnd { id: call.id, args })),
                    Err(e) => out.push(Ok(ChatEvent::Error(ProviderError {
                        kind: "invalid_tool_call".into(),
                        status: None,
                        message: truncate_body(&format!(
                            "invalid tool arguments for {}: {e}",
                            call.name
                        )),
                        retryable: false,
                    }))),
                }
            }
        }

        fn emit_usage(
            &mut self,
            out: &mut Vec<Result<ChatEvent, ProviderError>>,
            input: u64,
            output: u64,
            cache_read: u64,
        ) {
            if self.usage_emitted {
                return;
            }
            let cost = usage_cost(&self.model, input, output, cache_read);
            out.push(Ok(ChatEvent::Usage {
                input,
                output,
                cache_read,
                cache_write: 0,
                cost,
                estimated: false,
            }));
            self.usage_emitted = true;
        }

        fn emit_estimated_usage(&mut self, out: &mut Vec<Result<ChatEvent, ProviderError>>) {
            if self.usage_emitted {
                return;
            }
            let input = self.estimated_input;
            let output = self.output_bytes / 4;
            let cost = usage_cost(&self.model, input, output, 0);
            out.push(Ok(ChatEvent::Usage {
                input,
                output,
                cache_read: 0,
                cache_write: 0,
                cost,
                estimated: true,
            }));
            self.usage_emitted = true;
        }

        fn finish(&mut self, out: &mut Vec<Result<ChatEvent, ProviderError>>, reason: &str) {
            if self.finished {
                return;
            }
            self.flush_calls(out);
            out.push(Ok(ChatEvent::Finish {
                reason: reason.to_string(),
            }));
            self.finished = true;
        }
    }

    impl SseHandler for OpenAiHandler {
        fn event(&mut self, data: &str) -> Vec<Result<ChatEvent, ProviderError>> {
            let mut out = Vec::new();
            let data = data.trim();
            if data.is_empty() {
                return out;
            }
            if data == "[DONE]" {
                self.finish(&mut out, "stop");
                self.emit_estimated_usage(&mut out);
                return out;
            }
            let v = match serde_json::from_str::<serde_json::Value>(data) {
                Ok(v) => v,
                Err(e) => {
                    out.push(Ok(ChatEvent::Error(ProviderError {
                        kind: "decode".into(),
                        status: None,
                        message: truncate_body(&e.to_string()),
                        retryable: false,
                    })));
                    return out;
                }
            };
            if let Some(usage) = v.get("usage").filter(|u| u.is_object()) {
                let input = usage
                    .get("prompt_tokens")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0);
                let output = usage
                    .get("completion_tokens")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0);
                let cached = usage
                    .get("prompt_tokens_details")
                    .and_then(|d| d.get("cached_tokens"))
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0);
                if input > 0 || output > 0 {
                    self.emit_usage(&mut out, input, output, cached);
                }
            }
            let Some(choice) = v
                .get("choices")
                .and_then(|c| c.as_array())
                .and_then(|a| a.first())
            else {
                return out;
            };
            if let Some(delta) = choice.get("delta") {
                if let Some(content) = delta.get("content").and_then(|c| c.as_str())
                    && !content.is_empty()
                {
                    self.output_bytes += content.len() as u64;
                    out.push(Ok(ChatEvent::TextDelta(content.to_string())));
                }
                if let Some(reasoning) = delta.get("reasoning_content").and_then(|c| c.as_str())
                    && !reasoning.is_empty()
                {
                    self.output_bytes += reasoning.len() as u64;
                    out.push(Ok(ChatEvent::ReasoningDelta(reasoning.to_string())));
                }
                if let Some(list) = delta.get("tool_calls").and_then(|c| c.as_array()) {
                    for call in list {
                        let idx = call.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
                        let entry = self.calls.entry(idx).or_insert_with(|| CallAcc {
                            id: format!("call_{idx}"),
                            name: String::new(),
                            args: String::new(),
                        });
                        if let Some(id) = call
                            .get("id")
                            .and_then(|i| i.as_str())
                            .filter(|i| !i.is_empty())
                        {
                            entry.id = id.to_string();
                        }
                        if entry.name.is_empty()
                            && let Some(name) = call
                                .get("function")
                                .and_then(|f| f.get("name"))
                                .and_then(|n| n.as_str())
                                .filter(|n| !n.is_empty())
                        {
                            entry.name = name.to_string();
                            out.push(Ok(ChatEvent::ToolCallStart {
                                id: entry.id.clone(),
                                name: name.to_string(),
                            }));
                        }
                        if let Some(args) = call
                            .get("function")
                            .and_then(|f| f.get("arguments"))
                            .and_then(|a| a.as_str())
                        {
                            entry.args.push_str(args);
                            out.push(Ok(ChatEvent::ToolCallArgsDelta {
                                id: entry.id.clone(),
                                delta: args.to_string(),
                            }));
                        }
                    }
                }
                if let Some(finish) = choice.get("finish_reason").and_then(|f| f.as_str()) {
                    self.finish(&mut out, finish);
                }
            }
            out
        }

        fn end(&mut self) -> Vec<Result<ChatEvent, ProviderError>> {
            let mut out = Vec::new();
            self.finish(&mut out, "stop");
            self.emit_estimated_usage(&mut out);
            out
        }
    }

    #[async_trait]
    impl super::Provider for OpenAiCompatible {
        fn id(&self) -> &str {
            "openai-compatible"
        }
        async fn models(&self) -> Result<Vec<String>, ProviderError> {
            let url = format!("{}/models", self.base_url);
            let cancel = CancellationToken::new();
            let resp =
                send_with_retry(&cancel, || self.with_headers(self.client.get(&url))).await?;
            let v: serde_json::Value = resp.json().await.map_err(|e| ProviderError {
                kind: "decode".into(),
                status: None,
                message: truncate_body(&e.to_string()),
                retryable: false,
            })?;
            let mut out = Vec::new();
            if let Some(data) = v.get("data").and_then(|d| d.as_array()) {
                for m in data {
                    if let Some(id) = m.get("id").and_then(|i| i.as_str()) {
                        out.push(id.to_string());
                    }
                }
            }
            Ok(out)
        }
        async fn stream(
            &self,
            request: ChatRequest,
            cancel: CancellationToken,
        ) -> Result<BoxStream, ProviderError> {
            let url = format!("{}/chat/completions", self.base_url);
            let mut messages = Vec::new();
            for sys in &request.system {
                messages.push(serde_json::json!({"role": "system", "content": sys}));
            }
            for m in &request.messages {
                if !m.tool_calls.is_empty() {
                    let calls: Vec<serde_json::Value> = m
                        .tool_calls
                        .iter()
                        .map(|c| {
                            serde_json::json!({
                                "id": c.id,
                                "type": "function",
                                "function": {"name": c.name, "arguments": c.arguments},
                            })
                        })
                        .collect();
                    let content = if m.content.is_empty() {
                        serde_json::Value::Null
                    } else {
                        serde_json::json!(m.content)
                    };
                    messages.push(serde_json::json!({
                        "role": "assistant",
                        "content": content,
                        "tool_calls": calls,
                    }));
                } else if let Some(call_id) = &m.tool_call_id {
                    messages.push(serde_json::json!({
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": m.content,
                    }));
                } else {
                    messages.push(serde_json::json!({"role": m.role, "content": m.content}));
                }
            }
            let mut tools = Vec::new();
            for t in &request.tools {
                tools.push(serde_json::json!({"type": "function", "function": {"name": t.name, "description": t.description, "parameters": t.schema}}));
            }
            // Built as a map so `None` optionals are omitted, not serialized as
            // `null` (several providers reject that).
            let mut body = serde_json::Map::new();
            body.insert(
                "model".into(),
                serde_json::json!(self.model_id(&request.model.id)),
            );
            body.insert("messages".into(), serde_json::json!(messages));
            body.insert("stream".into(), serde_json::json!(true));
            body.insert(
                "stream_options".into(),
                serde_json::json!({"include_usage": true}),
            );
            if !tools.is_empty() {
                body.insert("tools".into(), serde_json::json!(tools));
            }
            if let Some(temperature) = request.temperature {
                body.insert("temperature".into(), serde_json::json!(temperature));
            }
            if let Some(max_tokens) = request.max_tokens {
                body.insert("max_tokens".into(), serde_json::json!(max_tokens));
            }
            let handler = OpenAiHandler {
                model: request.model.clone(),
                estimated_input: estimate_input_tokens(&request),
                calls: BTreeMap::new(),
                output_bytes: 0,
                usage_emitted: false,
                finished: false,
            };
            let resp = send_with_retry(&cancel, || {
                self.with_headers(
                    self.client
                        .post(&url)
                        .header("content-type", "application/json")
                        .json(&body),
                )
            })
            .await?;
            Ok(sse_stream(resp, cancel, handler))
        }
    }
}

pub mod anthropic {
    use super::*;
    use tokio_util::sync::CancellationToken;

    pub struct Anthropic {
        pub base_url: String,
        pub api_key: Option<String>,
        pub client: reqwest::Client,
    }

    impl Anthropic {
        pub fn new(api_key: Option<String>) -> Self {
            Self {
                base_url: "https://api.anthropic.com/v1".into(),
                api_key,
                client: http_client(),
            }
        }
    }

    struct ToolBlock {
        id: String,
        name: String,
        json: String,
        tool: bool,
    }

    struct AnthropicHandler {
        model: ModelRef,
        estimated_input: u64,
        blocks: BTreeMap<u64, ToolBlock>,
        input: u64,
        output: u64,
        cache_read: u64,
        cache_write: u64,
        saw_usage: bool,
        usage_emitted: bool,
        output_bytes: u64,
        finished: bool,
    }

    impl AnthropicHandler {
        fn emit_usage(&mut self, out: &mut Vec<Result<ChatEvent, ProviderError>>) {
            if self.usage_emitted {
                return;
            }
            let (input, output, cache_read, cache_write, estimated) = if self.saw_usage {
                (
                    self.input,
                    self.output,
                    self.cache_read,
                    self.cache_write,
                    false,
                )
            } else {
                (self.estimated_input, self.output_bytes / 4, 0, 0, true)
            };
            let cost = usage_cost(&self.model, input, output, cache_read);
            out.push(Ok(ChatEvent::Usage {
                input,
                output,
                cache_read,
                cache_write,
                cost,
                estimated,
            }));
            self.usage_emitted = true;
        }

        fn finish(&mut self, out: &mut Vec<Result<ChatEvent, ProviderError>>, reason: &str) {
            if self.finished {
                return;
            }
            out.push(Ok(ChatEvent::Finish {
                reason: reason.to_string(),
            }));
            self.finished = true;
        }
    }

    impl SseHandler for AnthropicHandler {
        fn event(&mut self, data: &str) -> Vec<Result<ChatEvent, ProviderError>> {
            let mut out = Vec::new();
            let data = data.trim();
            if data.is_empty() {
                return out;
            }
            let v = match serde_json::from_str::<serde_json::Value>(data) {
                Ok(v) => v,
                Err(e) => {
                    out.push(Ok(ChatEvent::Error(ProviderError {
                        kind: "decode".into(),
                        status: None,
                        message: truncate_body(&e.to_string()),
                        retryable: false,
                    })));
                    return out;
                }
            };
            match v.get("type").and_then(|t| t.as_str()) {
                Some("message_start") => {
                    out.push(Ok(ChatEvent::Start));
                    let usage = &v["message"]["usage"];
                    if usage.is_object() {
                        self.input = usage["input_tokens"].as_u64().unwrap_or(0);
                        self.output = usage["output_tokens"].as_u64().unwrap_or(0);
                        self.cache_read = usage["cache_read_input_tokens"].as_u64().unwrap_or(0);
                        self.cache_write =
                            usage["cache_creation_input_tokens"].as_u64().unwrap_or(0);
                        self.saw_usage = true;
                    }
                }
                Some("content_block_start") => {
                    let index = v.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
                    let block = &v["content_block"];
                    let tool = block.get("type").and_then(|t| t.as_str()) == Some("tool_use");
                    let id = if tool {
                        block
                            .get("id")
                            .and_then(|i| i.as_str())
                            .filter(|i| !i.is_empty())
                            .unwrap_or("call")
                            .to_string()
                    } else {
                        String::new()
                    };
                    let name = block
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or_default()
                        .to_string();
                    if tool {
                        out.push(Ok(ChatEvent::ToolCallStart {
                            id: id.clone(),
                            name: name.clone(),
                        }));
                    }
                    self.blocks.insert(
                        index,
                        ToolBlock {
                            id,
                            name,
                            json: String::new(),
                            tool,
                        },
                    );
                }
                Some("content_block_delta") => {
                    let index = v.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
                    let delta = &v["delta"];
                    match delta.get("type").and_then(|t| t.as_str()) {
                        Some("text_delta") => {
                            if let Some(text) = delta
                                .get("text")
                                .and_then(|t| t.as_str())
                                .filter(|t| !t.is_empty())
                            {
                                self.output_bytes += text.len() as u64;
                                out.push(Ok(ChatEvent::TextDelta(text.to_string())));
                            }
                        }
                        Some("thinking_delta") => {
                            if let Some(thinking) = delta
                                .get("thinking")
                                .and_then(|t| t.as_str())
                                .filter(|t| !t.is_empty())
                            {
                                out.push(Ok(ChatEvent::ReasoningDelta(thinking.to_string())));
                            }
                        }
                        Some("input_json_delta") => {
                            if let Some(part) = delta
                                .get("partial_json")
                                .and_then(|p| p.as_str())
                                .filter(|p| !p.is_empty())
                                && let Some(block) = self.blocks.get_mut(&index)
                            {
                                block.json.push_str(part);
                                out.push(Ok(ChatEvent::ToolCallArgsDelta {
                                    id: block.id.clone(),
                                    delta: part.to_string(),
                                }));
                            }
                        }
                        _ => {}
                    }
                }
                Some("content_block_stop") => {
                    let index = v.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
                    if let Some(block) = self.blocks.remove(&index)
                        && block.tool
                    {
                        let trimmed = block.json.trim().to_string();
                        if trimmed.is_empty() {
                            out.push(Ok(ChatEvent::ToolCallEnd {
                                id: block.id,
                                args: serde_json::json!({}),
                            }));
                        } else {
                            match serde_json::from_str::<serde_json::Value>(&trimmed) {
                                Ok(args) => {
                                    out.push(Ok(ChatEvent::ToolCallEnd { id: block.id, args }))
                                }
                                Err(e) => out.push(Ok(ChatEvent::Error(ProviderError {
                                    kind: "invalid_tool_call".into(),
                                    status: None,
                                    message: truncate_body(&format!(
                                        "invalid tool arguments for {}: {e}",
                                        block.name
                                    )),
                                    retryable: false,
                                }))),
                            }
                        }
                    }
                }
                Some("message_delta") => {
                    if let Some(usage) = v.get("usage").filter(|u| u.is_object())
                        && let Some(output) = usage.get("output_tokens").and_then(|o| o.as_u64())
                    {
                        self.output = output;
                        self.saw_usage = true;
                    }
                    let reason = v["delta"]["stop_reason"].as_str().unwrap_or("stop");
                    self.emit_usage(&mut out);
                    self.finish(&mut out, reason);
                }
                Some("message_stop") => {
                    self.emit_usage(&mut out);
                    self.finish(&mut out, "stop");
                }
                Some("error") => {
                    let error = &v["error"];
                    let ty = error
                        .get("type")
                        .and_then(|t| t.as_str())
                        .unwrap_or("api_error");
                    let retryable =
                        matches!(ty, "overloaded_error" | "rate_limit_error" | "api_error");
                    out.push(Ok(ChatEvent::Error(ProviderError {
                        kind: ty.to_string(),
                        status: None,
                        message: truncate_body(
                            error
                                .get("message")
                                .and_then(|m| m.as_str())
                                .unwrap_or("anthropic stream error"),
                        ),
                        retryable,
                    })));
                }
                _ => {}
            }
            out
        }

        fn end(&mut self) -> Vec<Result<ChatEvent, ProviderError>> {
            let mut out = Vec::new();
            for (_, block) in std::mem::take(&mut self.blocks) {
                if !block.tool {
                    continue;
                }
                let trimmed = block.json.trim().to_string();
                if trimmed.is_empty() {
                    out.push(Ok(ChatEvent::ToolCallEnd {
                        id: block.id,
                        args: serde_json::json!({}),
                    }));
                } else {
                    match serde_json::from_str::<serde_json::Value>(&trimmed) {
                        Ok(args) => out.push(Ok(ChatEvent::ToolCallEnd { id: block.id, args })),
                        Err(e) => out.push(Ok(ChatEvent::Error(ProviderError {
                            kind: "invalid_tool_call".into(),
                            status: None,
                            message: truncate_body(&format!(
                                "invalid tool arguments for {}: {e}",
                                block.name
                            )),
                            retryable: false,
                        }))),
                    }
                }
            }
            self.emit_usage(&mut out);
            self.finish(&mut out, "stop");
            out
        }
    }

    #[async_trait]
    impl super::Provider for Anthropic {
        fn id(&self) -> &str {
            "anthropic"
        }
        async fn models(&self) -> Result<Vec<String>, ProviderError> {
            Ok(vec![
                "claude-sonnet-4-5".into(),
                "claude-opus-4-1".into(),
                "claude-haiku-4-5".into(),
            ])
        }
        async fn stream(
            &self,
            request: ChatRequest,
            cancel: CancellationToken,
        ) -> Result<BoxStream, ProviderError> {
            let api_key = self
                .api_key
                .as_deref()
                .map(str::trim)
                .filter(|k| !k.is_empty())
                .ok_or_else(|| ProviderError {
                    kind: "auth".into(),
                    status: None,
                    message: "ANTHROPIC_API_KEY is not set".into(),
                    retryable: false,
                })?;
            let url = format!("{}/messages", self.base_url);
            let mut system: Vec<String> = request.system.clone();
            let mut messages = Vec::new();
            for m in &request.messages {
                match m.role.as_str() {
                    "system" => {
                        if !m.content.is_empty() {
                            system.push(m.content.clone());
                        }
                    }
                    "tool" => match m.tool_call_id.clone().filter(|id| !id.is_empty()) {
                        Some(id) => messages.push(serde_json::json!({
                            "role": "user",
                            "content": [{
                                "type": "tool_result",
                                "tool_use_id": id,
                                "content": m.content,
                            }],
                        })),
                        None => messages.push(serde_json::json!({
                            "role": "user",
                            "content": m.content,
                        })),
                    },
                    "assistant" => {
                        let mut blocks: Vec<serde_json::Value> = Vec::new();
                        if !m.content.is_empty() {
                            blocks.push(serde_json::json!({"type": "text", "text": m.content}));
                        }
                        for call in &m.tool_calls {
                            let input = serde_json::from_str::<serde_json::Value>(&call.arguments)
                                .unwrap_or_else(|_| serde_json::json!({}));
                            blocks.push(serde_json::json!({
                                "type": "tool_use",
                                "id": call.id,
                                "name": call.name,
                                "input": input,
                            }));
                        }
                        if !blocks.is_empty() {
                            messages.push(serde_json::json!({
                                "role": "assistant",
                                "content": blocks,
                            }));
                        }
                    }
                    _ => messages.push(serde_json::json!({
                        "role": "user",
                        "content": m.content,
                    })),
                }
            }
            let mut tools = Vec::new();
            for t in &request.tools {
                tools.push(serde_json::json!({"name": t.name, "description": t.description, "input_schema": t.schema}));
            }
            let mut body = serde_json::Map::new();
            body.insert("model".into(), serde_json::json!(request.model.id));
            body.insert(
                "max_tokens".into(),
                serde_json::json!(request.max_tokens.unwrap_or(8000)),
            );
            if !system.is_empty() {
                body.insert("system".into(), serde_json::json!(system.join("\n\n")));
            }
            body.insert("messages".into(), serde_json::json!(messages));
            if !tools.is_empty() {
                body.insert("tools".into(), serde_json::json!(tools));
            }
            body.insert("stream".into(), serde_json::json!(true));
            if let Some(temperature) = request.temperature {
                body.insert("temperature".into(), serde_json::json!(temperature));
            }
            let handler = AnthropicHandler {
                model: request.model.clone(),
                estimated_input: estimate_input_tokens(&request),
                blocks: BTreeMap::new(),
                input: 0,
                output: 0,
                cache_read: 0,
                cache_write: 0,
                saw_usage: false,
                usage_emitted: false,
                output_bytes: 0,
                finished: false,
            };
            let resp = send_with_retry(&cancel, || {
                self.client
                    .post(&url)
                    .header("content-type", "application/json")
                    .header("anthropic-version", "2023-06-01")
                    .header("x-api-key", api_key)
                    .json(&body)
            })
            .await?;
            Ok(sse_stream(resp, cancel, handler))
        }
    }
}

pub mod gemini {
    use super::*;
    use tokio_util::sync::CancellationToken;

    pub struct Gemini {
        pub base_url: String,
        pub api_key: Option<String>,
        pub client: reqwest::Client,
    }

    fn percent_encode_path(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
        out
    }

    impl Gemini {
        pub fn new(api_key: Option<String>) -> Self {
            Self {
                base_url: "https://generativelanguage.googleapis.com/v1beta".into(),
                api_key,
                client: http_client(),
            }
        }
    }

    struct GeminiHandler {
        model: ModelRef,
        estimated_input: u64,
        next_call: u64,
        input: u64,
        output: u64,
        cache_read: u64,
        saw_usage: bool,
        usage_emitted: bool,
        output_bytes: u64,
        finished: bool,
    }

    impl GeminiHandler {
        fn emit_usage(&mut self, out: &mut Vec<Result<ChatEvent, ProviderError>>) {
            if self.usage_emitted {
                return;
            }
            let (input, output, cache_read, estimated) = if self.saw_usage {
                (self.input, self.output, self.cache_read, false)
            } else {
                (self.estimated_input, self.output_bytes / 4, 0, true)
            };
            let cost = usage_cost(&self.model, input, output, cache_read);
            out.push(Ok(ChatEvent::Usage {
                input,
                output,
                cache_read,
                cache_write: 0,
                cost,
                estimated,
            }));
            self.usage_emitted = true;
        }
    }

    impl SseHandler for GeminiHandler {
        fn event(&mut self, data: &str) -> Vec<Result<ChatEvent, ProviderError>> {
            let mut out = Vec::new();
            let data = data.trim();
            if data.is_empty() {
                return out;
            }
            let v = match serde_json::from_str::<serde_json::Value>(data) {
                Ok(v) => v,
                Err(e) => {
                    out.push(Ok(ChatEvent::Error(ProviderError {
                        kind: "decode".into(),
                        status: None,
                        message: truncate_body(&e.to_string()),
                        retryable: false,
                    })));
                    return out;
                }
            };
            if let Some(error) = v.get("error") {
                let message = error
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("gemini stream error");
                out.push(Ok(ChatEvent::Error(http_error(
                    error.get("code").and_then(|c| c.as_u64()).unwrap_or(500) as u16,
                    message,
                ))));
                return out;
            }
            if let Some(usage) = v.get("usageMetadata").filter(|u| u.is_object()) {
                self.input = usage
                    .get("promptTokenCount")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(self.input);
                self.output = usage
                    .get("candidatesTokenCount")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(self.output);
                self.cache_read = usage
                    .get("cachedContentTokenCount")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(self.cache_read);
                self.saw_usage = true;
            }
            let Some(candidates) = v.get("candidates").and_then(|c| c.as_array()) else {
                return out;
            };
            for candidate in candidates {
                if let Some(parts) = candidate
                    .get("content")
                    .and_then(|c| c.get("parts"))
                    .and_then(|p| p.as_array())
                {
                    for part in parts {
                        if let Some(text) = part
                            .get("text")
                            .and_then(|t| t.as_str())
                            .filter(|t| !t.is_empty())
                        {
                            if part.get("thought").and_then(|t| t.as_bool()) == Some(true) {
                                out.push(Ok(ChatEvent::ReasoningDelta(text.to_string())));
                            } else {
                                self.output_bytes += text.len() as u64;
                                out.push(Ok(ChatEvent::TextDelta(text.to_string())));
                            }
                        }
                        if let Some(call) = part.get("functionCall") {
                            // Gemini has no call id of its own; mint a unique one
                            // so parallel calls do not collide.
                            let id = format!("call_{}", self.next_call);
                            self.next_call += 1;
                            let name = call
                                .get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("tool")
                                .to_string();
                            let args = call
                                .get("args")
                                .cloned()
                                .unwrap_or_else(|| serde_json::json!({}));
                            out.push(Ok(ChatEvent::ToolCallStart {
                                id: id.clone(),
                                name,
                            }));
                            out.push(Ok(ChatEvent::ToolCallEnd { id, args }));
                        }
                    }
                }
                if let Some(reason) = candidate.get("finishReason").and_then(|r| r.as_str()) {
                    let reason = match reason {
                        "STOP" => "stop",
                        "MAX_TOKENS" => "length",
                        other => other,
                    };
                    self.emit_usage(&mut out);
                    if !self.finished {
                        out.push(Ok(ChatEvent::Finish {
                            reason: reason.to_string(),
                        }));
                        self.finished = true;
                    }
                }
            }
            out
        }

        fn end(&mut self) -> Vec<Result<ChatEvent, ProviderError>> {
            let mut out = Vec::new();
            self.emit_usage(&mut out);
            if !self.finished {
                out.push(Ok(ChatEvent::Finish {
                    reason: "stop".into(),
                }));
                self.finished = true;
            }
            out
        }
    }

    #[async_trait]
    impl super::Provider for Gemini {
        fn id(&self) -> &str {
            "google"
        }
        async fn models(&self) -> Result<Vec<String>, ProviderError> {
            Ok(vec!["gemini-2.0-flash".into(), "gemini-2.0-pro".into()])
        }
        async fn stream(
            &self,
            request: ChatRequest,
            cancel: CancellationToken,
        ) -> Result<BoxStream, ProviderError> {
            let api_key = self
                .api_key
                .as_deref()
                .map(str::trim)
                .filter(|k| !k.is_empty())
                .ok_or_else(|| ProviderError {
                    kind: "auth".into(),
                    status: None,
                    message: "GEMINI_API_KEY is not set".into(),
                    retryable: false,
                })?;
            // The key travels in a header: a URL would reach error messages.
            // Model ids are percent-encoded: a `/` or space must not split the path.
            let url = format!(
                "{}/models/{}:streamGenerateContent?alt=sse",
                self.base_url.trim_end_matches('/'),
                percent_encode_path(&request.model.id)
            );
            let mut system: Vec<String> = request.system.clone();
            let mut tool_names: std::collections::HashMap<&str, &str> =
                std::collections::HashMap::new();
            for m in &request.messages {
                for call in &m.tool_calls {
                    tool_names.insert(call.id.as_str(), call.name.as_str());
                }
            }
            let mut contents = Vec::new();
            for m in &request.messages {
                if m.role == "system" {
                    if !m.content.is_empty() {
                        system.push(m.content.clone());
                    }
                } else if m.role == "tool" || m.tool_call_id.is_some() {
                    let id = m.tool_call_id.clone().unwrap_or_default();
                    let name = tool_names.get(id.as_str()).copied().unwrap_or(&id);
                    contents.push(serde_json::json!({
                        "role": "user",
                        "parts": [{"functionResponse": {
                            "name": name,
                            "response": {"result": m.content},
                        }}],
                    }));
                } else if m.role == "assistant" {
                    let mut parts = Vec::new();
                    if !m.content.is_empty() {
                        parts.push(serde_json::json!({"text": m.content}));
                    }
                    for call in &m.tool_calls {
                        let args = serde_json::from_str::<serde_json::Value>(&call.arguments)
                            .unwrap_or_else(|_| serde_json::json!({}));
                        parts.push(serde_json::json!({
                            "functionCall": {"name": call.name, "args": args},
                        }));
                    }
                    if !parts.is_empty() {
                        contents.push(serde_json::json!({"role": "model", "parts": parts}));
                    }
                } else {
                    contents.push(serde_json::json!({
                        "role": "user",
                        "parts": [{"text": m.content}],
                    }));
                }
            }
            let mut tools = Vec::new();
            for t in &request.tools {
                // Gemini rejects `additionalProperties` and other JSON-schema extensions.
                let mut schema = t.schema.clone();
                if let Some(obj) = schema.as_object_mut() {
                    obj.remove("additionalProperties");
                    obj.remove("$schema");
                }
                tools.push(serde_json::json!({"functionDeclarations": [{"name": t.name, "description": t.description, "parameters": schema}]}));
            }
            let mut generation = serde_json::Map::new();
            generation.insert(
                "maxOutputTokens".into(),
                serde_json::json!(request.max_tokens.unwrap_or(8000)),
            );
            if let Some(temperature) = request.temperature {
                generation.insert("temperature".into(), serde_json::json!(temperature));
            }
            let mut body = serde_json::Map::new();
            if !system.is_empty() {
                body.insert(
                    "systemInstruction".into(),
                    serde_json::json!({"parts": [{"text": system.join("\n\n")}]}),
                );
            }
            body.insert("contents".into(), serde_json::json!(contents));
            if !tools.is_empty() {
                body.insert("tools".into(), serde_json::json!(tools));
            }
            body.insert(
                "generationConfig".into(),
                serde_json::Value::Object(generation),
            );
            let handler = GeminiHandler {
                model: request.model.clone(),
                estimated_input: estimate_input_tokens(&request),
                next_call: 0,
                input: 0,
                output: 0,
                cache_read: 0,
                saw_usage: false,
                usage_emitted: false,
                output_bytes: 0,
                finished: false,
            };
            let resp = send_with_retry(&cancel, || {
                self.client
                    .post(&url)
                    .header("content-type", "application/json")
                    .header("x-goog-api-key", api_key)
                    .json(&body)
            })
            .await?;
            Ok(sse_stream(resp, cancel, handler))
        }
    }
}

pub mod credentials;
pub mod oauth;

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use serde_json::Value;
    use tokio_util::sync::CancellationToken;
    use wiremock::matchers::{method, path};
    use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

    fn request(provider: &str, model: &str) -> ChatRequest {
        ChatRequest {
            model: ModelRef {
                provider: provider.into(),
                id: model.into(),
                variant: None,
            },
            system: vec![],
            messages: vec![ChatMessage::new("user", "hi")],
            tools: vec![],
            temperature: None,
            max_tokens: None,
            metadata: Default::default(),
        }
    }

    fn sse(body: &str) -> ResponseTemplate {
        ResponseTemplate::new(200)
            .set_body_string(body)
            .insert_header("content-type", "text/event-stream")
    }

    #[tokio::test]
    async fn openai_stream_parses_text_and_tool() {
        let server = MockServer::start().await;
        let body = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"read\",\"arguments\":\"{\\\"path\\\":\\\"a.txt\\\"}\"}}]},\"finish_reason\":null}]}\n\n",
            "data: {\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":7}}\n\n",
            "data: [DONE]\n\n",
        );
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(sse(body))
            .mount(&server)
            .await;
        let provider =
            openai_compatible::OpenAiCompatible::new(&format!("{}/v1", server.uri()), None);
        let mut stream = provider
            .stream(request("openai", "gpt-4o-mini"), CancellationToken::new())
            .await
            .unwrap();
        let mut text = String::new();
        let mut saw_usage = false;
        while let Some(ev) = stream.next().await {
            match ev.unwrap() {
                ChatEvent::TextDelta(t) => text.push_str(&t),
                ChatEvent::ToolCallStart { name, .. } => assert_eq!(name, "read"),
                ChatEvent::ToolCallArgsDelta { delta, .. } => assert!(delta.contains("a.txt")),
                ChatEvent::Usage { input, output, .. } => {
                    assert_eq!((input, output), (12, 7));
                    saw_usage = true;
                }
                _ => {}
            }
        }
        assert_eq!(text, "Hello");
        assert!(saw_usage);
    }

    #[tokio::test]
    async fn anthropic_accumulates_tool_arguments() {
        let server = MockServer::start().await;
        let body = concat!(
            "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"output_tokens\":1,\"cache_read_input_tokens\":4}}}\n\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"read\",\"input\":{}}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"path\\\":\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\"a.txt\\\"}\"}}\n\n",
            "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":7}}\n\n",
            "data: {\"type\":\"message_stop\"}\n\n",
        );
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(sse(body))
            .mount(&server)
            .await;
        let provider = anthropic::Anthropic {
            base_url: format!("{}/v1", server.uri()),
            api_key: Some("test".into()),
            client: http_client(),
        };
        let mut stream = provider
            .stream(
                request("anthropic", "claude-sonnet-4-5"),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        let mut ended = None;
        let mut usage = None;
        while let Some(ev) = stream.next().await {
            match ev.unwrap() {
                ChatEvent::ToolCallEnd { id, args } => {
                    assert_eq!(id, "toolu_1");
                    ended = Some(args);
                }
                ChatEvent::Usage {
                    input,
                    output,
                    cache_read,
                    ..
                } => usage = Some((input, output, cache_read)),
                _ => {}
            }
        }
        assert_eq!(ended, Some(serde_json::json!({"path": "a.txt"})));
        assert_eq!(usage, Some((10, 7, 4)));
    }

    #[tokio::test]
    async fn anthropic_maps_tool_messages_and_hoists_system() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(sse("data: {\"type\":\"message_stop\"}\n\n"))
            .mount(&server)
            .await;
        let provider = anthropic::Anthropic {
            base_url: format!("{}/v1", server.uri()),
            api_key: Some("test".into()),
            client: http_client(),
        };
        let mut req = request("anthropic", "claude-sonnet-4-5");
        req.system = vec!["base".into()];
        req.messages = vec![
            ChatMessage::new("user", "hi"),
            ChatMessage::new("system", "extra rule"),
            ChatMessage {
                role: "assistant".into(),
                content: String::new(),
                tool_calls: vec![ToolCallRef {
                    id: "toolu_1".into(),
                    name: "read".into(),
                    arguments: "{\"path\":\"a.txt\"}".into(),
                }],
                tool_call_id: None,
            },
            ChatMessage {
                tool_call_id: Some("toolu_1".into()),
                ..ChatMessage::new("tool", "file body")
            },
        ];
        let _stream = provider
            .stream(req, CancellationToken::new())
            .await
            .unwrap();
        let received = server.received_requests().await.unwrap();
        let body: Value = serde_json::from_slice(&received[0].body).unwrap();
        let system = body["system"].as_str().unwrap_or_default();
        assert!(system.contains("base") && system.contains("extra rule"));
        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0]["role"], "user");
        assert_eq!(messages[1]["role"], "assistant");
        assert_eq!(messages[1]["content"][0]["type"], "tool_use");
        assert_eq!(messages[1]["content"][0]["id"], "toolu_1");
        assert_eq!(messages[2]["role"], "user");
        assert_eq!(messages[2]["content"][0]["type"], "tool_result");
        assert_eq!(messages[2]["content"][0]["tool_use_id"], "toolu_1");
    }

    struct NoNullOptionals;

    impl Match for NoNullOptionals {
        fn matches(&self, request: &Request) -> bool {
            let Ok(v) = serde_json::from_slice::<Value>(&request.body) else {
                return false;
            };
            let Some(obj) = v.as_object() else {
                return false;
            };
            !obj.contains_key("temperature") && !obj.contains_key("max_tokens")
        }
    }

    #[tokio::test]
    async fn openai_body_omits_none_optionals() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(NoNullOptionals)
            .respond_with(sse("data: [DONE]\n\n"))
            .mount(&server)
            .await;
        let provider =
            openai_compatible::OpenAiCompatible::new(&format!("{}/v1", server.uri()), None);
        let mut stream = provider
            .stream(request("openai", "gpt-4o-mini"), CancellationToken::new())
            .await
            .unwrap();
        while stream.next().await.is_some() {}
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn retries_retryable_status_then_succeeds() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "0")
                    .set_body_string("rate limited"),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"data":[{"id":"m-1"}]}"#))
            .mount(&server)
            .await;
        let provider =
            openai_compatible::OpenAiCompatible::new(&format!("{}/v1", server.uri()), None);
        assert_eq!(provider.models().await.unwrap(), vec!["m-1".to_string()]);
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[test]
    fn classifies_retryable_errors() {
        assert!(http_error(503, "unavailable").retryable);
        assert!(http_error(429, "slow").retryable);
        assert!(http_error(408, "timeout").retryable);
        assert!(!http_error(400, "bad request").retryable);
        assert_eq!(http_error(401, "no").kind, "auth");
        assert!(!http_error(401, "no").retryable);
        let overflow = http_error(400, "This model's maximum context length is 8192 tokens");
        assert_eq!(overflow.kind, "context_overflow");
        assert!(!overflow.retryable);
    }

    #[test]
    fn normalizes_gateway_base() {
        assert_eq!(
            normalize_v1_base("http://127.0.0.1:8081"),
            "http://127.0.0.1:8081/v1"
        );
        assert_eq!(
            normalize_v1_base("https://gw.example.com/"),
            "https://gw.example.com/v1"
        );
        assert_eq!(
            normalize_v1_base("https://gw.example.com/v1"),
            "https://gw.example.com/v1"
        );
        assert_eq!(
            normalize_v1_base("https://gw.example.com/v1/"),
            "https://gw.example.com/v1"
        );
    }

    #[test]
    fn trims_and_rejects_empty_sandbox_id() {
        assert_eq!(
            openai_compatible::sandbox_id(Some(" sbx_1 ".into())),
            Some("sbx_1".into())
        );
        assert_eq!(openai_compatible::sandbox_id(Some("   ".into())), None);
        assert_eq!(openai_compatible::sandbox_id(None), None);
    }

    #[tokio::test]
    async fn anthropic_reports_in_stream_errors() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(sse(
                "data: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"overloaded\"}}\n\n",
            ))
            .mount(&server)
            .await;
        let provider = anthropic::Anthropic {
            base_url: format!("{}/v1", server.uri()),
            api_key: Some("test".into()),
            client: http_client(),
        };
        let mut stream = provider
            .stream(
                request("anthropic", "claude-sonnet-4-5"),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        let mut error = None;
        while let Some(ev) = stream.next().await {
            if let ChatEvent::Error(e) = ev.unwrap() {
                error = Some(e);
            }
        }
        let error = error.expect("stream error event");
        assert_eq!(error.kind, "overloaded_error");
        assert!(error.retryable);
    }

    #[tokio::test]
    async fn gemini_sends_key_in_header_not_url() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(
                "/v1beta/models/gemini-2.0-flash:streamGenerateContent",
            ))
            .respond_with(sse(
                "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"hi\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":3,\"candidatesTokenCount\":2}}\n\n",
            ))
            .mount(&server)
            .await;
        let provider = gemini::Gemini {
            base_url: format!("{}/v1beta", server.uri()),
            api_key: Some("secret-key".into()),
            client: http_client(),
        };
        let mut stream = provider
            .stream(
                request("google", "gemini-2.0-flash"),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        let mut usage = None;
        while let Some(ev) = stream.next().await {
            if let ChatEvent::Usage { input, output, .. } = ev.unwrap() {
                usage = Some((input, output));
            }
        }
        assert_eq!(usage, Some((3, 2)));
        let received = server.received_requests().await.unwrap();
        let url = received[0].url.to_string();
        assert!(!url.contains("secret-key"));
        assert!(!received[0].url.query_pairs().any(|(key, _)| key == "key"));
        assert_eq!(
            received[0]
                .headers
                .get("x-goog-api-key")
                .unwrap()
                .to_str()
                .unwrap(),
            "secret-key"
        );
    }

    #[tokio::test]
    async fn gemini_fails_early_without_key() {
        let provider = gemini::Gemini {
            base_url: "http://127.0.0.1:1".into(),
            api_key: Some("  ".into()),
            client: http_client(),
        };
        let error = match provider
            .stream(
                request("google", "gemini-2.0-flash"),
                CancellationToken::new(),
            )
            .await
        {
            Ok(_) => panic!("stream should fail without a key"),
            Err(e) => e,
        };
        assert_eq!(error.kind, "auth");
        assert!(!error.retryable);
    }

    #[tokio::test]
    async fn fake_ignores_tool_results_and_parses_write_marker() {
        let mut req = request("fake", "fake-1");
        req.messages = vec![
            ChatMessage {
                tool_call_id: Some("call_1".into()),
                ..ChatMessage::new("tool", "WRITE:evil.txt:boom")
            },
            ChatMessage::new("user", "a:b WRITE:x.txt:hello"),
        ];
        let mut stream = fake::FakeProvider
            .stream(req, CancellationToken::new())
            .await
            .unwrap();
        let mut args = None;
        while let Some(ev) = stream.next().await {
            if let ChatEvent::ToolCallEnd { args: parsed, .. } = ev.unwrap() {
                args = Some(parsed);
            }
        }
        assert_eq!(
            args,
            Some(serde_json::json!({"path": "x.txt", "content": "hello"}))
        );

        let mut req = request("fake", "fake-1");
        req.messages = vec![ChatMessage {
            tool_call_id: Some("call_1".into()),
            ..ChatMessage::new("tool", "WRITE:evil.txt:boom")
        }];
        let mut stream = fake::FakeProvider
            .stream(req, CancellationToken::new())
            .await
            .unwrap();
        let mut text = String::new();
        while let Some(ev) = stream.next().await {
            match ev.unwrap() {
                ChatEvent::TextDelta(t) => text.push_str(&t),
                ChatEvent::ToolCallStart { .. } => panic!("tool result must not trigger a call"),
                _ => {}
            }
        }
        assert_eq!(text, "Fake response.");
    }

    #[tokio::test]
    async fn fake_does_not_repeat_a_tool_call() {
        let mut req = request("fake", "fake-1");
        req.messages = vec![
            ChatMessage::new("user", "WRITE:x.txt:hello"),
            ChatMessage {
                role: "assistant".into(),
                content: String::new(),
                tool_calls: vec![ToolCallRef {
                    id: "call_fake_1".into(),
                    name: "write".into(),
                    arguments: serde_json::json!({"path": "x.txt", "content": "hello"}).to_string(),
                }],
                tool_call_id: None,
            },
            ChatMessage {
                tool_call_id: Some("call_fake_1".into()),
                ..ChatMessage::new("tool", "ok")
            },
        ];
        let mut stream = fake::FakeProvider
            .stream(req, CancellationToken::new())
            .await
            .unwrap();
        let mut text = String::new();
        let mut calls = 0;
        while let Some(ev) = stream.next().await {
            match ev.unwrap() {
                ChatEvent::TextDelta(t) => text.push_str(&t),
                ChatEvent::ToolCallStart { .. } => calls += 1,
                _ => {}
            }
        }
        assert_eq!(calls, 0, "the already-issued call must not repeat");
        assert_eq!(text, "Fake response.");
    }
}
