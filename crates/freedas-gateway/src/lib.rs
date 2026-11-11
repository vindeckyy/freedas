//! OpenAI-compatible gateway: model listing, transparent proxying, `freedas/auto`
//! model routing, workspace budget enforcement, and usage metering.

use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::State,
    http::{
        HeaderMap, StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE},
    },
    response::Response,
    routing::{get, post},
};
use freedas_catalog::ModelInfo;
use freedas_router::StepContext;
use futures::{StreamExt, stream};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

type ApiError = (StatusCode, Json<Value>);
type ApiResult<T = Json<Value>> = Result<T, ApiError>;

/// Upstream credential per provider. The inbound workspace token is never
/// forwarded upstream.
#[derive(Clone)]
pub struct AppState {
    client: reqwest::Client,
    upstream: String,
    pool: Option<PgPool>,
    keys: Arc<BTreeMap<String, String>>,
    insecure_no_auth: bool,
}

impl AppState {
    pub fn new(upstream: String, pool: Option<PgPool>) -> Self {
        Self {
            client: reqwest::Client::new(),
            upstream: upstream.trim_end_matches('/').to_string(),
            pool,
            keys: Arc::new(BTreeMap::new()),
            insecure_no_auth: false,
        }
    }

    /// Registers an upstream API key for one provider.
    pub fn with_upstream_key(
        mut self,
        provider: impl Into<String>,
        key: impl Into<String>,
    ) -> Self {
        let key = key.into();
        if !key.trim().is_empty() {
            Arc::make_mut(&mut self.keys).insert(provider.into(), key);
        }
        self
    }

    /// Accepts any non-empty bearer without a database. Only for local testing;
    /// the binary refuses to start this way without an explicit flag.
    pub fn with_insecure_no_auth(mut self) -> Self {
        self.insecure_no_auth = true;
        self
    }

    fn key_for(&self, provider: &str) -> Option<&str> {
        self.keys.get(provider).map(String::as_str)
    }

    /// Providers with a configured upstream credential.
    fn authenticated_catalog(&self) -> Vec<ModelInfo> {
        freedas_catalog::builtin_catalog()
            .into_iter()
            .filter(|m| self.key_for(&m.provider).is_some())
            .collect()
    }
}

/// Provider env vars read by the binary at startup. `opencode-go` and `meta`
/// are wired here so the gateway's authenticated catalog covers the same
/// providers the session path reaches via OAuth (they share `OPENCODE_API_KEY`
/// across the OpenCode Go/Zen surfaces).
pub const PROVIDER_ENV_KEYS: &[(&str, &str)] = &[
    ("openai", "OPENAI_API_KEY"),
    ("anthropic", "ANTHROPIC_API_KEY"),
    ("google", "GEMINI_API_KEY"),
    ("openrouter", "OPENROUTER_API_KEY"),
    ("deepseek", "DEEPSEEK_API_KEY"),
    ("opencode-go", "OPENCODE_API_KEY"),
    ("meta", "META_API_KEY"),
];

/// Canonical upstream env is `FREEDAS_GATEWAY_UPSTREAM`; the legacy binary
/// name still works once so existing deploys do not silently reroute.
fn upstream_env() -> String {
    if let Ok(v) = std::env::var("FREEDAS_GATEWAY_UPSTREAM") {
        return v;
    }
    if let Ok(v) = std::env::var("FREEDAS_UPSTREAM_URL") {
        tracing::warn!("FREEDAS_UPSTREAM_URL is deprecated; use FREEDAS_GATEWAY_UPSTREAM");
        return v;
    }
    "https://api.openai.com/v1".into()
}

pub fn app() -> Router {
    let upstream = upstream_env();
    let mut state = AppState::new(upstream, None);
    for (provider, env) in PROVIDER_ENV_KEYS {
        if let Some(key) = std::env::var(env).ok().filter(|k| !k.trim().is_empty()) {
            state = state.with_upstream_key(*provider, key);
        }
    }
    if std::env::var("FREEDAS_GATEWAY_INSECURE_NO_AUTH").as_deref() == Ok("1") {
        state = state.with_insecure_no_auth();
    }
    app_with_state(state)
}

pub fn app_with_state(state: AppState) -> Router {
    Router::new()
        .route("/v1/models", get(models))
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/embeddings", post(embeddings))
        .with_state(state)
}

#[cfg(test)]
fn app_with_upstream(upstream: String) -> Router {
    app_with_state(
        AppState::new(upstream, None)
            .with_upstream_key("openai", "sk-upstream")
            .with_insecure_no_auth(),
    )
}

/// SHA-256 hex digest of the raw bearer token, the at-rest token representation.
pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?.trim();
    (!token.is_empty()).then_some(token)
}

fn error(status: StatusCode, kind: &str, message: &str) -> ApiError {
    (
        status,
        Json(json!({ "error": { "type": kind, "message": message } })),
    )
}

fn unauthorized() -> ApiError {
    error(
        StatusCode::UNAUTHORIZED,
        "invalid_request_error",
        "missing or invalid bearer token",
    )
}

fn forbidden(message: &str) -> ApiError {
    error(StatusCode::FORBIDDEN, "invalid_request_error", message)
}

fn bad_request(message: &str) -> ApiError {
    error(StatusCode::BAD_REQUEST, "invalid_request_error", message)
}

fn internal(_e: sqlx::Error) -> ApiError {
    error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        "database error",
    )
}

fn payment_required() -> ApiError {
    error(
        StatusCode::PAYMENT_REQUIRED,
        "insufficient_funds",
        "workspace balance or budget does not cover the request",
    )
}

#[derive(Debug, Clone, Default)]
struct Auth {
    token_id: Option<String>,
    user_id: Option<String>,
    workspace_id: Option<String>,
    scopes: Vec<String>,
}

/// Resolves the bearer token against `api_tokens`. Without a pool the gateway
/// only accepts requests in explicit `insecure_no_auth` mode.
async fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<Auth, ApiError> {
    let token = bearer(headers).ok_or_else(unauthorized)?;
    let Some(pool) = &state.pool else {
        if state.insecure_no_auth {
            return Ok(Auth::default());
        }
        return Err(unauthorized());
    };
    let row = sqlx::query_as::<_, (String, Option<String>, Option<String>, Option<String>)>(
        "SELECT id, user_id, workspace_id, scopes FROM api_tokens
         WHERE token_hash = $1 AND revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at > $2)",
    )
    .bind(hash_token(token))
    .bind(now_ms())
    .fetch_optional(pool)
    .await
    .map_err(internal)?
    .ok_or_else(unauthorized)?;
    Ok(Auth {
        token_id: Some(row.0),
        user_id: row.1,
        workspace_id: row.2,
        scopes: parse_scopes(row.3.as_deref()),
    })
}

fn parse_scopes(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or_default()
        .trim_matches(|c| c == '{' || c == '}')
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// A sandbox token is bound to one sandbox and may not act as a workspace key.
/// The sandbox id is client-supplied, so the gateway only accepts it when the
/// request names a sandbox the token is scoped to; anything else is rejected.
/// Non-sandbox scopes are allowlisted for model access: empty (legacy tokens
/// and `insecure_no_auth`), `model`, `write`, `read`, or `*`. Any other
/// explicit scope (e.g. billing-only) cannot call the model endpoints.
fn model_access_allowed(scopes: &[String], sandbox_header: Option<&str>) -> bool {
    let sandboxes: Vec<&str> = scopes
        .iter()
        .filter_map(|s| s.strip_prefix("sandbox:"))
        .collect();
    if !sandboxes.is_empty() {
        return sandbox_header.is_some_and(|id| sandboxes.contains(&id));
    }
    if scopes.is_empty() {
        return true;
    }
    scopes.iter().any(|s| {
        matches!(
            s.as_str(),
            "model" | "write" | "read" | "*" | "chat" | "completions"
        )
    })
}

fn ensure_model_access(auth: &Auth, headers: &HeaderMap) -> Result<(), ApiError> {
    let sandbox = headers
        .get("x-freedas-sandbox")
        .and_then(|v| v.to_str().ok());
    if model_access_allowed(&auth.scopes, sandbox) {
        Ok(())
    } else if auth.scopes.iter().any(|s| s.starts_with("sandbox:")) {
        Err(forbidden(
            "sandbox token is bound to a different sandbox or missing x-freedas-sandbox",
        ))
    } else {
        Err(forbidden("token scopes do not allow model access"))
    }
}

fn provider_of(model: &str) -> &str {
    model.split_once('/').map(|(p, _)| p).unwrap_or("openai")
}

async fn models(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    let auth = authenticate(&state, &headers).await?;
    ensure_model_access(&auth, &headers)?;
    let data: Vec<Value> = state
        .authenticated_catalog()
        .iter()
        .map(|m| {
            json!({
                "id": m.full_id(),
                "object": "model",
                "created": 0,
                "owned_by": m.provider,
            })
        })
        .collect();
    Ok(Json(json!({ "object": "list", "data": data })))
}

async fn chat_completions(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    let auth = authenticate(&state, &headers).await?;
    ensure_model_access(&auth, &headers)?;
    let mut request: Value =
        serde_json::from_slice(&body).map_err(|_| bad_request("request body must be JSON"))?;
    if !request.is_object() {
        return Err(bad_request("request body must be a JSON object"));
    }
    let requested = request
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if requested.is_empty() {
        return Err(bad_request("model is required"));
    }
    let stream = request
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let session = headers
        .get("x-freedas-session")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    // A caller must not bill another workspace by replaying its session id:
    // when the session is already recorded, its workspace must match the
    // token's. Unknown sessions are allowed; the control plane records them
    // on first use — a documented first-claim semantic: concurrent first-use
    // of a fresh id from two workspaces races, but metering always bills the
    // caller's own token, so no cross-workspace charge is possible.
    if let (Some(pool), Some(session_id), Some(workspace_id)) = (
        &state.pool,
        session.as_deref(),
        auth.workspace_id.as_deref(),
    ) && let Some(owner) = sqlx::query_scalar::<_, Option<String>>(
        "SELECT workspace_id FROM session_metadata WHERE session_id = $1",
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await
    .map_err(internal)?
    .flatten()
        && owner != workspace_id
    {
        return Err(forbidden("session belongs to another workspace"));
    }
    let input_tokens = estimate_input_tokens(&request);

    let mut routed = None;
    let concrete = if matches!(requested.as_str(), "freedas/auto" | "freedas/auto-cheap") {
        let decision = route(
            &requested,
            &request,
            &state.authenticated_catalog(),
            input_tokens,
            session.as_deref().unwrap_or(""),
        )
        .map_err(|e| {
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                &format!("routing failed: {e}"),
            )
        })?;
        routed = Some(decision.model.clone());
        decision.model
    } else {
        requested
    };

    let catalog = freedas_catalog::builtin_catalog();
    let info = freedas_catalog::get_model(&catalog, &concrete)
        .cloned()
        .ok_or_else(|| bad_request(&format!("unknown model: {concrete}")))?;
    if state.key_for(&info.provider).is_none() {
        return Err(gateway_error(&format!(
            "no upstream credential configured for provider {}",
            info.provider
        )));
    }
    request["model"] = json!(concrete);
    if stream {
        // Needed for the final usage chunk that the gateway meters.
        let options = request
            .as_object_mut()
            .expect("request is an object")
            .entry("stream_options")
            .or_insert_with(|| json!({}));
        if let Some(options) = options.as_object_mut() {
            options.insert("include_usage".into(), Value::Bool(true));
        }
    }
    let estimated_cost = estimate_cost(&info, input_tokens, request_max_tokens(&request));
    let reservation = reserve_for(&state, &auth, estimated_cost).await?;
    let forward_body = serde_json::to_vec(&request).map_err(|_| bad_request("invalid body"))?;
    let upstream = match send(&state, &info.provider, forward_body, "/chat/completions").await {
        Ok(upstream) => upstream,
        Err(e) => {
            release_reservation(state.pool.as_ref(), reservation).await;
            return Err(e);
        }
    };
    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = upstream.headers().get(CONTENT_TYPE).cloned();

    if !status.is_success() {
        let bytes = upstream.bytes().await.unwrap_or_default();
        release_reservation(state.pool.as_ref(), reservation).await;
        return Ok(raw_response(status, content_type, Body::from(bytes), None));
    }

    let meter = meter_for(
        &state,
        &auth,
        session,
        Pricing::Model(info),
        &concrete,
        input_tokens,
        reservation,
    );

    if stream {
        let body = match meter {
            Some(meter) => metered_body(upstream, meter),
            None => Body::from_stream(upstream.bytes_stream()),
        };
        return Ok(raw_response(status, content_type, body, routed.as_deref()));
    }

    let bytes = upstream
        .bytes()
        .await
        .map_err(|_| gateway_error("upstream request failed"))?;
    if let Some(meter) = meter {
        let value = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
        let usage = usage_from_body(&value, meter.estimated_input);
        record_meter(meter, usage).await;
    }
    Ok(raw_response(
        status,
        content_type,
        Body::from(bytes),
        routed.as_deref(),
    ))
}

/// Embedding input price per million tokens, per model (OpenAI list prices).
/// Kept here because the catalog has no embedding entries.
const EMBEDDING_PRICES: &[(&str, f64)] = &[
    ("text-embedding-3-small", 0.02),
    ("text-embedding-3-large", 0.13),
    ("text-embedding-ada-002", 0.10),
];

/// Input price per million tokens for a request model, with or without the
/// `openai/` prefix.
fn embedding_price(model: &str) -> Option<f64> {
    let bare = model.strip_prefix("openai/").unwrap_or(model);
    EMBEDDING_PRICES
        .iter()
        .find(|(m, _)| *m == bare)
        .map(|(_, p)| *p)
}

async fn embeddings(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    let auth = authenticate(&state, &headers).await?;
    ensure_model_access(&auth, &headers)?;

    let request: Value =
        serde_json::from_slice(&body).map_err(|_| bad_request("request body must be JSON"))?;
    if !request.is_object() {
        return Err(bad_request("request body must be a JSON object"));
    }
    let model = request
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if model.is_empty() {
        return Err(bad_request("model is required"));
    }
    // Embeddings is priced from a fixed table, so it cannot meter arbitrary
    // model names the way catalog-priced chat can; only known models pass.
    if embedding_price(&model).is_none() {
        return Err(bad_request(&format!("unknown embedding model: {model}")));
    }
    let provider = provider_of(&model).to_owned();
    if state.key_for(&provider).is_none() {
        return Err(gateway_error(&format!(
            "no upstream credential configured for provider {provider}"
        )));
    }
    let input_tokens = estimate_embedding_tokens(&request);
    let estimated_cost = embedding_cost(&model, input_tokens);
    let reservation = reserve_for(&state, &auth, estimated_cost).await?;
    let forward_body = serde_json::to_vec(&request).map_err(|_| bad_request("invalid body"))?;
    let upstream = match send(&state, &provider, forward_body, "/embeddings").await {
        Ok(upstream) => upstream,
        Err(e) => {
            release_reservation(state.pool.as_ref(), reservation).await;
            return Err(e);
        }
    };
    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = upstream.headers().get(CONTENT_TYPE).cloned();

    if !status.is_success() {
        let bytes = upstream.bytes().await.unwrap_or_default();
        release_reservation(state.pool.as_ref(), reservation).await;
        return Ok(raw_response(status, content_type, Body::from(bytes), None));
    }

    let bytes = upstream
        .bytes()
        .await
        .map_err(|_| gateway_error("upstream request failed"))?;
    if let Some(meter) = meter_for(
        &state,
        &auth,
        None,
        Pricing::Embedding(model.clone()),
        &model,
        input_tokens,
        reservation,
    ) {
        let value = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
        let usage = parse_usage(&value).unwrap_or(Usage {
            input_tokens,
            output_tokens: 0,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
        });
        record_meter(meter, usage).await;
    }
    Ok(raw_response(status, content_type, Body::from(bytes), None))
}

fn raw_response(
    status: StatusCode,
    content_type: Option<axum::http::HeaderValue>,
    body: Body,
    model: Option<&str>,
) -> Response {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    if let Some(value) = content_type {
        response.headers_mut().insert(CONTENT_TYPE, value);
    }
    add_model_header(&mut response, model);
    response
}

/// Sends a request upstream with the provider's own credential.
async fn send(
    state: &AppState,
    provider: &str,
    body: Vec<u8>,
    path: &str,
) -> Result<reqwest::Response, ApiError> {
    let key = state
        .key_for(provider)
        .ok_or_else(|| gateway_error("upstream credential is not configured"))?;
    state
        .client
        .post(format!("{}{path}", state.upstream))
        .header(AUTHORIZATION, format!("Bearer {key}"))
        .header(CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
        .map_err(|_| gateway_error("upstream request failed"))
}

fn gateway_error(message: &str) -> ApiError {
    error(StatusCode::BAD_GATEWAY, "server_error", message)
}

fn add_model_header(response: &mut Response, model: Option<&str>) {
    if let Some(model) = model
        && let Ok(value) = axum::http::HeaderValue::from_str(model)
    {
        response.headers_mut().insert("x-freedas-model", value);
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn month_start_ms() -> i64 {
    let now = time::OffsetDateTime::now_utc();
    let first = time::Date::from_calendar_date(now.year(), now.month(), 1)
        .expect("first of month is a valid date");
    first.midnight().assume_utc().unix_timestamp() * 1000
}

// ---------------------------------------------------------------------------
// Usage accounting
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Input tokens served from the provider cache; billed at the cache price.
    pub cache_read_tokens: u64,
    /// Input tokens written into the provider cache; billed at the
    /// cache-write price (typically higher than fresh input).
    pub cache_write_tokens: u64,
}

/// Reads OpenAI-style `usage.prompt_tokens` / `usage.completion_tokens`
/// (also accepts the Responses API `input_tokens` / `output_tokens` names).
/// `completion_tokens` is optional because embeddings report input only.
pub fn parse_usage(body: &Value) -> Option<Usage> {
    let usage = body.get("usage")?;
    let input = usage
        .get("prompt_tokens")
        .or_else(|| usage.get("input_tokens"))?
        .as_u64()?;
    let output = usage
        .get("completion_tokens")
        .or_else(|| usage.get("output_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let cache_read_tokens = usage
        .get("prompt_tokens_details")
        .and_then(|d| d.get("cached_tokens"))
        .and_then(Value::as_u64)
        .or_else(|| usage.get("cache_read_input_tokens").and_then(Value::as_u64))
        .unwrap_or(0);
    let cache_write_tokens = usage
        .get("cache_creation_input_tokens")
        .or_else(|| usage.get("cache_write_input_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    Some(Usage {
        input_tokens: input,
        output_tokens: output,
        cache_read_tokens,
        cache_write_tokens,
    })
}

pub fn estimate_input_tokens(request: &Value) -> u64 {
    let mut chars = 0usize;
    if let Some(messages) = request.get("messages").and_then(Value::as_array) {
        for message in messages {
            chars += content_chars(message.get("content"));
        }
    }
    chars += content_chars(request.get("system"));
    if let Some(tools) = request.get("tools") {
        chars += tools.to_string().chars().count();
    }
    (chars / 4).max(1) as u64
}

fn estimate_embedding_tokens(request: &Value) -> u64 {
    (content_chars(request.get("input")) / 4).max(1) as u64
}

fn content_chars(value: Option<&Value>) -> usize {
    match value {
        Some(Value::String(s)) => s.chars().count(),
        Some(Value::Array(parts)) => parts
            .iter()
            .map(|p| match p {
                Value::String(s) => s.chars().count(),
                _ => p
                    .get("text")
                    .and_then(Value::as_str)
                    .map(|s| s.chars().count())
                    .unwrap_or(0),
            })
            .sum(),
        Some(Value::Object(map)) => map
            .get("text")
            .and_then(Value::as_str)
            .map(|s| s.chars().count())
            .unwrap_or(0),
        _ => 0,
    }
}

/// Cost of the expected output budget (request `max_tokens`, else 1024) plus the
/// estimated input at this model's prices.
pub fn estimate_cost(model: &ModelInfo, input_tokens: u64, max_tokens: Option<u64>) -> f64 {
    let output = max_tokens.unwrap_or(1_024).min(model.max_output);
    model.estimate_cost(input_tokens, output)
}

fn usage_cost(model: &ModelInfo, usage: Usage) -> f64 {
    let cost = model.usage_cost(
        usage.input_tokens,
        usage.cache_read_tokens,
        usage.cache_write_tokens,
        usage.output_tokens,
    );
    (cost * 1e6).round() / 1e6
}

/// Cost of an embedding request. `model` is validated against
/// `EMBEDDING_PRICES` before metering, so an unknown name prices at 0.
fn embedding_cost(model: &str, input_tokens: u64) -> f64 {
    let price = embedding_price(model).unwrap_or_default();
    (input_tokens as f64 / 1e6 * price * 1e6).round() / 1e6
}

fn request_max_tokens(request: &Value) -> Option<u64> {
    request
        .get("max_tokens")
        .or_else(|| request.get("max_completion_tokens"))
        .and_then(Value::as_u64)
}

fn usage_from_body(body: &Value, estimated_input: u64) -> Usage {
    parse_usage(body).unwrap_or_else(|| Usage {
        input_tokens: estimated_input,
        output_tokens: output_estimate(body),
        cache_read_tokens: 0,
        cache_write_tokens: 0,
    })
}

/// Never record zero tokens when a provider omits usage.
fn output_estimate(body: &Value) -> u64 {
    let chars: usize = body
        .get("choices")
        .and_then(Value::as_array)
        .map(|choices| {
            choices
                .iter()
                .map(|c| {
                    c.get("message")
                        .and_then(|m| m.get("content"))
                        .and_then(Value::as_str)
                        .map(|s| s.chars().count())
                        .unwrap_or(0)
                })
                .sum()
        })
        .unwrap_or(0);
    (chars / 4).max(1) as u64
}

// ---------------------------------------------------------------------------
// Streaming usage tap
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Pricing {
    Model(ModelInfo),
    Embedding(String),
}

impl Pricing {
    fn cost(&self, usage: Usage) -> f64 {
        match self {
            Pricing::Model(model) => usage_cost(model, usage),
            Pricing::Embedding(model) => embedding_cost(model, usage.input_tokens),
        }
    }
}

/// Everything needed to meter one request once its response settles.
#[derive(Clone)]
struct Meter {
    pool: PgPool,
    token_id: Option<String>,
    workspace_id: String,
    user_id: Option<String>,
    session_id: Option<String>,
    model: String,
    pricing: Pricing,
    estimated_input: u64,
    reservation: Option<Reservation>,
}

fn meter_for(
    state: &AppState,
    auth: &Auth,
    session: Option<String>,
    pricing: Pricing,
    model: &str,
    estimated_input: u64,
    reservation: Option<Reservation>,
) -> Option<Meter> {
    let pool = state.pool.clone()?;
    let workspace_id = auth.workspace_id.clone()?;
    Some(Meter {
        pool,
        token_id: auth.token_id.clone(),
        workspace_id,
        user_id: auth.user_id.clone(),
        session_id: session,
        model: model.to_string(),
        pricing,
        estimated_input,
        reservation,
    })
}

async fn record_meter(meter: Meter, usage: Usage) {
    let cost = meter.pricing.cost(usage);
    if let Err(e) = record_usage(
        &meter.pool,
        meter.token_id.as_deref(),
        &meter.workspace_id,
        meter.user_id.as_deref(),
        meter.session_id.as_deref(),
        &meter.model,
        usage,
        cost,
        meter.reservation.as_ref(),
    )
    .await
    {
        tracing::warn!(error = %e, "gateway: usage metering failed");
    }
}

/// Parses SSE `data:` chunks, keeping the last usage object and the response
/// text length so a provider that omits usage is still metered.
#[derive(Default)]
struct SseTap {
    buffer: Vec<u8>,
    usage: Option<Usage>,
    output_chars: usize,
}

impl SseTap {
    fn observe(&mut self, chunk: &[u8]) {
        self.buffer.extend_from_slice(chunk);
        while let Some(pos) = self.buffer.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.buffer.drain(..=pos).collect();
            self.observe_line(&line);
        }
        // Never retain more than one unterminated line.
        if self.buffer.len() > 1 << 20 {
            let keep = self.buffer.len() - 4096;
            self.buffer.drain(..keep);
        }
    }

    fn observe_line(&mut self, line: &[u8]) {
        let text = String::from_utf8_lossy(line);
        let Some(data) = text.trim_end().strip_prefix("data:") else {
            return;
        };
        let data = data.trim();
        if data.is_empty() || data == "[DONE]" {
            return;
        }
        let Ok(value) = serde_json::from_str::<Value>(data) else {
            return;
        };
        if let Some(usage) = parse_usage(&value) {
            self.usage = Some(usage);
        }
        self.output_chars += delta_content_chars(&value);
    }

    fn usage(&self, estimated_input: u64) -> Usage {
        self.usage.unwrap_or(Usage {
            input_tokens: estimated_input,
            output_tokens: (self.output_chars / 4).max(1) as u64,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
        })
    }
}

fn delta_content_chars(value: &Value) -> usize {
    value
        .get("choices")
        .and_then(Value::as_array)
        .map(|choices| {
            choices
                .iter()
                .filter_map(|c| {
                    c.get("delta")
                        .and_then(|d| d.get("content"))
                        .and_then(Value::as_str)
                })
                .map(|s| s.chars().count())
                .sum()
        })
        .unwrap_or(0)
}

/// Stream state whose Drop records metering even when the client disconnects
/// before the terminal arm runs — a dropped Body must still debit real usage.
struct MeterState {
    tap: SseTap,
    meter: Option<Meter>,
}

impl MeterState {
    fn record(&mut self) {
        if let Some(meter) = self.meter.take() {
            let usage = self.tap.usage(meter.estimated_input);
            tokio::spawn(record_meter(meter, usage));
        }
    }
}

impl Drop for MeterState {
    fn drop(&mut self) {
        self.record();
    }
}

/// Forwards the upstream stream and meters it when it ends.
fn metered_body(upstream: reqwest::Response, meter: Meter) -> Body {
    let stream = stream::unfold(
        (
            upstream.bytes_stream(),
            MeterState {
                tap: SseTap::default(),
                meter: Some(meter),
            },
        ),
        |(mut chunks, mut state)| async move {
            match chunks.next().await {
                Some(Ok(chunk)) => {
                    state.tap.observe(&chunk);
                    Some((Ok::<Bytes, reqwest::Error>(chunk), (chunks, state)))
                }
                Some(Err(error)) => {
                    state.record();
                    Some((Err(error), (chunks, state)))
                }
                None => {
                    state.record();
                    None
                }
            }
        },
    );
    Body::from_stream(stream)
}

#[allow(clippy::too_many_arguments)]
async fn record_usage(
    pool: &PgPool,
    token_id: Option<&str>,
    workspace_id: &str,
    user_id: Option<&str>,
    session_id: Option<&str>,
    model: &str,
    usage: Usage,
    cost: f64,
    reservation: Option<&Reservation>,
) -> Result<(), sqlx::Error> {
    let event_id = format!("use_{}", ulid::Ulid::new());
    let provider = model.split_once('/').map(|(p, _)| p).unwrap_or("unknown");
    // Sub-half-microdollar costs round to zero and would ride free; clamp any
    // nonzero metered cost to the ledger's smallest representable debit.
    let cost = (cost * 1e6).round() / 1e6;
    let cost = if cost <= 0.0 && usage.input_tokens + usage.output_tokens > 0 {
        1e-6
    } else {
        cost
    };

    let mut tx = pool.begin().await?;
    // Serialize metering against reservations so the balance check below sees
    // every concurrent request's estimate.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(workspace_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO usage_events
         (id, workspace_id, user_id, session_id, kind, provider, model,
          input_tokens, output_tokens, cost_usd, created_at)
         VALUES ($1, $2, $3, $4, 'model', $5, $6, $7, $8, $9::numeric, $10)",
    )
    .bind(&event_id)
    .bind(workspace_id)
    .bind(user_id)
    .bind(session_id)
    .bind(provider)
    .bind(model)
    .bind(usage.input_tokens as i64)
    .bind(usage.output_tokens as i64)
    .bind(format!("{cost:.6}"))
    .bind(now_ms())
    .execute(&mut *tx)
    .await?;
    if let Some(reservation) = reservation
        && reservation.workspace_id == workspace_id
    {
        // The estimate was already debited; move the ledger to the real cost.
        let adjustment = ((reservation.amount - cost) * 1e6).round() / 1e6;
        if adjustment.abs() >= 1e-9 {
            sqlx::query(
                "INSERT INTO wallet_ledger (id, workspace_id, delta_usd, reason, ref, created_at)
                 VALUES ($1, $2, $3::numeric, 'reservation_reconcile', $4, $5)",
            )
            .bind(format!("led_{}", ulid::Ulid::new()))
            .bind(workspace_id)
            .bind(format!("{adjustment:.6}"))
            .bind(&reservation.id)
            .bind(now_ms())
            .execute(&mut *tx)
            .await?;
        }
    } else if cost > 0.0 {
        sqlx::query(
            "INSERT INTO wallet_ledger (id, workspace_id, delta_usd, reason, ref, created_at)
             VALUES ($1, $2, $3::numeric, $4, NULL, $5)",
        )
        .bind(format!("led_{}", ulid::Ulid::new()))
        .bind(workspace_id)
        .bind(format!("{:.6}", -cost))
        .bind(format!("model_usage:{event_id}"))
        .bind(now_ms())
        .execute(&mut *tx)
        .await?;
    }
    // The estimate-time check can be stale by the time the real cost lands
    // (retries, concurrent requests, underestimated output). Re-check inside
    // the same transaction so overspend is at least observed atomically;
    // metering must not fail the request that already consumed the tokens.
    let balance: f64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(delta_usd), 0)::float8 FROM wallet_ledger WHERE workspace_id = $1",
    )
    .bind(workspace_id)
    .fetch_one(&mut *tx)
    .await?;
    if balance < -1e-9 {
        // Error-level so alerting pipelines flag it: the workspace consumed
        // more than its estimate and the next request will hit an empty wallet.
        tracing::error!(
            workspace_id = %workspace_id,
            balance,
            cost,
            "gateway: workspace overspent after metering"
        );
    }
    tx.commit().await?;

    if let Some(id) = token_id {
        sqlx::query("UPDATE api_tokens SET last_used_at = $1 WHERE id = $2")
            .bind(now_ms())
            .bind(id)
            .execute(pool)
            .await?;
    }
    Ok(())
}

async fn release_reservation(pool: Option<&PgPool>, reservation: Option<Reservation>) {
    let (Some(pool), Some(reservation)) = (pool, reservation) else {
        return;
    };
    if reservation.amount <= 0.0 {
        return;
    }
    if let Err(e) = sqlx::query(
        "INSERT INTO wallet_ledger (id, workspace_id, delta_usd, reason, ref, created_at)
         VALUES ($1, $2, $3::numeric, 'reservation_release', $4, $5)",
    )
    .bind(format!("led_{}", ulid::Ulid::new()))
    .bind(&reservation.workspace_id)
    .bind(format!("{:.6}", reservation.amount))
    .bind(&reservation.id)
    .bind(now_ms())
    .execute(pool)
    .await
    {
        tracing::warn!(error = %e, "gateway: releasing reservation failed");
    }
}

// ---------------------------------------------------------------------------
// Budget enforcement
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct BudgetRow {
    pub scope: String,
    pub limit_usd: f64,
    pub period: String,
    /// Spend already attributed to this budget's scope for its period.
    pub spent: f64,
}

pub struct BudgetInputs<'a> {
    pub balance: f64,
    pub est_cost: f64,
    pub budgets: &'a [BudgetRow],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetDecision {
    Allowed,
    InsufficientFunds,
}

/// Funds must cover the estimate; every resolved budget caps spend for its
/// period.
pub fn budget_decision(input: &BudgetInputs<'_>) -> BudgetDecision {
    if input.balance + 1e-9 < input.est_cost {
        return BudgetDecision::InsufficientFunds;
    }
    for budget in input.budgets {
        if budget.spent + input.est_cost > budget.limit_usd + 1e-9 {
            return BudgetDecision::InsufficientFunds;
        }
    }
    BudgetDecision::Allowed
}

#[derive(Debug, Clone)]
pub struct Reservation {
    id: String,
    workspace_id: String,
    amount: f64,
}

async fn reserve_for(
    state: &AppState,
    auth: &Auth,
    est_cost: f64,
) -> Result<Option<Reservation>, ApiError> {
    let Some(pool) = &state.pool else {
        return Ok(None);
    };
    let workspace = auth
        .workspace_id
        .as_deref()
        .ok_or_else(|| forbidden("token is not bound to a workspace"))?;
    reserve_budget(pool, workspace, auth.user_id.as_deref(), est_cost)
        .await
        .map(Some)
}

/// Checks and reserves the estimate in one transaction, so concurrent requests
/// cannot both pass against the same balance.
async fn reserve_budget(
    pool: &PgPool,
    workspace_id: &str,
    user_id: Option<&str>,
    est_cost: f64,
) -> Result<Reservation, ApiError> {
    let mut tx = pool.begin().await.map_err(internal)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(workspace_id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;

    let balance = wallet_balance(&mut tx, workspace_id)
        .await
        .map_err(internal)?;
    let rows = sqlx::query_as::<_, (String, f64, String, Option<String>)>(
        "SELECT scope, limit_usd::float8, period, subject_id
           FROM budgets WHERE workspace_id = $1",
    )
    .bind(workspace_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(internal)?;
    let month = month_start_ms();
    let mut budgets = Vec::with_capacity(rows.len());
    for (scope, limit_usd, period, subject_id) in rows {
        let spent = match scope.as_str() {
            "user" => {
                let Some(user) = subject_id.as_deref().or(user_id) else {
                    continue;
                };
                // The workspace lock alone lets two concurrent calls by the
                // same user both pass; the per-user key serializes them.
                sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                    .bind(format!("{workspace_id}:user:{user}"))
                    .execute(&mut *tx)
                    .await
                    .map_err(internal)?;
                spent_user(&mut tx, workspace_id, user, &period, month)
                    .await
                    .map_err(internal)?
            }
            "team" => {
                let Some(team) = subject_id.as_deref() else {
                    continue;
                };
                sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                    .bind(format!("{workspace_id}:team:{team}"))
                    .execute(&mut *tx)
                    .await
                    .map_err(internal)?;
                spent_team(&mut tx, workspace_id, team, &period, month)
                    .await
                    .map_err(internal)?
            }
            _ => spent_workspace(&mut tx, workspace_id, &period, month)
                .await
                .map_err(internal)?,
        };
        budgets.push(BudgetRow {
            scope,
            limit_usd,
            period,
            spent,
        });
    }

    let inputs = BudgetInputs {
        balance,
        est_cost,
        budgets: &budgets,
    };
    if budget_decision(&inputs) == BudgetDecision::InsufficientFunds {
        return Err(payment_required());
    }

    let id = format!("rsv_{}", ulid::Ulid::new());
    sqlx::query(
        "INSERT INTO wallet_ledger (id, workspace_id, delta_usd, reason, ref, created_at)
         VALUES ($1, $2, $3::numeric, 'reservation', $4, $5)",
    )
    .bind(format!("led_{}", ulid::Ulid::new()))
    .bind(workspace_id)
    .bind(format!("{:.6}", -est_cost.max(1e-6)))
    .bind(&id)
    .bind(now_ms())
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    Ok(Reservation {
        id,
        workspace_id: workspace_id.to_string(),
        amount: est_cost.max(1e-6),
    })
}

async fn wallet_balance(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    workspace_id: &str,
) -> Result<f64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COALESCE(SUM(delta_usd), 0)::float8 FROM wallet_ledger WHERE workspace_id = $1",
    )
    .bind(workspace_id)
    .fetch_one(&mut **tx)
    .await
}

async fn spent_workspace(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    workspace_id: &str,
    period: &str,
    month: i64,
) -> Result<f64, sqlx::Error> {
    // Gross spend: metered model cost plus wallet-billed compute. Credits
    // (positive ledger deltas) must not offset it; mirrors control
    // `budget_spend`. In-flight estimates are not in `usage_events` yet,
    // so open reservations count too.
    let monthly = period == "monthly";
    let usage_sql = if monthly {
        "SELECT COALESCE(SUM(cost_usd), 0)::float8 FROM usage_events
          WHERE workspace_id = $1 AND created_at >= $2"
    } else {
        "SELECT COALESCE(SUM(cost_usd), 0)::float8 FROM usage_events
          WHERE workspace_id = $1"
    };
    let mut query = sqlx::query_scalar(usage_sql).bind(workspace_id);
    if monthly {
        query = query.bind(month);
    }
    let usage: f64 = query.fetch_one(&mut **tx).await?;
    let compute = compute_spend(&mut *tx, workspace_id, monthly, month).await?;
    let open = open_reservations(&mut *tx, workspace_id, monthly, month).await?;
    Ok(((usage + compute + open) * 1e6).round() / 1e6)
}

/// Sandbox compute is billed through the wallet, not `usage_events`, and
/// cannot be attributed to a person or team; only the workspace budget sees
/// it. Mirrors control `budget_spend`.
async fn compute_spend(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    workspace_id: &str,
    monthly: bool,
    month: i64,
) -> Result<f64, sqlx::Error> {
    let sql = if monthly {
        "SELECT COALESCE(SUM(-delta_usd), 0)::float8 FROM wallet_ledger
          WHERE workspace_id = $1 AND created_at >= $2 AND delta_usd < 0
            AND (reason LIKE 'compute%' OR reason LIKE 'sandbox_compute%')"
    } else {
        "SELECT COALESCE(SUM(-delta_usd), 0)::float8 FROM wallet_ledger
          WHERE workspace_id = $1 AND delta_usd < 0
            AND (reason LIKE 'compute%' OR reason LIKE 'sandbox_compute%')"
    };
    let mut query = sqlx::query_scalar(sql).bind(workspace_id);
    if monthly {
        query = query.bind(month);
    }
    query.fetch_one(&mut **tx).await
}

/// Estimates held by requests that reserved but have not metered yet: a
/// `reservation` debit with no matching reconcile/release row. Counted so
/// concurrent requests cannot each pass against the same balance. The ledger
/// carries no user/team attribution, so the workspace total counts against
/// user and team budgets too (fail closed).
async fn open_reservations(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    workspace_id: &str,
    monthly: bool,
    month: i64,
) -> Result<f64, sqlx::Error> {
    let sql = if monthly {
        "SELECT COALESCE(SUM(-r.delta_usd), 0)::float8 FROM wallet_ledger r
          WHERE r.workspace_id = $1 AND r.reason = 'reservation' AND r.created_at >= $2
            AND NOT EXISTS (SELECT 1 FROM wallet_ledger c
                            WHERE c.workspace_id = r.workspace_id AND c.ref = r.ref
                              AND (c.reason = 'reservation_reconcile'
                                   OR c.reason = 'reservation_release'))"
    } else {
        "SELECT COALESCE(SUM(-r.delta_usd), 0)::float8 FROM wallet_ledger r
          WHERE r.workspace_id = $1 AND r.reason = 'reservation'
            AND NOT EXISTS (SELECT 1 FROM wallet_ledger c
                            WHERE c.workspace_id = r.workspace_id AND c.ref = r.ref
                              AND (c.reason = 'reservation_reconcile'
                                   OR c.reason = 'reservation_release'))"
    };
    let mut query = sqlx::query_scalar(sql).bind(workspace_id);
    if monthly {
        query = query.bind(month);
    }
    query.fetch_one(&mut **tx).await
}

async fn spent_user(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    workspace_id: &str,
    user_id: &str,
    period: &str,
    month: i64,
) -> Result<f64, sqlx::Error> {
    let monthly = period == "monthly";
    let sql = if monthly {
        "SELECT COALESCE(SUM(cost_usd), 0)::float8 FROM usage_events
          WHERE workspace_id = $1 AND user_id = $2 AND created_at >= $3"
    } else {
        "SELECT COALESCE(SUM(cost_usd), 0)::float8 FROM usage_events
          WHERE workspace_id = $1 AND user_id = $2"
    };
    let mut query = sqlx::query_scalar(sql).bind(workspace_id).bind(user_id);
    if monthly {
        query = query.bind(month);
    }
    let usage: f64 = query.fetch_one(&mut **tx).await?;
    let open = open_reservations(&mut *tx, workspace_id, monthly, month).await?;
    Ok(((usage + open) * 1e6).round() / 1e6)
}

async fn spent_team(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    workspace_id: &str,
    team_id: &str,
    period: &str,
    month: i64,
) -> Result<f64, sqlx::Error> {
    let monthly = period == "monthly";
    let sql = if monthly {
        "SELECT COALESCE(SUM(cost_usd), 0)::float8 FROM usage_events
          WHERE workspace_id = $1
            AND user_id IN (SELECT user_id FROM team_members WHERE team_id = $2)
            AND created_at >= $3"
    } else {
        "SELECT COALESCE(SUM(cost_usd), 0)::float8 FROM usage_events
          WHERE workspace_id = $1
            AND user_id IN (SELECT user_id FROM team_members WHERE team_id = $2)"
    };
    let mut query = sqlx::query_scalar(sql).bind(workspace_id).bind(team_id);
    if monthly {
        query = query.bind(month);
    }
    let usage: f64 = query.fetch_one(&mut **tx).await?;
    let open = open_reservations(&mut *tx, workspace_id, monthly, month).await?;
    Ok(((usage + open) * 1e6).round() / 1e6)
}

// ---------------------------------------------------------------------------
// Auto model routing
// ---------------------------------------------------------------------------

fn route(
    requested: &str,
    request: &Value,
    catalog: &[ModelInfo],
    input_tokens: u64,
    session_hint: &str,
) -> Result<freedas_router::Decision, freedas_router::RouterError> {
    // The gateway is stateless, so derive the step from the conversation
    // instead of pinning it to zero: each message is one increment. The hint
    // is the session when one is given, otherwise a hash of the prompt so
    // concurrent anonymous requests do not share exploration randomness.
    let messages = request
        .get("messages")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let turn = messages
        .iter()
        .filter(|m| m.get("role").and_then(Value::as_str) == Some("user"))
        .count()
        .saturating_sub(1) as u32;
    let step = messages.len().min(u32::MAX as usize) as u32;
    let prompt = last_user_text(request);
    let hint_owned;
    let hint = if session_hint.is_empty() || session_hint == "gateway" {
        let mut h: u64 = 0xcbf29ce484222325;
        for &b in prompt.as_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        hint_owned = format!("anon-{h:016x}");
        &hint_owned
    } else {
        session_hint
    };
    let ctx = StepContext {
        // `auto-cheap` reuses the quick-plan selection: cheap tier, lower floor.
        agent: if requested == "freedas/auto-cheap" {
            "plan-quick".into()
        } else {
            "build".into()
        },
        turn,
        step,
        prompt,
        estimated_input_tokens: input_tokens,
        tool_calls_so_far: 0,
        failures_so_far: 0,
        files_touched: 0,
        last_error: None,
        plan_mode: false,
        review_mode: false,
        pinned_model: None,
        workspace_remaining_usd: None,
        quality_floor: None,
        max_escalations: None,
        estimated_cached_input: 0,
    };
    // The gateway has no per-session learning history; use static priors.
    freedas_router::select_with(&ctx, catalog, &[], hint, false)
}

fn last_user_text(request: &Value) -> String {
    request
        .get("messages")
        .and_then(Value::as_array)
        .and_then(|messages| {
            messages
                .iter()
                .rev()
                .find(|m| m.get("role").and_then(Value::as_str) == Some("user"))
        })
        .map(|message| match message.get("content") {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Array(parts)) => parts
                .iter()
                .filter_map(|p| p.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n"),
            _ => String::new(),
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::Request;
    use tower::ServiceExt;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn body_json(response: Response) -> Value {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        serde_json::from_slice(&bytes).expect("json")
    }

    #[tokio::test]
    async fn lists_models_in_openai_shape() {
        let app = app_with_upstream("http://127.0.0.1:1/v1".into());
        let request = Request::builder()
            .uri("/v1/models")
            .header("authorization", "Bearer test")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value = body_json(response).await;
        assert_eq!(value["object"], "list");
        let data = value["data"].as_array().expect("data array");
        assert!(!data.is_empty());
        assert_eq!(data[0]["object"], "model");
        assert!(data[0]["id"].as_str().unwrap().contains('/'));
        assert!(data[0]["owned_by"].is_string());
        // Only providers with an upstream key are listed.
        assert!(data.iter().all(|m| m["owned_by"] == "openai"));
    }

    #[tokio::test]
    async fn rejects_missing_token() {
        let app = app_with_upstream("http://127.0.0.1:1/v1".into());
        let request = Request::builder()
            .uri("/v1/models")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let value = body_json(response).await;
        assert_eq!(value["error"]["type"], "invalid_request_error");
    }

    #[tokio::test]
    async fn refuses_requests_without_a_database_unless_insecure() {
        let state = AppState::new("http://127.0.0.1:1/v1".into(), None)
            .with_upstream_key("openai", "sk-upstream");
        let app = app_with_state(state);
        let request = Request::builder()
            .uri("/v1/models")
            .header("authorization", "Bearer anything")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn never_forwards_the_inbound_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(header("authorization", "Bearer sk-upstream"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(r#"{"id":"c1"}"#, "application/json"),
            )
            .mount(&server)
            .await;

        let app = app_with_upstream(format!("{}/v1", server.uri()));
        let request = Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer workspace-token")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"model":"openai/gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}"#,
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 1);
        let authorization = requests[0]
            .headers
            .get("authorization")
            .expect("authorization header")
            .to_str()
            .unwrap();
        assert_eq!(authorization, "Bearer sk-upstream");
        assert!(!authorization.contains("workspace-token"));
        assert!(!String::from_utf8_lossy(&requests[0].body).contains("workspace-token"));
    }

    #[tokio::test]
    async fn rejects_unknown_models() {
        let app = app_with_upstream("http://127.0.0.1:1/v1".into());
        let request = Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer test")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"model":"openai/not-a-model","messages":[]}"#,
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let value = body_json(response).await;
        assert!(
            value["error"]["message"]
                .as_str()
                .unwrap()
                .contains("unknown model")
        );
    }

    #[tokio::test]
    async fn proxies_chat_completions() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(header("authorization", "Bearer sk-upstream"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(r#"{"id":"chatcmpl-1"}"#, "application/json"),
            )
            .mount(&server)
            .await;

        let app = app_with_upstream(format!("{}/v1", server.uri()));
        let request = Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer sk-test")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"model":"openai/gpt-4o-mini","messages":[]}"#,
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get("x-freedas-model").is_none());
        let value = body_json(response).await;
        assert_eq!(value["id"], "chatcmpl-1");
    }

    #[tokio::test]
    async fn routes_auto_model_before_forwarding() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                r#"{"id":"c1","usage":{"prompt_tokens":5,"completion_tokens":2}}"#,
                "application/json",
            ))
            .mount(&server)
            .await;

        let app = app_with_upstream(format!("{}/v1", server.uri()));
        let request = Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer sk-test")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"model":"freedas/auto","messages":[{"role":"user","content":"Fix a typo in the README"}]}"#,
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let routed = response
            .headers()
            .get("x-freedas-model")
            .expect("routed model header")
            .to_str()
            .unwrap()
            .to_owned();
        assert_ne!(routed, "freedas/auto");
        assert!(freedas_catalog::get_model(&freedas_catalog::builtin_catalog(), &routed).is_some());

        let requests = server.received_requests().await.expect("requests");
        let sent: Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(sent["model"], routed);
    }

    #[tokio::test]
    async fn forwards_upstream_error_status() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/embeddings"))
            .respond_with(ResponseTemplate::new(429).set_body_string("rate limited"))
            .mount(&server)
            .await;

        let app = app_with_upstream(format!("{}/v1", server.uri()));
        let request = Request::builder()
            .method("POST")
            .uri("/v1/embeddings")
            .header("authorization", "Bearer sk-test")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"model":"openai/text-embedding-3-small","input":"hi"}"#,
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn hashes_tokens_as_lowercase_sha256_hex() {
        assert_eq!(
            hash_token("test"),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
        assert_eq!(hash_token("x").len(), 64);
    }

    #[test]
    fn sandbox_scopes_require_a_matching_sandbox() {
        assert!(model_access_allowed(&[], None));
        assert!(model_access_allowed(&["read".into()], None));
        assert!(!model_access_allowed(&["sandbox:sbx_1".into()], None));
        assert!(!model_access_allowed(
            &["sandbox:sbx_1".into()],
            Some("sbx_2")
        ));
        assert!(model_access_allowed(
            &["sandbox:sbx_1".into()],
            Some("sbx_1")
        ));
    }

    #[test]
    fn budget_blocks_short_balance_and_every_budget_scope() {
        let none: &[BudgetRow] = &[];
        let ok = BudgetInputs {
            balance: 5.0,
            est_cost: 0.01,
            budgets: none,
        };
        assert_eq!(budget_decision(&ok), BudgetDecision::Allowed);

        let over_estimate = BudgetInputs {
            balance: 0.02,
            est_cost: 0.03,
            budgets: none,
        };
        assert_eq!(
            budget_decision(&over_estimate),
            BudgetDecision::InsufficientFunds
        );

        let budgets = vec![
            BudgetRow {
                scope: "workspace".into(),
                limit_usd: 1.0,
                period: "total".into(),
                spent: 0.99,
            },
            BudgetRow {
                scope: "user".into(),
                limit_usd: 0.0,
                period: "total".into(),
                spent: 0.0,
            },
            BudgetRow {
                scope: "team".into(),
                limit_usd: 100.0,
                period: "monthly".into(),
                spent: 99.99,
            },
        ];
        let over = BudgetInputs {
            balance: 100.0,
            est_cost: 0.02,
            budgets: &budgets,
        };
        assert_eq!(budget_decision(&over), BudgetDecision::InsufficientFunds);
        let under = BudgetInputs {
            balance: 100.0,
            est_cost: 0.02,
            budgets: &budgets[1..],
        };
        assert_eq!(budget_decision(&under), BudgetDecision::InsufficientFunds);
    }

    #[test]
    fn parses_openai_usage_with_cached_tokens() {
        let value = json!({"usage":{"prompt_tokens":12,"completion_tokens":3}});
        assert_eq!(
            parse_usage(&value),
            Some(Usage {
                input_tokens: 12,
                output_tokens: 3,
                cache_read_tokens: 0,
                cache_write_tokens: 0,
            })
        );
        assert_eq!(parse_usage(&json!({"id":"x"})), None);
        assert_eq!(
            parse_usage(&json!({"usage":{"input_tokens":1,"output_tokens":2}})),
            Some(Usage {
                input_tokens: 1,
                output_tokens: 2,
                cache_read_tokens: 0,
                cache_write_tokens: 0,
            })
        );
        assert_eq!(
            parse_usage(&json!({"usage":{"prompt_tokens":100,"completion_tokens":5,
                "prompt_tokens_details":{"cached_tokens":80}}})),
            Some(Usage {
                input_tokens: 100,
                output_tokens: 5,
                cache_read_tokens: 80,
                cache_write_tokens: 0,
            })
        );
        assert_eq!(
            parse_usage(&json!({"usage":{"prompt_tokens":7}})),
            Some(Usage {
                input_tokens: 7,
                output_tokens: 0,
                cache_read_tokens: 0,
                cache_write_tokens: 0,
            })
        );
    }

    #[test]
    fn cached_tokens_bill_at_the_cache_price() {
        let catalog = freedas_catalog::builtin_catalog();
        let model =
            freedas_catalog::get_model(&catalog, "anthropic/claude-sonnet-4-5").expect("model");
        let full = usage_cost(
            model,
            Usage {
                input_tokens: 1_000_000,
                output_tokens: 0,
                cache_read_tokens: 0,
                cache_write_tokens: 0,
            },
        );
        let cached = usage_cost(
            model,
            Usage {
                input_tokens: 1_000_000,
                output_tokens: 0,
                cache_read_tokens: 1_000_000,
                cache_write_tokens: 0,
            },
        );
        assert!((full - 3.0).abs() < 1e-9);
        assert!(cached < full);
        assert!((cached - model.cost_cache_read).abs() < 1e-9);
    }

    #[test]
    fn input_estimate_includes_tools_and_system() {
        let bare = estimate_input_tokens(&json!({"messages":[]}));
        let with_tools = estimate_input_tokens(&json!({
            "messages": [],
            "system": "a".repeat(400),
            "tools": [{"type":"function","function":{"name":"read","description":"reads files","parameters":{"type":"object"}}}],
        }));
        assert!(with_tools > bare + 100);
    }

    #[test]
    fn sse_tap_reads_usage_split_across_chunks() {
        let mut tap = SseTap::default();
        tap.observe(b"data: {\"choices\":[{\"delta\":{\"content\":\"hello \"}}]}\n\nda");
        assert_eq!(tap.usage(50).input_tokens, 50);
        tap.observe(
            b"ta: {\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":4,",
        );
        tap.observe(b"\"prompt_tokens_details\":{\"cached_tokens\":2}}}\n\ndata: [DONE]\n\n");
        let usage = tap.usage(50);
        assert_eq!(
            usage,
            Usage {
                input_tokens: 11,
                output_tokens: 4,
                cache_read_tokens: 2,
                cache_write_tokens: 0,
            }
        );
    }

    #[test]
    fn sse_tap_estimates_when_no_usage_chunk_arrives() {
        let mut tap = SseTap::default();
        tap.observe(b"data: {\"choices\":[{\"delta\":{\"content\":\"abcdefgh\"}}]}\n\n");
        let usage = tap.usage(20);
        assert_eq!(usage.input_tokens, 20);
        assert_eq!(usage.output_tokens, 2);
    }

    #[test]
    fn embedding_cost_is_per_model() {
        let small = embedding_cost("text-embedding-3-small", 1_000_000);
        let large = embedding_cost("text-embedding-3-large", 1_000_000);
        let ada = embedding_cost("openai/text-embedding-ada-002", 1_000_000);
        assert_eq!(small, 0.02);
        assert_eq!(large, 0.13);
        assert_eq!(ada, 0.10);
        assert_eq!(embedding_cost("no-such-model", 1_000_000), 0.0);
    }
}
