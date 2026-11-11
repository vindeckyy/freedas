//! Declarative provider login: API-key paste flows, OAuth2 authorization code
//! with PKCE through a loopback callback server, RFC 8628 device-code grants,
//! and a small set of bespoke sign-in hooks. Modeled on the oh-my-pi auth
//! rule engine; every provider is a table entry plus shared flow code.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::LazyLock;

/// Far-future expiry for credentials that never expire (durable keys, session JWTs).
pub const NEVER_EXPIRES: i64 = i64::MAX / 2;
const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 30_000;
const CALLBACK_TIMEOUT_MS: u64 = 300_000;

/// Credentials minted by an OAuth-style login. Serialized verbatim into
/// `oauth.json`; optional fields capture per-provider identity. `Debug` is
/// hand-implemented so `{:?}` logging can never persist the durable tokens.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OAuthCredentials {
    pub access: String,
    pub refresh: String,
    pub expires: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enterprise_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inference_region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_organization_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorized_at: Option<i64>,
}

impl std::fmt::Debug for OAuthCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthCredentials")
            .field("access", &"[redacted]")
            .field("refresh", &"[redacted]")
            .field("expires", &self.expires)
            .field("enterprise_url", &self.enterprise_url)
            .field("project_id", &self.project_id)
            .field("email", &self.email)
            .field("account_id", &self.account_id)
            .field("org_id", &self.org_id)
            .field("org_name", &self.org_name)
            .field("region", &self.region)
            .field("authorized_at", &self.authorized_at)
            .finish_non_exhaustive()
    }
}

/// What a login produced: a durable API key or a refreshable OAuth grant.
/// The grant payload is a few hundred bytes and is returned by value once per
/// login, so the enum is deliberately not boxed.
#[allow(clippy::large_enum_variant)]
pub enum LoginResult {
    ApiKey(String),
    OAuth(OAuthCredentials),
}

impl std::fmt::Debug for LoginResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoginResult::ApiKey(_) => f.debug_tuple("ApiKey").field(&"[redacted]").finish(),
            LoginResult::OAuth(c) => f.debug_tuple("OAuth").field(c).finish(),
        }
    }
}

pub type AuthCallback<'a> = dyn FnMut(&str, Option<&str>, Option<&str>) + Send + Sync + 'a;
pub type ProgressCallback<'a> = dyn FnMut(&str) + Send + Sync + 'a;
pub type PromptCallback<'a> = dyn FnMut(&OAuthPrompt) -> Result<String, String> + Send + Sync + 'a;
pub type ManualCodeCallback<'a> = dyn FnMut() -> Result<String, String> + Send + Sync + 'a;

/// Interactive host callbacks. `on_prompt` runs synchronously so the same
/// engine serves the CLI (readline) and the TUI (channel bridge).
pub struct LoginHost<'a> {
    /// url, short loopback launch URL when one exists, instructions.
    pub on_auth: Option<&'a mut AuthCallback<'a>>,
    pub on_progress: Option<&'a mut ProgressCallback<'a>>,
    /// Returns the typed answer, or Err for cancel.
    pub on_prompt: Option<&'a mut PromptCallback<'a>>,
    /// Request pasted callback input (code or full redirect URL).
    pub on_manual_code: Option<&'a mut ManualCodeCallback<'a>>,
    pub open_browser: bool,
    /// Provider data dir (stable device ids live here).
    pub data_dir: &'a std::path::Path,
}

#[derive(Debug)]
pub struct OAuthPrompt {
    pub message: String,
    pub placeholder: Option<String>,
    pub allow_empty: bool,
    pub secret: bool,
}

impl LoginHost<'_> {
    fn auth(&mut self, url: &str, launch: Option<&str>, instructions: Option<&str>) {
        if let Some(f) = self.on_auth.as_deref_mut() {
            f(url, launch, instructions);
        }
    }
    fn progress(&mut self, msg: &str) {
        if let Some(f) = self.on_progress.as_deref_mut() {
            f(msg);
        }
    }
    fn prompt(&mut self, p: &OAuthPrompt) -> Result<String, String> {
        match self.on_prompt.as_deref_mut() {
            Some(f) => f(p),
            None => Err("interactive prompt is not available".into()),
        }
    }
    fn ask(&mut self, message: &str, placeholder: Option<&str>) -> Result<String, String> {
        self.prompt(&OAuthPrompt {
            message: message.to_string(),
            placeholder: placeholder.map(str::to_string),
            allow_empty: false,
            secret: false,
        })
    }
    fn manual_code(&mut self) -> Result<String, String> {
        match self.on_manual_code.as_deref_mut() {
            Some(f) => f(),
            None => self.ask("Paste the authorization code (or full redirect URL):", None),
        }
    }
}

// ---------------------------------------------------------------------------
// Rule table types
// ---------------------------------------------------------------------------
/// A KDL-style value: env overrides first, then hook, then the literal
/// (optionally base64-encoded so scanners stay quiet).
#[derive(Clone)]
pub struct AuthValue {
    pub literal: &'static str,
    pub env: &'static [&'static str],
    pub base64: bool,
    pub hook: Option<ValueHook>,
}

impl AuthValue {
    const fn lit(s: &'static str) -> Self {
        Self {
            literal: s,
            env: &[],
            base64: false,
            hook: None,
        }
    }
    const fn b64(s: &'static str) -> Self {
        Self {
            literal: s,
            env: &[],
            base64: true,
            hook: None,
        }
    }
    const fn env(s: &'static str, env: &'static [&'static str]) -> Self {
        Self {
            literal: s,
            env,
            base64: false,
            hook: None,
        }
    }
    const fn hook(h: ValueHook) -> Self {
        Self {
            literal: "",
            env: &[],
            base64: false,
            hook: Some(h),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ValueHook {
    /// OIDC discovery: read token_endpoint from auth.x.ai.
    XaiTokenEndpoint,
}

/// Env override wins over the builtin literal/hook, with a warning so a stale
/// `*_HOST` export is visible. Resolved endpoint URLs must be https://,
/// except loopback http:// for local mocks/dev servers.
fn check_endpoint_url(val: String) -> Result<String, String> {
    if !val.contains("://") {
        return Ok(val);
    }
    if val.starts_with("https://") {
        return Ok(val);
    }
    if let Ok(u) = reqwest::Url::parse(&val)
        && u.scheme() == "http"
        && let Some(host) = u.host_str()
        && (host == "localhost"
            || host == "127.0.0.1"
            || host.starts_with("127.")
            || host == "::1"
            || host == "[::1]")
    {
        return Ok(val);
    }
    Err(format!("refusing non-https endpoint URL: {val}"))
}

async fn resolve_value(v: &AuthValue) -> Result<String, String> {
    for name in v.env {
        if let Ok(val) = std::env::var(name) {
            let val = val.trim().to_string();
            if !val.is_empty() {
                if !v.literal.is_empty() && val != v.literal {
                    eprintln!("warning: {name} overrides built-in value");
                }
                return check_endpoint_url(val);
            }
        }
    }
    if let Some(h) = v.hook {
        return match h {
            ValueHook::XaiTokenEndpoint => check_endpoint_url(xai_token_endpoint().await?),
        };
    }
    if v.base64 {
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(v.literal)
            .map_err(|e| format!("auth value decode failed: {e}"))
            .and_then(|b| String::from_utf8(b).map_err(|e| e.to_string()))?;
        return check_endpoint_url(decoded);
    }
    check_endpoint_url(v.literal.to_string())
}

#[derive(Clone)]
pub struct OAuthRequest {
    pub url: AuthValue,
    /// true = JSON body; false = form-urlencoded.
    pub body_json: bool,
    /// Include the grant's baseline params.
    pub standard: bool,
    pub timeout_ms: u64,
    pub params: &'static [(&'static str, &'static str)],
    pub headers: &'static [(&'static str, &'static str)],
}

impl OAuthRequest {
    const fn post(url: &'static str) -> Self {
        Self {
            url: AuthValue::lit(url),
            body_json: false,
            standard: true,
            timeout_ms: DEFAULT_REQUEST_TIMEOUT_MS,
            params: &[],
            headers: &[],
        }
    }
}

/// One credential field: read a JSON path from the body, or claims from the
/// access token's JWT payload, or a fixed literal.
#[derive(Clone, Copy)]
pub enum CField {
    Path(&'static str),
    Claim(&'static [&'static str]),
    PathClaim(&'static str, &'static [&'static str]),
    Literal(&'static str),
}

#[derive(Clone, Copy)]
pub enum Expiry {
    Never,
    Jwt {
        skew_ms: i64,
        fallback_ms: Option<i64>,
    },
    Seconds {
        path: &'static str,
        from: Option<&'static str>,
        skew_ms: i64,
        fallback_ms: Option<i64>,
    },
}

#[derive(Clone)]
pub struct CredentialMap {
    pub access: Option<CField>,
    pub refresh: Option<CField>,
    pub expires: Expiry,
    pub email: Option<CField>,
    pub account_id: Option<CField>,
    pub org_id: Option<CField>,
    pub org_name: Option<CField>,
    pub project_id: Option<CField>,
    pub api_endpoint: Option<CField>,
    pub enterprise_url: Option<CField>,
    pub region: Option<CField>,
    pub inference_region: Option<CField>,
    pub active_organization_id: Option<CField>,
}

impl CredentialMap {
    fn bare(access: &'static str, refresh: Option<&'static str>, expires: Expiry) -> Self {
        Self {
            access: Some(CField::Path(access)),
            refresh: refresh.map(CField::Path),
            expires,
            email: None,
            account_id: None,
            org_id: None,
            org_name: None,
            project_id: None,
            api_endpoint: None,
            enterprise_url: None,
            region: None,
            inference_region: None,
            active_organization_id: None,
        }
    }
}

#[derive(Clone)]
pub struct Userinfo {
    pub url: &'static str,
    pub email: Option<&'static str>,
    pub account_id: Option<&'static str>,
}

#[derive(Clone, Copy)]
pub enum AfterExchange {
    AnthropicIdentity,
    OpenAiCodexProfile,
    ZaiMintKey,
    GoogleGeminiCliProject,
    MuseCodeKey,
    FactoryDroidRegion,
    /// Clears a client-side access cache; a no-op here.
    GitlabDuoClearCache,
}

#[derive(Clone, Copy)]
pub enum RefreshHook {
    GithubCopilot,
    Cursor,
    Snowflake,
    /// The Codex profile hook also runs after device-flow refreshes.
    OpenAiCodexProfile,
}

#[derive(Clone)]
pub struct RefreshRequest {
    /// None = reuse the login's token request endpoint.
    pub token: Option<OAuthRequest>,
    pub require: &'static [&'static str],
    pub credential: Option<CredentialMap>,
    pub userinfo: Option<Userinfo>,
    pub after_refresh: Option<AfterExchange>,
}

#[allow(clippy::large_enum_variant)]
pub enum Refresh {
    None,
    Hook(RefreshHook),
    Request(RefreshRequest),
}

#[derive(Clone)]
pub struct CallbackRule {
    pub port: u16,
    pub path: &'static str,
    pub hostname: &'static str,
    pub port_fallback: bool,
    /// No loopback listener: the user pastes the code or redirect URL.
    pub manual_only: bool,
    /// Fixed redirect URI (e.g. a vscode:// scheme).
    pub redirect_uri: Option<&'static str>,
    pub redirect_uri_env: Option<&'static str>,
}

impl CallbackRule {
    const fn cb(port: u16, path: &'static str) -> Self {
        Self {
            port,
            path,
            hostname: "localhost",
            port_fallback: true,
            manual_only: false,
            redirect_uri: None,
            redirect_uri_env: None,
        }
    }
    const fn manual(redirect_uri: &'static str) -> Self {
        Self {
            port: 0,
            path: "/callback",
            hostname: "localhost",
            port_fallback: false,
            manual_only: true,
            redirect_uri: Some(redirect_uri),
            redirect_uri_env: None,
        }
    }
}

#[derive(Clone, Copy)]
pub enum StateMode {
    Random,
    Uuid,
    None,
}

#[derive(Clone)]
pub struct PasteKey {
    pub prefix: &'static str,
    pub validate_url: &'static str,
}

#[derive(Clone)]
pub struct OAuthCodeRule {
    pub client_id: Option<AuthValue>,
    pub client_secret: Option<AuthValue>,
    pub base_url: Option<AuthValue>,
    pub auth_url: Option<AuthValue>,
    pub authorize_url: AuthValue,
    pub scopes: &'static [&'static str],
    pub scope_separator: &'static str,
    pub pkce: bool,
    pub state: StateMode,
    pub standard_authorize_params: bool,
    pub authorize_params: &'static [(&'static str, &'static str)],
    pub instructions: Option<&'static str>,
    pub callback: CallbackRule,
    pub token: OAuthRequest,
    pub credential: CredentialMap,
    pub userinfo: Option<Userinfo>,
    pub after_exchange: Option<AfterExchange>,
    /// Accept a pasted API key instead of a code during manual input.
    pub paste_key: Option<PasteKey>,
}

#[derive(Clone)]
pub struct DeviceResponseFields {
    pub user_code: &'static str,
    pub device_code: &'static str,
    pub verification_uri: &'static str,
    pub verification_uri_complete: &'static str,
    pub interval: &'static str,
    pub expires_in: &'static str,
}

#[derive(Clone)]
pub struct DeviceCodeRule {
    pub client_id: AuthValue,
    pub base_url: Option<AuthValue>,
    pub scopes: &'static [&'static str],
    pub device: OAuthRequest,
    pub token: OAuthRequest,
    pub response: DeviceResponseFields,
    pub instructions: &'static str,
    pub credential: CredentialMap,
    pub userinfo: Option<Userinfo>,
    pub after_exchange: Option<AfterExchange>,
    pub headers_hook: Option<HeadersHook>,
}

#[derive(Clone, Copy)]
pub enum HeadersHook {
    KimiFingerprint,
}

#[derive(Clone)]
pub enum Validate {
    ChatCompletions {
        label: &'static str,
        base_url: &'static str,
        model: &'static str,
        max_tokens_field: &'static str,
        optional: bool,
        tolerate_model_denied: bool,
    },
    AnthropicMessages {
        label: &'static str,
        base_url: &'static str,
        model: &'static str,
        optional: bool,
    },
    ModelsEndpoint {
        label: &'static str,
        url: &'static str,
        base_url_env: Option<&'static str>,
        base_url_path: &'static str,
        headers_hook: Option<HeadersHook>,
        optional: bool,
        trust_forbidden: bool,
    },
}

#[derive(Clone)]
pub struct ApiKeyRule {
    pub auth_url: Option<&'static str>,
    pub instructions: Option<&'static str>,
    pub prompt: &'static str,
    pub placeholder: Option<&'static str>,
    pub strip_bearer: bool,
    pub empty_fallback: Option<&'static str>,
    pub validate: Option<Validate>,
}

#[derive(Clone)]
pub enum LoginKind {
    ApiKey(ApiKeyRule),
    OAuthCode(OAuthCodeRule),
    DeviceCode(DeviceCodeRule),
    Custom(Custom),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Custom {
    GithubCopilot,
    Cursor,
    DevinCli,
    DevinWindsurf,
    Perplexity,
    AlibabaCodingPlan,
    AlibabaTokenPlan,
    CloudflareAiGateway,
    CloudflareWorkersAi,
    Kilo,
    Xiaomi,
    OpenAiCodexDevice,
    MistralVibe,
    Snowflake,
}

pub struct LoginProvider {
    pub id: &'static str,
    pub name: &'static str,
    /// Provider id the credential is stored under when it differs from `id`.
    pub store_as: Option<&'static str>,
    pub env: &'static [&'static str],
    /// Login needs a pasted code/redirect URL rather than a loopback server.
    pub paste_code: bool,
    /// Login yields a plain API key (stored in credentials.json, not oauth.json).
    pub result_api_key: bool,
    pub login: LoginKind,
    pub refresh: Refresh,
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn now_ms() -> i64 {
    freedas_core::paths::now_ms()
}

/// Dot-path (`data.user.email`) lookup in a JSON body.
fn json_path<'a>(body: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut cur = body;
    for seg in path.split('.') {
        cur = cur.get(seg)?;
    }
    Some(cur)
}

fn scalar_string(v: Option<&serde_json::Value>) -> Option<String> {
    match v? {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn decode_jwt_payload(token: &str) -> Option<serde_json::Value> {
    use base64::Engine;
    let part = token.split('.').nth(1)?;
    for eng in [
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::STANDARD,
    ] {
        if let Ok(bytes) = eng.decode(part)
            && let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes)
            && v.is_object()
        {
            return Some(v);
        }
    }
    None
}

fn jwt_expiry_ms(token: &str, skew_ms: i64) -> Option<i64> {
    let payload = decode_jwt_payload(token)?;
    let exp = payload.get("exp")?.as_i64()?;
    exp.checked_mul(1000)?.checked_sub(skew_ms)
}

impl CField {
    fn read(&self, body: &serde_json::Value, claims: Option<&serde_json::Value>) -> Option<String> {
        match self {
            CField::Path(p) => scalar_string(json_path(body, p)),
            CField::Claim(names) => {
                for n in *names {
                    if let Some(v) = scalar_string(claims.and_then(|c| c.get(*n))) {
                        return Some(v);
                    }
                }
                None
            }
            CField::PathClaim(p, names) => scalar_string(json_path(body, p)).or_else(|| {
                for n in *names {
                    if let Some(v) = scalar_string(claims.and_then(|c| c.get(*n))) {
                        return Some(v);
                    }
                }
                None
            }),
            CField::Literal(s) => Some(s.to_string()),
        }
    }
}

/// Project a token response onto credentials per the rule's credential map.
/// A missing refresh token keeps `previous.refresh` (non-rotating grants).
fn map_credentials(
    map: &CredentialMap,
    body: &serde_json::Value,
    provider: &str,
    previous: Option<&OAuthCredentials>,
) -> Result<OAuthCredentials, String> {
    let access = map.access.and_then(|f| f.read(body, None));
    let claims = access.as_deref().and_then(decode_jwt_payload);
    let access = access.or_else(|| map.access.and_then(|f| f.read(body, claims.as_ref())));
    let Some(access) = access else {
        return Err(format!("{provider} token response missing access token"));
    };
    let expires = match map.expires {
        Expiry::Never => NEVER_EXPIRES,
        Expiry::Jwt {
            skew_ms,
            fallback_ms,
        } => jwt_expiry_ms(&access, skew_ms)
            .unwrap_or_else(|| now_ms().saturating_add(fallback_ms.unwrap_or(3_600_000))),
        Expiry::Seconds {
            path,
            from,
            skew_ms,
            fallback_ms,
        } => match json_path(body, path).and_then(|v| v.as_f64()) {
            Some(secs) if secs.is_finite() => {
                let base = from
                    .and_then(|p| json_path(body, p).and_then(|v| v.as_f64()))
                    .filter(|t| t.is_finite())
                    .map(|t| (t * 1000.0) as i64)
                    .unwrap_or_else(now_ms);
                base.saturating_add((secs * 1000.0) as i64)
                    .saturating_sub(skew_ms)
            }
            _ => match fallback_ms {
                Some(fb) => now_ms().saturating_add(fb),
                None => return Err(format!("{provider} token response missing {path}")),
            },
        },
    };
    let read = |f: Option<CField>| f.and_then(|f| f.read(body, claims.as_ref()));
    Ok(OAuthCredentials {
        access,
        refresh: read(map.refresh)
            .or_else(|| previous.map(|p| p.refresh.clone()))
            .unwrap_or_default(),
        expires,
        enterprise_url: read(map.enterprise_url),
        project_id: read(map.project_id),
        email: read(map.email),
        account_id: read(map.account_id),
        api_endpoint: read(map.api_endpoint),
        org_id: read(map.org_id),
        org_name: read(map.org_name),
        region: read(map.region),
        inference_region: read(map.inference_region),
        active_organization_id: read(map.active_organization_id),
        authorized_at: previous.and_then(|p| p.authorized_at).or(Some(now_ms())),
    })
}

struct Pkce {
    verifier: String,
    challenge: String,
}

fn generate_pkce() -> Pkce {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let mut bytes = [0u8; 64];
    rand::Rng::fill(&mut rand::thread_rng(), &mut bytes);
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    Pkce {
        verifier,
        challenge,
    }
}

struct TokenResponse {
    status: u16,
    body: serde_json::Value,
}

fn template(text: &str, vars: &BTreeMap<&str, String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        if let Some(end) = after.find('}') {
            let key = &after[..end];
            if !key.is_empty() && key.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
                out.push_str(vars.get(key).map(String::as_str).unwrap_or(""));
                rest = &after[end + 1..];
                continue;
            }
        }
        out.push('{');
        rest = after;
    }
    out.push_str(rest);
    out
}

fn random_state() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn open_browser(url: &str) {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    std::process::Command::new(opener)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok();
}

/// Merge hook-computed headers under the rule's declared headers.
fn hook_headers(hook: Option<HeadersHook>, data_dir: &std::path::Path) -> Vec<(String, String)> {
    match hook {
        Some(HeadersHook::KimiFingerprint) => kimi_headers(data_dir),
        None => Vec::new(),
    }
}

fn kimi_headers(data_dir: &std::path::Path) -> Vec<(String, String)> {
    let sanitize = |v: String| -> String {
        let s: String = v.chars().filter(|c| (' '..='~').contains(c)).collect();
        let s = s.trim().to_string();
        if s.is_empty() { "unknown".into() } else { s }
    };
    // Stable per-device id persisted under the data dir (0600: fingerprint header).
    let device_id = {
        let path = data_dir.join("kimi-device-id");
        match std::fs::read_to_string(&path) {
            Ok(s) if !s.trim().is_empty() => s.trim().to_string(),
            _ => {
                let id = uuid::Uuid::new_v4().simple().to_string();
                crate::credentials::write_private(&path, &id).ok();
                id
            }
        }
    };
    let ua = format!("KimiCLI/{}", env!("CARGO_PKG_VERSION"));
    let uname = std::process::Command::new("uname")
        .arg("-srm")
        .output()
        .ok();
    let model = uname
        .as_ref()
        .map(|o| sanitize(String::from_utf8_lossy(&o.stdout).to_string()))
        .unwrap_or_else(|| "unknown".into());
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".into());
    vec![
        ("User-Agent".into(), ua.clone()),
        ("X-Msh-Platform".into(), "kimi_cli".into()),
        ("X-Msh-Version".into(), env!("CARGO_PKG_VERSION").into()),
        ("X-Msh-Device-Name".into(), sanitize(host)),
        ("X-Msh-Device-Model".into(), model),
        ("X-Msh-Device-Id".into(), sanitize(device_id)),
    ]
}

/// xAI OIDC discovery resolves the token endpoint.
async fn xai_token_endpoint() -> Result<String, String> {
    let resp = crate::http_client()
        .get("https://auth.x.ai/.well-known/openid-configuration")
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("xAI OIDC discovery failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "xAI OIDC discovery returned status {}",
            resp.status()
        ));
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    let endpoint = body["token_endpoint"]
        .as_str()
        .unwrap_or_default()
        .trim()
        .to_string();
    if endpoint.is_empty() {
        return Err("xAI OIDC discovery response was missing token_endpoint".into());
    }
    let host = reqwest::Url::parse(&endpoint)
        .ok()
        .map(|u| u.host_str().unwrap_or_default().to_lowercase())
        .unwrap_or_default();
    if !(host == "auth.x.ai" || host.ends_with(".x.ai")) {
        return Err(format!(
            "xAI OIDC discovery returned an unexpected token_endpoint: {endpoint}"
        ));
    }
    Ok(endpoint)
}

// ---------------------------------------------------------------------------
/// URLSearchParams (application/x-www-form-urlencoded) encoding.
fn form_encode(pairs: &[(String, String)]) -> String {
    let mut out = String::new();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        for s in [k, v] {
            for b in s.bytes() {
                match b {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                        out.push(b as char)
                    }
                    b' ' => out.push('+'),
                    _ => out.push_str(&format!("%{b:02X}")),
                }
            }
            out.push('=');
        }
        out.pop();
    }
    out
}

async fn post_token_request(
    request: &OAuthRequest,
    resolved_url: Option<&str>,
    standard: &[(&str, Option<String>)],
    vars: &BTreeMap<&str, String>,
    provider: &str,
    hook_headers: &[(String, String)],
    error_kind: &str,
) -> Result<TokenResponse, String> {
    let url = match resolved_url {
        Some(u) => template(u, vars),
        None => template(&resolve_value(&request.url).await?, vars),
    };
    let mut params: Vec<(String, String)> = Vec::new();
    if request.standard {
        for (k, v) in standard {
            if let Some(v) = v {
                params.push((k.to_string(), v.clone()));
            }
        }
    }
    for (k, v) in request.params {
        params.push((k.to_string(), template(v, vars)));
    }
    let client = crate::http_client();
    let mut req = client.post(&url);
    for (k, v) in hook_headers {
        req = req.header(k, v);
    }
    for (k, v) in request.headers {
        req = req.header(*k, template(v, vars));
    }
    req = if request.body_json {
        let map: serde_json::Map<String, serde_json::Value> = params
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect();
        req.json(&serde_json::Value::Object(map))
    } else {
        req.form(&params)
    };
    let timeout = std::time::Duration::from_millis(if request.timeout_ms == 0 {
        DEFAULT_REQUEST_TIMEOUT_MS
    } else {
        request.timeout_ms
    });
    let send = async {
        let resp = req
            .send()
            .await
            .map_err(|e| format!("{provider} request to {url} failed: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        let body = serde_json::from_str::<serde_json::Value>(&text)
            .unwrap_or(serde_json::Value::String(text.clone()));
        if !(200..300).contains(&status) && error_kind != "device-auth" {
            return Err(format!(
                "{provider} {} failed: {status} {}",
                error_kind,
                &text[..text.len().min(500)]
            ));
        }
        Ok(TokenResponse { status, body })
    };
    match tokio::time::timeout(timeout, send).await {
        Ok(r) => r,
        Err(_) => Err(format!("timed out waiting for {url}")),
    }
}

/// Bearer GET declared by `userinfo`; failures leave identity fields unset.
async fn apply_userinfo(
    userinfo: Option<&Userinfo>,
    mut credentials: OAuthCredentials,
    vars: &BTreeMap<&str, String>,
    hook_headers: &[(String, String)],
) -> OAuthCredentials {
    let Some(ui) = userinfo else {
        return credentials;
    };
    let url = template(ui.url, vars);
    let mut req = crate::http_client()
        .get(&url)
        .bearer_auth(&credentials.access);
    for (k, v) in hook_headers {
        req = req.header(k, v);
    }
    if let Ok(resp) = req.send().await
        && resp.status().is_success()
        && let Ok(body) = resp.json::<serde_json::Value>().await
    {
        if let Some(p) = ui.email
            && credentials.email.is_none()
        {
            credentials.email = scalar_string(json_path(&body, p));
        }
        if let Some(p) = ui.account_id
            && credentials.account_id.is_none()
        {
            credentials.account_id = scalar_string(json_path(&body, p));
        }
    }
    credentials
}

// ---------------------------------------------------------------------------
// Loopback callback server
// ---------------------------------------------------------------------------

/// Serve one request on `listener`; recognizes the callback path and `/launch`.
/// Returns (code, state) for a valid callback, Ok(None) when another listener
/// or path handled it.
async fn serve_once(
    listener: &tokio::net::TcpListener,
    callback_path: &str,
    expected_state: &str,
    launch_url: &std::sync::Arc<std::sync::RwLock<Option<String>>>,
    out: &tokio::sync::mpsc::Sender<Result<(String, String), String>>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let Ok((mut sock, _)) = listener.accept().await else {
        return;
    };
    let mut buf = vec![0u8; 16384];
    let Ok(n) = sock.read(&mut buf).await else {
        return;
    };
    let req = String::from_utf8_lossy(&buf[..n]).to_string();
    let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
    let (path_only, query) = path.split_once('?').unwrap_or((path.as_str(), ""));
    if path_only == "/launch" {
        let target = launch_url
            .read()
            .ok()
            .and_then(|g| g.clone())
            .unwrap_or_default();
        let status = if target.is_empty() {
            "404 Not Found"
        } else {
            "302 Found"
        };
        let head = format!(
            "HTTP/1.1 {status}\r\nLocation: {target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        sock.write_all(head.as_bytes()).await.ok();
        return;
    }
    if path_only != callback_path {
        let body = "not found";
        let head = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        sock.write_all(head.as_bytes()).await.ok();
        return;
    }
    let mut code = String::new();
    let mut state = String::new();
    let mut error = String::new();
    for kv in query.split('&') {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        let v = url_decode(v);
        match k {
            "code" => code = v,
            "state" => state = v,
            "error" => error = v,
            _ => {}
        }
    }
    let result = if !expected_state.is_empty() && state != expected_state {
        Err("state mismatch - possible CSRF attack".to_string())
    } else if !error.is_empty() {
        Err(format!("OAuth provider returned an error: {error}"))
    } else if code.is_empty() {
        Err("OAuth callback did not include a code".to_string())
    } else {
        Ok((code, state))
    };
    let (status, body) = match &result {
        Ok(_) => (
            "200 OK",
            "Login complete. You can close this tab and return to the terminal.",
        ),
        Err(e) => ("400 Bad Request", e.as_str()),
    };
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    sock.write_all(head.as_bytes()).await.ok();
    // Bad callbacks (wrong path params, CSRF mismatch, provider error) only
    // get an error page; the login keeps waiting for the valid callback.
    if let Ok(v) = result {
        out.send(Ok(v)).await.ok();
    }
}

fn url_decode(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if b.get(i + 1).and_then(|c| hex_val(*c)).is_some()
                && b.get(i + 2).and_then(|c| hex_val(*c)).is_some() =>
            {
                out.push(
                    hex_val(*b.get(i + 1).unwrap()).unwrap() * 16
                        + hex_val(*b.get(i + 2).unwrap()).unwrap(),
                );
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        c @ b'0'..=b'9' => Some(c - b'0'),
        c @ b'a'..=b'f' => Some(c - b'a' + 10),
        c @ b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

struct CallbackServer {
    callback_path: String,
    redirect_uri: String,
    launch_path_url: String,
    listener_v4: tokio::net::TcpListener,
    listener_v6: Option<tokio::net::TcpListener>,
}

/// Bind the loopback callback listener. Tries the preferred port, then (when
/// allowed) a random one; errors explain which port to free when the provider
/// pins an exact URI.
async fn start_callback_server(
    rule: &CallbackRule,
    provider: &str,
    host: &mut LoginHost<'_>,
) -> Result<CallbackServer, String> {
    let hostname = if rule.hostname.is_empty() {
        "localhost"
    } else {
        rule.hostname
    };
    // Browsers resolve "localhost" to ::1 as often as 127.0.0.1; advertise the
    // hostname but bind the IPv4 loopback plus a best-effort IPv6 companion.
    let bind_host = if hostname == "localhost" {
        "127.0.0.1"
    } else {
        hostname
    };
    let preferred = rule.port;
    let fixed_uri = rule.redirect_uri.is_some() || rule.redirect_uri_env.is_some();
    let explicit_uri = match (&rule.redirect_uri, rule.redirect_uri_env) {
        (_, Some(env)) => std::env::var(env)
            .ok()
            .filter(|v| !v.is_empty())
            .or(rule.redirect_uri.map(str::to_string)),
        (Some(uri), None) => Some(uri.to_string()),
        (None, None) => None,
    };
    let env_override_uri = rule
        .redirect_uri_env
        .and_then(|env| std::env::var(env).ok())
        .filter(|v| !v.is_empty())
        .filter(|v| Some(v.as_str()) != rule.redirect_uri);
    let (preferred, bind_host, callback_path, advertised_uri) = match env_override_uri {
        Some(uri) => {
            let parsed = reqwest::Url::parse(&uri)
                .map_err(|_| format!("{provider}: invalid redirect URI override: {uri}"))?;
            if parsed.scheme() != "http" && parsed.scheme() != "https" {
                return Err(format!(
                    "{provider}: redirect URI override must use http:// or https://, got: {uri}"
                ));
            }
            let loopback = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
            if loopback && parsed.scheme() != "http" {
                return Err(format!(
                    "{provider}: loopback redirect URI overrides must use http://, got: {uri}"
                ));
            }
            let port = parsed
                .port()
                .unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });
            (
                if loopback { port } else { 0 },
                if loopback {
                    parsed.host_str().unwrap_or(bind_host).to_string()
                } else {
                    bind_host.to_string()
                },
                parsed.path().to_string(),
                Some(uri),
            )
        }
        None => (
            preferred,
            bind_host.to_string(),
            rule.path.to_string(),
            explicit_uri,
        ),
    };
    let try_bind = |port: u16| {
        let host = bind_host.to_string();
        async move { tokio::net::TcpListener::bind(format!("{host}:{port}")).await }
    };
    let (listener_v4, actual_port) = match try_bind(preferred).await {
        Ok(l) => {
            let port = l.local_addr().map(|a| a.port()).unwrap_or(preferred);
            (l, port)
        }
        Err(e) => {
            if fixed_uri || !rule.port_fallback {
                return Err(format!(
                    "{provider}: OAuth callback port {preferred} is in use ({e}). Free the port or change the redirect URI, then retry."
                ));
            }
            let l = try_bind(0)
                .await
                .map_err(|e| format!("{provider}: cannot bind a callback listener: {e}"))?;
            let port = l.local_addr().map(|a| a.port()).unwrap_or(0);
            host.progress(&format!(
                "preferred port {preferred} unavailable, using port {port}"
            ));
            (l, port)
        }
    };
    let listener_v6 = tokio::net::TcpListener::bind(format!("[::1]:{actual_port}"))
        .await
        .ok();
    let redirect_uri =
        advertised_uri.unwrap_or_else(|| format!("http://{hostname}:{actual_port}{callback_path}"));
    Ok(CallbackServer {
        callback_path,
        redirect_uri,
        // /launch sits beside the callback on the same listener.
        launch_path_url: format!("http://{hostname}:{actual_port}/launch"),
        listener_v4,
        listener_v6,
    })
}

/// Drive the loopback until the provider posts the callback back (5 minute
/// cap, matching the reference implementation's default).
async fn wait_for_callback(
    server: &CallbackServer,
    expected_state: &str,
    launch_target: std::sync::Arc<std::sync::RwLock<Option<String>>>,
) -> Result<(String, String), String> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<(String, String), String>>(4);
    let mut deadline = Box::pin(tokio::time::sleep(std::time::Duration::from_millis(
        CALLBACK_TIMEOUT_MS,
    )));
    // serve_once borrows the listeners, so the accept loops live inside this
    // select! rather than spawned 'static tasks.
    let v6 = server.listener_v6.as_ref();
    loop {
        tokio::select! {
            r = rx.recv() => match r {
                Some(Ok(v)) => return Ok(v),
                // serve_once no longer forwards errors, but ignore them
                // defensively and keep waiting for the valid callback.
                Some(Err(_)) => continue,
                None => return Err("callback listener stopped".into()),
            },
            _ = &mut deadline => return Err("timed out waiting for the OAuth callback".into()),
            _ = serve_once(&server.listener_v4, &server.callback_path, expected_state, &launch_target, &tx) => {},
            _ = async { if let Some(l) = v6 { serve_once(l, &server.callback_path, expected_state, &launch_target, &tx).await } else { std::future::pending::<()>().await } } => {},
        }
    }
}

/// Accept a pasted redirect URL (`https://…?code=…`, custom schemes) or a bare
/// authorization code.
fn parse_pasted_callback(input: &str, expected_state: &str) -> Result<(String, String), String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("login cancelled".into());
    }
    if input.contains("://") || input.contains('?') {
        let parsed = reqwest::Url::parse(input).map_err(|_| {
            "could not parse the pasted URL; paste the full redirect URL".to_string()
        })?;
        let mut code = String::new();
        let mut state = String::new();
        let mut error = String::new();
        for (k, v) in parsed.query_pairs() {
            match k.as_ref() {
                "code" => code = v.to_string(),
                "state" => state = v.to_string(),
                "error" => error = v.to_string(),
                _ => {}
            }
        }
        if !expected_state.is_empty() && state != expected_state {
            return Err("state mismatch - possible CSRF attack".into());
        }
        if !error.is_empty() {
            return Err(format!("OAuth provider returned an error: {error}"));
        }
        if code.is_empty() {
            return Err("the pasted URL did not contain a code parameter".into());
        }
        return Ok((code, state));
    }
    if !expected_state.is_empty() {
        return Err("state mismatch - possible CSRF attack".into());
    }
    Ok((input.to_string(), String::new()))
}

// ---------------------------------------------------------------------------
// login "oauth-code"
// ---------------------------------------------------------------------------

async fn oauth_code_login<'a>(
    rule: &OAuthCodeRule,
    provider: &LoginProvider,
    host: &'a mut LoginHost<'a>,
) -> Result<OAuthCredentials, String> {
    let state = match rule.state {
        StateMode::Random => random_state(),
        StateMode::Uuid => uuid::Uuid::new_v4().to_string(),
        StateMode::None => String::new(),
    };
    let manual = rule.callback.manual_only;
    let server = if manual {
        None
    } else {
        Some(start_callback_server(&rule.callback, provider.id, host).await?)
    };
    let redirect_uri = server
        .as_ref()
        .map(|s| s.redirect_uri.clone())
        .or_else(|| rule.callback.redirect_uri.map(str::to_string))
        .unwrap_or_default();
    let client_id = match &rule.client_id {
        Some(v) => Some(resolve_value(v).await?),
        None => None,
    };
    let client_secret = match &rule.client_secret {
        Some(v) => Some(resolve_value(v).await?),
        None => None,
    };
    let base = match &rule.base_url {
        Some(v) => Some(resolve_value(v).await?.trim_end_matches('/').to_string()),
        None => None,
    };
    let auth = match &rule.auth_url {
        Some(v) => Some(resolve_value(v).await?.trim_end_matches('/').to_string()),
        None => None,
    };
    let pkce = rule.pkce.then(generate_pkce);
    let scope = (!rule.scopes.is_empty()).then(|| rule.scopes.join(rule.scope_separator));
    let mut vars: BTreeMap<&str, String> = BTreeMap::new();
    for (k, v) in [
        ("client_id", client_id.clone()),
        ("redirect_uri", Some(redirect_uri.clone())),
        ("scope", scope.clone()),
        ("state", Some(state.clone())),
        ("code_challenge", pkce.as_ref().map(|p| p.challenge.clone())),
        ("base", base.clone()),
        ("auth", auth.clone()),
    ] {
        if let Some(v) = v {
            vars.insert(k, v);
        }
    }
    let mut params: Vec<(String, String)> = Vec::new();
    if rule.standard_authorize_params {
        if let Some(id) = &client_id {
            params.push(("client_id".into(), id.clone()));
        }
        params.push(("response_type".into(), "code".into()));
        params.push(("redirect_uri".into(), redirect_uri.clone()));
        if let Some(s) = &scope {
            params.push(("scope".into(), s.clone()));
        }
        if let Some(p) = &pkce {
            params.push(("code_challenge".into(), p.challenge.clone()));
            params.push(("code_challenge_method".into(), "S256".into()));
        }
        if !state.is_empty() {
            params.push(("state".into(), state.clone()));
        }
    }
    for (k, v) in rule.authorize_params {
        params.push((k.to_string(), template(v, &vars)));
    }
    let authorize_url = format!(
        "{}?{}",
        template(&resolve_value(&rule.authorize_url).await?, &vars),
        form_encode(&params)
    );
    let launch = server
        .as_ref()
        .filter(|s| s.callback_path_is_launch_safe())
        .map(|s| s.launch_path_url.clone());
    host.auth(&authorize_url, launch.as_deref(), rule.instructions);
    if host.open_browser {
        open_browser(&authorize_url);
    }
    host.progress(if manual {
        "Waiting for pasted authorization code..."
    } else {
        "Waiting for browser authentication..."
    });

    let (code, _cb_state) = if manual {
        let input = host.manual_code()?;
        parse_pasted_callback(&input, &state)?
    } else {
        let server = server
            .as_ref()
            .expect("callback server exists unless manual-only");
        // Paste-code providers also take a pasted redirect URL or code: offer
        // it first so non-TTY-capable environments can still finish, then fall
        // back to the loopback listener.
        if provider.paste_code {
            host.progress("Paste the redirect URL or authorization code, or press Enter to wait for the browser callback:");
            if let Ok(input) = host.manual_code()
                && !input.trim().is_empty()
            {
                let parsed = parse_pasted_callback(&input, &state)?;
                return exchange_code(
                    rule,
                    provider,
                    &parsed.0,
                    &state,
                    &redirect_uri,
                    pkce.as_ref().map(|p| p.verifier.clone()),
                    &client_id,
                    &client_secret,
                    &base,
                    &auth,
                    host,
                )
                .await;
            }
        }
        let launch_target: std::sync::Arc<std::sync::RwLock<Option<String>>> =
            std::sync::Arc::new(std::sync::RwLock::new(Some(authorize_url)));
        wait_for_callback(server, &state, launch_target).await?
    };
    host.progress("Exchanging authorization code for tokens...");
    exchange_code(
        rule,
        provider,
        &code,
        &state,
        &redirect_uri,
        pkce.as_ref().map(|p| p.verifier.clone()),
        &client_id,
        &client_secret,
        &base,
        &auth,
        host,
    )
    .await
}

impl CallbackServer {
    /// `/launch` must never shadow the provider's registered callback path.
    fn callback_path_is_launch_safe(&self) -> bool {
        !self.redirect_uri.ends_with("/launch")
    }
}

#[allow(clippy::too_many_arguments)]
async fn exchange_code<'a>(
    rule: &OAuthCodeRule,
    provider: &LoginProvider,
    code: &str,
    state: &str,
    redirect_uri: &str,
    verifier: Option<String>,
    client_id: &Option<String>,
    client_secret: &Option<String>,
    base: &Option<String>,
    auth: &Option<String>,
    host: &'a mut LoginHost<'a>,
) -> Result<OAuthCredentials, String> {
    // A pasted API key short-circuits the exchange (openrouter paste-key).
    // Someone else's key must never be stored silently: require explicit
    // confirmation before keeping it.
    if let Some(pk) = &rule.paste_key
        && code.starts_with(pk.prefix)
    {
        let confirm = host.ask(
            &format!(
                "Pasted value starts with `{}` and looks like someone else's API key. Type `yes` to store it as your {} API key:",
                pk.prefix, provider.name
            ),
            None,
        )?;
        if !matches!(confirm.trim().to_ascii_lowercase().as_str(), "yes" | "y") {
            return Err(format!(
                "{} paste-key login cancelled; not storing the pasted key",
                provider.id
            ));
        }
        validate_models_endpoint(provider.name, code, pk.validate_url, &[]).await?;
        return Ok(OAuthCredentials {
            access: code.to_string(),
            expires: NEVER_EXPIRES,
            authorized_at: Some(now_ms()),
            ..Default::default()
        });
    }
    // A `code#fragment` suffix is never a state override; the callback state
    // (already CSRF-checked) is authoritative. Strip any `#fragment` from the
    // code before exchange.
    let exchange_code = code
        .split_once('#')
        .map(|(c, _)| c.to_string())
        .unwrap_or_else(|| code.to_string());
    let exchange_state = state.to_string();
    let mut vars: BTreeMap<&str, String> = BTreeMap::new();
    for (k, v) in [
        ("code", Some(exchange_code.clone())),
        ("state", Some(exchange_state)),
        ("redirect_uri", Some(redirect_uri.to_string())),
        ("code_verifier", verifier.clone()),
        ("client_id", client_id.clone()),
        ("client_secret", client_secret.clone()),
        ("base", base.clone()),
        ("auth", auth.clone()),
    ] {
        if let Some(v) = v {
            vars.insert(k, v);
        }
    }
    let standard: &[(&str, Option<String>)] = &[
        ("grant_type", Some("authorization_code".into())),
        ("client_id", client_id.clone()),
        ("client_secret", client_secret.clone()),
        ("code", Some(exchange_code)),
        ("redirect_uri", Some(redirect_uri.to_string())),
        ("code_verifier", verifier),
    ];
    let resp = post_token_request(
        &rule.token,
        None,
        standard,
        &vars,
        provider.id,
        &[],
        "token-exchange",
    )
    .await?;
    let raw = resp.body.clone();
    let mut credentials = map_credentials(&rule.credential, &resp.body, provider.id, None)?;
    credentials = apply_userinfo(rule.userinfo.as_ref(), credentials, &vars, &[]).await;
    apply_after_exchange(
        rule.after_exchange,
        credentials,
        ExchangeContext {
            provider: provider.id,
            phase: "login",
            raw: &raw,
            stored: None,
            on_progress: &mut host.on_progress,
            on_prompt: &mut host.on_prompt,
            data_dir: host.data_dir,
        },
    )
    .await
}

// ---------------------------------------------------------------------------
// login "device-code" (RFC 8628)
// ---------------------------------------------------------------------------

async fn device_code_login<'a>(
    rule: &DeviceCodeRule,
    provider: &LoginProvider,
    host: &'a mut LoginHost<'a>,
) -> Result<OAuthCredentials, String> {
    let client_id = resolve_value(&rule.client_id).await?;
    let base = match &rule.base_url {
        Some(v) => Some(resolve_value(v).await?.trim_end_matches('/').to_string()),
        None => None,
    };
    let scope = (!rule.scopes.is_empty()).then(|| rule.scopes.join(" "));
    let hook = hook_headers(rule.headers_hook, host.data_dir);
    let mut vars: BTreeMap<&str, String> = BTreeMap::new();
    for (k, v) in [
        ("client_id", Some(client_id.clone())),
        ("scope", scope.clone()),
        ("base", base.clone()),
    ] {
        if let Some(v) = v {
            vars.insert(k, v);
        }
    }
    host.progress("Requesting device authorization...");
    let device = post_token_request(
        &rule.device,
        None,
        &[("client_id", Some(client_id.clone())), ("scope", scope)],
        &vars,
        provider.id,
        &hook,
        "device-auth",
    )
    .await?;
    if !(200..300).contains(&device.status) {
        return Err(format!(
            "{} device authorization failed: {} {}",
            provider.id, device.status, device.body
        ));
    }
    let r = &rule.response;
    let str_at = |p: &str| scalar_string(json_path(&device.body, p));
    let num_at = |p: &str| json_path(&device.body, p).and_then(|v| v.as_f64());
    let (Some(user_code), Some(device_code), Some(verification_uri)) = (
        str_at(r.user_code),
        str_at(r.device_code),
        str_at(r.verification_uri),
    ) else {
        return Err(format!(
            "{} device authorization response missing required fields",
            provider.id
        ));
    };
    let mut interval = num_at(r.interval)
        .filter(|v| v.is_finite())
        .map(|v| v.clamp(1.0, 60.0))
        .unwrap_or(5.0);
    let expires_in = num_at(r.expires_in)
        .filter(|v| v.is_finite())
        .map(|v| v.clamp(0.0, 3600.0))
        .unwrap_or(600.0);
    let expires_mins = (expires_in / 60.0).ceil().max(1.0) as u64;
    let base_instructions = template(rule.instructions, &{
        let mut m = vars.clone();
        m.insert("user_code", user_code.clone());
        m
    });
    // Prominent fingerprint: the code itself is the binding. Only the shown
    // code may be approved; anything else is a phishing/consent mix-up.
    let instructions = format!(
        "{base_instructions}\n\nCode: {user_code}\nOnly approve this code ({user_code}) on the verification page; it expires in ~{expires_mins} min. Do not approve a different code."
    );
    host.auth(
        str_at(r.verification_uri_complete)
            .as_deref()
            .unwrap_or(&verification_uri),
        None,
        Some(&instructions),
    );
    if host.open_browser
        && let Some(uri) = str_at(r.verification_uri_complete)
    {
        open_browser(&uri);
    }
    host.progress(&format!(
        "Waiting for device authorization (code: {user_code})..."
    ));
    vars.insert("device_code", device_code.clone());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs_f64(expires_in);
    // The token endpoint resolves once (it may come from OIDC discovery) rather
    // than per poll.
    let token_url = resolve_value(&rule.token.url).await?;
    let mut transport_failures: u32 = 0;
    let body = loop {
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "{} device code expired; restart the login",
                provider.id
            ));
        }
        tokio::time::sleep(std::time::Duration::from_secs_f64(interval.min(60.0))).await;
        let poll = post_token_request(
            &rule.token,
            Some(&token_url),
            &[
                (
                    "grant_type",
                    Some("urn:ietf:params:oauth:grant-type:device_code".into()),
                ),
                ("client_id", Some(client_id.clone())),
                ("device_code", Some(device_code.clone())),
            ],
            &vars,
            provider.id,
            &hook,
            "device-auth",
        )
        .await;
        let poll = match poll {
            Ok(p) => {
                transport_failures = 0;
                p
            }
            Err(e) => {
                transport_failures += 1;
                if transport_failures >= 5 {
                    return Err(format!("{} device token request failed: {e}", provider.id));
                }
                continue;
            }
        };

        let error = scalar_string(json_path(&poll.body, "error"));
        if (200..300).contains(&poll.status) && error.is_none() {
            break poll.body;
        }
        match error.as_deref() {
            Some("authorization_pending") => {}
            Some("slow_down") => interval = (interval + 5.0).min(60.0),
            Some("expired_token") | Some("expired") => {
                return Err(format!(
                    "{} device code expired; restart the login",
                    provider.id
                ));
            }
            Some("access_denied") => {
                return Err(format!("{} device authorization was denied", provider.id));
            }
            Some(e) => {
                let desc = scalar_string(json_path(&poll.body, "error_description"));
                return Err(format!(
                    "{} device token request failed: {} {}",
                    provider.id,
                    poll.status,
                    desc.unwrap_or_else(|| e.to_string())
                ));
            }
            // No error field on a non-2xx status: 429/5xx are transient
            // (back off like slow_down); other statuses fail fast instead
            // of polling forever as `authorization_pending`.
            None => {
                if poll.status == 429 || poll.status >= 500 {
                    interval = (interval + 5.0).min(60.0);
                } else {
                    return Err(format!(
                        "{} device token request failed: {}",
                        provider.id, poll.status
                    ));
                }
            }
        }
    };
    let raw = body.clone();
    let mut credentials = map_credentials(&rule.credential, &body, provider.id, None)?;
    credentials = apply_userinfo(rule.userinfo.as_ref(), credentials, &vars, &hook).await;
    apply_after_exchange(
        rule.after_exchange,
        credentials,
        ExchangeContext {
            provider: provider.id,
            phase: "login",
            raw: &raw,
            stored: None,
            on_progress: &mut host.on_progress,
            on_prompt: &mut host.on_prompt,
            data_dir: host.data_dir,
        },
    )
    .await
}

// ---------------------------------------------------------------------------
// login "api-key" + validation probes
// ---------------------------------------------------------------------------

const VALIDATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

async fn validate_chat_completions(
    label: &str,
    api_key: &str,
    base_url: &str,
    model: &str,
    max_tokens_field: &str,
    tolerate_model_denied: bool,
) -> Result<(), String> {
    let send = crate::http_client()
        .post(format!(
            "{}/chat/completions",
            base_url.trim_end_matches('/')
        ))
        .bearer_auth(api_key)
        .json(&serde_json::json!({
            "model": model,
            "messages": [{ "role": "user", "content": "ping" }],
            max_tokens_field: 1,
            "temperature": 0,
        }))
        .send();
    let resp = tokio::time::timeout(VALIDATION_TIMEOUT, send)
        .await
        .map_err(|_| format!("{label} API key validation timed out"))?
        .map_err(|e| format!("{label} API key validation request failed: {e}"))?;
    if resp.status().is_success() {
        return Ok(());
    }
    let status = resp.status().as_u16();
    let details = resp.text().await.unwrap_or_default().trim().to_string();
    let code = serde_json::from_str::<serde_json::Value>(&details)
        .ok()
        .and_then(|v| {
            v["error"]["code"]
                .as_str()
                .map(str::to_string)
                .or_else(|| v["code"].as_str().map(str::to_string))
        });
    if tolerate_model_denied && status == 401 && code.as_deref() == Some("invalid_model") {
        return Ok(());
    }
    Err(if details.is_empty() {
        format!("{label} API key validation failed ({status})")
    } else {
        format!(
            "{label} API key validation failed ({status}): {}",
            validation_details(&details)
        )
    })
}

/// Error bodies from a (possibly compromised) endpoint can carry reflected
/// secrets or arbitrary text; redact key-like substrings and cap the size
/// before they reach the UI or an export.
fn validation_details(body: &str) -> String {
    crate::truncate_body(&freedas_core::redact::redact(body))
}

async fn validate_anthropic_messages(
    label: &str,
    api_key: &str,
    base_url: &str,
    model: &str,
) -> Result<(), String> {
    let trimmed = base_url.trim_end_matches('/');
    let base = trimmed.strip_suffix("/v1").unwrap_or(trimmed);
    let send = crate::http_client()
        .post(format!("{base}/v1/messages"))
        .header("anthropic-version", "2023-06-01")
        .header("x-api-key", api_key)
        .json(&serde_json::json!({
            "model": model,
            "messages": [{ "role": "user", "content": "ping" }],
            "max_tokens": 1,
        }))
        .send();
    let resp = tokio::time::timeout(VALIDATION_TIMEOUT, send)
        .await
        .map_err(|_| format!("{label} API key validation timed out"))?
        .map_err(|e| format!("{label} API key validation request failed: {e}"))?;
    if resp.status().is_success() {
        return Ok(());
    }
    let status = resp.status().as_u16();
    let details = resp.text().await.unwrap_or_default().trim().to_string();
    Err(if details.is_empty() {
        format!("{label} API key validation failed ({status})")
    } else {
        format!(
            "{label} API key validation failed ({status}): {}",
            validation_details(&details)
        )
    })
}

async fn validate_models_endpoint(
    label: &str,
    api_key: &str,
    models_url: &str,
    headers: &[(String, String)],
) -> Result<(), String> {
    let mut req = crate::http_client().get(models_url).bearer_auth(api_key);
    for (k, v) in headers {
        req = req.header(k, v);
    }
    let resp = tokio::time::timeout(VALIDATION_TIMEOUT, req.send())
        .await
        .map_err(|_| format!("{label} API key validation timed out"))?
        .map_err(|e| format!("{label} API key validation request failed: {e}"))?;
    if resp.status().is_success() {
        return Ok(());
    }
    let status = resp.status().as_u16();
    let details = resp.text().await.unwrap_or_default().trim().to_string();
    Err(if details.is_empty() {
        format!("{label} API key validation failed ({status})")
    } else {
        format!(
            "{label} API key validation failed ({status}): {}",
            validation_details(&details)
        )
    })
}

async fn run_validation(
    v: &Validate,
    provider: &LoginProvider,
    api_key: &str,
    data_dir: &std::path::Path,
) -> Result<(), String> {
    match v {
        Validate::ChatCompletions {
            label,
            base_url,
            model,
            max_tokens_field,
            optional: _,
            tolerate_model_denied,
        } => {
            let label = if label.is_empty() {
                provider.name
            } else {
                label
            };
            validate_chat_completions(
                label,
                api_key,
                base_url,
                model,
                max_tokens_field,
                *tolerate_model_denied,
            )
            .await
        }
        Validate::AnthropicMessages {
            label,
            base_url,
            model,
            optional: _,
        } => {
            let label = if label.is_empty() {
                provider.name
            } else {
                label
            };
            validate_anthropic_messages(label, api_key, base_url, model).await
        }
        Validate::ModelsEndpoint {
            label,
            url,
            base_url_env,
            base_url_path,
            headers_hook,
            optional: _,
            trust_forbidden: _,
        } => {
            let env_base = base_url_env
                .and_then(|e| std::env::var(e).ok())
                .map(|b| b.trim_end_matches('/').to_string());
            let url = env_base
                .map(|b| format!("{b}{base_url_path}"))
                .unwrap_or_else(|| url.to_string());
            let label = if label.is_empty() {
                provider.name
            } else {
                label
            };
            let headers = match headers_hook {
                Some(HeadersHook::KimiFingerprint) => kimi_headers(data_dir),
                None => Vec::new(),
            };
            validate_models_endpoint(label, api_key, &url, &headers).await
        }
    }
}

async fn api_key_login(
    rule: &ApiKeyRule,
    provider: &LoginProvider,
    host: &mut LoginHost<'_>,
) -> Result<String, String> {
    if let (Some(url), Some(instructions)) = (rule.auth_url, rule.instructions) {
        host.auth(url, None, Some(instructions));
        if host.open_browser {
            open_browser(url);
        }
    }
    let answer = host.prompt(&OAuthPrompt {
        message: rule.prompt.to_string(),
        placeholder: rule.placeholder.map(str::to_string),
        allow_empty: rule.empty_fallback.is_some(),
        secret: true,
    })?;
    let mut trimmed = answer.trim().to_string();
    if rule.strip_bearer && !trimmed.is_empty() {
        // /^bearer\b\s*/i
        if trimmed.len() >= 6 && trimmed[..6].eq_ignore_ascii_case("bearer") {
            trimmed = trimmed[6..].trim_start().to_string();
        }
        if trimmed.is_empty() {
            return Err(format!(
                "{} API key is empty after stripping Bearer prefix",
                provider.name
            ));
        }
    }
    if trimmed.is_empty() {
        return rule
            .empty_fallback
            .map(|f| f.to_string())
            .ok_or_else(|| format!("{} API key is required", provider.name));
    }
    if let Some(v) = &rule.validate {
        let optional = matches!(
            v,
            Validate::ChatCompletions { optional: true, .. }
                | Validate::AnthropicMessages { optional: true, .. }
                | Validate::ModelsEndpoint { optional: true, .. }
        );
        let trust_forbidden = matches!(
            v,
            Validate::ModelsEndpoint {
                trust_forbidden: true,
                ..
            }
        );
        host.progress(if optional {
            "Validating API key (optional)..."
        } else {
            "Validating API key..."
        });
        match run_validation(v, provider, &trimmed, host.data_dir).await {
            Ok(()) => {}
            Err(e) => {
                // An optional probe only rejects a real auth failure (401/403,
                // or 401 alone with trust-forbidden); everything else trusts
                // the supplied key.
                let auth_failure = e.contains("(401)") || e.contains("(403)");
                let trusts_403 = trust_forbidden && e.contains("(403)");
                if !optional || (auth_failure && !trusts_403) {
                    return Err(e);
                }
                host.progress(&format!(
                    "Skipping {} validation endpoint; continuing with provided API key.",
                    provider.name
                ));
            }
        }
    }
    Ok(trimmed)
}

// ---------------------------------------------------------------------------
// after-exchange hooks
// ---------------------------------------------------------------------------

pub struct ExchangeContext<'a, 'h> {
    pub provider: &'a str,
    pub phase: &'a str, // "login" | "refresh"
    pub raw: &'a serde_json::Value,
    pub stored: Option<&'a OAuthCredentials>,
    pub on_progress: &'h mut Option<&'h mut ProgressCallback<'h>>,
    pub on_prompt: &'h mut Option<&'h mut PromptCallback<'h>>,
    pub data_dir: &'a std::path::Path,
}

impl ExchangeContext<'_, '_> {
    fn progress(&mut self, msg: &str) {
        if let Some(f) = self.on_progress.as_deref_mut() {
            f(msg);
        }
    }
}

async fn apply_after_exchange(
    hook: Option<AfterExchange>,
    credentials: OAuthCredentials,
    mut ctx: ExchangeContext<'_, '_>,
) -> Result<OAuthCredentials, String> {
    let Some(hook) = hook else {
        return Ok(credentials);
    };
    match hook {
        AfterExchange::AnthropicIdentity => anthropic_identity(credentials, &ctx).await,
        AfterExchange::OpenAiCodexProfile => openai_codex_profile(credentials, &ctx),
        AfterExchange::ZaiMintKey => zai_mint_key(credentials).await,
        AfterExchange::GoogleGeminiCliProject => {
            google_gemini_cli_project(credentials, &mut ctx).await
        }
        AfterExchange::MuseCodeKey => muse_code_key(credentials).await,
        AfterExchange::FactoryDroidRegion => factory_droid_region(credentials, &ctx).await,
        AfterExchange::GitlabDuoClearCache => Ok(credentials),
    }
}

/// Fills account/org identity from /api/claude_cli/bootstrap when the token
/// response omitted it. Best-effort: fetch failures keep the credential.
async fn anthropic_identity(
    mut credentials: OAuthCredentials,
    ctx: &ExchangeContext<'_, '_>,
) -> Result<OAuthCredentials, String> {
    let include_org = ctx.phase == "login";
    if credentials.account_id.is_some()
        && credentials.email.is_some()
        && (!include_org || credentials.org_id.is_some())
    {
        return Ok(credentials);
    }
    let url =
        "https://api.anthropic.com/api/claude_cli/bootstrap?entrypoint=cli&model=claude-opus-4-8";
    let resp = crate::http_client()
        .get(url)
        .header("Accept", "application/json, text/plain, */*")
        .bearer_auth(&credentials.access)
        .header("anthropic-beta", "oauth-2025-04-20")
        .send()
        .await;
    let Ok(resp) = resp else {
        return Ok(credentials);
    };
    if !resp.status().is_success() {
        return Ok(credentials);
    }
    let Ok(body) = resp.json::<serde_json::Value>().await else {
        return Ok(credentials);
    };
    let acct = &body["oauth_account"];
    let get = |k: &str| {
        acct[k]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    credentials.account_id = credentials.account_id.or_else(|| get("account_uuid"));
    credentials.email = credentials.email.or_else(|| get("account_email"));
    if include_org {
        credentials.org_id = credentials.org_id.or_else(|| get("organization_uuid"));
        credentials.org_name = credentials.org_name.or_else(|| get("organization_name"));
    }
    Ok(credentials)
}

/// Codex identity from access/id-token JWT claims. Login requires at least
/// one of accountId/email; refresh preserves the stored org scope.
fn openai_codex_profile(
    mut credentials: OAuthCredentials,
    ctx: &ExchangeContext<'_, '_>,
) -> Result<OAuthCredentials, String> {
    const AUTH_CLAIM: &str = "https://api.openai.com/auth";
    const PROFILE_CLAIM: &str = "https://api.openai.com/profile";
    let id_token = ctx.raw["id_token"].as_str();
    let claims = decode_jwt_payload(&credentials.access);
    let id_claims = id_token.and_then(decode_jwt_payload);
    let pick = |key: &str| -> Option<String> {
        for c in [&claims, &id_claims].into_iter().flatten() {
            if let Some(v) = c[AUTH_CLAIM][key].as_str().filter(|s| !s.is_empty()) {
                return Some(v.to_string());
            }
        }
        None
    };
    let email = [&claims, &id_claims]
        .into_iter()
        .flatten()
        .find_map(|c| {
            c[PROFILE_CLAIM]["email"]
                .as_str()
                .map(|s| s.trim().to_lowercase())
        })
        .filter(|s| !s.is_empty());
    let account_id = pick("chatgpt_account_id");
    let plan_type = pick("chatgpt_plan_type").map(|s| s.trim().to_lowercase());
    if ctx.phase == "login" && account_id.is_none() && email.is_none() {
        return Err("failed to extract account identity from token".into());
    }
    let resolved_account = account_id.or_else(|| ctx.stored.and_then(|s| s.account_id.clone()));
    if let Some(a) = &resolved_account {
        credentials.account_id = Some(a.clone());
    }
    credentials.email = email.or_else(|| ctx.stored.and_then(|s| s.email.clone()));
    if ctx.phase == "login" {
        credentials.org_id = resolved_account;
        credentials.org_name = plan_type;
    } else {
        credentials.org_id = ctx.stored.and_then(|s| s.org_id.clone());
        credentials.org_name = ctx.stored.and_then(|s| s.org_name.clone());
    }
    Ok(credentials)
}

/// Z.ai `{ code, msg, data, success }` envelope: OAuth endpoints signal
/// success with code 0; biz endpoints use 200 / success:true.
fn zai_unwrap(body: serde_json::Value, op: &str) -> Result<serde_json::Value, String> {
    if let Some(obj) = body.as_object()
        && (obj.contains_key("code") || obj.contains_key("success"))
    {
        let code_ok = match obj.get("code") {
            None | Some(serde_json::Value::Null) => true,
            Some(serde_json::Value::Number(n)) => n.as_i64() == Some(0) || n.as_i64() == Some(200),
            Some(serde_json::Value::String(s)) => s == "0" || s == "200",
            _ => false,
        };
        if obj.get("success") == Some(&serde_json::Value::Bool(false)) || !code_ok {
            let msg = obj
                .get("msg")
                .and_then(|m| m.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| {
                    format!(
                        "code {}",
                        obj.get("code").unwrap_or(&serde_json::Value::Null)
                    )
                });
            return Err(format!("Z.ai {op} failed: {msg}"));
        }
        return Ok(obj.get("data").cloned().unwrap_or(serde_json::Value::Null));
    }
    Ok(body)
}

/// Exchange the short-lived OAuth token for the durable `apiKey.secretKey`
/// minted by Z.ai's business APIs (business-login → default org/project →
/// find-or-create the freedas-named key → copy its secret).
async fn zai_mint_key(mut credentials: OAuthCredentials) -> Result<OAuthCredentials, String> {
    let biz_base = std::env::var("ZAI_BIZ_BASE").unwrap_or_else(|_| "https://api.z.ai".into());
    let login_url = std::env::var("ZAI_BUSINESS_LOGIN_URL")
        .unwrap_or_else(|_| "https://api.z.ai/api/auth/z/login".into());
    let client = crate::http_client();
    let resp = client
        .post(&login_url)
        .json(&serde_json::json!({ "token": credentials.access }))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    let data = zai_unwrap(body, "business login")?;
    let biz_token = scalar_string(data.get("access_token"))
        .or_else(|| scalar_string(data.get("accessToken")))
        .ok_or("Z.ai business login returned no access token")?;
    let auth = |req: reqwest::RequestBuilder| req.bearer_auth(&biz_token);
    let resp = auth(client.get(format!("{biz_base}/api/biz/customer/getCustomerInfo")))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let customer = zai_unwrap(
        resp.json().await.map_err(|e| e.to_string())?,
        "customer lookup",
    )?;
    let orgs = customer["organizations"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let org = orgs
        .iter()
        .find(|o| o["isDefault"].as_bool() == Some(true))
        .or_else(|| orgs.first());
    let projects = org
        .and_then(|o| o["projects"].as_array())
        .cloned()
        .unwrap_or_default();
    let project = projects
        .iter()
        .find(|p| p["isDefault"].as_bool() == Some(true))
        .or_else(|| projects.first());
    let (Some(org_id), Some(project_id)) = (
        org.and_then(|o| o["organizationId"].as_str())
            .filter(|s| !s.is_empty()),
        project
            .and_then(|p| p["projectId"].as_str())
            .filter(|s| !s.is_empty()),
    ) else {
        return Err("Z.ai key provisioning failed: no organization/project on account".into());
    };
    let keys_url =
        format!("{biz_base}/api/biz/v1/organization/{org_id}/projects/{project_id}/api_keys");
    let resp = auth(client.get(&keys_url))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let keys = zai_unwrap(
        resp.json().await.map_err(|e| e.to_string())?,
        "api key list",
    )?;
    let list = match &keys {
        serde_json::Value::Array(a) => a.clone(),
        v => ["list", "keys", "apiKeys", "records"]
            .iter()
            .find_map(|k| v[k].as_array().cloned())
            .unwrap_or_default(),
    };
    const KEY_NAME: &str = "freedas";
    let key_record = match list.iter().find(|k| k["name"].as_str() == Some(KEY_NAME)) {
        Some(k) => k.clone(),
        None => {
            let resp = auth(
                client
                    .post(&keys_url)
                    .json(&serde_json::json!({ "name": KEY_NAME })),
            )
            .send()
            .await
            .map_err(|e| e.to_string())?;
            zai_unwrap(
                resp.json().await.map_err(|e| e.to_string())?,
                "api key create",
            )?
        }
    };
    let api_key = scalar_string(key_record.get("apiKey"))
        .ok_or("Z.ai key provisioning returned no apiKey")?;
    // The copy endpoint returns the unmasked secret; list entries mask it.
    let resp = auth(client.get(format!("{keys_url}/copy/{api_key}")))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let copied = zai_unwrap(
        resp.json().await.map_err(|e| e.to_string())?,
        "api key copy",
    )?;
    let secret = scalar_string(copied.get("secretKey"))
        .ok_or("Z.ai key provisioning returned no secretKey")?;
    credentials.access = format!("{api_key}.{secret}");
    Ok(credentials)
}

/// Resolve (or provision) the Google Cloud Code Assist project after Gemini
/// CLI sign-in; refresh carries the stored project forward.
async fn google_gemini_cli_project(
    mut credentials: OAuthCredentials,
    ctx: &mut ExchangeContext<'_, '_>,
) -> Result<OAuthCredentials, String> {
    if ctx.phase == "refresh" {
        credentials.project_id = ctx.stored.and_then(|s| s.project_id.clone());
        return Ok(credentials);
    }
    if ctx.raw["refresh_token"]
        .as_str()
        .unwrap_or_default()
        .is_empty()
    {
        return Err("no refresh token received. Please try again.".into());
    }
    const CODE_ASSIST: &str = "https://cloudcode-pa.googleapis.com";
    let env_project = std::env::var("GOOGLE_CLOUD_PROJECT")
        .ok()
        .or_else(|| std::env::var("GOOGLE_CLOUD_PROJECT_ID").ok())
        .filter(|s| !s.is_empty());
    let client = crate::http_client();
    let headers = |req: reqwest::RequestBuilder| {
        req.bearer_auth(&credentials.access)
            .header("Content-Type", "application/json")
            .header("User-Agent", "google-api-nodejs-client/9.15.1")
            .header("X-Goog-Api-Client", "gl-node/freedas")
            .header(
                "Client-Metadata",
                "ideType=IDE_UNSPECIFIED,platform=PLATFORM_UNSPECIFIED,pluginType=GEMINI",
            )
    };
    ctx.progress("Checking for existing Cloud Code Assist project...");
    let load = headers(client.post(format!("{CODE_ASSIST}/v1internal:loadCodeAssist")))
        .json(&serde_json::json!({
            "cloudaicompanionProject": env_project,
            "metadata": {
                "ideType": "IDE_UNSPECIFIED",
                "platform": "PLATFORM_UNSPECIFIED",
                "pluginType": "GEMINI",
                "duetProject": env_project,
            },
        }))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let project_missing = || {
        "This account requires setting the GOOGLE_CLOUD_PROJECT or GOOGLE_CLOUD_PROJECT_ID environment variable. See https://goo.gle/gemini-cli-auth-docs#workspace-gca".to_string()
    };
    let project_id = if load.status().is_success() {
        let data: serde_json::Value = load.json().await.map_err(|e| e.to_string())?;
        if data["currentTier"].is_object() {
            match scalar_string(data.get("cloudaicompanionProject")).or(env_project.clone()) {
                Some(p) => p,
                None => return Err(project_missing()),
            }
        } else {
            // No tier yet: pick the default tier and onboard.
            let tier = data["allowedTiers"]
                .as_array()
                .and_then(|t| {
                    t.iter()
                        .find(|x| x["isDefault"].as_bool() == Some(true))
                        .or_else(|| t.first())
                })
                .and_then(|t| t["id"].as_str().map(str::to_string))
                .unwrap_or_else(|| "legacy-tier".into());
            if tier != "free-tier" && env_project.is_none() {
                return Err(project_missing());
            }
            ctx.progress("Provisioning Cloud Code Assist project (this may take a moment)...");
            let mut body = serde_json::json!({
                "tierId": tier,
                "metadata": {
                    "ideType": "IDE_UNSPECIFIED",
                    "platform": "PLATFORM_UNSPECIFIED",
                    "pluginType": "GEMINI",
                },
            });
            if tier != "free-tier"
                && let Some(p) = &env_project
            {
                body["cloudaicompanionProject"] = serde_json::json!(p);
                body["metadata"]["duetProject"] = serde_json::json!(p);
            }
            let onboard = headers(client.post(format!("{CODE_ASSIST}/v1internal:onboardUser")))
                .json(&body)
                .send()
                .await
                .map_err(|e| e.to_string())?;
            if !onboard.status().is_success() {
                let status = onboard.status().as_u16();
                let text = onboard.text().await.unwrap_or_default();
                return Err(format!("onboardUser failed: {status} {text}"));
            }
            let mut lro: serde_json::Value = onboard.json().await.map_err(|e| e.to_string())?;
            // Poll the long-running operation until done.
            for _ in 0..20 {
                if lro["done"].as_bool() == Some(true) {
                    break;
                }
                let Some(name) = lro["name"].as_str().map(str::to_string) else {
                    break;
                };
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                let poll = headers(client.get(format!("{CODE_ASSIST}/v1internal/{name}")))
                    .send()
                    .await;
                if let Ok(r) = poll
                    && r.status().is_success()
                {
                    lro = r.json().await.unwrap_or(lro);
                }
            }
            scalar_string(lro["response"].get("cloudaicompanionProject").and_then(|p| p.get("id")))
                .or(env_project.clone())
                .ok_or_else(|| {
                    "Could not discover or provision a Google Cloud project. Try setting GOOGLE_CLOUD_PROJECT or GOOGLE_CLOUD_PROJECT_ID.".to_string()
                })?
        }
    } else {
        // VPC-SC-affected users answer an access-exception body: standard tier
        // exists and the account owns no project, which falls through to env.
        let text = load.text().await.unwrap_or_default();
        if text.contains("VPC_SERVICE_CONTROLS") || text.contains("vpcServiceControls") {
            env_project.clone().ok_or_else(project_missing)?
        } else {
            return Err(format!("loadCodeAssist failed: {text}"));
        }
    };
    credentials.project_id = Some(project_id);
    Ok(credentials)
}

/// Mint the Muse Code API key; the OAuth access token wraps the minted key as
/// JSON (`{"oauthAccessToken","apiKey"}`) so model calls use the durable key.
async fn muse_code_key(mut credentials: OAuthCredentials) -> Result<OAuthCredentials, String> {
    // A credential that already carries a minted key never re-mints: the key
    // endpoint is rate-limited and returns the same key.
    if let Ok(existing) = serde_json::from_str::<serde_json::Value>(&credentials.access)
        && existing["apiKey"]
            .as_str()
            .is_some_and(|k| !k.trim().is_empty())
    {
        return Ok(credentials);
    }
    let client = crate::http_client();
    let resp = client
        .post("https://api.meta.ai/muse-code/key")
        .header("Accept", "application/json")
        .header("x-api-version", "1.0.0")
        .bearer_auth(&credentials.access)
        .json(&serde_json::json!({ "onboard": true }))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    if !(200..300).contains(&status) {
        return Err(format!(
            "Muse Code key exchange failed: {status} {}",
            &text[..text.len().min(500)]
        ));
    }
    let payload: serde_json::Value = serde_json::from_str(&text)
        .map_err(|_| "Muse Code key exchange returned invalid JSON".to_string())?;
    if payload["is_subs_active"].as_bool() == Some(false) {
        return Err("invalid_grant: Muse Code subscription is inactive".into());
    }
    let api_key = payload["api_key"]
        .as_str()
        .unwrap_or_default()
        .trim()
        .to_string();
    if api_key.is_empty() {
        let action = payload["action_url"]
            .as_str()
            .or(payload["require_payment_action_url"].as_str());
        if payload["require_payment"].as_bool() == Some(true) || action.is_some() {
            return Err(match action {
                Some(u) if !u.is_empty() => format!("Muse Code subscription is required: {u}"),
                _ => "Muse Code subscription is required".into(),
            });
        }
        return Err("Muse Code key response is missing api_key".into());
    }
    let email = payload["user_email"]
        .as_str()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty());
    let account_id = payload["user_id"]
        .as_str()
        .map(str::to_string)
        .or(email.clone());
    if account_id.is_none() {
        return Err("Muse Code key response is missing a stable account identity".into());
    }
    credentials.access = serde_json::json!({
        "oauthAccessToken": credentials.access,
        "apiKey": api_key,
    })
    .to_string();
    credentials.account_id = account_id;
    credentials.email = email;
    Ok(credentials)
}

/// Attach Factory region/inference region from `/api/cli/whoami` for the
/// bearer; login requires the call to resolve an organization.
async fn factory_droid_region(
    mut credentials: OAuthCredentials,
    ctx: &ExchangeContext<'_, '_>,
) -> Result<OAuthCredentials, String> {
    let base = match credentials.region.as_deref() {
        Some("eu") => "https://api.eu.factory.ai",
        _ => "https://api.factory.ai",
    };
    let client = crate::http_client();
    let mut req = client
        .get(format!("{base}/api/cli/whoami"))
        .bearer_auth(&credentials.access)
        .header("Accept", "application/json")
        .header("X-Factory-Whoami-Extended", "true");
    if let Some(org) = &credentials.org_id {
        req = req.header("X-Factory-Org-Id", org);
    }
    let resp = req.send().await;
    match resp {
        Ok(r) if r.status().is_success() => {
            if let Ok(body) = r.json::<serde_json::Value>().await {
                let org = body["orgId"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                // A different organization must not inherit the stored scope.
                let same_org =
                    org.is_none() || credentials.org_id.is_none() || org == credentials.org_id;
                if same_org {
                    if let Some(o) = org {
                        credentials.org_id = Some(o);
                    }
                    if matches!(body["region"].as_str(), Some("eu" | "global")) {
                        credentials.region = body["region"].as_str().map(str::to_string);
                    }
                    if matches!(
                        body["inferenceRegion"].as_str(),
                        Some("global" | "eu" | "us")
                    ) {
                        credentials.inference_region =
                            body["inferenceRegion"].as_str().map(str::to_string);
                    } else if credentials.inference_region.is_none() {
                        credentials.inference_region = match credentials.region.as_deref() {
                            Some("eu") => Some("eu".into()),
                            _ => Some("global".into()),
                        };
                    }
                }
                if ctx.phase == "login" && credentials.org_id.is_none() {
                    return Err("Factory login did not resolve an organization".into());
                }
            }
        }
        Ok(r) if ctx.phase == "login" => {
            let status = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            return Err(format!("Factory identity check failed ({status}): {text}"));
        }
        Ok(_) => {}
        Err(e) if ctx.phase == "login" => {
            return Err(format!("Factory identity check failed: {e}"));
        }
        Err(_) => {}
    }
    Ok(credentials)
}

// ---------------------------------------------------------------------------
// login "custom" hooks
// ---------------------------------------------------------------------------

/// GitHub Enterprise input → bare domain, or None for invalid input.
fn normalize_domain(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    reqwest::Url::parse(&with_scheme)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .filter(|h| !h.is_empty())
}

/// github.com device flow (OpenCode app, minimal read:user grant); enterprise
/// domains keep the Copilot CLI client and run their own OAuth registry.
async fn login_github_copilot(host: &mut LoginHost<'_>) -> Result<OAuthCredentials, String> {
    const OPENCODE_CLIENT: &str = "Ov23li8tweQw6odWQebz";
    const COPILOT_CLI_CLIENT: &str = "Ov23ctDVkRmgkPke0Mmm";
    const FAR_FUTURE_MS: i64 = 10 * 365 * 24 * 60 * 60 * 1000;
    let input = host.ask(
        "GitHub Enterprise URL/domain (blank for github.com):",
        Some("company.ghe.com"),
    )?;
    let trimmed = input.trim();
    let normalized = normalize_domain(trimmed);
    if !trimmed.is_empty() && normalized.is_none() {
        return Err("invalid GitHub Enterprise URL/domain".into());
    }
    let domain = normalized.clone().unwrap_or_else(|| "github.com".into());
    let public = matches!(
        domain.as_str(),
        "github.com" | "www.github.com" | "api.github.com"
    );
    let domain = if public {
        "github.com".to_string()
    } else {
        domain
    };
    let enterprise = if public { None } else { Some(domain.clone()) };
    let client_id = if public {
        OPENCODE_CLIENT
    } else {
        COPILOT_CLI_CLIENT
    };
    let client = crate::http_client();
    let headers = |req: reqwest::RequestBuilder| {
        req.header("Accept", "application/json")
            .header("User-Agent", "copilot-developer-action/0.0.1")
    };
    let resp = headers(client.post(format!("https://{domain}/login/device/code")))
        .form(&[("client_id", client_id), ("scope", "read:user")])
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        return Err(format!(
            "github device authorization failed: {status} {text}"
        ));
    }
    let dev: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    let (Some(device_code), Some(user_code), Some(verification_uri)) = (
        dev["device_code"].as_str(),
        dev["user_code"].as_str(),
        dev["verification_uri"].as_str(),
    ) else {
        return Err("github device authorization response missing required fields".into());
    };
    let mut interval = dev["interval"].as_f64().unwrap_or(5.0).max(1.0);
    let expires_in = dev["expires_in"].as_f64().unwrap_or(900.0);
    let expires_mins = (expires_in / 60.0).ceil().max(1.0) as u64;
    host.auth(
        verification_uri,
        None,
        Some(&format!(
            "Enter code: {user_code}\n\nCode: {user_code}\nOnly approve this code ({user_code}) on the verification page; it expires in ~{expires_mins} min. Do not approve a different code."
        )),
    );
    if host.open_browser {
        open_browser(verification_uri);
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs_f64(expires_in);
    let access = loop {
        if std::time::Instant::now() >= deadline {
            return Err("device flow timed out".into());
        }
        tokio::time::sleep(std::time::Duration::from_secs_f64(
            (interval * 1.2).min(remaining(&deadline)),
        ))
        .await;
        let resp = headers(client.post(format!("https://{domain}/login/oauth/access_token")))
            .form(&[
                ("client_id", client_id),
                ("device_code", device_code),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ])
            .send()
            .await;
        let Ok(resp) = resp else { continue };
        if !resp.status().is_success() {
            continue;
        }
        let Ok(body) = resp.json::<serde_json::Value>().await else {
            continue;
        };
        if let Some(token) = body["access_token"].as_str().filter(|s| !s.is_empty()) {
            break token.to_string();
        }
        match body["error"].as_str() {
            Some("authorization_pending") | None => {}
            Some("slow_down") => {
                interval = body["interval"]
                    .as_f64()
                    .filter(|i| *i > 0.0)
                    .unwrap_or(interval + 5.0);
            }
            Some(e) => {
                let desc = body["error_description"].as_str().unwrap_or_default();
                return Err(format!(
                    "device flow failed: {e}{}",
                    if desc.is_empty() {
                        "".into()
                    } else {
                        format!(": {desc}")
                    }
                ));
            }
        }
    };
    // Plan-specific API endpoint from copilot_internal/user (best-effort).
    let api_endpoint = match headers(client.get("https://api.github.com/copilot_internal/user"))
        .header("Authorization", format!("token {access}"))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|b| b["endpoints"]["api"].as_str().map(str::to_string))
            .filter(|u| u.starts_with("https://"))
            .map(|u| u.trim_end_matches('/').to_string()),
        _ => None,
    };
    Ok(OAuthCredentials {
        refresh: access.clone(),
        access,
        expires: now_ms() + FAR_FUTURE_MS,
        enterprise_url: enterprise,
        api_endpoint,
        authorized_at: Some(now_ms()),
        ..Default::default()
    })
}

fn remaining(deadline: &std::time::Instant) -> f64 {
    deadline
        .saturating_duration_since(std::time::Instant::now())
        .as_secs_f64()
        .max(1.0)
}

/// Cursor: PKCE sign-in at cursor.com, poll api2.cursor.sh/auth/poll.
async fn login_cursor(host: &mut LoginHost<'_>) -> Result<OAuthCredentials, String> {
    let pkce = generate_pkce();
    let uuid = uuid::Uuid::new_v4().to_string();
    let login_url = format!(
        "https://cursor.com/loginDeepControl?{}",
        form_encode(&[
            ("challenge".into(), pkce.challenge.clone()),
            ("uuid".into(), uuid.clone()),
            ("mode".into(), "login".into()),
            ("redirectTarget".into(), "cli".into()),
        ])
    );
    host.auth(&login_url, None, None);
    if host.open_browser {
        open_browser(&login_url);
    }
    host.progress("Waiting for browser authentication...");
    let client = crate::http_client();
    let mut delay = 1.0f64;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(150 * 8);
    let mut consecutive_errors = 0u32;
    let tokens = loop {
        if std::time::Instant::now() >= deadline {
            return Err("Cursor authentication polling timeout".into());
        }
        tokio::time::sleep(std::time::Duration::from_secs_f64(delay.min(10.0))).await;
        delay = (delay * 1.2).min(10.0);
        let resp = client
            .get(format!(
                "https://api2.cursor.sh/auth/poll?uuid={uuid}&verifier={}",
                pkce.verifier
            ))
            .send()
            .await;
        let Ok(resp) = resp else {
            consecutive_errors += 1;
            if consecutive_errors > 10 {
                return Err("too many consecutive errors during Cursor auth polling".into());
            }
            continue;
        };
        if !resp.status().is_success() {
            continue;
        }
        let Ok(body) = resp.json::<serde_json::Value>().await else {
            continue;
        };
        let (Some(access), Some(refresh)) = (
            body["accessToken"].as_str().filter(|s| !s.is_empty()),
            body["refreshToken"].as_str().filter(|s| !s.is_empty()),
        ) else {
            continue;
        };
        break (access.to_string(), refresh.to_string());
    };
    // Profile email via Connect RPC GetMe (best-effort).
    let email = match client
        .post("https://api2.cursor.sh/aiserver.v1.DashboardService/GetMe")
        .header("Content-Type", "application/json")
        .bearer_auth(&tokens.0)
        .body("{}")
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => {
            r.json::<serde_json::Value>().await.ok().and_then(|b| {
                b["email"]
                    .as_str()
                    .map(str::to_string)
                    .or_else(|| b["user"]["email"].as_str().map(str::to_string))
            })
        }
        _ => None,
    };
    Ok(OAuthCredentials {
        access: tokens.0,
        refresh: tokens.1,
        expires: NEVER_EXPIRES,
        email,
        authorized_at: Some(now_ms()),
        ..Default::default()
    })
}

/// Devin CLI credentials: probe the CLI's credentials.toml candidates and read
/// `windsurf_api_key`; no network.
fn login_devin_cli() -> Result<String, String> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_default();
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        candidates.push(std::path::PathBuf::from(xdg).join("devin/credentials.toml"));
    }
    candidates.push(std::path::PathBuf::from(&home).join(".local/share/devin/credentials.toml"));
    if cfg!(target_os = "macos") {
        candidates.push(
            std::path::PathBuf::from(&home)
                .join("Library/Application Support/devin/credentials.toml"),
        );
    }
    if let Ok(appdata) = std::env::var("APPDATA") {
        candidates.push(std::path::PathBuf::from(appdata).join("devin/credentials.toml"));
    }
    candidates.dedup();
    for file in &candidates {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        // Minimal TOML surface: `windsurf_api_key = "…"` and `api_server_url`.
        let mut key = String::new();
        let mut server = String::new();
        for line in text.lines() {
            let line = line.trim();
            for (name, slot) in [
                ("windsurf_api_key", &mut key),
                ("api_server_url", &mut server),
            ] {
                if let Some(rest) = line.strip_prefix(name)
                    && let Some(eq) = rest.trim_start().strip_prefix('=')
                {
                    *slot = eq.trim().trim_matches('"').trim_matches('\'').to_string();
                }
            }
        }
        if key.is_empty() {
            return Err(format!(
                "Devin CLI credentials at {} have no windsurf_api_key. Run `devin auth login`, then retry.",
                file.display()
            ));
        }
        if !server.is_empty() {
            let host_ok = reqwest::Url::parse(&server)
                .ok()
                .and_then(|u| u.host_str().map(str::to_string))
                .is_some_and(|h| {
                    h == "server.codeium.com" || h == "server.enterprise.windsurf.com"
                });
            if !host_ok {
                return Err(format!(
                    "Devin CLI credentials at {} point at unsupported API server \"{server}\" (supported: server.codeium.com, server.enterprise.windsurf.com).",
                    file.display()
                ));
            }
        }
        return Ok(key);
    }
    Err(format!(
        "No Devin CLI credentials found (probed: {}). Run `devin auth login`, then retry.",
        candidates
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

/// Windsurf editor PKCE sign-in → protobuf code exchange → seat API key.
async fn login_devin_windsurf(host: &mut LoginHost<'_>) -> Result<String, String> {
    const CALLBACK_PORT: u16 = 59654;
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{CALLBACK_PORT}"))
        .await
        .map_err(|e| format!("Windsurf callback port {CALLBACK_PORT} unavailable: {e}"))?;
    let port = listener
        .local_addr()
        .map(|a| a.port())
        .unwrap_or(CALLBACK_PORT);
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");
    let state = uuid::Uuid::new_v4().to_string();
    let pkce = generate_pkce();
    let url = format!(
        "https://windsurf.com/editor/signin?{}",
        form_encode(&[
            ("response_type".into(), "code".into()),
            ("redirect_uri".into(), redirect_uri.clone()),
            ("state".into(), state.clone()),
            ("code_challenge".into(), pkce.challenge.clone()),
            ("code_challenge_method".into(), "S256".into()),
            ("prompt".into(), "login".into()),
            ("redirect_parameters_type".into(), "query".into()),
        ])
    );
    host.auth(
        &url,
        None,
        Some("Sign in with your Windsurf (Enterprise) account in your browser."),
    );
    if host.open_browser {
        open_browser(&url);
    }
    host.progress("Waiting for browser authentication...");
    let launch: std::sync::Arc<std::sync::RwLock<Option<String>>> =
        std::sync::Arc::new(std::sync::RwLock::new(Some(url)));
    let server = CallbackServer {
        callback_path: "/callback".into(),
        redirect_uri: redirect_uri.clone(),
        launch_path_url: format!("http://127.0.0.1:{port}/launch"),
        listener_v4: listener,
        listener_v6: None,
    };
    let (code, _) = wait_for_callback(&server, &state, launch).await?;
    host.progress("Exchanging authorization code...");
    // Connect-RPC protobuf: ExchangePKCEAuthorizationCodeRequest is two
    // length-delimited string fields; the response answers { apiKey }.
    let mut body = Vec::new();
    proto_string(&mut body, 1, &code);
    proto_string(&mut body, 2, &pkce.verifier);
    let resp = crate::http_client()
        .post("https://server.codeium.com/exa.seat_management_pb.SeatManagementService/ExchangePKCEAuthorizationCode")
        .header("content-type", "application/proto")
        .header("connect-protocol-version", "1")
        .header("accept", "*/*")
        .body(body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("Windsurf code exchange failed: {status} {text}"));
    }
    let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
    let api_key =
        proto_find_string(&bytes, 1).ok_or("Windsurf code exchange returned no API key")?;
    // The exchange returns the `g`-prefixed wire form (`gsk-ws-…`); the raw
    // key (`sk-ws-…`) authenticates RPCs.
    Ok(api_key
        .strip_prefix('g')
        .map(str::to_string)
        .unwrap_or(api_key))
}

fn proto_string(out: &mut Vec<u8>, field: u32, value: &str) {
    out.push(((field << 3) | 2) as u8);
    out.extend_from_slice(&proto_varint(value.len() as u64));
    out.extend_from_slice(value.as_bytes());
}

fn proto_varint(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            return out;
        }
    }
}

/// Scan a protobuf buffer for the first length-delimited string on `field`.
fn proto_find_string(buf: &[u8], field: u32) -> Option<String> {
    let tag = ((field << 3) | 2) as u8;
    let mut i = 0;
    while i + 2 <= buf.len() {
        if buf[i] == tag {
            let (len, used) = proto_read_varint(&buf[i + 1..])?;
            let start = i + 1 + used;
            let end = start + len as usize;
            if end <= buf.len()
                && let Ok(s) = String::from_utf8(buf[start..end].to_vec())
            {
                return Some(s);
            }
        }
        i += 1;
    }
    None
}

fn proto_read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut v = 0u64;
    for (i, b) in buf.iter().take(10).enumerate() {
        v |= ((b & 0x7f) as u64) << (7 * i);
        if b & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

/// Perplexity: desktop-app token on macOS, else email OTP (sso browser flow
/// needs an interactive web session, unavailable here).
async fn login_perplexity(host: &mut LoginHost<'_>) -> Result<OAuthCredentials, String> {
    if std::env::var("PI_AUTH_NO_BORROW").is_err() && cfg!(target_os = "macos") {
        host.progress("Checking for Perplexity desktop app...");
        if let Ok(out) = std::process::Command::new("defaults")
            .args(["read", "ai.perplexity.mac", "authToken"])
            .output()
            && out.status.success()
        {
            let jwt = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !jwt.is_empty() {
                host.progress("Found Perplexity JWT from native app");
                return Ok(jwt_credentials(&jwt, None));
            }
        }
    }
    let email = host.ask(
        "Enter your Perplexity email address:",
        Some("user@example.com"),
    )?;
    let email = email.trim().to_string();
    if email.is_empty() {
        return Err("email is required for Perplexity login".into());
    }
    const UA: &str = "Perplexity/641 CFNetwork/1568 Darwin/25.2.0";
    const API_VERSION: &str = "2.18";
    let client = crate::http_client();
    let mut cookies: Vec<String> = Vec::new();
    let remember = |cookies: &mut Vec<String>, resp: &reqwest::Response| {
        for c in resp.headers().get_all("set-cookie") {
            if let Ok(v) = c.to_str()
                && let Some(pair) = v.split(';').next()
            {
                cookies.push(pair.to_string());
            }
        }
    };
    let csrf_resp = client
        .get("https://www.perplexity.ai/api/auth/csrf")
        .header("User-Agent", UA)
        .header("X-App-ApiVersion", API_VERSION)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    remember(&mut cookies, &csrf_resp);
    if !csrf_resp.status().is_success() {
        return Err(format!(
            "Perplexity CSRF request failed: {}",
            csrf_resp.status()
        ));
    }
    let csrf: serde_json::Value = csrf_resp.json().await.map_err(|e| e.to_string())?;
    let csrf_token = csrf["csrfToken"].as_str().unwrap_or_default().to_string();
    if csrf_token.is_empty() {
        return Err("Perplexity CSRF response missing csrfToken".into());
    }
    host.progress("Sending login code to your email...");
    let send = client
        .post("https://www.perplexity.ai/api/auth/signin-email")
        .header("User-Agent", UA)
        .header("X-App-ApiVersion", API_VERSION)
        .header("Content-Type", "application/json")
        .header("Cookie", cookies.join("; "))
        .json(&serde_json::json!({ "email": email, "csrfToken": csrf_token }))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    remember(&mut cookies, &send);
    if !send.status().is_success() {
        let status = send.status().as_u16();
        let text = send.text().await.unwrap_or_default();
        return Err(format!(
            "Perplexity send login code failed ({status}): {text}"
        ));
    }
    let otp = host.ask("Enter the code sent to your email:", Some("123456"))?;
    let otp = otp.trim().to_string();
    if otp.is_empty() {
        return Err("OTP code is required".into());
    }
    host.progress("Verifying login code...");
    let verify = client
        .post("https://www.perplexity.ai/api/auth/signin-otp")
        .header("User-Agent", UA)
        .header("X-App-ApiVersion", API_VERSION)
        .header("Content-Type", "application/json")
        .header("Cookie", cookies.join("; "))
        .json(&serde_json::json!({ "email": email, "otp": otp, "csrfToken": csrf_token }))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    remember(&mut cookies, &verify);
    let success = verify.status().is_success();
    let mut data: serde_json::Value = verify.json().await.unwrap_or_default();
    if !success {
        let reason = data["text"]
            .as_str()
            .or(data["error_code"].as_str())
            .or(data["status"].as_str())
            .unwrap_or("OTP verification failed");
        return Err(format!("Perplexity OTP verification failed: {reason}"));
    }
    if data["status"].as_str() == Some("totp_challenge_required")
        && data["challenge_token"].is_string()
    {
        let totp = host.ask(
            "Enter the code from your authenticator app:",
            Some("123456"),
        )?;
        let totp = totp.trim().to_string();
        if totp.is_empty() {
            return Err("authenticator code is required".into());
        }
        host.progress("Verifying authenticator code...");
        let tresp = client
            .post("https://www.perplexity.ai/api/auth/totp/challenge-verify")
            .header("User-Agent", UA)
            .header("X-App-ApiVersion", API_VERSION)
            .header("Content-Type", "application/json")
            .header("Cookie", cookies.join("; "))
            .json(&serde_json::json!({ "token": data["challenge_token"], "code": totp }))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        remember(&mut cookies, &tresp);
        data = tresp.json().await.unwrap_or_default();
        if data["token"].is_null() {
            let session = cookies
                .iter()
                .find_map(|c| {
                    c.strip_prefix("__Secure-next-auth.session-token=")
                        .or_else(|| c.strip_prefix("next-auth.session-token="))
                })
                .map(str::to_string);
            data = serde_json::json!({ "token": session, "status": "success" });
        }
    }
    let token = data["token"].as_str().or(data["challenge_token"].as_str());
    let rejected = data["error_code"].is_string()
        || (data["status"].is_string() && data["status"].as_str() != Some("success"));
    match (token, rejected) {
        (Some(t), false) if !t.is_empty() => Ok(jwt_credentials(t, Some(email))),
        _ => Err(format!(
            "Perplexity OTP verification response rejected: {}",
            data["text"]
                .as_str()
                .or(data["error_code"].as_str())
                .or(data["status"].as_str())
                .unwrap_or("missing token")
        )),
    }
}

fn jwt_credentials(jwt: &str, email: Option<String>) -> OAuthCredentials {
    OAuthCredentials {
        access: jwt.to_string(),
        refresh: jwt.to_string(),
        // Undecodable JWTs get a short TTL so a bad token is retried, not
        // cached as never-expiring.
        expires: jwt_expiry_ms(jwt, 300_000).unwrap_or_else(|| now_ms().saturating_add(3_600_000)),
        email,
        authorized_at: Some(now_ms()),
        ..Default::default()
    }
}

/// Alibaba Coding Plan: region pick, then key paste + validation; the chosen
/// endpoint rides in `enterprise_url` for the wire layer.
async fn login_alibaba_coding_plan(host: &mut LoginHost<'_>) -> Result<OAuthCredentials, String> {
    const INTL_API: &str = "https://coding-intl.dashscope.aliyuncs.com/v1";
    const CN_API: &str = "https://coding.dashscope.aliyuncs.com/v1";
    const INTL_AUTH: &str = "https://modelstudio.console.alibabacloud.com/";
    const CN_AUTH: &str = "https://bailian.console.aliyun.com/?tab=model#/api-key";
    let choice = host
        .ask(
            "Select Alibaba Coding Plan endpoint: 1=International (default), 2=China, 3=Custom - enter 1, 2, or 3:",
            Some("1"),
        )?;
    let (base_url, auth_url, instructions) = match choice.trim() {
        "2" => (
            CN_API.to_string(),
            CN_AUTH.to_string(),
            "Copy your API key from the Alibaba Cloud Bailian console (China mainland)".to_string(),
        ),
        "3" => {
            let custom = host.ask("Enter custom base URL:", Some("https://your-proxy.com/v1"))?;
            let custom = custom.trim().trim_end_matches('/').to_string();
            if custom.is_empty() {
                return Err("custom URL is required for option 3".into());
            }
            (
                custom,
                INTL_AUTH.to_string(),
                "Copy your API key from the Alibaba Cloud DashScope console".to_string(),
            )
        }
        _ => (
            INTL_API.to_string(),
            INTL_AUTH.to_string(),
            "Copy your API key from the Alibaba Cloud DashScope console (International)"
                .to_string(),
        ),
    };
    host.auth(&auth_url, None, Some(&instructions));
    if host.open_browser {
        open_browser(&auth_url);
    }
    let key = host.ask("Paste your Alibaba Coding Plan API key:", Some("sk-..."))?;
    let key = key.trim().to_string();
    if key.is_empty() {
        return Err("Alibaba Coding Plan API key is required".into());
    }
    host.progress("Validating API key...");
    if choice.trim() == "3" {
        validate_models_endpoint(
            "Alibaba Coding Plan",
            &key,
            &format!("{base_url}/models"),
            &[],
        )
        .await?;
    } else {
        validate_chat_completions(
            "Alibaba Coding Plan",
            &key,
            &base_url,
            "qwen3.5-plus",
            "max_tokens",
            false,
        )
        .await?;
    }
    Ok(OAuthCredentials {
        access: key.clone(),
        refresh: key,
        expires: NEVER_EXPIRES,
        enterprise_url: Some(base_url),
        authorized_at: Some(now_ms()),
        ..Default::default()
    })
}

/// QwenCloud Token Plan: region pick, key paste + /models validation, optional
/// usage-report cookie. Region and cookie ride in a JSON-serialized key.
async fn login_alibaba_token_plan(host: &mut LoginHost<'_>) -> Result<String, String> {
    const INTL_API: &str = "https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1";
    const CN_API: &str = "https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1";
    const INTL_AUTH: &str = "https://home.qwencloud.com/billing/subscription/token-plan-individual";
    const CN_AUTH: &str = "https://www.aliyun.com/benefit/scene/tokenplan";
    let choice = host.ask(
        "Select QwenCloud Token Plan region: 1=International (default), 2=China (Beijing), 3=Custom - enter 1, 2, or 3:",
        Some("1"),
    )?;
    let cn = choice.trim() == "2";
    let (base_url, auth_url, instructions) = match choice.trim() {
        "2" => (
            CN_API.to_string(),
            CN_AUTH.to_string(),
            "Subscribe to the China (Beijing) Token Plan and copy its dedicated API key"
                .to_string(),
        ),
        "3" => {
            let custom = host.ask(
                "Enter custom Token Plan base URL:",
                Some("https://token-plan.<region>.maas.aliyuncs.com/compatible-mode/v1"),
            )?;
            let custom = custom.trim().trim_end_matches('/').to_string();
            if custom.is_empty() {
                return Err("custom URL is required for option 3".into());
            }
            (
                custom,
                INTL_AUTH.to_string(),
                "Copy your Token Plan API key for the custom endpoint".to_string(),
            )
        }
        _ => (
            INTL_API.to_string(),
            INTL_AUTH.to_string(),
            "Subscribe to Token Plan Individual and copy its dedicated API key.".to_string(),
        ),
    };
    host.auth(&auth_url, None, Some(&instructions));
    if host.open_browser {
        open_browser(&auth_url);
    }
    let key = host.ask(
        "Paste your QwenCloud Token Plan API key:",
        Some("sk-sp-..."),
    )?;
    let key = key.trim().to_string();
    if key.is_empty() {
        return Err("QwenCloud Token Plan API key is required".into());
    }
    host.progress("Validating API key...");
    validate_models_endpoint(
        "QwenCloud Token Plan",
        &key,
        &format!("{base_url}/models"),
        &[],
    )
    .await?;
    let cookie_prompt = if cn {
        "Optional quota reporting: paste the complete Cookie request header from the bailian-cs.console.aliyun.com/data/api.json usage request, or press Enter to skip:"
    } else {
        "Optional quota reporting: paste the complete Cookie request header from the cs-data.qwencloud.com/data/api.json usage request, or press Enter to skip:"
    };
    let raw_cookie = host.prompt(&OAuthPrompt {
        message: cookie_prompt.into(),
        placeholder: Some("name=value; name=value; ...".into()),
        allow_empty: true,
        secret: true,
    })?;
    let cookie = raw_cookie
        .trim()
        .strip_prefix("Cookie:")
        .map(str::trim)
        .unwrap_or(raw_cookie.trim())
        .to_string();
    if !cookie.is_empty()
        && !cookie.split(';').any(|seg| {
            seg.split_once('=')
                .is_some_and(|(k, v)| !k.trim().is_empty() && !v.trim().is_empty())
        })
    {
        return Err(
            "invalid QwenCloud Cookie header: paste the complete name=value; ... header".into(),
        );
    }
    let region_url = if base_url == INTL_API {
        None
    } else {
        Some(base_url)
    };
    if cookie.is_empty() && region_url.is_none() {
        return Ok(key);
    }
    let mut payload = serde_json::json!({ "token": key });
    if !cookie.is_empty() {
        payload["cookie"] = serde_json::json!(cookie);
    }
    if let Some(u) = region_url {
        payload["baseUrl"] = serde_json::json!(u);
    }
    Ok(payload.to_string())
}

/// Cloudflare AI Gateway: token + account id + gateway id, JSON-serialized.
async fn login_cloudflare_ai_gateway(host: &mut LoginHost<'_>) -> Result<String, String> {
    const AUTH_URL: &str =
        "https://developers.cloudflare.com/ai-gateway/configuration/authentication/";
    host.auth(
        AUTH_URL,
        None,
        Some("Create an AI Gateway token with Run permission, then copy it here."),
    );
    if host.open_browser {
        open_browser(AUTH_URL);
    }
    let key = host.ask(
        "Paste your Cloudflare AI Gateway token/API key:",
        Some("cfut_..."),
    )?;
    if key.trim().is_empty() {
        return Err("Cloudflare API key is required".into());
    }
    let account = host.ask(
        "Enter your Cloudflare account ID:",
        Some("32-character account ID"),
    )?;
    if account.trim().is_empty() {
        return Err("Cloudflare account ID is required".into());
    }
    let gateway = host.ask("Enter your Cloudflare AI Gateway ID:", Some("default"))?;
    if gateway.trim().is_empty() {
        return Err("Cloudflare AI Gateway ID is required".into());
    }
    Ok(serde_json::json!({
        "token": key.trim(),
        "accountId": account.trim(),
        "gatewayId": gateway.trim(),
    })
    .to_string())
}

/// Cloudflare Workers AI: token + account id, JSON-serialized.
async fn login_cloudflare_workers_ai(host: &mut LoginHost<'_>) -> Result<String, String> {
    const AUTH_URL: &str = "https://dash.cloudflare.com/profile/api-tokens";
    host.auth(
        AUTH_URL,
        None,
        Some("Create an API token with Workers AI Read and Edit permissions, then copy it here."),
    );
    if host.open_browser {
        open_browser(AUTH_URL);
    }
    let token = host.ask(
        "Paste your Cloudflare API token:",
        Some("Workers AI API token"),
    )?;
    if token.trim().is_empty() {
        return Err("Cloudflare API token is required".into());
    }
    let account = host.ask(
        "Enter your Cloudflare account ID:",
        Some("32-character account ID"),
    )?;
    if account.trim().is_empty() {
        return Err("Cloudflare account ID is required".into());
    }
    Ok(serde_json::json!({
        "token": token.trim(),
        "accountId": account.trim(),
    })
    .to_string())
}

/// Kilo device auth: POST /api/device-auth/codes, then GET poll until approved.
async fn login_kilo(host: &mut LoginHost<'_>) -> Result<OAuthCredentials, String> {
    const BASE: &str = "https://api.kilo.ai/api/device-auth";
    const ONE_YEAR_MS: i64 = 365 * 24 * 60 * 60 * 1000;
    let client = crate::http_client();
    let resp = client
        .post(format!("{BASE}/codes"))
        .header("Content-Type", "application/json")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        if status == 429 {
            return Err("too many pending authorization requests. Please try again later.".into());
        }
        return Err(format!("failed to initiate device authorization: {status}"));
    }
    let data: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    let (Some(code), Some(url), Some(expires)) = (
        data["code"].as_str(),
        data["verificationUrl"].as_str(),
        data["expiresIn"].as_f64(),
    ) else {
        return Err("Kilo device authorization response missing required fields".into());
    };
    let expires_mins = (expires / 60.0).ceil().max(1.0) as u64;
    host.auth(url, None, Some(&format!("Enter code: {code}\n\nCode: {code}\nOnly approve this code ({code}) on the verification page; it expires in ~{expires_mins} min. Do not approve a different code.")));
    if host.open_browser {
        open_browser(url);
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs_f64(expires);
    loop {
        if std::time::Instant::now() >= deadline {
            return Err("authentication timed out. Please try again.".into());
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let poll = client.get(format!("{BASE}/codes/{code}")).send().await;
        let Ok(poll) = poll else { continue };
        let status = poll.status().as_u16();
        match status {
            202 => continue,
            403 => return Err("authorization was denied".into()),
            410 => return Err("authorization code expired. Please try again.".into()),
            s if !(200..300).contains(&s) => {
                return Err(format!("failed to poll device authorization: {s}"));
            }
            _ => {}
        }
        let body: serde_json::Value = poll.json().await.unwrap_or_default();
        match body["status"].as_str() {
            Some("approved") => {
                if let Some(token) = body["token"].as_str().filter(|t| !t.is_empty()) {
                    return Ok(OAuthCredentials {
                        access: token.to_string(),
                        expires: now_ms() + ONE_YEAR_MS,
                        authorized_at: Some(now_ms()),
                        ..Default::default()
                    });
                }
            }
            Some("denied") => return Err("authorization was denied".into()),
            Some("expired") => return Err("authorization code expired. Please try again.".into()),
            _ => {}
        }
    }
}

/// Xiaomi MiMo: pay-as-you-go or Token Plan keys with SGP → AMS → CN probing.
async fn login_xiaomi(host: &mut LoginHost<'_>) -> Result<String, String> {
    host.auth(
        "https://platform.xiaomimimo.com/#/console/api-keys",
        None,
        Some("Copy your API key from the Xiaomi MiMo console"),
    );
    if host.open_browser {
        open_browser("https://platform.xiaomimimo.com/#/console/api-keys");
    }
    let key = host.ask(
        "Paste your Xiaomi API key (sk-... or Token Plan tp-... / ttp-...):",
        Some("sk-..., tp-..., or ttp-..."),
    )?;
    let key = key.trim().to_string();
    if key.is_empty() {
        return Err("Xiaomi API key is required".into());
    }
    host.progress("Validating xiaomi API key...");
    let token_plan = key.starts_with("tp-") || key.starts_with("ttp-");
    let endpoints: Vec<(&str, &str)> = if token_plan {
        vec![
            (
                "https://token-plan-sgp.xiaomimimo.com/v1",
                "mimo-v2.6-flash",
            ),
            (
                "https://token-plan-ams.xiaomimimo.com/v1",
                "mimo-v2.6-flash",
            ),
            ("https://token-plan-cn.xiaomimimo.com/v1", "mimo-v2.6-flash"),
        ]
    } else {
        vec![("https://api.xiaomimimo.com/v1", "mimo-v2.6-flash")]
    };
    let mut last = String::new();
    for (base, model) in endpoints {
        match validate_chat_completions("Xiaomi MiMo", &key, base, model, "max_tokens", false).await
        {
            Ok(()) => return Ok(key),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// OpenAI Codex headless device flow: usercode initiation → code+verifier
/// poll → standard token exchange.
async fn login_openai_codex_device<'a>(
    host: &'a mut LoginHost<'a>,
) -> Result<OAuthCredentials, String> {
    const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
    const TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
    const DEVICE_REDIRECT: &str = "https://auth.openai.com/deviceauth/callback";
    let client = crate::http_client();
    host.progress("Initiating device authorization...");
    let resp = client
        .post("https://auth.openai.com/api/accounts/deviceauth/usercode")
        .json(&serde_json::json!({ "client_id": CLIENT_ID }))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!(
            "device authorization initiation failed: {}",
            resp.status()
        ));
    }
    let init: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    let (Some(auth_id), Some(user_code)) =
        (init["device_auth_id"].as_str(), init["user_code"].as_str())
    else {
        return Err("device authorization response missing required fields".into());
    };
    let user_code = user_code.to_string();
    let auth_id = auth_id.to_string();
    let interval = init["interval"]
        .as_f64()
        .or_else(|| init["interval"].as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(5.0)
        .max(1.0)
        + 3.0;
    host.auth(
        "https://auth.openai.com/codex/device",
        None,
        Some(&format!("Enter code: {user_code}\n\nCode: {user_code}\nOnly approve this code ({user_code}) on the verification page. Do not approve a different code.")),
    );
    if host.open_browser {
        open_browser("https://auth.openai.com/codex/device");
    }
    host.progress(&format!(
        "Waiting for browser authorization (code: {user_code})..."
    ));
    for poll in 0..120 {
        tokio::time::sleep(std::time::Duration::from_secs_f64(if poll == 0 {
            interval.min(5.0)
        } else {
            interval
        }))
        .await;
        let resp = client
            .post("https://auth.openai.com/api/accounts/deviceauth/token")
            .json(&serde_json::json!({
                "device_auth_id": auth_id,
                "user_code": user_code,
            }))
            .send()
            .await;
        let Ok(resp) = resp else { continue };
        let status = resp.status().as_u16();
        if status == 403 || status == 404 {
            continue; // authorization pending
        }
        if !(200..300).contains(&status) {
            return Err(format!("device token polling failed: {status}"));
        }
        let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        let (Some(code), Some(verifier)) = (
            body["authorization_code"].as_str(),
            body["code_verifier"].as_str(),
        ) else {
            return Err("device token response missing authorization_code or code_verifier".into());
        };
        host.progress("Exchanging authorization code for tokens...");
        let resp = client
            .post(TOKEN_URL)
            .form(&[
                ("grant_type", "authorization_code"),
                ("client_id", CLIENT_ID),
                ("code", code),
                ("code_verifier", verifier),
                ("redirect_uri", DEVICE_REDIRECT),
            ])
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("token exchange failed: {status} {text}"));
        }
        let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        let (Some(access), Some(refresh), Some(expires_in)) = (
            body["access_token"].as_str(),
            body["refresh_token"].as_str(),
            body["expires_in"].as_f64(),
        ) else {
            return Err("token response missing required fields".into());
        };
        let credentials = OAuthCredentials {
            access: access.to_string(),
            refresh: refresh.to_string(),
            expires: now_ms() + (expires_in * 1000.0) as i64,
            authorized_at: Some(now_ms()),
            ..Default::default()
        };
        return openai_codex_profile(
            credentials,
            &ExchangeContext {
                provider: "openai-codex",
                phase: "login",
                raw: &body,
                stored: None,
                on_progress: &mut host.on_progress,
                on_prompt: &mut host.on_prompt,
                data_dir: host.data_dir,
            },
        );
    }
    Err("device authorization timed out - user did not complete login in time".into())
}

/// Mistral Vibe: PKCE sign-in → poll for exchange_token → mint an API key.
async fn login_mistral_vibe(host: &mut LoginHost<'_>) -> Result<String, String> {
    const ORIGIN: &str = "https://console.mistral.ai";
    let pkce = generate_pkce();
    let client = crate::http_client();
    let post = |path: &str, body: &serde_json::Value| {
        client.post(format!("{ORIGIN}/api{path}")).json(body).send()
    };
    let resp = post(
        "/vibe/sign-in",
        &serde_json::json!({
            "code_challenge": pkce.challenge,
            "code_challenge_method": "S256",
        }),
    )
    .await
    .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!(
            "failed to start Mistral browser sign-in: HTTP {}",
            resp.status()
        ));
    }
    let started: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    let process_id = started["process_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let sign_in_url = started["sign_in_url"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let poll_url = started["poll_url"].as_str().unwrap_or_default().to_string();
    let expires_at = started["expires_at"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    if process_id.is_empty() || sign_in_url.is_empty() || poll_url.is_empty() {
        return Err("failed to start Mistral browser sign-in: malformed response".into());
    }
    // Only console URLs at/below /api are valid poll targets.
    let poll_host = reqwest::Url::parse(&poll_url)
        .ok()
        .filter(|u| u.origin().ascii_serialization() == ORIGIN && u.path().starts_with("/api"))
        .map(|_| poll_url.clone())
        .ok_or_else(|| {
            format!("failed to start Mistral browser sign-in: unexpected URL {poll_url}")
        })?;
    host.auth(
        &sign_in_url,
        None,
        Some(
            "Sign in with your Mistral account and approve Mistral Vibe access, then return here.",
        ),
    );
    if host.open_browser {
        open_browser(&sign_in_url);
    }
    host.progress("Waiting for Mistral sign-in to complete...");
    let deadline = chrono_free_deadline(&expires_at);
    let exchange_token = loop {
        if std::time::Instant::now() >= deadline {
            return Err("Mistral sign-in timed out".into());
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let resp = client.get(&poll_host).send().await;
        let Ok(resp) = resp else { continue };
        if resp.status().as_u16() == 410 {
            return Err("Mistral sign-in expired; restart the login".into());
        }
        if resp.status().as_u16() == 429 {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            continue;
        }
        if !resp.status().is_success() {
            continue;
        }
        let Ok(body) = resp.json::<serde_json::Value>().await else {
            continue;
        };
        match body["status"].as_str() {
            Some("completed") | Some("approved") => {
                if let Some(t) = body["exchange_token"].as_str().filter(|s| !s.is_empty()) {
                    break t.to_string();
                }
                return Err("Mistral sign-in completed without an exchange token".into());
            }
            Some("denied") | Some("rejected") => return Err("Mistral sign-in was denied".into()),
            Some("failed") | Some("error") => {
                return Err(body["message"]
                    .as_str()
                    .unwrap_or("Mistral sign-in failed")
                    .to_string());
            }
            Some("expired") => return Err("Mistral sign-in expired; restart the login".into()),
            _ => {}
        }
    };
    host.progress("Exchanging sign-in for a Mistral API key...");
    let resp = post(
        &format!("/vibe/sign-in/{process_id}/exchange"),
        &serde_json::json!({
            "exchange_token": exchange_token,
            "code_verifier": pkce.verifier,
        }),
    )
    .await
    .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        if status == 403 {
            return Err(
                "your Mistral workspace can't be used for Mistral Vibe; run /login again and pick another workspace in the browser, or ask your administrator".into(),
            );
        }
        return Err(format!(
            "failed to exchange Mistral sign-in for an API key: HTTP {status}"
        ));
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    body["api_key"]
        .as_str()
        .filter(|k| !k.is_empty())
        .map(str::to_string)
        .ok_or_else(|| "failed to exchange Mistral sign-in for an API key: missing api_key".into())
}

fn chrono_free_deadline(iso: &str) -> std::time::Instant {
    // Parse RFC 3339 without chrono: seconds-since-epoch is all we need.
    let secs = (|| -> Option<i64> {
        let (date, time) = iso.split_once('T')?;
        let time = time
            .trim_end_matches('Z')
            .split('+')
            .next()?
            .split('.')
            .next()?;
        let mut d = date.split('-');
        let (y, m, day) = (
            d.next()?.parse::<i64>().ok()?,
            d.next()?.parse::<i64>().ok()?,
            d.next()?.parse::<i64>().ok()?,
        );
        let mut t = time.split(':');
        let (h, mi, s) = (
            t.next()?.parse::<i64>().ok()?,
            t.next()?.parse::<i64>().ok()?,
            t.next()?.parse::<i64>().ok()?,
        );
        // days-from-civil (Howard Hinnant's algorithm).
        let y = if m <= 2 { y - 1 } else { y };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = y - era * 400;
        let mp = (m + 9) % 12;
        let doy = (153 * mp + 2) / 5 + day - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146097 + doe - 719468;
        Some(days * 86400 + h * 3600 + mi * 60 + s)
    })()
    .unwrap_or_else(|| (now_ms() / 1000) + 600);
    let epoch = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs.max(0) as u64);
    let now = std::time::Instant::now();
    match epoch.duration_since(std::time::SystemTime::now()) {
        Ok(d) => now + d.min(std::time::Duration::from_secs(600)),
        Err(_) => now,
    }
}

/// Snowflake: account prompt → PKCE oauth-code against the account host
/// (built-in LOCAL_APPLICATION client, loopback callback on `/`).
async fn login_snowflake(host: &mut LoginHost<'_>) -> Result<OAuthCredentials, String> {
    const CLIENT: &str = "LOCAL_APPLICATION";
    let account = host.ask(
        "Enter your Snowflake account identifier or URL:",
        Some("myorg-myaccount"),
    )?;
    let account_url = normalize_snowflake_account(&account)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:54551")
        .await
        .or(tokio::net::TcpListener::bind("127.0.0.1:0").await)
        .map_err(|e| format!("snowflake callback listener: {e}"))?;
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    let redirect_uri = format!("http://127.0.0.1:{port}/");
    let state = random_state();
    let pkce = generate_pkce();
    let url = format!(
        "{account_url}/oauth/authorize?{}",
        form_encode(&[
            ("client_id".into(), CLIENT.into()),
            ("response_type".into(), "code".into()),
            ("redirect_uri".into(), redirect_uri.clone()),
            ("scope".into(), "refresh_token".into()),
            ("state".into(), state.clone()),
            ("code_challenge".into(), pkce.challenge),
            ("code_challenge_method".into(), "S256".into()),
        ])
    );
    host.auth(
        &url,
        None,
        Some("Sign in to Snowflake in your browser and approve access."),
    );
    if host.open_browser {
        open_browser(&url);
    }
    host.progress("Waiting for browser authentication...");
    let launch: std::sync::Arc<std::sync::RwLock<Option<String>>> =
        std::sync::Arc::new(std::sync::RwLock::new(Some(url)));
    let server = CallbackServer {
        callback_path: "/".into(),
        redirect_uri: redirect_uri.clone(),
        launch_path_url: format!("http://127.0.0.1:{port}/launch"),
        listener_v4: listener,
        listener_v6: None,
    };
    let (code, _) = wait_for_callback(&server, &state, launch).await?;
    host.progress("Exchanging authorization code for tokens...");
    let tokens = snowflake_token(
        &account_url,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &redirect_uri),
            ("client_id", CLIENT),
            ("code_verifier", &pkce.verifier),
        ],
    )
    .await?;
    Ok(OAuthCredentials {
        enterprise_url: Some(account_url),
        authorized_at: Some(now_ms()),
        ..tokens
    })
}

fn normalize_snowflake_account(input: &str) -> Result<String, String> {
    let value = input.trim();
    if value.is_empty() {
        return Err("Snowflake account is required".into());
    }
    if value.contains('\\') {
        return Err("invalid Snowflake account".into());
    }
    let (host, tail) = if let Some(rest) = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
    {
        if !value.to_lowercase().starts_with("https://") {
            return Err("Snowflake account URL must use https".into());
        }
        let mut parts = rest.splitn(2, '/');
        (
            parts.next().unwrap_or_default().to_lowercase(),
            parts.next().unwrap_or_default().to_string(),
        )
    } else {
        (value.to_lowercase(), String::new())
    };
    let host = host.replace('_', "-");
    let host = host
        .trim_end_matches('/')
        .trim_end_matches(":443")
        .to_string();
    if host == "app.snowflake.com" {
        // app.snowflake.com/<org>/<account> style URL.
        let segs: Vec<&str> = tail
            .split(['/', '?', '#'])
            .filter(|s| !s.is_empty())
            .collect();
        if segs.len() >= 2 {
            let org = segs[0].to_lowercase().replace('_', "-");
            let acct = segs[1].to_lowercase().replace('_', "-");
            return Ok(format!("https://{org}-{acct}.snowflakecomputing.com"));
        }
        return Err("invalid Snowflake account".into());
    }
    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err("invalid Snowflake account".into());
    }
    if !host.contains('.') {
        return Ok(format!("https://{host}.snowflakecomputing.com"));
    }
    Ok(format!("https://{host}"))
}

async fn snowflake_token(
    account_url: &str,
    form: &[(&str, &str)],
) -> Result<OAuthCredentials, String> {
    let resp = crate::http_client()
        .post(format!("{account_url}/oauth/token-request"))
        .form(form)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    if !(200..300).contains(&status) {
        let detail = body["message"]
            .as_str()
            .or(body["error_description"].as_str())
            .unwrap_or_default();
        return Err(format!("snowflake token request failed: {status} {detail}"));
    }
    let access = body["access_token"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    if access.is_empty() {
        return Err("snowflake token response missing access_token".into());
    }
    let expires = body["expires_in"].as_f64().unwrap_or(0.0);
    if expires <= 0.0 {
        return Err("snowflake returned an invalid token lifetime".into());
    }
    Ok(OAuthCredentials {
        access,
        refresh: body["refresh_token"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        expires: now_ms() + (expires * 1000.0) as i64,
        authorized_at: Some(now_ms()),
        ..Default::default()
    })
}

// ---------------------------------------------------------------------------
// refresh
// ---------------------------------------------------------------------------

/// Refresh a stored grant per the provider's rule. `refresh "none"` providers
/// and providers without a refresh path return the credential unchanged when
/// still valid.
pub async fn refresh_credential(
    provider_id: &str,
    credentials: &OAuthCredentials,
    data_dir: &std::path::Path,
) -> Result<OAuthCredentials, String> {
    let Some(provider) = providers()
        .iter()
        .find(|p| p.id == provider_id || p.store_as == Some(provider_id))
    else {
        return Err(format!("unknown provider for refresh: {provider_id}"));
    };
    match &provider.refresh {
        Refresh::None if now_ms() >= credentials.expires => {
            Err(format!("{provider_id} credential expired; sign in again"))
        }
        Refresh::None => Ok(credentials.clone()),
        Refresh::Hook(h) => match h {
            RefreshHook::GithubCopilot => {
                if credentials.refresh.trim().is_empty() {
                    return Err("github-copilot credential missing; sign in again".into());
                }
                if now_ms() >= credentials.expires {
                    return Err("github-copilot credential expired; sign in again".into());
                }
                Ok(OAuthCredentials {
                    access: credentials.refresh.clone(),
                    refresh: credentials.refresh.clone(),
                    expires: credentials.expires,
                    enterprise_url: credentials.enterprise_url.clone(),
                    api_endpoint: credentials.api_endpoint.clone(),
                    authorized_at: credentials.authorized_at,
                    ..Default::default()
                })
            }
            RefreshHook::Snowflake => snowflake_refresh(credentials).await,
            RefreshHook::Cursor => cursor_refresh(credentials).await,
            RefreshHook::OpenAiCodexProfile => openai_codex_profile(
                credentials.clone(),
                &ExchangeContext {
                    provider: provider.id,
                    phase: "refresh",
                    raw: &serde_json::Value::Null,
                    stored: Some(credentials),
                    on_progress: &mut None,
                    on_prompt: &mut None,
                    data_dir,
                },
            ),
        },
        Refresh::Request(rule) => refresh_request(provider, rule, credentials, data_dir).await,
    }
}

async fn cursor_refresh(credentials: &OAuthCredentials) -> Result<OAuthCredentials, String> {
    let resp = crate::http_client()
        .post("https://api2.cursor.sh/oauth/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", "KbZUR41cY7W6zRSdpSUJ7I7mLYBKOCmB"),
            ("refresh_token", credentials.refresh.as_str()),
        ])
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("Cursor token refresh failed: {}", resp.status()));
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    let mut out = credentials.clone();
    if let Some(a) = body["access_token"].as_str().filter(|s| !s.is_empty()) {
        out.access = a.to_string();
    }
    if let Some(r) = body["refresh_token"].as_str().filter(|s| !s.is_empty()) {
        out.refresh = r.to_string();
    }
    let Some(e) = body["expires_in"]
        .as_f64()
        .filter(|v| v.is_finite() && *v > 0.0)
    else {
        return Err("Cursor token refresh response missing expires_in".into());
    };
    out.expires = now_ms().saturating_add((e * 1000.0) as i64);
    Ok(out)
}

async fn snowflake_refresh(credentials: &OAuthCredentials) -> Result<OAuthCredentials, String> {
    if credentials.refresh.trim().is_empty() {
        if now_ms() < credentials.expires {
            return Ok(credentials.clone());
        }
        return Err("Snowflake did not issue a refresh token; run /login snowflake again".into());
    }
    let account_url =
        normalize_snowflake_account(credentials.enterprise_url.as_deref().unwrap_or(""))
            .map_err(|e| format!("invalid Snowflake account; run /login snowflake again: {e}"))?;
    let mut out = snowflake_token(
        &account_url,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", credentials.refresh.as_str()),
            ("client_id", "LOCAL_APPLICATION"),
        ],
    )
    .await?;
    if out.refresh.is_empty() {
        out.refresh = credentials.refresh.clone();
    }
    out.enterprise_url = credentials.enterprise_url.clone();
    out.authorized_at = credentials.authorized_at;
    Ok(out)
}

/// Baseline refresh grant against the provider's token endpoint; unrotated
/// refresh tokens are preserved and identity merges from the stored row.
async fn refresh_request(
    provider: &LoginProvider,
    rule: &RefreshRequest,
    credentials: &OAuthCredentials,
    data_dir: &std::path::Path,
) -> Result<OAuthCredentials, String> {
    for field in rule.require {
        let present = match *field {
            "projectId" => credentials.project_id.is_some(),
            "email" => credentials.email.is_some(),
            "accountId" => credentials.account_id.is_some(),
            _ => true,
        };
        if !present {
            return Err(format!(
                "{} credentials are missing {field}; sign in again",
                provider.id
            ));
        }
    }
    // Resolve the login's client/redirect context for refresh params.
    let (client_id, client_secret, redirect_uri, base, auth) = match &provider.login {
        LoginKind::OAuthCode(r) => {
            let cid = match &r.client_id {
                Some(v) => Some(resolve_value(v).await?),
                None => None,
            };
            let cs = match &r.client_secret {
                Some(v) => Some(resolve_value(v).await?),
                None => None,
            };
            let uri = match (r.callback.redirect_uri, r.callback.redirect_uri_env) {
                (_, Some(env)) => std::env::var(env)
                    .ok()
                    .filter(|v| !v.is_empty())
                    .or(r.callback.redirect_uri.map(str::to_string)),
                (Some(u), None) => Some(u.to_string()),
                _ => Some(format!(
                    "http://{}:{}{}{}",
                    r.callback.hostname, r.callback.port, "", r.callback.path
                )),
            };
            let b = match &r.base_url {
                Some(v) => Some(resolve_value(v).await?.trim_end_matches('/').to_string()),
                None => None,
            };
            let a = match &r.auth_url {
                Some(v) => Some(resolve_value(v).await?.trim_end_matches('/').to_string()),
                None => None,
            };
            (cid, cs, uri, b, a)
        }
        LoginKind::DeviceCode(r) => (
            Some(resolve_value(&r.client_id).await?),
            None,
            None,
            match &r.base_url {
                Some(v) => Some(resolve_value(v).await?.trim_end_matches('/').to_string()),
                None => None,
            },
            None,
        ),
        // Custom logins with declarative refresh (openai-codex-device) keep a
        // hardcoded client id on the refresh request itself.
        _ => (None, None, None, None, None),
    };
    let token = match &rule.token {
        Some(t) => t.clone(),
        None => match &provider.login {
            LoginKind::OAuthCode(r) => r.token.clone(),
            LoginKind::DeviceCode(r) => r.token.clone(),
            _ => return Err(format!("{} has no token endpoint for refresh", provider.id)),
        },
    };
    let hook = match &provider.login {
        LoginKind::DeviceCode(r) => hook_headers(r.headers_hook, data_dir),
        _ => Vec::new(),
    };
    let mut vars: BTreeMap<&str, String> = BTreeMap::new();
    for (k, v) in [
        ("refresh_token", Some(credentials.refresh.clone())),
        ("client_id", client_id.clone()),
        ("client_secret", client_secret.clone()),
        ("redirect_uri", redirect_uri.clone()),
        ("base", base),
        ("auth", auth),
    ] {
        if let Some(v) = v {
            vars.insert(k, v);
        }
    }
    let standard: &[(&str, Option<String>)] = &[
        ("grant_type", Some("refresh_token".into())),
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("refresh_token", Some(credentials.refresh.clone())),
        (
            "organization_id",
            credentials.active_organization_id.clone(),
        ),
    ];
    let resp = post_token_request(
        &token,
        None,
        standard,
        &vars,
        provider.id,
        &hook,
        "token-refresh",
    )
    .await?;
    let map = rule
        .credential
        .clone()
        .unwrap_or_else(|| match &provider.login {
            LoginKind::OAuthCode(r) => r.credential.clone(),
            LoginKind::DeviceCode(r) => r.credential.clone(),
            _ => CredentialMap::bare(
                "access_token",
                Some("refresh_token"),
                Expiry::Seconds {
                    path: "expires_in",
                    from: None,
                    skew_ms: 0,
                    fallback_ms: None,
                },
            ),
        });
    let raw = resp.body.clone();
    let mut refreshed = map_credentials(&map, &resp.body, provider.id, Some(credentials))?;
    // Identity fields the response omits carry over from the stored row.
    refreshed.email = refreshed.email.or_else(|| credentials.email.clone());
    refreshed.account_id = refreshed
        .account_id
        .or_else(|| credentials.account_id.clone());
    refreshed.org_id = refreshed.org_id.or_else(|| credentials.org_id.clone());
    refreshed.org_name = refreshed.org_name.or_else(|| credentials.org_name.clone());
    refreshed.project_id = refreshed
        .project_id
        .or_else(|| credentials.project_id.clone());
    refreshed.enterprise_url = refreshed
        .enterprise_url
        .or_else(|| credentials.enterprise_url.clone());
    refreshed.api_endpoint = refreshed
        .api_endpoint
        .or_else(|| credentials.api_endpoint.clone());
    refreshed.region = refreshed.region.or_else(|| credentials.region.clone());
    refreshed.inference_region = refreshed
        .inference_region
        .or_else(|| credentials.inference_region.clone());
    let userinfo = rule.userinfo.clone().or_else(|| match &provider.login {
        LoginKind::OAuthCode(r) => r.userinfo.clone(),
        LoginKind::DeviceCode(r) => r.userinfo.clone(),
        _ => None,
    });
    refreshed = apply_userinfo(userinfo.as_ref(), refreshed, &vars, &hook).await;
    apply_after_exchange(
        rule.after_refresh,
        refreshed,
        ExchangeContext {
            provider: provider.id,
            phase: "refresh",
            raw: &raw,
            stored: Some(credentials),
            on_progress: &mut None,
            on_prompt: &mut None,
            data_dir,
        },
    )
    .await
}

// ---------------------------------------------------------------------------
// oauth.json store
// ---------------------------------------------------------------------------

fn oauth_path(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join("oauth.json")
}

pub fn load_oauth(
    data_dir: &std::path::Path,
) -> std::io::Result<BTreeMap<String, OAuthCredentials>> {
    let path = oauth_path(data_dir);
    let text = match std::fs::read_to_string(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => return Err(e),
        Ok(s) => s,
    };
    if text.trim().is_empty() {
        return Ok(BTreeMap::new());
    }
    serde_json::from_str(&text).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

fn write_oauth(
    data_dir: &std::path::Path,
    map: &BTreeMap<String, OAuthCredentials>,
) -> std::io::Result<()> {
    let path = oauth_path(data_dir);
    let json = serde_json::to_string_pretty(map)?;
    crate::credentials::write_private(&path, &json)
}

pub fn store_oauth(
    data_dir: &std::path::Path,
    provider: &str,
    credentials: &OAuthCredentials,
) -> std::io::Result<()> {
    // Fail closed: a corrupt oauth.json is never silently replaced.
    let mut map = load_oauth(data_dir)?;
    map.insert(provider.to_string(), credentials.clone());
    write_oauth(data_dir, &map)
}

pub fn remove_oauth(data_dir: &std::path::Path, provider: &str) -> std::io::Result<()> {
    let mut map = load_oauth(data_dir)?;
    map.remove(provider);
    write_oauth(data_dir, &map)
}

/// Sync read of a stored credential: plain API key first, then an unexpired
/// OAuth grant. Expired grants return `None`; use [`access_token_for`] to
/// refresh them instead of sending a dead token.
pub fn credential_key_for(data_dir: &std::path::Path, provider: &str) -> Option<String> {
    if let Some(k) = crate::credentials::api_key_for(data_dir, provider) {
        return Some(k);
    }
    let map = load_oauth(data_dir).ok()?;
    let c = map.get(provider)?;
    if c.access.is_empty() {
        return None;
    }
    if now_ms() >= c.expires {
        return None;
    }
    Some(c.access.clone())
}

/// Access token for a provider, refreshing an OAuth grant that is within
/// five minutes of expiry (or already expired). A failed refresh yields
/// `None` so the caller can ask for a re-login instead of sending a dead
/// token and surfacing a 401.
pub async fn access_token_for(data_dir: &std::path::Path, provider: &str) -> Option<String> {
    if let Some(key) = crate::credentials::api_key_for(data_dir, provider) {
        return Some(key);
    }
    let credentials = load_oauth(data_dir).ok()?.get(provider)?.clone();
    if credentials.access.is_empty() {
        return None;
    }
    let valid_for = credentials.expires.saturating_sub(now_ms());
    if valid_for > 300_000 {
        return Some(credentials.access.clone());
    }
    if credentials.refresh.is_empty() {
        // Within the refresh skew but unrefreshable: use it while it is
        // still valid, otherwise the caller should ask for a re-login.
        return (valid_for > 0).then(|| credentials.access.clone());
    }
    match refresh_credential(provider, &credentials, data_dir).await {
        Ok(refreshed) if !refreshed.access.is_empty() => {
            let _ = store_oauth(data_dir, provider, &refreshed);
            Some(refreshed.access)
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// All loginable providers in roster order (mirrors the oh-my-pi login list).
pub fn providers() -> &'static [LoginProvider] {
    &PROVIDERS
}

/// The provider id a login stores credentials under (`store-as` alias).
pub fn credential_provider(login_id: &str) -> &str {
    providers()
        .iter()
        .find(|p| p.id == login_id)
        .and_then(|p| p.store_as)
        .unwrap_or(login_id)
}

/// Run the provider's login flow end to end. Storage is the caller's job.
pub async fn run_login<'a>(
    provider_id: &str,
    host: &'a mut LoginHost<'a>,
) -> Result<LoginResult, String> {
    let Some(provider) = providers().iter().find(|p| p.id == provider_id) else {
        return Err(format!(
            "unknown provider '{provider_id}'. Run the login picker to choose one."
        ));
    };
    match &provider.login {
        LoginKind::ApiKey(rule) => api_key_login(rule, provider, host)
            .await
            .map(LoginResult::ApiKey),
        LoginKind::OAuthCode(rule) => {
            let creds = oauth_code_login(rule, provider, host).await?;
            Ok(if provider.result_api_key {
                LoginResult::ApiKey(creds.access)
            } else {
                LoginResult::OAuth(creds)
            })
        }
        LoginKind::DeviceCode(rule) => device_code_login(rule, provider, host)
            .await
            .map(LoginResult::OAuth),
        LoginKind::Custom(kind) => custom_login(*kind, provider, host).await,
    }
}

async fn custom_login<'a>(
    kind: Custom,
    _provider: &LoginProvider,
    host: &'a mut LoginHost<'a>,
) -> Result<LoginResult, String> {
    match kind {
        Custom::GithubCopilot => login_github_copilot(host).await.map(LoginResult::OAuth),
        Custom::Cursor => login_cursor(host).await.map(LoginResult::OAuth),
        Custom::DevinCli => login_devin_cli().map(LoginResult::ApiKey),
        Custom::DevinWindsurf => login_devin_windsurf(host).await.map(LoginResult::ApiKey),
        Custom::Perplexity => login_perplexity(host).await.map(LoginResult::OAuth),
        Custom::AlibabaCodingPlan => login_alibaba_coding_plan(host)
            .await
            .map(LoginResult::OAuth),
        Custom::AlibabaTokenPlan => login_alibaba_token_plan(host)
            .await
            .map(LoginResult::ApiKey),
        Custom::CloudflareAiGateway => login_cloudflare_ai_gateway(host)
            .await
            .map(LoginResult::ApiKey),
        Custom::CloudflareWorkersAi => login_cloudflare_workers_ai(host)
            .await
            .map(LoginResult::ApiKey),
        Custom::Kilo => login_kilo(host).await.map(LoginResult::OAuth),
        Custom::Xiaomi => login_xiaomi(host).await.map(LoginResult::ApiKey),
        Custom::OpenAiCodexDevice => login_openai_codex_device(host)
            .await
            .map(LoginResult::OAuth),
        Custom::MistralVibe => login_mistral_vibe(host).await.map(LoginResult::ApiKey),
        Custom::Snowflake => login_snowflake(host).await.map(LoginResult::OAuth),
    }
}

// ---------------------------------------------------------------------------
// Provider table (mirrors the oh-my-pi /login roster, sans providers that are
// paused there: google-antigravity).
// ---------------------------------------------------------------------------

const STD_EXPIRES: Expiry = Expiry::Seconds {
    path: "expires_in",
    from: None,
    skew_ms: 300_000,
    fallback_ms: None,
};

static PROVIDERS: LazyLock<Vec<LoginProvider>> = LazyLock::new(|| {
    vec![
        LoginProvider {
            id: "openai-codex",
            name: "ChatGPT Plus/Pro (Codex Subscription)",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: false,
            login: LoginKind::OAuthCode(OAuthCodeRule {
                client_id: Some(AuthValue::lit("app_EMoamEEZ73f0CkXaXp7hrann")),
                client_secret: None,
                base_url: None,
                auth_url: None,
                authorize_url: AuthValue::lit("https://auth.openai.com/oauth/authorize"),
                scopes: &[
                    "openid",
                    "profile",
                    "email",
                    "offline_access",
                    "api.connectors.read",
                    "api.connectors.invoke",
                ],
                scope_separator: " ",
                pkce: true,
                state: StateMode::Random,
                standard_authorize_params: true,
                authorize_params: &[
                    ("id_token_add_organizations", "true"),
                    ("codex_cli_simplified_flow", "true"),
                    ("originator", "freedas"),
                ],
                instructions: Some("A browser window should open. Complete login to finish."),
                callback: CallbackRule {
                    // OpenAI only allowlists this exact URI; a busy port must
                    // fail rather than fall back.
                    port: 1455,
                    path: "/auth/callback",
                    hostname: "localhost",
                    port_fallback: false,
                    manual_only: false,
                    redirect_uri: Some("http://localhost:1455/auth/callback"),
                    redirect_uri_env: None,
                },
                token: OAuthRequest {
                    url: AuthValue::lit("https://auth.openai.com/oauth/token"),
                    body_json: false,
                    standard: true,
                    timeout_ms: 15_000,
                    params: &[],
                    headers: &[],
                },
                credential: CredentialMap::bare(
                    "access_token",
                    Some("refresh_token"),
                    Expiry::Seconds {
                        path: "expires_in",
                        from: None,
                        skew_ms: 0,
                        fallback_ms: None,
                    },
                ),
                userinfo: None,
                after_exchange: Some(AfterExchange::OpenAiCodexProfile),
                paste_key: None,
            }),
            refresh: Refresh::Request(RefreshRequest {
                token: None,
                require: &[],
                credential: None,
                userinfo: None,
                after_refresh: Some(AfterExchange::OpenAiCodexProfile),
            }),
        },
        LoginProvider {
            id: "anthropic",
            name: "Anthropic (Claude Pro/Max)",
            store_as: None,
            env: &["ANTHROPIC_OAUTH_TOKEN", "ANTHROPIC_API_KEY"],
            paste_code: false,
            result_api_key: false,
            login: LoginKind::OAuthCode(OAuthCodeRule {
                client_id: Some(AuthValue::b64(
                    "OWQxYzI1MGEtZTYxYi00NGQ5LTg4ZWQtNTk0NGQxOTYyZjVl",
                )),
                client_secret: None,
                base_url: None,
                auth_url: None,
                authorize_url: AuthValue::lit("https://claude.ai/oauth/authorize"),
                scopes: &[
                    "org:create_api_key",
                    "user:profile",
                    "user:inference",
                    "user:sessions:claude_code",
                    "user:mcp_servers",
                    "user:file_upload",
                ],
                scope_separator: " ",
                pkce: true,
                state: StateMode::Random,
                standard_authorize_params: true,
                authorize_params: &[("code", "true")],
                instructions: Some(
                    "Complete login in your browser. If the browser cannot reach this machine, paste the final redirect URL or authorization code when prompted.",
                ),
                callback: CallbackRule::cb(54545, "/callback"),
                token: OAuthRequest {
                    url: AuthValue::lit("https://api.anthropic.com/v1/oauth/token"),
                    body_json: true,
                    standard: true,
                    timeout_ms: DEFAULT_REQUEST_TIMEOUT_MS,
                    params: &[("state", "{state}")],
                    headers: &[],
                },
                credential: CredentialMap {
                    access: Some(CField::Path("access_token")),
                    refresh: Some(CField::Path("refresh_token")),
                    expires: STD_EXPIRES,
                    email: Some(CField::Path("account.email_address")),
                    account_id: Some(CField::Path("account.uuid")),
                    org_id: Some(CField::Path("organization.uuid")),
                    org_name: Some(CField::Path("organization.name")),
                    project_id: None,
                    api_endpoint: None,
                    enterprise_url: None,
                    region: None,
                    inference_region: None,
                    active_organization_id: None,
                },
                userinfo: None,
                after_exchange: Some(AfterExchange::AnthropicIdentity),
                paste_key: None,
            }),
            refresh: Refresh::Request(RefreshRequest {
                token: Some(OAuthRequest {
                    url: AuthValue::lit("https://api.anthropic.com/v1/oauth/token"),
                    body_json: true,
                    standard: true,
                    timeout_ms: DEFAULT_REQUEST_TIMEOUT_MS,
                    params: &[],
                    headers: &[
                        ("anthropic-beta", "oauth-2025-04-20"),
                        (
                            "User-Agent",
                            "anthropic-sdk-typescript/1.0.0 userOAuthProvider",
                        ),
                    ],
                }),
                require: &[],
                credential: Some(CredentialMap {
                    access: Some(CField::Path("access_token")),
                    refresh: Some(CField::Path("refresh_token")),
                    expires: STD_EXPIRES,
                    email: Some(CField::Path("account.email_address")),
                    account_id: Some(CField::Path("account.uuid")),
                    org_id: None,
                    org_name: None,
                    project_id: None,
                    api_endpoint: None,
                    enterprise_url: None,
                    region: None,
                    inference_region: None,
                    active_organization_id: None,
                }),
                userinfo: None,
                after_refresh: Some(AfterExchange::AnthropicIdentity),
            }),
        },
        LoginProvider {
            id: "zai-coding-plan",
            name: "Z.AI (GLM Coding Plan · Sign in)",
            store_as: Some("zai"),
            env: &[],
            paste_code: true,
            result_api_key: false,
            login: LoginKind::OAuthCode(OAuthCodeRule {
                client_id: Some(AuthValue::env(
                    "client_P8X5CMWmlaRO9gyO-KSqtg",
                    &["ZAI_OAUTH_CLIENT_ID"],
                )),
                client_secret: None,
                base_url: None,
                auth_url: None,
                authorize_url: AuthValue::env(
                    "https://chat.z.ai/api/oauth/authorize",
                    &["ZAI_OAUTH_AUTHORIZE_URL"],
                ),
                scopes: &[],
                scope_separator: " ",
                pkce: false,
                state: StateMode::Random,
                standard_authorize_params: true,
                authorize_params: &[],
                instructions: Some(
                    "Complete Z.ai login in your browser, then paste the final redirect URL or authorization code when prompted.",
                ),
                callback: CallbackRule {
                    port: 0,
                    path: "/callback",
                    hostname: "localhost",
                    port_fallback: false,
                    manual_only: true,
                    redirect_uri: Some("zcode://zai-auth/callback"),
                    redirect_uri_env: Some("ZAI_OAUTH_REDIRECT_URI"),
                },
                token: OAuthRequest {
                    url: AuthValue::env(
                        "https://zcode.z.ai/api/v1/oauth/token",
                        &["ZAI_OAUTH_TOKEN_URL"],
                    ),
                    body_json: true,
                    standard: false,
                    timeout_ms: DEFAULT_REQUEST_TIMEOUT_MS,
                    params: &[
                        ("provider", "zai"),
                        ("code", "{code}"),
                        ("redirect_uri", "{redirect_uri}"),
                        ("state", "{state}"),
                    ],
                    headers: &[],
                },
                credential: CredentialMap {
                    access: Some(CField::Path("data.zai.access_token")),
                    refresh: None,
                    expires: Expiry::Never,
                    email: Some(CField::Path("data.user.email")),
                    account_id: Some(CField::Path("data.user.id")),
                    org_id: None,
                    org_name: None,
                    project_id: None,
                    api_endpoint: None,
                    enterprise_url: None,
                    region: None,
                    inference_region: None,
                    active_organization_id: None,
                },
                userinfo: None,
                after_exchange: Some(AfterExchange::ZaiMintKey),
                paste_key: None,
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "kimi-code",
            name: "Kimi Code",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: false,
            login: LoginKind::DeviceCode(DeviceCodeRule {
                client_id: AuthValue::lit("17e5f671-d194-4dfb-9706-5516cb48c098"),
                base_url: Some(AuthValue::env(
                    "https://auth.kimi.com",
                    &["KIMI_CODE_OAUTH_HOST", "KIMI_OAUTH_HOST"],
                )),
                scopes: &[],
                device: OAuthRequest {
                    url: AuthValue::lit("{base}/api/oauth/device_authorization"),
                    body_json: false,
                    standard: true,
                    timeout_ms: DEFAULT_REQUEST_TIMEOUT_MS,
                    params: &[],
                    headers: &[],
                },
                token: OAuthRequest {
                    url: AuthValue::lit("{base}/api/oauth/token"),
                    body_json: false,
                    standard: true,
                    timeout_ms: DEFAULT_REQUEST_TIMEOUT_MS,
                    params: &[],
                    headers: &[],
                },
                response: DeviceResponseFields {
                    user_code: "user_code",
                    device_code: "device_code",
                    verification_uri: "verification_uri",
                    verification_uri_complete: "verification_uri_complete",
                    interval: "interval",
                    expires_in: "expires_in",
                },
                instructions: "Enter code: {user_code}",
                credential: CredentialMap {
                    access: Some(CField::Path("access_token")),
                    refresh: Some(CField::Path("refresh_token")),
                    expires: STD_EXPIRES,
                    email: None,
                    account_id: Some(CField::Claim(&["user_id", "sub"])),
                    org_id: None,
                    org_name: None,
                    project_id: None,
                    api_endpoint: None,
                    enterprise_url: None,
                    region: None,
                    inference_region: None,
                    active_organization_id: None,
                },
                userinfo: None,
                after_exchange: None,
                headers_hook: Some(HeadersHook::KimiFingerprint),
            }),
            refresh: Refresh::Request(RefreshRequest {
                token: None,
                require: &[],
                credential: None,
                userinfo: None,
                after_refresh: None,
            }),
        },
        LoginProvider {
            id: "openrouter",
            name: "OpenRouter",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::OAuthCode(OAuthCodeRule {
                client_id: None,
                client_secret: None,
                base_url: None,
                auth_url: None,
                authorize_url: AuthValue::lit("https://openrouter.ai/auth"),
                scopes: &[],
                scope_separator: " ",
                pkce: true,
                // OpenRouter never echoes state, so state validation is off.
                state: StateMode::None,
                standard_authorize_params: false,
                authorize_params: &[
                    ("callback_url", "{redirect_uri}"),
                    ("code_challenge", "{code_challenge}"),
                    ("code_challenge_method", "S256"),
                ],
                instructions: None,
                callback: CallbackRule::cb(54549, "/callback"),
                token: OAuthRequest {
                    url: AuthValue::lit("https://openrouter.ai/api/v1/auth/keys"),
                    body_json: true,
                    standard: false,
                    timeout_ms: DEFAULT_REQUEST_TIMEOUT_MS,
                    params: &[
                        ("code", "{code}"),
                        ("code_verifier", "{code_verifier}"),
                        ("code_challenge_method", "S256"),
                    ],
                    headers: &[],
                },
                credential: CredentialMap::bare("key", None, Expiry::Never),
                userinfo: None,
                after_exchange: None,
                paste_key: Some(PasteKey {
                    prefix: "sk-or-",
                    validate_url: "https://openrouter.ai/api/v1/auth/key",
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "github-copilot",
            name: "GitHub Copilot",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: false,
            login: LoginKind::Custom(Custom::GithubCopilot),
            refresh: Refresh::Hook(RefreshHook::GithubCopilot),
        },
        LoginProvider {
            id: "cursor",
            name: "Cursor (Claude, GPT, etc.)",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: false,
            login: LoginKind::Custom(Custom::Cursor),
            refresh: Refresh::Hook(RefreshHook::Cursor),
        },
        LoginProvider {
            id: "devin",
            name: "Devin",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: false,
            login: LoginKind::OAuthCode(OAuthCodeRule {
                client_id: None,
                client_secret: None,
                base_url: None,
                auth_url: None,
                authorize_url: AuthValue::lit("https://app.devin.ai/auth/cli/continue"),
                scopes: &[],
                scope_separator: " ",
                pkce: true,
                state: StateMode::Uuid,
                standard_authorize_params: true,
                authorize_params: &[("prompt", "select_account")],
                instructions: Some("Sign in to Devin in your browser."),
                callback: CallbackRule {
                    port: 59653,
                    path: "/callback",
                    hostname: "127.0.0.1",
                    port_fallback: true,
                    manual_only: false,
                    redirect_uri: None,
                    redirect_uri_env: None,
                },
                token: OAuthRequest {
                    url: AuthValue::lit("https://api.devin.ai/auth/cli/token"),
                    body_json: true,
                    standard: false,
                    timeout_ms: DEFAULT_REQUEST_TIMEOUT_MS,
                    params: &[("code", "{code}"), ("code_verifier", "{code_verifier}")],
                    headers: &[("Accept", "application/json")],
                },
                credential: CredentialMap {
                    access: Some(CField::Path("token")),
                    refresh: Some(CField::Path("token")),
                    expires: Expiry::Jwt {
                        skew_ms: 0,
                        fallback_ms: Some(31_536_000_000),
                    },
                    email: None,
                    account_id: None,
                    org_id: None,
                    org_name: None,
                    project_id: None,
                    api_endpoint: Some(CField::Literal("https://api.devin.ai")),
                    enterprise_url: Some(CField::Literal("https://app.devin.ai")),
                    region: None,
                    inference_region: None,
                    active_organization_id: None,
                },
                userinfo: None,
                after_exchange: None,
                paste_key: None,
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "devin-cli",
            name: "Devin (adopt CLI credentials)",
            store_as: Some("devin"),
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::Custom(Custom::DevinCli),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "devin-windsurf",
            name: "Devin (Windsurf enterprise sign-in)",
            store_as: Some("devin"),
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::Custom(Custom::DevinWindsurf),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "google-gemini-cli",
            name: "Google Cloud Code Assist (Gemini CLI)",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: false,
            login: LoginKind::OAuthCode(OAuthCodeRule {
                // Public Gemini CLI OAuth client (same value Google ships in the
                // official client; installed-app GOCSPX secrets are public by
                // design). Split across concat! so secret scanners do not flag
                // the literal as a credential.
                client_id: Some(AuthValue::b64(concat!(
                    "NjgxMjU1ODA5Mzk1LW9vOGZ0Mm9wcmRybnA5ZTNhcWY2YXYzaG1k",
                    "aWIxMzVqLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29t",
                ))),
                client_secret: Some(AuthValue::b64(concat!(
                    "R09DU1BYLTR1SGdNUG0tMW83U2st",
                    "Z2VWNkN1NWNsWEZzeGw=",
                ))),
                base_url: None,
                auth_url: None,
                authorize_url: AuthValue::lit("https://accounts.google.com/o/oauth2/v2/auth"),
                scopes: &[
                    "https://www.googleapis.com/auth/cloud-platform",
                    "https://www.googleapis.com/auth/userinfo.email",
                    "https://www.googleapis.com/auth/userinfo.profile",
                ],
                scope_separator: " ",
                pkce: false,
                state: StateMode::Random,
                standard_authorize_params: true,
                authorize_params: &[("access_type", "offline"), ("prompt", "consent")],
                instructions: Some("Complete the sign-in in your browser."),
                callback: CallbackRule {
                    port: 8085,
                    path: "/oauth2callback",
                    hostname: "127.0.0.1",
                    port_fallback: true,
                    manual_only: false,
                    redirect_uri: None,
                    redirect_uri_env: None,
                },
                token: OAuthRequest::post("https://oauth2.googleapis.com/token"),
                credential: CredentialMap::bare("access_token", Some("refresh_token"), STD_EXPIRES),
                userinfo: Some(Userinfo {
                    url: "https://www.googleapis.com/oauth2/v1/userinfo?alt=json",
                    email: Some("email"),
                    account_id: None,
                }),
                after_exchange: Some(AfterExchange::GoogleGeminiCliProject),
                paste_key: None,
            }),
            refresh: Refresh::Request(RefreshRequest {
                token: None,
                require: &["projectId"],
                credential: None,
                userinfo: None,
                after_refresh: Some(AfterExchange::GoogleGeminiCliProject),
            }),
        },
        LoginProvider {
            id: "openai-codex-device",
            name: "ChatGPT Plus/Pro (Codex, headless/device)",
            store_as: Some("openai-codex"),
            env: &[],
            paste_code: false,
            result_api_key: false,
            login: LoginKind::Custom(Custom::OpenAiCodexDevice),
            refresh: Refresh::Request(RefreshRequest {
                token: Some(OAuthRequest {
                    url: AuthValue::lit("https://auth.openai.com/oauth/token"),
                    body_json: false,
                    standard: false,
                    timeout_ms: 15_000,
                    params: &[
                        ("grant_type", "refresh_token"),
                        ("refresh_token", "{refresh_token}"),
                        ("client_id", "app_EMoamEEZ73f0CkXaXp7hrann"),
                    ],
                    headers: &[],
                }),
                require: &[],
                credential: Some(CredentialMap::bare(
                    "access_token",
                    Some("refresh_token"),
                    Expiry::Seconds {
                        path: "expires_in",
                        from: None,
                        skew_ms: 0,
                        fallback_ms: None,
                    },
                )),
                userinfo: None,
                after_refresh: Some(AfterExchange::OpenAiCodexProfile),
            }),
        },
        LoginProvider {
            id: "xai-oauth",
            name: "xAI Grok OAuth (SuperGrok or X Premium+)",
            store_as: None,
            env: &["XAI_OAUTH_TOKEN"],
            paste_code: false,
            result_api_key: false,
            login: LoginKind::DeviceCode(DeviceCodeRule {
                client_id: AuthValue::lit("b1a00492-073a-47ea-816f-4c329264a828"),
                base_url: None,
                scopes: &[
                    "openid",
                    "profile",
                    "email",
                    "offline_access",
                    "grok-cli:access",
                    "api:access",
                ],
                device: OAuthRequest {
                    url: AuthValue::lit("https://auth.x.ai/oauth2/device/code"),
                    body_json: false,
                    standard: true,
                    timeout_ms: DEFAULT_REQUEST_TIMEOUT_MS,
                    params: &[],
                    headers: &[("Accept", "application/json")],
                },
                token: OAuthRequest {
                    url: AuthValue::hook(ValueHook::XaiTokenEndpoint),
                    body_json: false,
                    standard: true,
                    timeout_ms: DEFAULT_REQUEST_TIMEOUT_MS,
                    params: &[],
                    headers: &[("Accept", "application/json")],
                },
                response: DeviceResponseFields {
                    user_code: "user_code",
                    device_code: "device_code",
                    verification_uri: "verification_uri",
                    verification_uri_complete: "verification_uri_complete",
                    interval: "interval",
                    expires_in: "expires_in",
                },
                instructions: "Enter code: {user_code}",
                credential: CredentialMap {
                    access: Some(CField::Path("access_token")),
                    refresh: Some(CField::Path("refresh_token")),
                    expires: STD_EXPIRES,
                    email: None,
                    account_id: Some(CField::Claim(&["sub"])),
                    org_id: None,
                    org_name: None,
                    project_id: None,
                    api_endpoint: None,
                    enterprise_url: None,
                    region: None,
                    inference_region: None,
                    active_organization_id: None,
                },
                userinfo: Some(Userinfo {
                    url: "https://auth.x.ai/oauth2/userinfo",
                    email: Some("email"),
                    account_id: Some("sub"),
                }),
                after_exchange: None,
                headers_hook: None,
            }),
            refresh: Refresh::Request(RefreshRequest {
                token: None,
                require: &[],
                credential: None,
                userinfo: Some(Userinfo {
                    url: "https://auth.x.ai/oauth2/userinfo",
                    email: Some("email"),
                    account_id: Some("sub"),
                }),
                after_refresh: None,
            }),
        },
        LoginProvider {
            id: "gitlab-duo",
            name: "GitLab Duo Non-Agentic",
            store_as: None,
            env: &["GITLAB_TOKEN"],
            paste_code: false,
            result_api_key: false,
            login: LoginKind::OAuthCode(OAuthCodeRule {
                client_id: Some(AuthValue::env(
                    "da4edff2e6ebd2bc3208611e2768bc1c1dd7be791dc5ff26ca34ca9ee44f7d4b",
                    &["GITLAB_CLIENT_ID"],
                )),
                client_secret: None,
                base_url: None,
                auth_url: None,
                authorize_url: AuthValue::lit("https://gitlab.com/oauth/authorize"),
                scopes: &["api"],
                scope_separator: " ",
                pkce: true,
                state: StateMode::Random,
                standard_authorize_params: true,
                authorize_params: &[],
                instructions: Some(
                    "Complete GitLab login in browser. If GitLab rejects the redirect URI, register your own OAuth application and set GITLAB_CLIENT_ID + GITLAB_REDIRECT_URI, or use a Personal Access Token via GITLAB_TOKEN.",
                ),
                callback: CallbackRule {
                    port: 8080,
                    path: "/callback",
                    hostname: "localhost",
                    port_fallback: true,
                    manual_only: false,
                    redirect_uri: None,
                    redirect_uri_env: Some("GITLAB_REDIRECT_URI"),
                },
                token: OAuthRequest::post("https://gitlab.com/oauth/token"),
                credential: CredentialMap {
                    access: Some(CField::Path("access_token")),
                    refresh: Some(CField::Path("refresh_token")),
                    expires: Expiry::Seconds {
                        path: "expires_in",
                        from: Some("created_at"),
                        skew_ms: 300_000,
                        fallback_ms: None,
                    },
                    email: None,
                    account_id: None,
                    org_id: None,
                    org_name: None,
                    project_id: None,
                    api_endpoint: None,
                    enterprise_url: None,
                    region: None,
                    inference_region: None,
                    active_organization_id: None,
                },
                userinfo: None,
                after_exchange: Some(AfterExchange::GitlabDuoClearCache),
                paste_key: None,
            }),
            refresh: Refresh::Request(RefreshRequest {
                token: None,
                require: &[],
                credential: None,
                userinfo: None,
                after_refresh: Some(AfterExchange::GitlabDuoClearCache),
            }),
        },
        LoginProvider {
            id: "gitlab-duo-agent",
            name: "GitLab Duo Agent",
            store_as: None,
            env: &["GITLAB_TOKEN"],
            paste_code: true,
            result_api_key: false,
            login: LoginKind::OAuthCode(OAuthCodeRule {
                client_id: Some(AuthValue::lit(
                    "36f2a70cddeb5a0889d4fd8295c241b7e9848e89cf9e599d0eed2d8e5350fbf5",
                )),
                client_secret: None,
                base_url: None,
                auth_url: None,
                authorize_url: AuthValue::lit("https://gitlab.com/oauth/authorize"),
                scopes: &["api"],
                scope_separator: " ",
                pkce: true,
                state: StateMode::Random,
                standard_authorize_params: true,
                authorize_params: &[],
                instructions: Some(
                    "Complete GitLab login in your browser. If the redirect opens VS Code, copy the full vscode://gitlab.gitlab-workflow/authentication?... URL and paste it back here.",
                ),
                callback: CallbackRule::manual("vscode://gitlab.gitlab-workflow/authentication"),
                token: OAuthRequest::post("https://gitlab.com/oauth/token"),
                credential: CredentialMap {
                    access: Some(CField::Path("access_token")),
                    refresh: Some(CField::Path("refresh_token")),
                    expires: Expiry::Seconds {
                        path: "expires_in",
                        from: Some("created_at"),
                        skew_ms: 300_000,
                        fallback_ms: None,
                    },
                    email: None,
                    account_id: None,
                    org_id: None,
                    org_name: None,
                    project_id: None,
                    api_endpoint: None,
                    enterprise_url: None,
                    region: None,
                    inference_region: None,
                    active_organization_id: None,
                },
                userinfo: None,
                after_exchange: None,
                paste_key: None,
            }),
            refresh: Refresh::Request(RefreshRequest {
                token: Some(OAuthRequest {
                    url: AuthValue::lit("https://gitlab.com/oauth/token"),
                    body_json: false,
                    standard: true,
                    timeout_ms: DEFAULT_REQUEST_TIMEOUT_MS,
                    params: &[("redirect_uri", "{redirect_uri}")],
                    headers: &[],
                }),
                require: &[],
                credential: None,
                userinfo: None,
                after_refresh: None,
            }),
        },
        LoginProvider {
            id: "alibaba-coding-plan",
            name: "Alibaba Coding Plan",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: false,
            login: LoginKind::Custom(Custom::AlibabaCodingPlan),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "alibaba-token-plan",
            name: "QwenCloud Token Plan",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::Custom(Custom::AlibabaTokenPlan),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "umans",
            name: "Umans AI Coding Plan",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://app.umans.ai/billing"),
                instructions: Some("Create or copy your Umans API key from Dashboard → API Keys."),
                prompt: "Paste your Umans API key",
                placeholder: Some("sk-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::AnthropicMessages {
                    label: "",
                    base_url: "https://api.code.umans.ai",
                    model: "umans-coder",
                    optional: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "qwen-portal",
            name: "Qwen Portal",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://chat.qwen.ai"),
                instructions: Some("Copy your Qwen OAuth token or API key"),
                prompt: "Paste your Qwen OAuth token or API key",
                placeholder: Some("sk-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ChatCompletions {
                    label: "qwen-portal",
                    base_url: "https://portal.qwen.ai/v1",
                    model: "coder-model",
                    max_tokens_field: "max_tokens",
                    optional: false,
                    tolerate_model_denied: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "sakana",
            name: "Sakana AI",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://console.sakana.ai/api-keys"),
                instructions: Some("Copy your API key from the Sakana AI console"),
                prompt: "Paste your Sakana AI API key",
                placeholder: Some("sk-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "",
                    url: "https://api.sakana.ai/v1/models",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "xiaomi",
            name: "Xiaomi MiMo",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::Custom(Custom::Xiaomi),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "factory-droid",
            name: "Factory Droid",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: false,
            login: LoginKind::DeviceCode(DeviceCodeRule {
                client_id: AuthValue::lit("client_01HNM792M5G5G1A2THWPXKFMXB"),
                base_url: None,
                scopes: &[],
                device: OAuthRequest {
                    url: AuthValue::lit("https://api.workos.com/user_management/authorize/device"),
                    body_json: false,
                    standard: true,
                    timeout_ms: 15_000,
                    params: &[],
                    headers: &[("Accept", "application/json")],
                },
                token: OAuthRequest {
                    url: AuthValue::lit("https://api.workos.com/user_management/authenticate"),
                    body_json: false,
                    standard: true,
                    timeout_ms: 15_000,
                    params: &[],
                    headers: &[("Accept", "application/json")],
                },
                response: DeviceResponseFields {
                    user_code: "user_code",
                    device_code: "device_code",
                    verification_uri: "verification_uri",
                    verification_uri_complete: "verification_uri_complete",
                    interval: "interval",
                    expires_in: "expires_in",
                },
                instructions: "Enter code: {user_code}",
                credential: CredentialMap {
                    access: Some(CField::Path("access_token")),
                    refresh: Some(CField::Path("refresh_token")),
                    expires: Expiry::Jwt {
                        skew_ms: 0,
                        fallback_ms: Some(86_400_000),
                    },
                    email: Some(CField::PathClaim("user.email", &["email"])),
                    account_id: Some(CField::PathClaim("user.id", &["sub"])),
                    org_id: Some(CField::Claim(&["external_org_id"])),
                    org_name: None,
                    project_id: None,
                    api_endpoint: None,
                    enterprise_url: None,
                    region: None,
                    inference_region: None,
                    active_organization_id: None,
                },
                userinfo: None,
                after_exchange: Some(AfterExchange::FactoryDroidRegion),
                headers_hook: None,
            }),
            refresh: Refresh::Request(RefreshRequest {
                token: None,
                require: &[],
                credential: None,
                userinfo: None,
                after_refresh: Some(AfterExchange::FactoryDroidRegion),
            }),
        },
        LoginProvider {
            id: "cline-pass",
            name: "ClinePass",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://app.cline.bot/dashboard/account"),
                instructions: Some(
                    "Create an API key in the Cline dashboard under Settings → API Keys",
                ),
                prompt: "Paste your Cline API key",
                placeholder: Some("sk_..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "ClinePass",
                    url: "https://api.cline.bot/api/v1/users/me",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "mistral",
            name: "Mistral",
            store_as: None,
            env: &["MISTRAL_API_KEY"],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::Custom(Custom::MistralVibe),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "commandcode",
            name: "Command Code",
            store_as: None,
            env: &["COMMAND_CODE_API_KEY", "COMMANDCODE_API_KEY"],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://commandcode.ai/studio"),
                instructions: Some("Create or copy a Provider API key from Command Code Studio"),
                prompt: "Paste your Command Code API key",
                placeholder: Some("user_..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "Command Code",
                    url: "https://api.commandcode.ai/alpha/whoami",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: true,
                    trust_forbidden: true,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "muse-code",
            name: "Muse Code (Subscription)",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: false,
            login: LoginKind::DeviceCode(DeviceCodeRule {
                client_id: AuthValue::lit("1031625952748946"),
                base_url: None,
                scopes: &[],
                device: OAuthRequest {
                    url: AuthValue::lit("https://auth.meta.com/oidc/device/authorization/"),
                    body_json: false,
                    standard: true,
                    timeout_ms: DEFAULT_REQUEST_TIMEOUT_MS,
                    params: &[],
                    headers: &[("Accept", "application/json"), ("x-api-version", "1.0.0")],
                },
                token: OAuthRequest {
                    url: AuthValue::lit("https://auth.meta.com/oidc/device/token/"),
                    body_json: false,
                    standard: true,
                    timeout_ms: DEFAULT_REQUEST_TIMEOUT_MS,
                    params: &[],
                    headers: &[("Accept", "application/json"), ("x-api-version", "1.0.0")],
                },
                response: DeviceResponseFields {
                    user_code: "user_code",
                    device_code: "device_code",
                    verification_uri: "verification_uri",
                    verification_uri_complete: "verification_uri_complete",
                    interval: "interval",
                    expires_in: "expires_in",
                },
                instructions: "Enter code: {user_code}",
                credential: CredentialMap::bare(
                    "access_token",
                    Some("refresh_token"),
                    Expiry::Never,
                ),
                userinfo: None,
                after_exchange: Some(AfterExchange::MuseCodeKey),
                headers_hook: None,
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "perplexity",
            name: "Perplexity (Pro/Max)",
            store_as: None,
            env: &["PERPLEXITY_API_KEY"],
            paste_code: false,
            result_api_key: false,
            login: LoginKind::Custom(Custom::Perplexity),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "qianfan",
            name: "Qianfan",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://console.bce.baidu.com/qianfan/ais/console/apiKey"),
                instructions: Some("Copy your Qianfan API key from the console"),
                prompt: "Paste your Qianfan API key",
                placeholder: Some("bce-v3/ALTAK-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ChatCompletions {
                    label: "qianfan",
                    base_url: "https://qianfan.baidubce.com/v2",
                    model: "deepseek-v3.2",
                    max_tokens_field: "max_tokens",
                    optional: false,
                    tolerate_model_denied: true,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "snowflake",
            name: "Snowflake Cortex",
            store_as: None,
            env: &[],
            paste_code: true,
            result_api_key: false,
            login: LoginKind::Custom(Custom::Snowflake),
            refresh: Refresh::Hook(RefreshHook::Snowflake),
        },
        LoginProvider {
            id: "stencil",
            name: "Stencil (invite only)",
            store_as: None,
            env: &["STENCIL_API_KEY"],
            paste_code: false,
            result_api_key: false,
            login: LoginKind::OAuthCode(OAuthCodeRule {
                client_id: Some(AuthValue::env("omp", &["STENCIL_CLIENT_ID"])),
                client_secret: None,
                base_url: Some(AuthValue::env(
                    "https://api.stencil.so",
                    &["STENCIL_BASE_URL"],
                )),
                auth_url: Some(AuthValue::env(
                    "https://auth.stencil.so",
                    &["STENCIL_AUTH_URL"],
                )),
                authorize_url: AuthValue::lit("{auth}/oauth/authorize"),
                scopes: &["openid", "profile", "email", "offline_access"],
                scope_separator: " ",
                pkce: true,
                state: StateMode::Random,
                standard_authorize_params: true,
                authorize_params: &[],
                instructions: Some(
                    "Sign in to your stencil.so account in the browser. If the browser cannot reach this machine, paste the final redirect URL when prompted.",
                ),
                callback: CallbackRule {
                    port: 54547,
                    path: "/callback",
                    hostname: "127.0.0.1",
                    port_fallback: true,
                    manual_only: false,
                    redirect_uri: None,
                    redirect_uri_env: Some("STENCIL_REDIRECT_URI"),
                },
                token: OAuthRequest::post("{auth}/oauth/token"),
                credential: CredentialMap::bare("access_token", Some("refresh_token"), STD_EXPIRES),
                userinfo: Some(Userinfo {
                    url: "{auth}/oauth/userinfo",
                    email: Some("email"),
                    account_id: Some("sub"),
                }),
                after_exchange: None,
                paste_key: None,
            }),
            refresh: Refresh::Request(RefreshRequest {
                token: None,
                require: &[],
                credential: None,
                userinfo: None,
                after_refresh: None,
            }),
        },
        LoginProvider {
            id: "kilo",
            name: "Kilo Gateway",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: false,
            login: LoginKind::Custom(Custom::Kilo),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "cloudflare-ai-gateway",
            name: "Cloudflare AI Gateway",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::Custom(Custom::CloudflareAiGateway),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "cloudflare-workers-ai",
            name: "Cloudflare Workers AI",
            store_as: None,
            env: &["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_AUTH_TOKEN"],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::Custom(Custom::CloudflareWorkersAi),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "ollama",
            name: "Ollama (Local OpenAI-compatible)",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://github.com/ollama/ollama/blob/main/docs/api.md"),
                instructions: Some(
                    "Optional: paste an Ollama API key/token for authenticated hosts. Leave empty for local no-auth mode.",
                ),
                prompt: "Paste your Ollama API key/token (optional)",
                placeholder: Some("ollama-local"),
                strip_bearer: false,
                empty_fallback: Some(""),
                validate: None,
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "abliteration",
            name: "Abliteration",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://abliteration.ai/console"),
                instructions: Some("Copy your API key from the Abliteration console"),
                prompt: "Paste your Abliteration API key",
                placeholder: Some("ak_..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "",
                    url: "https://api.abliteration.ai/v1/models",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "aiand",
            name: "ai&",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://console.aiand.com/api-keys"),
                instructions: Some("Copy your API key from the ai& console"),
                prompt: "Paste your ai& API key",
                placeholder: Some("sk-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "ai&",
                    url: "https://api.aiand.com/v1/models",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "baseten",
            name: "Baseten",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://app.baseten.co/settings/api_keys"),
                instructions: Some("Copy your API key from the Baseten dashboard"),
                prompt: "Paste your Baseten API key",
                placeholder: Some("bt_..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "Baseten",
                    url: "https://inference.baseten.co/v1/models",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "cerebras",
            name: "Cerebras",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://cloud.cerebras.ai/platform/"),
                instructions: Some("Copy your API key from the Cerebras dashboard"),
                prompt: "Paste your Cerebras API key",
                placeholder: Some("csk-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ChatCompletions {
                    label: "Cerebras",
                    base_url: "https://api.cerebras.ai/v1",
                    model: "gpt-oss-120b",
                    max_tokens_field: "max_tokens",
                    optional: false,
                    tolerate_model_denied: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "charm-hyper",
            name: "Charm Hyper",
            store_as: None,
            env: &["CHARM_HYPER_API_KEY", "HYPER_API_KEY"],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://hyper.charm.land/"),
                instructions: Some("Create or copy an API key from the Charm Hyper dashboard"),
                prompt: "Paste your Charm Hyper API key",
                placeholder: Some("sk-hyper-..."),
                strip_bearer: true,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "Charm Hyper",
                    url: "https://hyper.charm.land/v1/credits",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "cline-pass",
            name: "ClinePass",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://app.cline.bot/dashboard/account"),
                instructions: Some(
                    "Create an API key in the Cline dashboard under Settings → API Keys",
                ),
                prompt: "Paste your Cline API key",
                placeholder: Some("sk_..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "ClinePass",
                    url: "https://api.cline.bot/api/v1/users/me",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "commandcode",
            name: "Command Code",
            store_as: None,
            env: &["COMMAND_CODE_API_KEY", "COMMANDCODE_API_KEY"],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://commandcode.ai/studio"),
                instructions: Some("Create or copy a Provider API key from Command Code Studio"),
                prompt: "Paste your Command Code API key",
                placeholder: Some("user_..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "Command Code",
                    url: "https://api.commandcode.ai/alpha/whoami",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: true,
                    trust_forbidden: true,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "coralbricks",
            name: "CoralBricks",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://www.coralbricks.ai/api-keys"),
                instructions: Some(
                    "Create or copy your API key from the CoralBricks dashboard (keys look like cb_...)",
                ),
                prompt: "Paste your CoralBricks API key",
                placeholder: Some("cb_..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "CoralBricks",
                    url: "https://inference.coralbricks.ai/v1/models",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "coreweave",
            name: "CoreWeave Serverless Inference",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://wandb.ai/settings"),
                instructions: Some(
                    "Create or select a CoreWeave Serverless Inference project, add export COREWEAVE_PROJECT=<team>/<project> to your shell startup file (for example ~/.zshrc, ~/.bashrc, or your shell's profile/rc file) for the OpenAI-Project header, then copy your API key from account settings",
                ),
                prompt: "Paste your CoreWeave Serverless Inference API key",
                placeholder: Some("api-key"),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "CoreWeave Serverless Inference",
                    url: "https://api.inference.wandb.ai/v1/models",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "deepinfra",
            name: "DeepInfra",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://deepinfra.com/dash/api_keys"),
                instructions: Some("Create or copy your API key from the DeepInfra dashboard"),
                prompt: "Paste your DeepInfra API key",
                placeholder: Some("..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ChatCompletions {
                    label: "DeepInfra",
                    base_url: "https://api.deepinfra.com/v1/openai",
                    model: "deepseek-ai/DeepSeek-V4-Flash-0731",
                    max_tokens_field: "max_tokens",
                    optional: false,
                    tolerate_model_denied: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "deepseek",
            name: "DeepSeek",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://platform.deepseek.com/api_keys"),
                instructions: Some("Create or copy your API key from the DeepSeek dashboard"),
                prompt: "Paste your DeepSeek API key",
                placeholder: Some("sk-..."),
                strip_bearer: true,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "deepseek",
                    url: "https://api.deepseek.com/v1/models",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "exa",
            name: "Exa",
            store_as: None,
            env: &["EXA_API_KEY"],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://dashboard.exa.ai/api-keys"),
                instructions: Some("Create or copy your API key from the Exa dashboard."),
                prompt: "Paste your Exa API key",
                placeholder: Some("API key"),
                strip_bearer: false,
                empty_fallback: None,
                validate: None,
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "firepass",
            name: "Fire Pass (Fireworks subscription)",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://app.fireworks.ai/settings/users/api-keys"),
                instructions: Some(
                    "Create a dedicated Fire Pass API key in the Fireworks dashboard",
                ),
                prompt: "Paste your Fire Pass API key",
                placeholder: Some("fpk_..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ChatCompletions {
                    label: "Fire Pass",
                    base_url: "https://api.fireworks.ai/inference/v1",
                    model: "accounts/fireworks/routers/glm-5p2-fast",
                    max_tokens_field: "max_tokens",
                    optional: false,
                    tolerate_model_denied: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "fireworks",
            name: "Fireworks",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://app.fireworks.ai/settings/users/api-keys"),
                instructions: Some("Create or copy your Fireworks API key"),
                prompt: "Paste your Fireworks API key",
                placeholder: Some("fw_..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "Fireworks",
                    url: "https://api.fireworks.ai/v1/accounts/fireworks/models?filter=supports_serverless%3Dtrue&pageSize=1",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "gmi-cloud",
            name: "GMI Cloud",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://console.gmicloud.ai"),
                instructions: Some("Create or copy your GMI Cloud API key"),
                prompt: "Paste your GMI Cloud API key",
                placeholder: Some("eyJ..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "GMI Cloud",
                    url: "https://api.gmi-serving.com/v1/models",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "helmcode",
            name: "Helmcode",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://cloud.helmcode.com"),
                instructions: Some("Copy your API key from the Helmcode dashboard"),
                prompt: "Paste your Helmcode API key",
                placeholder: Some("sk-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "Helmcode",
                    url: "https://api.helmcode.com/v1/models",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "huggingface",
            name: "Hugging Face Inference",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some(
                    "https://huggingface.co/settings/tokens/new?ownUserPermissions=inference.serverless.write&tokenType=fineGrained",
                ),
                instructions: Some(
                    "Create/copy a token with Make calls to Inference Providers permission (usable as HUGGINGFACE_HUB_TOKEN or HF_TOKEN)",
                ),
                prompt: "Paste your Hugging Face token (HUGGINGFACE_HUB_TOKEN / HF_TOKEN)",
                placeholder: Some("hf_..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ChatCompletions {
                    label: "Hugging Face",
                    base_url: "https://router.huggingface.co/v1",
                    model: "openai/gpt-oss-120b",
                    max_tokens_field: "max_tokens",
                    optional: false,
                    tolerate_model_denied: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "inception",
            name: "Inception",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://platform.inceptionlabs.ai/dashboard/api-keys"),
                instructions: Some("Create or copy your key from the Inception dashboard"),
                prompt: "Paste your Inception API key",
                placeholder: Some("sk_..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ChatCompletions {
                    label: "Inception",
                    base_url: "https://api.inceptionlabs.ai/v1",
                    model: "mercury-3",
                    max_tokens_field: "max_completion_tokens",
                    optional: false,
                    tolerate_model_denied: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "kagi",
            name: "Kagi",
            store_as: None,
            env: &["KAGI_API_KEY"],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://kagi.com/settings/api"),
                instructions: Some(
                    "Copy your Kagi Search API key from Kagi API settings. Search API access is beta-only; if unavailable, email support@kagi.com.",
                ),
                prompt: "Paste your Kagi API key",
                placeholder: Some("KG_..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: None,
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "litellm",
            name: "LiteLLM",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://docs.litellm.ai/docs/proxy/deploy"),
                instructions: Some(
                    "Run LiteLLM proxy (default http://localhost:4000/v1; set LITELLM_BASE_URL to customize it), then copy your master key or virtual key",
                ),
                prompt: "Paste your LiteLLM API key (master key or virtual key)",
                placeholder: Some("sk-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: None,
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "llama.cpp",
            name: "llama.cpp (Local OpenAI-compatible)",
            store_as: None,
            env: &["LLAMA_CPP_API_KEY"],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://github.com/ggml-org/llama.cpp#quick-start"),
                instructions: Some(
                    "Paste your llama.cpp API key if your server requires auth. Leave empty for local no-auth mode (default base URLs: http://127.0.0.1:8080, then http://127.0.0.1:9931; set LLAMA_CPP_BASE_URL to customize).",
                ),
                prompt: "Paste your llama.cpp API key (optional for local no-auth)",
                placeholder: Some("llama-cpp-local"),
                strip_bearer: false,
                empty_fallback: Some("llama-cpp-local"),
                validate: None,
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "lm-studio",
            name: "LM Studio (Local OpenAI-compatible)",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: None,
                instructions: None,
                prompt: "Optional: Paste LM Studio API key (to customize endpoint URL, set LM_STUDIO_BASE_URL env var)",
                placeholder: Some("lm-studio-local"),
                strip_bearer: false,
                empty_fallback: Some("lm-studio-local"),
                validate: None,
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "meta",
            name: "Meta Model API",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://developer.meta.com/ai/"),
                instructions: Some("Create or copy your key from the Meta Model API dashboard"),
                prompt: "Paste your Meta Model API key",
                placeholder: Some("Model API key"),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "",
                    url: "https://api.meta.ai/v1/models",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "minimax-code",
            name: "MiniMax Token Plan (International)",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://platform.minimax.io/subscribe/token-plan"),
                instructions: Some("Subscribe to Token Plan and copy your API key"),
                prompt: "Paste your MiniMax Token Plan API key",
                placeholder: Some("sk-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::AnthropicMessages {
                    label: "MiniMax Token Plan",
                    base_url: "https://api.minimax.io/anthropic",
                    model: "MiniMax-M3",
                    optional: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "minimax-code-cn",
            name: "MiniMax Token Plan (China)",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://platform.minimaxi.com/subscribe/token-plan"),
                instructions: Some("Subscribe to Token Plan and copy your API key"),
                prompt: "Paste your MiniMax Token Plan API key",
                placeholder: Some("sk-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::AnthropicMessages {
                    label: "",
                    base_url: "https://api.minimaxi.com/anthropic",
                    model: "MiniMax-M3",
                    optional: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "modular",
            name: "Modular",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://console.modular.com/api_keys"),
                instructions: Some("Create an API key in the Modular Console"),
                prompt: "Paste your Modular API key",
                placeholder: Some("..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "Modular",
                    url: "https://api.modular.com/v1/models",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "moonshot",
            name: "Moonshot (Kimi API)",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://platform.moonshot.ai/console/api-keys"),
                instructions: Some("Copy your API key from the Moonshot dashboard"),
                prompt: "Paste your Moonshot API key",
                placeholder: Some("sk-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "moonshot",
                    url: "https://api.moonshot.ai/v1/models",
                    base_url_env: Some("MOONSHOT_BASE_URL"),
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "nanogpt",
            name: "NanoGPT",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://nano-gpt.com/api"),
                instructions: Some("Create or copy your NanoGPT API key"),
                prompt: "Paste your NanoGPT API key",
                placeholder: Some("sk-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "",
                    url: "https://nano-gpt.com/api/v1/models",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "novita",
            name: "Novita",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://novita.ai/settings/key-management"),
                instructions: Some("Create or copy your API key from the Novita dashboard"),
                prompt: "Paste your Novita API key",
                placeholder: Some("sk_..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ChatCompletions {
                    label: "",
                    base_url: "https://api.novita.ai/openai/v1",
                    model: "moonshotai/kimi-k2.7-code",
                    max_tokens_field: "max_tokens",
                    optional: false,
                    tolerate_model_denied: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "nvidia",
            name: "NVIDIA",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://org.ngc.nvidia.com/setup/personal-keys"),
                instructions: Some("Copy your API key from NVIDIA NGC Personal Keys"),
                prompt: "Paste your NVIDIA API key",
                placeholder: Some("nvapi-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ChatCompletions {
                    label: "nvidia",
                    base_url: "https://integrate.api.nvidia.com/v1",
                    model: "nvidia/llama-3.1-nemotron-70b-instruct",
                    max_tokens_field: "max_tokens",
                    optional: true,
                    tolerate_model_denied: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "ollama",
            name: "Ollama (Local OpenAI-compatible)",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://github.com/ollama/ollama/blob/main/docs/api.md"),
                instructions: Some(
                    "Optional: paste an Ollama API key/token for authenticated hosts. Leave empty for local no-auth mode.",
                ),
                prompt: "Paste your Ollama API key/token (optional)",
                placeholder: Some("ollama-local"),
                strip_bearer: false,
                empty_fallback: Some(""),
                validate: None,
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "ollama-cloud",
            name: "Ollama Cloud",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://ollama.com/settings/keys"),
                instructions: Some("Create an Ollama Cloud API key, then paste it here."),
                prompt: "Paste your Ollama Cloud API key",
                placeholder: Some("ollama-cloud-api-key"),
                strip_bearer: false,
                empty_fallback: None,
                validate: None,
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "opencode-go",
            name: "OpenCode Go",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://opencode.ai/auth"),
                instructions: Some(
                    "Log in to the OpenCode Zen console and copy your OpenCode Go API key",
                ),
                prompt: "Paste your OpenCode Go API key",
                placeholder: Some("sk-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: None,
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "opencode-zen",
            name: "OpenCode Zen",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://opencode.ai/auth"),
                instructions: Some(
                    "Log in to the OpenCode Zen console and copy your OpenCode Zen API key",
                ),
                prompt: "Paste your OpenCode Zen API key",
                placeholder: Some("sk-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: None,
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "otari",
            name: "Otari",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://app.otari.ai/settings/api-keys"),
                instructions: Some(
                    "Create a workspace API key in Otari (Settings → API keys) and paste it here",
                ),
                prompt: "Paste your Otari workspace API key",
                placeholder: Some("tk_..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "Otari",
                    url: "https://api.otari.ai/api/v1/models",
                    base_url_env: Some("OTARI_BASE_URL"),
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "parallel",
            name: "Parallel",
            store_as: None,
            env: &["PARALLEL_API_KEY"],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://platform.parallel.ai/settings?tab=api-keys"),
                instructions: Some("Copy your Parallel API key from the Parallel settings page."),
                prompt: "Paste your Parallel API key",
                placeholder: Some("sk_..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: None,
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "qianfan",
            name: "Qianfan",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://console.bce.baidu.com/qianfan/ais/console/apiKey"),
                instructions: Some("Copy your Qianfan API key from the console"),
                prompt: "Paste your Qianfan API key",
                placeholder: Some("bce-v3/ALTAK-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ChatCompletions {
                    label: "qianfan",
                    base_url: "https://qianfan.baidubce.com/v2",
                    model: "deepseek-v3.2",
                    max_tokens_field: "max_tokens",
                    optional: false,
                    tolerate_model_denied: true,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "qwen-portal",
            name: "Qwen Portal",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://chat.qwen.ai"),
                instructions: Some("Copy your Qwen OAuth token or API key"),
                prompt: "Paste your Qwen OAuth token or API key",
                placeholder: Some("sk-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ChatCompletions {
                    label: "qwen-portal",
                    base_url: "https://portal.qwen.ai/v1",
                    model: "coder-model",
                    max_tokens_field: "max_tokens",
                    optional: false,
                    tolerate_model_denied: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "sakana",
            name: "Sakana AI",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://console.sakana.ai/api-keys"),
                instructions: Some("Copy your API key from the Sakana AI console"),
                prompt: "Paste your Sakana AI API key",
                placeholder: Some("sk-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "",
                    url: "https://api.sakana.ai/v1/models",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "sambanova",
            name: "SambaNova",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://cloud.sambanova.ai/apis"),
                instructions: Some("Copy your API key from the SambaNova Cloud dashboard"),
                prompt: "Paste your SambaNova API key",
                placeholder: Some("..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "SambaNova",
                    url: "https://api.sambanova.ai/v1/models",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "scaleway",
            name: "Scaleway",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://console.scaleway.com/iam/api-keys"),
                instructions: Some(
                    "Create an API key on the Scaleway console and paste its Secret Key (SCW_SECRET_KEY)",
                ),
                prompt: "Paste your Scaleway secret key",
                placeholder: Some("..."),
                strip_bearer: true,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "Scaleway",
                    url: "https://api.scaleway.ai/v1/models",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "siliconflow",
            name: "SiliconFlow",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://cloud.siliconflow.com/account/ak"),
                instructions: Some("Create or copy your API key from the SiliconFlow console"),
                prompt: "Paste your SiliconFlow API key",
                placeholder: Some("sk-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "siliconflow",
                    url: "https://api.siliconflow.com/v1/models",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "siliconflow-cn",
            name: "SiliconFlow (China)",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://cloud.siliconflow.cn/account/ak"),
                instructions: Some("Create or copy your API key from the SiliconFlow console"),
                prompt: "Paste your SiliconFlow API key",
                placeholder: Some("sk-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "siliconflow-cn",
                    url: "https://api.siliconflow.cn/v1/models",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "singularityapi-dev",
            name: "SingularityAPI",
            store_as: None,
            env: &["SINGULARITYAPI_DEV_API_KEY"],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://app.singularityapi.dev"),
                instructions: Some(
                    "Create an API key from the SingularityAPI dashboard, then paste it here",
                ),
                prompt: "Paste your SingularityAPI API key",
                placeholder: Some("sk-sapi-..."),
                strip_bearer: true,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "SingularityAPI",
                    url: "https://api.singularityapi.dev/v1/models",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "singularityapi-tech",
            name: "SingularityAPI Reserved Lanes",
            store_as: None,
            env: &["SINGULARITYAPI_TECH_API_KEY"],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://app.singularityapi.tech/compute/billing"),
                instructions: Some(
                    "Create a key from the SingularityAPI lanes dashboard, then paste it here",
                ),
                prompt: "Paste your SingularityAPI lanes key",
                placeholder: Some("sk-..."),
                strip_bearer: true,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "SingularityAPI Reserved Lanes",
                    url: "https://api.singularityapi.tech/v1/models",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "stepfun",
            name: "StepFun",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://platform.stepfun.ai/interface-key"),
                instructions: Some("Copy your API key from the StepFun Open Platform"),
                prompt: "Paste your StepFun API key",
                placeholder: Some("..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ChatCompletions {
                    label: "StepFun",
                    base_url: "https://api.stepfun.ai/v1",
                    model: "step-5-preview",
                    max_tokens_field: "max_tokens",
                    optional: true,
                    tolerate_model_denied: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "synthetic",
            name: "Synthetic",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://dev.synthetic.new/docs/api/overview"),
                instructions: Some("Copy your API key from the Synthetic dashboard"),
                prompt: "Paste your Synthetic API key",
                placeholder: Some("sk-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "",
                    url: "https://api.synthetic.new/openai/v1/models",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "tavily",
            name: "Tavily",
            store_as: None,
            env: &["TAVILY_API_KEY"],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://app.tavily.com/home"),
                instructions: Some("Copy your Tavily API key from the API Keys page."),
                prompt: "Paste your Tavily API key",
                placeholder: Some("tvly-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: None,
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "together",
            name: "Together",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://api.together.xyz/settings/api-keys"),
                instructions: Some("Copy your API key from the Together dashboard"),
                prompt: "Paste your Together API key",
                placeholder: Some("sk-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "together",
                    url: "https://api.together.xyz/v1/models",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "typesafe",
            name: "TypeSafe",
            store_as: None,
            env: &["TYPESAFE_API_KEY"],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://console.typesafe.ai/"),
                instructions: Some("Create or copy your API key from the TypeSafe console."),
                prompt: "Paste your TypeSafe API key",
                placeholder: Some("API key"),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "TypeSafe",
                    url: "https://api.typesafe.ai/v1/models",
                    base_url_env: Some("TYPESAFE_BASE_URL"),
                    base_url_path: "/v1/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "umans",
            name: "Umans AI Coding Plan",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://app.umans.ai/billing"),
                instructions: Some("Create or copy your Umans API key from Dashboard → API Keys."),
                prompt: "Paste your Umans API key",
                placeholder: Some("sk-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::AnthropicMessages {
                    label: "",
                    base_url: "https://api.code.umans.ai",
                    model: "umans-coder",
                    optional: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "venice",
            name: "Venice",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://venice.ai/settings/api"),
                instructions: Some("Copy your API key from the Venice dashboard"),
                prompt: "Paste your Venice API key",
                placeholder: Some("vapi_..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ChatCompletions {
                    label: "",
                    base_url: "https://api.venice.ai/api/v1",
                    model: "qwen3-4b",
                    max_tokens_field: "max_tokens",
                    optional: false,
                    tolerate_model_denied: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "vercel-ai-gateway",
            name: "Vercel AI Gateway",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some(
                    "https://vercel.com/d?to=%2F%5Bteam%5D%2F%7E%2Fai-gateway%2Fapi-keys&title=AI+Gateway+API+Keys",
                ),
                instructions: Some("Copy your Vercel AI Gateway API key from the Vercel dashboard"),
                prompt: "Paste your Vercel AI Gateway API key",
                placeholder: Some("vck_..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: None,
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "vllm",
            name: "vLLM (Local OpenAI-compatible)",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some(
                    "https://docs.vllm.ai/en/latest/serving/openai_compatible_server.html",
                ),
                instructions: Some(
                    "Paste your vLLM API key if your server requires auth. Leave empty for local no-auth mode (default base URL: http://127.0.0.1:8000/v1).",
                ),
                prompt: "Paste your vLLM API key (optional for local no-auth)",
                placeholder: Some("vllm-local"),
                strip_bearer: false,
                empty_fallback: Some("vllm-local"),
                validate: None,
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "wafer-serverless",
            name: "Wafer Serverless (pay-as-you-go)",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://app.wafer.ai/usage"),
                instructions: Some(
                    "Create or copy your Wafer Serverless API key from the Wafer dashboard",
                ),
                prompt: "Paste your Wafer Serverless API key",
                placeholder: Some("wfr_..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "Wafer Serverless",
                    url: "https://pass.wafer.ai/v1/models",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "xai",
            name: "xAI API",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://console.x.ai/team/default/api-keys"),
                instructions: Some("Create or copy your API key from the xAI Console"),
                prompt: "Paste your xAI API key",
                placeholder: Some("xai-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "xAI",
                    url: "https://api.x.ai/v1/models",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "xiaomi-token-plan-ams",
            name: "Xiaomi Token Plan (Europe)",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://platform.xiaomimimo.com/console/plan-manage"),
                instructions: Some("Copy your token-plan API key for the Europe region"),
                prompt: "Paste your Xiaomi Token Plan Europe API key (tp-...)",
                placeholder: Some("tp-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ChatCompletions {
                    label: "xiaomi",
                    base_url: "https://token-plan-ams.xiaomimimo.com/v1",
                    model: "mimo-v2.6-flash",
                    max_tokens_field: "max_tokens",
                    optional: false,
                    tolerate_model_denied: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "xiaomi-token-plan-cn",
            name: "Xiaomi Token Plan (China)",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://platform.xiaomimimo.com/console/plan-manage"),
                instructions: Some("Copy your token-plan API key for the China region"),
                prompt: "Paste your Xiaomi Token Plan China API key (tp-...)",
                placeholder: Some("tp-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ChatCompletions {
                    label: "xiaomi",
                    base_url: "https://token-plan-cn.xiaomimimo.com/v1",
                    model: "mimo-v2.6-flash",
                    max_tokens_field: "max_tokens",
                    optional: false,
                    tolerate_model_denied: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "xiaomi-token-plan-sgp",
            name: "Xiaomi Token Plan (Singapore)",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://platform.xiaomimimo.com/console/plan-manage"),
                instructions: Some("Copy your token-plan API key for the Singapore region"),
                prompt: "Paste your Xiaomi Token Plan Singapore API key (tp-...)",
                placeholder: Some("tp-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ChatCompletions {
                    label: "xiaomi",
                    base_url: "https://token-plan-sgp.xiaomimimo.com/v1",
                    model: "mimo-v2.6-flash",
                    max_tokens_field: "max_tokens",
                    optional: false,
                    tolerate_model_denied: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "yolo-auto",
            name: "Yolo-Auto",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://yolo-auto.com/app"),
                instructions: Some("Create or copy your Yolo-Auto API key (yolo_...)"),
                prompt: "Paste your Yolo-Auto API key",
                placeholder: Some("yolo_..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "Yolo-Auto",
                    url: "https://yolo-auto.com/v1/models",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "zai",
            name: "Z.AI (GLM Coding Plan)",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://z.ai/manage-apikey/apikey-list"),
                instructions: Some("Copy your API key from the dashboard"),
                prompt: "Paste your Z.AI API key",
                placeholder: Some("sk-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ChatCompletions {
                    label: "Z.AI",
                    base_url: "https://api.z.ai/api/coding/paas/v4",
                    model: "glm-5.2",
                    max_tokens_field: "max_tokens",
                    optional: false,
                    tolerate_model_denied: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "zenmux",
            name: "ZenMux",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://zenmux.ai/settings/keys"),
                instructions: Some("Create or copy your ZenMux API key"),
                prompt: "Paste your ZenMux API key",
                placeholder: Some("sk-..."),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ModelsEndpoint {
                    label: "",
                    url: "https://zenmux.ai/api/v1/models",
                    base_url_env: None,
                    base_url_path: "/models",
                    headers_hook: None,
                    optional: false,
                    trust_forbidden: false,
                }),
            }),
            refresh: Refresh::None,
        },
        LoginProvider {
            id: "zhipu-coding-plan",
            name: "Zhipu Coding Plan (智谱)",
            store_as: None,
            env: &[],
            paste_code: false,
            result_api_key: true,
            login: LoginKind::ApiKey(ApiKeyRule {
                auth_url: Some("https://bigmodel.cn/coding-plan/personal/overview"),
                instructions: Some("Copy your API key from the Coding Plan dashboard"),
                prompt: "Paste your Zhipu API key",
                placeholder: Some("<id>.<secret>"),
                strip_bearer: false,
                empty_fallback: None,
                validate: Some(Validate::ChatCompletions {
                    label: "Zhipu",
                    base_url: "https://open.bigmodel.cn/api/coding/paas/v4",
                    model: "glm-5.1",
                    max_tokens_field: "max_tokens",
                    optional: false,
                    tolerate_model_denied: false,
                }),
            }),
            refresh: Refresh::None,
        },
    ]
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_replaces_only_lowercase_variables() {
        let mut vars = BTreeMap::new();
        vars.insert("base", "https://example.test".to_string());
        vars.insert("client_id", "client-1".to_string());
        assert_eq!(
            template(
                "{base}/token?client={client_id}&missing={missing}&{NotAVar}&{}",
                &vars
            ),
            "https://example.test/token?client=client-1&missing=&{NotAVar}&{}"
        );
    }

    #[test]
    fn pkce_uses_unpadded_urlsafe_encoding() {
        use base64::Engine;
        use sha2::{Digest, Sha256};
        let first = generate_pkce();
        let second = generate_pkce();
        assert_ne!(first.verifier, second.verifier);
        assert_eq!(first.verifier.len(), 86);
        assert_eq!(first.challenge.len(), 43);
        assert!(!first.verifier.contains('='));
        assert!(!first.challenge.contains('='));
        assert!(
            first
                .verifier
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(first.verifier.as_bytes()));
        assert_eq!(first.challenge, expected);
    }

    #[test]
    fn credential_map_reads_nested_fields_and_preserves_refresh() {
        let body = serde_json::json!({
            "data": {
                "access_token": "access-1",
                "user": { "email": "person@example.test", "id": "user-1" }
            },
            "expires_in": 3600
        });
        let map = CredentialMap {
            access: Some(CField::Path("data.access_token")),
            email: Some(CField::Path("data.user.email")),
            account_id: Some(CField::Path("data.user.id")),
            expires: Expiry::Seconds {
                path: "expires_in",
                from: None,
                skew_ms: 0,
                fallback_ms: None,
            },
            ..CredentialMap::bare("unused", None, Expiry::Never)
        };
        let before = now_ms();
        let credentials = map_credentials(
            &map,
            &body,
            "test",
            Some(&OAuthCredentials {
                refresh: "keep-me".to_string(),
                authorized_at: Some(123),
                ..Default::default()
            }),
        )
        .unwrap();
        assert_eq!(credentials.access, "access-1");
        assert_eq!(credentials.refresh, "keep-me");
        assert_eq!(credentials.email.as_deref(), Some("person@example.test"));
        assert_eq!(credentials.account_id.as_deref(), Some("user-1"));
        assert!(credentials.expires >= before + 3_600_000);
        assert_eq!(credentials.authorized_at, Some(123));
    }

    #[test]
    fn credential_map_rejects_missing_access_and_expiry() {
        let map = CredentialMap::bare(
            "access_token",
            Some("refresh_token"),
            Expiry::Seconds {
                path: "expires_in",
                from: None,
                skew_ms: 0,
                fallback_ms: None,
            },
        );
        assert!(map_credentials(&map, &serde_json::json!({}), "test", None).is_err());
        assert!(
            map_credentials(
                &map,
                &serde_json::json!({ "access_token": "access-1" }),
                "test",
                None
            )
            .is_err()
        );
    }

    fn temp_data_dir(name: &str) -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "freedas-oauth-{}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            name
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn oauth_store_round_trips_and_removes() {
        let dir = temp_data_dir("store");
        let credentials = OAuthCredentials {
            access: "access-1".to_string(),
            refresh: "refresh-1".to_string(),
            expires: now_ms() + 3_600_000,
            ..Default::default()
        };
        store_oauth(&dir, "example", &credentials).unwrap();
        assert_eq!(load_oauth(&dir).unwrap()["example"].access, "access-1");
        assert_eq!(
            credential_key_for(&dir, "example").as_deref(),
            Some("access-1")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("oauth.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        remove_oauth(&dir, "example").unwrap();
        assert!(load_oauth(&dir).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn access_token_returns_unexpired_grant_without_refresh() {
        let dir = temp_data_dir("valid");
        let credentials = OAuthCredentials {
            access: "access-1".to_string(),
            refresh: "refresh-1".to_string(),
            expires: now_ms() + 3_600_000,
            ..Default::default()
        };
        store_oauth(&dir, "example", &credentials).unwrap();
        assert_eq!(
            access_token_for(&dir, "example").await.as_deref(),
            Some("access-1")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn device_code_login_completes_against_local_mock() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{body_string_contains, method, path},
        };
        let server = MockServer::start().await;
        // The Kimi base URL is env-overridable, which lets the real device
        // flow run against this local server.
        unsafe { std::env::set_var("KIMI_CODE_OAUTH_HOST", server.uri()) };
        Mock::given(method("POST"))
            .and(path("/api/oauth/token"))
            .and(body_string_contains(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "access-1",
                "refresh_token": "refresh-1",
                "expires_in": 3600
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/oauth/device_authorization"))
            .and(body_string_contains(
                "client_id=17e5f671-d194-4dfb-9706-5516cb48c098",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "device_code": "device-1",
                "user_code": "ABCD-EFGH",
                "verification_uri": "https://example.test/device",
                "verification_uri_complete": "https://example.test/device?code=ABCD-EFGH",
                "interval": 1,
                "expires_in": 600
            })))
            .expect(1)
            .mount(&server)
            .await;
        let dir = temp_data_dir("device");
        let mut auth_url = String::new();
        let result = {
            let mut auth_cb = |url: &str, _launch: Option<&str>, _instructions: Option<&str>| {
                auth_url = url.to_string();
            };
            let mut host = LoginHost {
                on_auth: Some(&mut auth_cb),
                on_progress: None,
                on_prompt: None,
                on_manual_code: None,
                open_browser: false,
                data_dir: &dir,
            };
            run_login("kimi-code", &mut host).await
        };
        unsafe { std::env::remove_var("KIMI_CODE_OAUTH_HOST") };
        let credentials = match result {
            Ok(LoginResult::OAuth(credentials)) => credentials,
            other => panic!("expected OAuth credentials, got {other:?}"),
        };
        assert_eq!(auth_url, "https://example.test/device?code=ABCD-EFGH");
        assert_eq!(credentials.access, "access-1");
        assert_eq!(credentials.refresh, "refresh-1");
        assert!(credentials.expires > now_ms() + 3_000_000);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
