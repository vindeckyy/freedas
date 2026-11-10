//! MCP client manager: tools, prompts, and resources from MCP servers.

pub mod oauth;

use rmcp::model::{CallToolRequestParams, ClientConfig, ListToolsResult, ProtocolVersion};
use rmcp::service::{ClientLifecycleMode, RoleClient, RunningService, serve_client_with_lifecycle};
use rmcp::transport::ConfigureCommandExt;
use rmcp::transport::TokioChildProcess;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStatus {
    pub name: String,
    pub state: String,
    /// `None` until the server has been connected and listed.
    pub tools: Option<usize>,
    pub prompts: Option<usize>,
    pub error: Option<String>,
}

impl ServerStatus {
    pub fn tools_label(&self) -> String {
        self.tools
            .map(|n| n.to_string())
            .unwrap_or_else(|| "unknown".into())
    }

    pub fn prompts_label(&self) -> String {
        self.prompts
            .map(|n| n.to_string())
            .unwrap_or_else(|| "unknown".into())
    }
}

/// Live connections, reused across calls so each server is spawned once.
struct CachedServer {
    config_key: String,
    server: std::sync::Arc<McpServer>,
    tools: Option<usize>,
    prompts: Option<usize>,
}

fn cache() -> &'static std::sync::Mutex<std::collections::HashMap<String, CachedServer>> {
    static CACHE: std::sync::LazyLock<
        std::sync::Mutex<std::collections::HashMap<String, CachedServer>>,
    > = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    &CACHE
}

/// Approval store for project-sourced MCP servers, mirroring the plugin trust
/// file: one hash per server, re-approved whenever the config changes.
const TRUST_FILE: &str = "trusted_mcp.json";
const TRUST_ENV: &str = "FREEDAS_MCP_TRUST";
/// Explicit headless/CI opt-in mirroring `Config::trust_project_code`.
const TRUST_PROJECT_ENV: &str = "FREEDAS_TRUST_PROJECT_CODE";

/// Identity of a server config; any change reconnects (url, command, headers,
/// environment, cwd, timeout).
fn config_key(cfg: &freedas_core::config::McpServerConfig) -> String {
    format!(
        "{:?}|{:?}|{:?}|{:?}|{:?}|{:?}",
        cfg.url, cfg.command, cfg.headers, cfg.environment, cfg.cwd, cfg.timeout_ms
    )
}

/// Hash of the security-sensitive server fields. Any change to command, url,
/// or headers changes the hash and needs re-approval.
fn mcp_approval_hash(cfg: &freedas_core::config::McpServerConfig) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(config_key(cfg).as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn mcp_trust_file() -> std::path::PathBuf {
    let cwd = std::env::current_dir().unwrap_or_default();
    freedas_core::paths::Paths::resolve(cwd)
        .data_dir
        .join(TRUST_FILE)
}

fn mcp_trust_opt_in() -> bool {
    matches!(
        std::env::var(TRUST_ENV).ok().as_deref(),
        Some("1" | "true" | "yes")
    )
}

/// Explicit headless/CI opt-in mirroring `Config::trust_project_code`.
fn trust_project_code_opt_in() -> bool {
    matches!(
        std::env::var(TRUST_PROJECT_ENV).ok().as_deref(),
        Some("1" | "true" | "yes")
    )
}

fn read_approvals(file: &std::path::Path) -> std::collections::BTreeMap<String, String> {
    std::fs::read_to_string(file)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn write_approvals(
    file: &std::path::Path,
    approved: &std::collections::BTreeMap<String, String>,
) -> Result<(), String> {
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let text = serde_json::to_string_pretty(approved).map_err(|e| e.to_string())?;
    std::fs::write(file, text).map_err(|e| format!("write {}: {e}", file.display()))
}

/// Fail closed unless this server's config hash is approved or an explicit
/// opt-in records/allows it. `allow_project_code` mirrors
/// `Config::trust_project_code` and bypasses the per-server check.
fn ensure_mcp_trusted_in(
    store: &std::path::Path,
    name: &str,
    cfg: &freedas_core::config::McpServerConfig,
    allow_project_code: bool,
) -> Result<(), String> {
    let hash = mcp_approval_hash(cfg);
    let mut approved = read_approvals(store);
    if approved.get(name).is_some_and(|known| known == &hash) {
        return Ok(());
    }
    if allow_project_code || trust_project_code_opt_in() {
        return Ok(());
    }
    if !mcp_trust_opt_in() {
        return Err(format!(
            "mcp server {name} is not trusted (config sha256 {hash}); re-run with {TRUST_ENV}=1 to approve it"
        ));
    }
    approved.insert(name.to_owned(), hash);
    write_approvals(store, &approved)?;
    Ok(())
}

/// Credential stored by `mcp auth` as `mcp-<name>`.
fn credential_for(name: &str) -> Option<String> {
    let cwd = std::env::current_dir().unwrap_or_default();
    let paths = freedas_core::paths::Paths::resolve(cwd);
    freedas_provider::credentials::api_key_for(&paths.data_dir, &format!("mcp-{name}"))
}

async fn cached_connect_with_approval(
    name: &str,
    cfg: &freedas_core::config::McpServerConfig,
    allow_project_code: bool,
) -> Result<std::sync::Arc<McpServer>, String> {
    let key = config_key(cfg);
    let hit = cache()
        .lock()
        .expect("mcp cache")
        .get(name)
        .filter(|c| c.config_key == key)
        .map(|c| c.server.clone());
    if let Some(server) = hit {
        return Ok(server);
    }
    let auth = credential_for(name);
    let server = match connect_configured_with_approval(
        name,
        cfg,
        auth.as_deref(),
        allow_project_code,
    )
    .await
    {
        Ok(server) => server,
        Err(e) if is_auth_failure(&e) => match refreshed_credential(name).await {
            Some(refreshed) => {
                connect_configured_with_approval(name, cfg, Some(&refreshed), allow_project_code)
                    .await
                    .map_err(|retry| format!("{e}; refresh retry: {retry}"))?
            }
            None => return Err(e),
        },
        Err(e) => return Err(e),
    };
    let server = std::sync::Arc::new(server);
    cache().lock().expect("mcp cache").insert(
        name.to_string(),
        CachedServer {
            config_key: key,
            server: server.clone(),
            tools: None,
            prompts: None,
        },
    );
    Ok(server)
}

fn is_auth_failure(message: &str) -> bool {
    message.contains("401") || message.to_lowercase().contains("unauthorized")
}

async fn refreshed_credential(name: &str) -> Option<String> {
    let cwd = std::env::current_dir().unwrap_or_default();
    let paths = freedas_core::paths::Paths::resolve(cwd);
    freedas_provider::credentials::refresh_stored(&paths.data_dir, &format!("mcp-{name}")).await
}

pub struct McpServer {
    pub name: String,
    pub client: RunningService<RoleClient, ClientConfig>,
    /// Timeout bound applied to handshakes and calls (`0` = none).
    pub timeout_ms: u64,
}

/// A prompt advertised by an MCP server, exposed as the slash command
/// `/<server>:<prompt>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashPrompt {
    pub name: String,
    pub description: String,
    pub arguments: Vec<PromptArg>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptArg {
    pub name: String,
    pub description: Option<String>,
    pub required: bool,
}

pub async fn connect_stdio(
    name: &str,
    command: &[String],
    cwd: Option<&str>,
    environment: &std::collections::BTreeMap<String, String>,
    timeout_ms: u64,
) -> Result<McpServer, String> {
    connect_stdio_with(name, command, cwd, environment, timeout_ms).await
}

/// Stdio transport with the configured `environment` map applied to the child
/// process and a `timeout_ms` bound on the initialize handshake (`0` = none).
pub async fn connect_stdio_with(
    name: &str,
    command: &[String],
    cwd: Option<&str>,
    environment: &std::collections::BTreeMap<String, String>,
    timeout_ms: u64,
) -> Result<McpServer, String> {
    if command.is_empty() {
        return Err("no command".into());
    }
    let program = command[0].clone();
    let args = command[1..].to_vec();
    let cwd_owned = cwd.map(str::to_string);
    let env_owned = environment.clone();
    let transport = TokioChildProcess::new(tokio::process::Command::new(&program).configure(
        move |cmd| {
            cmd.args(&args)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                // Inherit: a piped handle would fill up and stall servers that log.
                .stderr(std::process::Stdio::inherit());
            // Never leak provider keys into local servers; re-add a minimal set.
            cmd.env_clear();
            for key in [
                "PATH",
                "HOME",
                "USER",
                "LOGNAME",
                "SHELL",
                "TMPDIR",
                "TEMP",
                "TMP",
                "SYSTEMROOT",
                "SYSTEMDRIVE",
                "LANG",
                "LC_ALL",
            ] {
                if let Ok(value) = std::env::var(key) {
                    cmd.env(key, value);
                }
            }
            if let Some(dir) = &cwd_owned {
                cmd.current_dir(dir);
            }
            for (key, value) in &env_owned {
                cmd.env(key, value);
            }
        },
    ))
    .map_err(|e| format!("{name}: spawn: {e}"))?;
    with_timeout(
        timeout_ms,
        name,
        serve_client_with_lifecycle(
            ClientConfig::default(),
            transport,
            ClientLifecycleMode::Initialize,
        ),
    )
    .await
    .map(|client| McpServer {
        name: name.to_string(),
        client,
        timeout_ms,
    })
}

async fn with_timeout<T, E: std::fmt::Display>(
    timeout_ms: u64,
    name: &str,
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, String> {
    if timeout_ms == 0 {
        return future.await.map_err(|e| format!("{name}: {e}"));
    }
    match tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), future).await {
        Ok(result) => result.map_err(|e| format!("{name}: {e}")),
        Err(_) => Err(format!("{name}: timed out after {timeout_ms}ms")),
    }
}

/// Connect one server using its config entry: remote servers use the
/// streamable HTTP transport with `headers`, local servers the stdio
/// transport with `environment`, `cwd`, and `timeout_ms`.
///
/// Project-sourced servers fail closed until approved once: the first connect
/// (and any connect after the command, url, or headers change) returns an
/// error with approval instructions instead of spawning code. Headless runs
/// opt in with `FREEDAS_MCP_TRUST=1` (per-server hash pin) or the
/// `Config::trust_project_code` flag (via `connect_configured_with_approval`).
pub async fn connect_configured(
    name: &str,
    cfg: &freedas_core::config::McpServerConfig,
    auth_header: Option<&str>,
) -> Result<McpServer, String> {
    connect_configured_with_approval(name, cfg, auth_header, false).await
}

/// [`connect_configured`] with an explicit project-code bypass. Callers that
/// track config origin pass `allow_project_code` for global-config servers;
/// `Config::trust_project_code` sets the same bypass for project servers.
pub async fn connect_configured_with_approval(
    name: &str,
    cfg: &freedas_core::config::McpServerConfig,
    auth_header: Option<&str>,
    allow_project_code: bool,
) -> Result<McpServer, String> {
    ensure_mcp_trusted_in(&mcp_trust_file(), name, cfg, allow_project_code)?;
    if let Some(url) = &cfg.url {
        connect_http_with_timeout(name, url, &cfg.headers, auth_header, cfg.timeout_ms).await
    } else if let Some(cmd) = &cfg.command {
        connect_stdio_with(
            name,
            cmd,
            cfg.cwd.as_deref(),
            &cfg.environment,
            cfg.timeout_ms,
        )
        .await
    } else {
        Err(format!("no url or command for mcp server {name}"))
    }
}

/// Connect every enabled server and list its prompts as slash commands named
/// `<server>:<prompt>`. A server that fails to connect is skipped. Connections
/// are cached and authenticated with the credential stored by `mcp auth`.
pub async fn discover_slash_commands(
    configs: &std::collections::BTreeMap<String, freedas_core::config::McpServerConfig>,
) -> Vec<SlashPrompt> {
    discover_slash_commands_with_approval(configs, false).await
}

/// [`discover_slash_commands`] with an explicit project-code bypass; see
/// [`connect_configured_with_approval`].
pub async fn discover_slash_commands_with_approval(
    configs: &std::collections::BTreeMap<String, freedas_core::config::McpServerConfig>,
    allow_project_code: bool,
) -> Vec<SlashPrompt> {
    let mut out = Vec::new();
    for (name, cfg) in configs {
        if cfg.disabled {
            continue;
        }
        let server = match cached_connect_with_approval(name, cfg, allow_project_code).await {
            Ok(server) => server,
            Err(e) => {
                eprintln!("mcp {name}: {e}");
                continue;
            }
        };
        let prompts = guarded_call(
            server.as_ref(),
            "prompts/list",
            server.client.list_prompts(None),
        )
        .await;
        match prompts {
            Ok(result) => {
                let tools = guarded_call(
                    server.as_ref(),
                    "tools/list",
                    server.client.list_tools(None),
                )
                .await
                .ok()
                .map(|t| t.tools.len());
                if let Some(entry) = cache().lock().expect("mcp cache").get_mut(name) {
                    entry.prompts = Some(result.prompts.len());
                    entry.tools = tools;
                }
                out.extend(result.prompts.into_iter().map(|prompt| {
                    SlashPrompt {
                        name: format!("{name}:{}", prompt.name),
                        description: prompt.description.unwrap_or_default(),
                        arguments: prompt
                            .arguments
                            .unwrap_or_default()
                            .into_iter()
                            .map(|arg| PromptArg {
                                name: arg.name,
                                description: arg.description,
                                required: arg.required.unwrap_or(false),
                            })
                            .collect(),
                    }
                }));
            }
            Err(e) => {
                // The cached connection may be dead; the next call reconnects.
                cache().lock().expect("mcp cache").remove(name);
                eprintln!("mcp {name}: prompts: {e}");
            }
        }
    }
    out
}

pub async fn connect_http(name: &str, url: &str) -> Result<McpServer, String> {
    connect_http_with(name, url, &std::collections::BTreeMap::new(), None).await
}

/// HTTP transport with configured headers and an optional `Authorization`
/// value (the credential stored by `mcp auth`).
pub async fn connect_http_with(
    name: &str,
    url: &str,
    headers: &std::collections::BTreeMap<String, String>,
    auth_header: Option<&str>,
) -> Result<McpServer, String> {
    connect_http_with_timeout(name, url, headers, auth_header, 30_000).await
}

/// HTTP transport with a `timeout_ms` bound on the initialize handshake
/// (`0` = none); the bound also sizes the transport control timeouts.
pub async fn connect_http_with_timeout(
    name: &str,
    url: &str,
    headers: &std::collections::BTreeMap<String, String>,
    auth_header: Option<&str>,
    timeout_ms: u64,
) -> Result<McpServer, String> {
    // Never send credentials over cleartext: https, or http loopback only.
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("{name}: invalid mcp url: {e}"))?;
    let loopback = matches!(
        parsed.host_str(),
        Some("127.0.0.1") | Some("::1") | Some("localhost")
    );
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && loopback) {
        return Err(format!("{name}: mcp url must use https (got {url})"));
    }
    use rmcp::transport::streamable_http_client::{
        StreamableHttpClientTransport, StreamableHttpClientTransportConfig,
    };
    let mut config = StreamableHttpClientTransportConfig::with_uri(url);
    if timeout_ms != 0 {
        let bound = std::time::Duration::from_millis(timeout_ms);
        config.control_request_timeout = bound;
        config.session_recovery_timeout = bound;
    }
    if let Some(auth) = auth_header {
        config.auth_header = Some(auth.to_string());
    }
    for (k, v) in headers {
        let name = http::HeaderName::from_bytes(k.as_bytes()).map_err(|e| e.to_string())?;
        let value = http::HeaderValue::from_str(v).map_err(|e| e.to_string())?;
        config.custom_headers.insert(name, value);
    }
    let transport = StreamableHttpClientTransport::from_config(config);
    with_timeout(
        timeout_ms,
        name,
        serve_client_with_lifecycle(
            ClientConfig::default(),
            transport,
            ClientLifecycleMode::Initialize,
        ),
    )
    .await
    .map(|client| McpServer {
        name: name.to_string(),
        client,
        timeout_ms,
    })
}

/// Run one MCP call with the server's `timeout_ms` bound (`0` = none). On
/// timeout the session is cancelled so a hung server cannot stall the run.
async fn guarded_call<T, E: std::fmt::Display>(
    server: &McpServer,
    op: &str,
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, String> {
    if server.timeout_ms == 0 {
        return future
            .await
            .map_err(|e| format!("{}: {op}: {e}", server.name));
    }
    match tokio::time::timeout(std::time::Duration::from_millis(server.timeout_ms), future).await {
        Ok(result) => result.map_err(|e| format!("{}: {op}: {e}", server.name)),
        Err(_) => {
            server.client.cancellation_token().cancel();
            Err(format!(
                "{}: {op}: timed out after {}ms",
                server.name, server.timeout_ms
            ))
        }
    }
}

pub async fn list_tools(server: &McpServer) -> Result<ListToolsResult, String> {
    guarded_call(server, "tools/list", server.client.list_tools(None)).await
}

pub async fn list_prompts(server: &McpServer) -> Result<Vec<String>, String> {
    let result = guarded_call(server, "prompts/list", server.client.list_prompts(None)).await?;
    Ok(result
        .prompts
        .into_iter()
        .map(|p| p.name.to_string())
        .collect())
}

/// Run one tool call. The caller must have authorized
/// `tool_permission_action(server.name, name)` through the permission engine
/// before calling: this library cannot enforce the check (no access to the
/// permission rules or the user), it only executes.
pub async fn call_tool(
    server: &McpServer,
    name: &str,
    args: serde_json::Value,
) -> Result<serde_json::Value, String> {
    debug_assert!(
        !server.name.is_empty() && !name.is_empty(),
        "call_tool requires a permission-checked server tool name"
    );
    let obj = arguments_object(name, args)?;
    let params = CallToolRequestParams::new(name.to_string()).with_arguments(obj);
    let result = guarded_call(server, "tools/call", server.client.call_tool(params)).await?;
    serde_json::to_value(result).map_err(|e| e.to_string())
}

fn arguments_object(
    tool: &str,
    args: serde_json::Value,
) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    match args {
        serde_json::Value::Object(obj) => Ok(obj),
        other => Err(format!(
            "tool {tool} arguments must be a JSON object, got {}",
            type_name(&other)
        )),
    }
}

fn type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

pub fn status_from_config(config: &freedas_core::config::Config) -> Vec<ServerStatus> {
    let cache = cache().lock().expect("mcp cache");
    config
        .mcp
        .iter()
        .map(|(name, cfg)| {
            let cached = cache.get(name).filter(|c| c.config_key == config_key(cfg));
            ServerStatus {
                name: name.clone(),
                state: if cfg.disabled {
                    "disabled".into()
                } else if cached.is_some() {
                    "connected".into()
                } else {
                    "unknown".into()
                },
                tools: cached.and_then(|c| c.tools),
                prompts: cached.and_then(|c| c.prompts),
                error: None,
            }
        })
        .collect()
}

/// Permission action for an MCP tool. The `:` separator never appears in a
/// sanitized component, so unlike a `_` join this cannot collide
/// (`a_b`+`c` vs `a`+`b_c` stay distinct).
pub fn tool_permission_action(server: &str, tool: &str) -> String {
    format!(
        "{}:{}",
        sanitize_component(server),
        sanitize_component(tool)
    )
}

fn sanitize_component(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

pub fn protocol_version() -> ProtocolVersion {
    ProtocolVersion::LATEST
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    use freedas_core::config::McpServerConfig;
    use std::collections::BTreeMap;

    /// Minimal MCP server: answers `initialize` and `prompts/list`, and echoes
    /// `MCP_TEST_ENV` so the test can observe the environment it was given.
    const MOCK_SERVER: &str = r#"
import json, os, sys
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    method, ident = msg.get("method"), msg.get("id")
    if method == "initialize":
        result = {
            "protocolVersion": msg["params"]["protocolVersion"],
            "capabilities": {"prompts": {"listChanged": False}, "tools": {}},
            "serverInfo": {"name": "mock", "version": "1.0"},
        }
    elif method == "prompts/list":
        result = {"prompts": [{
            "name": "greet",
            "description": os.environ.get("MCP_TEST_ENV", "missing"),
            "arguments": [{"name": "who", "description": "recipient", "required": True}],
        }]}
    else:
        if ident is None:
            continue
        result = {}
    print(json.dumps({"jsonrpc": "2.0", "id": ident, "result": result}), flush=True)
"#;

    fn have_python() -> bool {
        std::process::Command::new("python3")
            .arg("--version")
            .output()
            .is_ok_and(|out| out.status.success())
    }

    fn mock_config() -> McpServerConfig {
        McpServerConfig {
            command: Some(vec![
                "python3".into(),
                "-c".into(),
                MOCK_SERVER.trim().into(),
            ]),
            environment: BTreeMap::from([("MCP_TEST_ENV".into(), "applied-env".into())]),
            timeout_ms: 10_000,
            ..McpServerConfig::default()
        }
    }

    #[tokio::test]
    async fn discover_applies_environment_and_prefixes_prompts() {
        if !have_python() {
            eprintln!("skipping: python3 unavailable");
            return;
        }
        let configs = BTreeMap::from([
            ("mock".to_string(), mock_config()),
            (
                "off".to_string(),
                McpServerConfig {
                    disabled: true,
                    ..mock_config()
                },
            ),
        ]);
        let prompts = discover_slash_commands_with_approval(&configs, true).await;
        assert_eq!(
            prompts.len(),
            1,
            "disabled server must be skipped: {prompts:?}"
        );
        assert_eq!(prompts[0].name, "mock:greet");
        assert_eq!(prompts[0].description, "applied-env");
        assert_eq!(prompts[0].arguments.len(), 1);
        assert_eq!(prompts[0].arguments[0].name, "who");
        assert!(prompts[0].arguments[0].required);
    }

    #[test]
    fn non_object_tool_arguments_are_rejected() {
        let err = arguments_object("demo", serde_json::json!([1, 2])).unwrap_err();
        assert!(err.contains("must be a JSON object"), "got {err}");
        assert!(arguments_object("demo", serde_json::json!({"a": 1})).is_ok());
    }

    #[test]
    fn status_is_unknown_until_connected() {
        let mut config = freedas_core::config::Config::default();
        config
            .mcp
            .insert("status-test".into(), McpServerConfig::default());
        config.mcp.insert(
            "status-off".into(),
            McpServerConfig {
                disabled: true,
                ..McpServerConfig::default()
            },
        );
        let statuses = status_from_config(&config);
        let enabled = statuses.iter().find(|s| s.name == "status-test").unwrap();
        assert_eq!(enabled.state, "unknown");
        assert_eq!(enabled.tools, None);
        assert_eq!(enabled.tools_label(), "unknown");
        let off = statuses.iter().find(|s| s.name == "status-off").unwrap();
        assert_eq!(off.state, "disabled");
    }

    #[test]
    fn cache_key_tracks_command_and_url() {
        let a = McpServerConfig {
            command: Some(vec!["a".into()]),
            ..McpServerConfig::default()
        };
        let b = McpServerConfig {
            command: Some(vec!["b".into()]),
            ..McpServerConfig::default()
        };
        assert_ne!(config_key(&a), config_key(&b));
    }

    #[tokio::test]
    async fn handshake_timeout_is_bounded() {
        if !have_python() {
            eprintln!("skipping: python3 unavailable");
            return;
        }
        let cfg = McpServerConfig {
            command: Some(vec![
                "python3".into(),
                "-c".into(),
                "import time; time.sleep(30)".into(),
            ]),
            timeout_ms: 300,
            ..McpServerConfig::default()
        };
        let started = std::time::Instant::now();
        let err = match connect_configured_with_approval("slow", &cfg, None, true).await {
            Ok(_) => panic!("handshake must time out"),
            Err(err) => err,
        };
        assert!(err.contains("timed out after 300ms"), "got {err}");
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }

    #[test]
    fn approval_hash_covers_command_url_and_headers() {
        let base = mock_config();
        let mut changed = base.clone();
        changed.command = Some(vec!["other".into()]);
        assert_ne!(mcp_approval_hash(&base), mcp_approval_hash(&changed));
        let mut changed = base.clone();
        changed.url = Some("https://mcp.example.com/other".into());
        assert_ne!(mcp_approval_hash(&base), mcp_approval_hash(&changed));
        let mut changed = base.clone();
        changed.headers.insert("X-Team".into(), "core".into());
        assert_ne!(mcp_approval_hash(&base), mcp_approval_hash(&changed));
    }

    fn unique_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("freedas-mcp-trust-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn unapproved_server_fails_closed_with_instructions() {
        let dir = unique_dir("fail-closed");
        let store = dir.join("trusted_mcp.json");
        let err = ensure_mcp_trusted_in(&store, "mock", &mock_config(), false).unwrap_err();
        assert!(err.contains("is not trusted"), "{err}");
        assert!(err.contains(TRUST_ENV), "{err}");
        // Explicit bypass does not touch the store.
        assert!(ensure_mcp_trusted_in(&store, "mock", &mock_config(), true).is_ok());
        assert!(!store.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recorded_approval_breaks_on_config_change() {
        let dir = unique_dir("reapprove");
        let store = dir.join("trusted_mcp.json");
        let cfg = mock_config();
        write_approvals(
            &store,
            &BTreeMap::from([("mock".into(), mcp_approval_hash(&cfg))]),
        )
        .unwrap();
        assert!(ensure_mcp_trusted_in(&store, "mock", &cfg, false).is_ok());
        let mut changed = cfg.clone();
        changed.command = Some(vec!["other".into()]);
        let err = ensure_mcp_trusted_in(&store, "mock", &changed, false).unwrap_err();
        assert!(err.contains("is not trusted"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
