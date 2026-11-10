use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use crate::error::FreedasError;
use crate::paths::Paths;

/// How tool permission asks are resolved. `Bypass` approves everything not
/// explicitly denied, `Auto` keeps asks (and auto-rejects them headless), and
/// `Ask` prompts even where a rule would allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionMode {
    #[default]
    Bypass,
    Auto,
    Ask,
}

impl PermissionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            PermissionMode::Bypass => "bypass",
            PermissionMode::Auto => "auto",
            PermissionMode::Ask => "ask",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            PermissionMode::Bypass => "Bypass",
            PermissionMode::Auto => "Auto",
            PermissionMode::Ask => "Ask every time",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "bypass" => Some(PermissionMode::Bypass),
            "auto" => Some(PermissionMode::Auto),
            "ask" | "ask-every-time" | "manual" => Some(PermissionMode::Ask),
            _ => None,
        }
    }

    /// `(auto, manual)` flags for the session's tool context booleans.
    pub fn flags(self) -> (bool, bool) {
        match self {
            PermissionMode::Bypass => (true, false),
            PermissionMode::Auto => (false, false),
            PermissionMode::Ask => (false, true),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Config {
    pub schema: Option<String>,
    pub model: Option<String>,
    pub small_model: Option<String>,
    pub variant: Option<String>,
    pub permission_mode: PermissionMode,
    pub default_agent: String,
    pub subagent_depth: u8,
    pub disabled_providers: Vec<String>,
    pub instructions: Vec<String>,
    pub skills: Vec<String>,
    pub permission: PermissionConfig,
    pub memory: MemoryConfig,
    pub router: RouterConfig,
    pub standards: StandardsConfig,
    pub sandbox: SandboxConfig,
    pub snapshots: bool,
    /// Allow project-sourced executable content (path-based `plugin` entries
    /// and project `mcp` servers) without per-item hash approval. Default
    /// false: project code fails closed until approved once, and re-approval
    /// is required whenever the file or server config changes. Headless runs
    /// can set this (or `FREEDAS_TRUST_PROJECT_CODE=1`) to opt in explicitly.
    pub trust_project_code: bool,
    pub mcp: BTreeMap<String, McpServerConfig>,
    pub plugin: Vec<PluginSpec>,
    pub server: ServerConfig,
    pub websearch: WebSearchConfig,
    pub telemetry: bool,
    pub workspace: Option<String>,
    pub theme: Option<String>,
    pub max_steps: u32,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema: None,
            model: Some("freedas/auto".into()),
            small_model: Some("freedas/auto-cheap".into()),
            variant: None,
            permission_mode: PermissionMode::Bypass,
            default_agent: "build".into(),
            subagent_depth: 1,
            disabled_providers: Vec::new(),
            instructions: Vec::new(),
            skills: Vec::new(),
            permission: PermissionConfig::default(),
            memory: MemoryConfig::default(),
            router: RouterConfig::default(),
            standards: StandardsConfig::default(),
            sandbox: SandboxConfig::default(),
            snapshots: true,
            trust_project_code: false,
            mcp: BTreeMap::new(),
            plugin: Vec::new(),
            server: ServerConfig::default(),
            websearch: WebSearchConfig::default(),
            telemetry: false,
            workspace: None,
            theme: None,
            max_steps: 50,
            extra: BTreeMap::new(),
        }
    }
}

impl Config {
    /// Filter for catalog and provider-registry construction: a disabled
    /// provider's models must never be selectable.
    pub fn provider_enabled(&self, provider: &str) -> bool {
        !self.disabled_providers.iter().any(|p| p == provider)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PermissionConfig {
    pub rules: Vec<PermissionRule>,
}

impl<'de> serde::Deserialize<'de> for PermissionConfig {
    /// Accepts both `{"rules": [...]}` and the documented per-tool shape
    /// `{"edit": "allow", "bash": {"git push": "ask", "*": "allow"}}`.
    /// Rules keep file order so the last match wins as documented; unknown
    /// effects are rejected instead of silently dropped (fail closed).
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = <serde_json::Value as serde::Deserialize>::deserialize(d)?;
        let mut rules = Vec::new();
        if let Some(obj) = v.as_object() {
            for (key, val) in obj {
                if key == "rules" {
                    let arr = val.as_array().ok_or_else(|| {
                        serde::de::Error::custom("permission.rules: expected an array")
                    })?;
                    for (i, r) in arr.iter().enumerate() {
                        let rule =
                            serde_json::from_value::<PermissionRule>(r.clone()).map_err(|e| {
                                serde::de::Error::custom(format!("permission.rules[{i}]: {e}"))
                            })?;
                        validate_rule(&rule).map_err(serde::de::Error::custom)?;
                        rules.push(rule);
                    }
                    continue;
                }
                push_tool_rules(&mut rules, key, val).map_err(serde::de::Error::custom)?;
            }
        } else if !v.is_null() {
            return Err(serde::de::Error::custom(
                "permission: expected an object of rules",
            ));
        }
        Ok(PermissionConfig { rules })
    }
}

fn validate_rule(rule: &PermissionRule) -> Result<(), String> {
    match rule.effect.to_ascii_lowercase().as_str() {
        "allow" | "ask" | "deny" => Ok(()),
        other => Err(format!(
            "permission: unknown effect `{other}` for {} `{}` (expected allow, ask, or deny)",
            rule.action, rule.resource
        )),
    }
}

fn push_tool_rules(
    rules: &mut Vec<PermissionRule>,
    tool: &str,
    val: &serde_json::Value,
) -> Result<(), String> {
    match val {
        serde_json::Value::String(effect) => {
            let rule = PermissionRule::new(tool, "*", effect);
            validate_rule(&rule)?;
            rules.push(rule);
        }
        serde_json::Value::Object(map) => {
            for (pat, eff) in map {
                let effect = eff.as_str().ok_or_else(|| {
                    format!("permission.{tool}: `{pat}` must be allow, ask, or deny")
                })?;
                let rule = PermissionRule::new(tool, pat, effect);
                validate_rule(&rule)?;
                rules.push(rule);
            }
        }
        _ => {
            return Err(format!(
                "permission.{tool}: expected an effect or a map of patterns"
            ));
        }
    }
    Ok(())
}

impl Default for PermissionConfig {
    fn default() -> Self {
        Self {
            rules: vec![
                PermissionRule::new("*", "*", "allow"),
                PermissionRule::new("read", "*.env", "ask"),
                PermissionRule::new("read", "*.env.*", "ask"),
                PermissionRule::new("read", "*.env.example", "allow"),
                PermissionRule::new("read", "*.env.sample", "allow"),
                PermissionRule::new("read", "*.pem", "ask"),
                PermissionRule::new("read", "*.key", "ask"),
                PermissionRule::new("read", "*id_rsa", "ask"),
                PermissionRule::new("read", "*credentials.json", "ask"),
                PermissionRule::new("read", "*.aws/credentials", "ask"),
                PermissionRule::new("external_directory", "*", "ask"),
                PermissionRule::new("browser", "*", "ask"),
                PermissionRule::new("question", "*", "allow"),
            ],
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PermissionRule {
    pub action: String,
    pub resource: String,
    pub effect: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl PermissionRule {
    pub fn new(action: &str, resource: &str, effect: &str) -> Self {
        Self {
            action: action.into(),
            resource: resource.into(),
            effect: effect.into(),
            source: None,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct MemoryConfig {
    pub enabled: bool,
    pub profile: bool,
    pub recall: RecallConfig,
    pub distill: DistillConfig,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            profile: true,
            recall: RecallConfig::default(),
            distill: DistillConfig::default(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct RecallConfig {
    pub limit: usize,
}

impl Default for RecallConfig {
    fn default() -> Self {
        Self { limit: 8 }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct DistillConfig {
    pub enabled: bool,
}

impl Default for DistillConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct RouterConfig {
    pub mode: String,
    pub quality_floor: f32,
    pub max_escalations: u8,
    pub learn: bool,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            mode: "auto".into(),
            quality_floor: 0.80,
            max_escalations: 2,
            learn: true,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct StandardsConfig {
    pub enabled: bool,
    pub commands: Vec<String>,
    pub max_attempts: u8,
    pub block_on_failure: bool,
    pub review: bool,
}

impl Default for StandardsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            commands: Vec::new(),
            max_attempts: 3,
            block_on_failure: true,
            review: false,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct SandboxConfig {
    pub mode: String,
    pub network: String,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            mode: "auto".into(),
            network: "deny".into(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct McpServerConfig {
    #[serde(rename = "type")]
    pub server_type: Option<String>,
    pub url: Option<String>,
    pub command: Option<Vec<String>>,
    pub cwd: Option<String>,
    pub environment: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    pub oauth: bool,
    pub disabled: bool,
    pub timeout_ms: u64,
}

impl Default for McpServerConfig {
    fn default() -> Self {
        Self {
            server_type: None,
            url: None,
            command: None,
            cwd: None,
            environment: BTreeMap::new(),
            headers: BTreeMap::new(),
            oauth: false,
            disabled: false,
            timeout_ms: 30000,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(untagged)]
pub enum PluginSpec {
    Simple(String),
    WithOptions {
        package: String,
        options: serde_json::Value,
    },
}

impl<'de> serde::Deserialize<'de> for PluginSpec {
    /// Accepts `"name"`, `{"package": "…", "options": {…}}`, or the documented
    /// tuple form `["./path.ts", {"issuer": "acme"}]`.
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = <serde_json::Value as serde::Deserialize>::deserialize(d)?;
        match &v {
            serde_json::Value::String(s) => Ok(PluginSpec::Simple(s.clone())),
            serde_json::Value::Array(a) if !a.is_empty() => {
                let package = match a[0].as_str().filter(|s| !s.is_empty()) {
                    Some(s) => s.to_string(),
                    None => return Err(serde::de::Error::custom("invalid plugin spec")),
                };
                let options = a.get(1).cloned().unwrap_or(serde_json::json!({}));
                Ok(PluginSpec::WithOptions { package, options })
            }
            serde_json::Value::Object(_) => {
                let package = match v
                    .get("package")
                    .and_then(|p| p.as_str())
                    .filter(|s| !s.is_empty())
                {
                    Some(s) => s.to_string(),
                    None => return Err(serde::de::Error::custom("invalid plugin spec")),
                };
                let options = v.get("options").cloned().unwrap_or(serde_json::json!({}));
                Ok(PluginSpec::WithOptions { package, options })
            }
            _ => Err(serde::de::Error::custom("invalid plugin spec")),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub hostname: String,
    pub port: u16,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            hostname: "127.0.0.1".into(),
            port: 4096,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct WebSearchConfig {
    pub provider: String,
}

impl Default for WebSearchConfig {
    fn default() -> Self {
        Self {
            provider: "duckduckgo".into(),
        }
    }
}

fn load_into(cand: &Path, merged: &mut serde_json::Value) -> Result<(), FreedasError> {
    if !cand.exists() {
        return Ok(());
    }
    let text = std::fs::read_to_string(cand)
        .map_err(|e| FreedasError::Config(format!("{}: {e}", cand.display())))?;
    let json = parse_jsonc(&text, cand)?;
    if !json.is_object() {
        return Err(FreedasError::Config(format!(
            "{}: expected a JSON object",
            cand.display()
        )));
    }
    let base = cand.parent().unwrap_or(Path::new("."));
    let substituted = substitute_value(&json, base)?;
    for key in ["model", "small_model"] {
        if let Some(m) = substituted.get(key).and_then(|v| v.as_str()) {
            check_model_in(cand, key, m)?;
        }
    }
    deep_merge(merged, substituted);
    Ok(())
}

fn check_model_in(cand: &Path, key: &str, model: &str) -> Result<(), FreedasError> {
    if check_model(model).is_err() {
        return Err(FreedasError::Config(format!(
            "{}: invalid `{key}` `{model}`: expected provider/model or freedas/auto",
            cand.display()
        )));
    }
    Ok(())
}

fn substitute(s: &str, base: &Path) -> Result<String, FreedasError> {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let tail = &rest[start + 1..];
        if tail.starts_with("env:") {
            let end = tail
                .find('}')
                .ok_or_else(|| FreedasError::Config("unterminated {env:…} in config".into()))?;
            let var = &tail[4..end];
            let value = std::env::var(var)
                .map_err(|_| FreedasError::Config(format!("missing environment variable {var}")))?;
            out.push_str(&value);
            rest = &tail[end + 1..];
        } else if tail.starts_with("file:") {
            let end = tail
                .find('}')
                .ok_or_else(|| FreedasError::Config("unterminated {file:…} in config".into()))?;
            let rel = &tail[5..end];
            out.push_str(read_substituted_file(base, rel)?.trim());
            rest = &tail[end + 1..];
        } else {
            out.push('{');
            rest = tail;
        }
    }
    out.push_str(rest);
    Ok(out)
}

/// Read a `{file:path}` operand. Only relative paths that stay inside the
/// config file's directory are allowed, and the content is size-capped.
///
/// Note: substituted content bypasses the `read` permission engine — e.g.
/// `{file:.env}` under `instructions` injects the file without the `ask`
/// dialog the `read` tool would trigger. Callers under sensitive keys are
/// warned via `warn_sensitive_substitution`.
fn read_substituted_file(base: &Path, rel: &str) -> Result<String, FreedasError> {
    const CAP: u64 = 1024 * 1024;
    let rel_path = Path::new(rel);
    if rel_path.is_absolute()
        || rel_path
            .components()
            .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(FreedasError::Config(format!(
            "{{file:{rel}}}: absolute paths and `..` are not allowed"
        )));
    }
    let target = base.join(rel_path);
    let base_canon = base.canonicalize().unwrap_or_else(|_| base.to_path_buf());
    let canon = target
        .canonicalize()
        .map_err(|e| FreedasError::Config(format!("cannot read {}: {e}", target.display())))?;
    if !canon.starts_with(&base_canon) {
        return Err(FreedasError::Config(format!(
            "{{file:{rel}}}: escapes the config directory"
        )));
    }
    let len = std::fs::metadata(&canon)
        .map_err(|e| FreedasError::Config(format!("cannot read {}: {e}", canon.display())))?
        .len();
    if len > CAP {
        return Err(FreedasError::Config(format!(
            "{{file:{rel}}}: larger than {CAP} bytes"
        )));
    }
    std::fs::read_to_string(&canon)
        .map_err(|e| FreedasError::Config(format!("cannot read {}: {e}", canon.display())))
}

fn parse_jsonc(text: &str, path: &Path) -> Result<serde_json::Value, FreedasError> {
    let json: serde_json::Value =
        jsonc_parser::parse_to_serde_value(text, &jsonc_parser::ParseOptions::default())
            .map_err(|e| FreedasError::Config(format!("{}: {e}", path.display())))?;
    Ok(json)
}

/// Top-level config keys whose values are security-sensitive: network
/// endpoints and credentials (`mcp`), executed code (`plugin`), prompt text
/// (`instructions`, `skills`), the permission engine itself (`permission`),
/// and the bind endpoint (`server`). `{env:}`/`{file:}` expansion inside one
/// of these is warned about (see `warn_sensitive_substitution`) because a
/// repo-controlled config file could otherwise redirect traffic or exfiltrate
/// a secret without a permission prompt.
fn sensitive_substitution_key(top: &str) -> bool {
    matches!(
        top,
        "mcp" | "plugin" | "instructions" | "skills" | "permission" | "server"
    )
}

/// Warn when `{env:}`/`{file:}` substitution fires inside a
/// security-sensitive key. `{env:}` there can redirect an endpoint (e.g. an
/// `mcp` URL) or leak a secret into a header, command, or prompt; `{file:}`
/// additionally bypasses the `read` permission engine (no `ask` for secrets),
/// so both are called out with the key that triggered them. This warns rather
/// than denies to preserve legitimate local use.
fn warn_sensitive_substitution(s: &str, top: Option<&str>) {
    let Some(key) = top else {
        return;
    };
    if !sensitive_substitution_key(key) {
        return;
    }
    if s.contains("{env:") {
        eprintln!(
            "warning: {{env:…}} in config key `{key}` (sensitive keys: mcp, plugin, instructions, skills, permission, server): \
             a repo-controlled config could redirect an endpoint or exfiltrate a secret without a permission prompt"
        );
    }
    if s.contains("{file:") {
        eprintln!(
            "warning: {{file:…}} in config key `{key}` bypasses the `read` permission engine (no ask for secrets); \
             contents are injected without a prompt"
        );
    }
}

fn substitute_value(v: &serde_json::Value, base: &Path) -> Result<serde_json::Value, FreedasError> {
    substitute_value_at(v, base, None)
}

fn substitute_value_at(
    v: &serde_json::Value,
    base: &Path,
    top: Option<&str>,
) -> Result<serde_json::Value, FreedasError> {
    match v {
        serde_json::Value::String(s) => {
            warn_sensitive_substitution(s, top);
            Ok(serde_json::Value::String(substitute(s, base)?))
        }
        serde_json::Value::Array(a) => Ok(serde_json::Value::Array(
            a.iter()
                .map(|x| substitute_value_at(x, base, top))
                .collect::<std::result::Result<Vec<_>, FreedasError>>()?,
        )),
        serde_json::Value::Object(o) => {
            Ok(
                serde_json::Value::Object(
                    o.iter()
                        .map(|(k, x)| {
                            let child = match top {
                                Some(t) => Some(t),
                                None => Some(k.as_str()),
                            };
                            Ok::<(String, serde_json::Value), FreedasError>((
                                k.clone(),
                                substitute_value_at(x, base, child)?,
                            ))
                        })
                        .collect::<std::result::Result<
                            serde_json::Map<String, serde_json::Value>,
                            FreedasError,
                        >>()?,
                ),
            )
        }
        other => Ok(other.clone()),
    }
}

fn deep_merge(base: &mut serde_json::Value, overlay: serde_json::Value) {
    match (base, overlay) {
        (serde_json::Value::Object(b), serde_json::Value::Object(o)) => {
            for (k, v) in o {
                match b.get_mut(&k) {
                    Some(existing) => {
                        // Only instructions/skills/plugin concat; other arrays replace.
                        if matches!(k.as_str(), "instructions" | "skills" | "plugin")
                            && matches!(existing, serde_json::Value::Array(_))
                            && matches!(v, serde_json::Value::Array(_))
                        {
                            if let (
                                serde_json::Value::Array(b_arr),
                                serde_json::Value::Array(v_arr),
                            ) = (&mut *existing, v)
                            {
                                b_arr.extend(v_arr);
                            }
                        } else {
                            deep_merge(existing, v);
                        }
                    }
                    None => {
                        b.insert(k, v);
                    }
                }
            }
        }
        (b, o) => *b = o,
    }
}

/// System, global, and Midas-migration config files, lowest to highest.
/// Midas fallbacks sort before their native counterparts so native wins.
fn global_candidates(paths: &Paths) -> Vec<PathBuf> {
    vec![
        PathBuf::from("/etc/freedas/freedas.json"),
        PathBuf::from("/etc/freedas/freedas.jsonc"),
        paths.home.join(".config").join("midas").join("midas.json"),
        paths.home.join(".config").join("midas").join("midas.jsonc"),
        paths.global_config(),
        paths.config_dir.join("freedas.jsonc"),
    ]
}

/// Project config files, lowest to highest: direct files from the farthest
/// ancestor down to the project directory, then `.freedas`/`.midas` files in
/// the same order.
fn project_candidates(paths: &Paths) -> Vec<PathBuf> {
    let mut ancestors = Vec::new();
    let mut dir = paths.project_root.clone();
    loop {
        ancestors.push(dir.clone());
        match dir.parent() {
            Some(parent) => dir = parent.to_path_buf(),
            None => break,
        }
    }
    ancestors.reverse();
    let mut v = Vec::new();
    for a in &ancestors {
        for name in ["midas.json", "midas.jsonc", "freedas.json", "freedas.jsonc"] {
            v.push(a.join(name));
        }
    }
    for a in &ancestors {
        for dir in [".midas", ".freedas"] {
            for name in ["midas.json", "midas.jsonc", "freedas.json", "freedas.jsonc"] {
                v.push(a.join(dir).join(name));
            }
        }
    }
    v
}

/// Default TTL for the cached organization settings, applied to the wrapped
/// form when `ttl_secs` is absent and unconditionally to the bare-object form
/// (via file mtime, which is its only age bound).
const DEFAULT_ORG_TTL_SECS: i64 = 3600;

pub fn load(paths: &Paths, disable_project: bool) -> Result<Config, FreedasError> {
    let mut merged = serde_json::json!({});
    // Precedence: system and global files, then cached organization settings,
    // then project files (unless disabled), then the environment.
    // `MIDAS_CONFIG` is the migration alias; a native `FREEDAS_CONFIG` wins.
    if let Ok(explicit) = std::env::var("FREEDAS_CONFIG").or_else(|_| std::env::var("MIDAS_CONFIG"))
    {
        // One file replaces the system, global, org, and project layers.
        load_into(Path::new(&explicit), &mut merged)?;
    } else {
        for cand in global_candidates(paths) {
            load_into(&cand, &mut merged)?;
        }
        let org_cache = paths.cache_dir.join("org-settings.json");
        if let Ok(text) = std::fs::read_to_string(&org_cache)
            && let Ok(v) = serde_json::from_str::<serde_json::Value>(&text)
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(i64::MAX);
            // Wrapped cache `{fetched_at, ttl_secs?, settings}` expires; bare
            // objects stay backward compatible. Parse errors already skip.
            if let Some(obj) = v.as_object()
                && (obj.contains_key("fetched_at") || obj.contains_key("settings"))
            {
                let fetched = obj.get("fetched_at").and_then(|x| x.as_i64()).unwrap_or(0);
                let fetched = if fetched > 1_000_000_000_000 {
                    fetched / 1000
                } else {
                    fetched
                };
                let ttl = obj
                    .get("ttl_secs")
                    .and_then(|x| x.as_i64())
                    .unwrap_or(DEFAULT_ORG_TTL_SECS);
                if now - fetched <= ttl
                    && let Some(settings) = obj.get("settings")
                    && settings.is_object()
                {
                    deep_merge(&mut merged, settings.clone());
                }
            } else if v.is_object() {
                // Bare objects carry no `fetched_at`, so the file mtime is the
                // age bound and the default TTL applies unconditionally; a
                // stale planted policy must not apply forever. An unreadable
                // mtime fails closed (cache skipped).
                let fresh = std::fs::metadata(&org_cache)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .is_some_and(|age| now - age.as_secs() as i64 <= DEFAULT_ORG_TTL_SECS);
                if fresh {
                    deep_merge(&mut merged, v);
                }
            }
        }
        if !disable_project {
            for cand in project_candidates(paths) {
                load_into(&cand, &mut merged)?;
            }
        }
    }

    if let Ok(m) = std::env::var("FREEDAS_MODEL").or_else(|_| std::env::var("MIDAS_MODEL")) {
        check_model_in(Path::new("FREEDAS_MODEL"), "model", &m)?;
        merged["model"] = serde_json::json!(m);
    }
    let user_permission = merged.get("permission").is_some();
    let mut config: Config =
        serde_json::from_value(merged).map_err(|e| FreedasError::Config(format!("{e}")))?;
    for (key, value) in [
        ("model", &config.model),
        ("small_model", &config.small_model),
    ] {
        if let Some(m) = value.as_deref()
            && check_model(m).is_err()
        {
            return Err(FreedasError::Config(format!(
                "invalid `{key}` `{m}`: expected provider/model or freedas/auto"
            )));
        }
    }
    if user_permission {
        // A user `permission` block is parsed on its own, so re-attach the
        // built-in defaults ahead of it; last match wins.
        let mut rules = PermissionConfig::default().rules;
        rules.append(&mut config.permission.rules);
        config.permission.rules = rules;
    }
    config.sandbox.network = normalize_network(&config.sandbox.network)?;
    Ok(config)
}

/// Only the exact value `allow` opens the sandbox network; every other value
/// is rejected so a typo cannot silently widen the sandbox.
fn normalize_network(network: &str) -> Result<String, FreedasError> {
    match network.trim().to_ascii_lowercase().as_str() {
        "allow" => Ok("allow".into()),
        "deny" => Ok("deny".into()),
        other => Err(FreedasError::Config(format!(
            "sandbox.network: `{other}` is not valid; use \"allow\" or \"deny\""
        ))),
    }
}

fn validate(model: &str) -> Result<(), FreedasError> {
    if model == "freedas/auto" || model == "freedas/auto-cheap" {
        return Ok(());
    }
    if model.matches('/').count() == 1
        && let Some((provider, name)) = model.split_once('/')
        && !provider.is_empty()
        && !name.is_empty()
    {
        return Ok(());
    }
    Err(FreedasError::Config(format!(
        "invalid model `{model}`: expected provider/model or freedas/auto"
    )))
}

pub fn check_model(model: &str) -> Result<(), FreedasError> {
    validate(model)
}

/// The global config file that was actually loaded: `.jsonc` overlays `.json`,
/// so write to whichever one exists, defaulting to `freedas.json`.
fn loaded_global_config(paths: &crate::paths::Paths) -> PathBuf {
    let jsonc = paths.config_dir.join("freedas.jsonc");
    if jsonc.exists() {
        jsonc
    } else {
        paths.global_config()
    }
}

/// Append an "always allow" rule for an action/resource to the global config;
/// used when a permission prompt is answered `Always`.
pub fn remember_rule(
    paths: &crate::paths::Paths,
    action: &str,
    resource: &str,
) -> std::io::Result<()> {
    let path = loaded_global_config(paths);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Read as JSONC so comment-bearing config files still parse. A parse error
    // is propagated rather than replaced, so a corrupt file is never lost.
    let mut root: serde_json::Value = if path.exists() {
        let text = std::fs::read_to_string(&path)?;
        jsonc_parser::parse_to_serde_value(&text, &jsonc_parser::ParseOptions::default()).map_err(
            |e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{}: {e}", path.display()),
                )
            },
        )?
    } else {
        serde_json::json!({})
    };
    if !root.is_object() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{}: expected a JSON object", path.display()),
        ));
    }
    if !root["permission"].is_object() && !root["permission"].is_null() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{}: `permission` must be an object", path.display()),
        ));
    }
    if !root["permission"]["rules"].is_array() {
        root["permission"]["rules"] = serde_json::json!([]);
    }
    if let Some(arr) = root["permission"]["rules"].as_array_mut() {
        arr.push(serde_json::json!({
            "action": action,
            "resource": resource,
            "effect": "allow",
        }));
    }
    // The write back is plain JSON, which strips comments (documented tradeoff).
    let body = serde_json::to_vec_pretty(&root)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    write_atomic(&path, &body)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or(Path::new("."));
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = dir.join(format!(
        ".{}.tmp-{}-{stamp}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    {
        let mut f = std::fs::File::create(&tmp)?;
        if let Err(e) = f.write_all(bytes).and_then(|_| f.sync_all()) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_paths(root: &Path) -> Paths {
        Paths {
            home: root.join("home"),
            config_dir: root.join("config"),
            data_dir: root.join("data"),
            state_dir: root.join("state"),
            cache_dir: root.join("cache"),
            bin_dir: root.join("bin"),
            project_root: root.join("repo").join("sub"),
        }
    }

    #[test]
    fn model_validation() {
        assert!(check_model("freedas/auto").is_ok());
        assert!(check_model("anthropic/claude-sonnet-5-5").is_ok());
        assert!(check_model("no-slash").is_err());
    }

    #[test]
    fn disabled_providers_filter() {
        let config = Config {
            disabled_providers: vec!["openai".into()],
            ..Default::default()
        };
        assert!(!config.provider_enabled("openai"));
        assert!(config.provider_enabled("anthropic"));
    }

    #[test]
    fn default_permission_rules_cover_secrets() {
        let rules = PermissionConfig::default().rules;
        for (action, resource) in [
            ("read", "*.pem"),
            ("read", "*.key"),
            ("read", "*id_rsa"),
            ("read", "*credentials.json"),
            ("read", "*.aws/credentials"),
        ] {
            assert!(
                rules
                    .iter()
                    .any(|r| r.action == action && r.resource == resource && r.effect == "ask"),
                "missing ask rule for {action} {resource}"
            );
        }
    }

    #[test]
    fn project_candidates_put_direct_files_before_dot_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let paths = temp_paths(dir.path());
        let c = project_candidates(&paths);
        let repo = dir.path().join("repo");
        let at = |p: PathBuf| c.iter().position(|x| *x == p).unwrap();
        let direct_far = at(repo.join("freedas.json"));
        let direct_near = at(paths.project_root.join("freedas.json"));
        let dot_near = at(paths.project_root.join(".freedas").join("freedas.json"));
        assert!(direct_far < direct_near);
        assert!(direct_near < dot_near);
        let first_dot = c
            .iter()
            .position(|x| {
                x.components()
                    .any(|k| k.as_os_str() == ".freedas" || k.as_os_str() == ".midas")
            })
            .unwrap();
        assert!(direct_near < first_dot);
        assert!(c[..first_dot].iter().all(|x| {
            !x.components()
                .any(|k| k.as_os_str() == ".freedas" || k.as_os_str() == ".midas")
        }));
    }

    /// One test covers every `load` behaviour so `FREEDAS_CONFIG`, which is
    /// process-global, cannot race with another test in this binary.
    #[test]
    fn load_reads_cwd_config_and_honours_explicit_file() {
        let dir = tempfile::tempdir().unwrap();
        let paths = temp_paths(dir.path());
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&paths.project_root).unwrap();
        std::fs::create_dir_all(&paths.cache_dir).unwrap();

        std::fs::write(repo.join("freedas.json"), r#"{"model":"openai/gpt"}"#).unwrap();
        std::fs::write(
            paths.project_root.join("freedas.json"),
            r#"{"model":"anthropic/near"}"#,
        )
        .unwrap();
        let config = load(&paths, false).unwrap();
        assert_eq!(config.model.as_deref(), Some("anthropic/near"));

        // disable_project skips the whole project layer.
        let config = load(&paths, true).unwrap();
        assert_ne!(config.model.as_deref(), Some("anthropic/near"));

        std::fs::write(
            paths.project_root.join("freedas.json"),
            r#"{"model":"local"}"#,
        )
        .unwrap();
        let err = load(&paths, false).unwrap_err().to_string();
        assert!(
            err.contains("freedas.json") && err.contains("`model`"),
            "{err}"
        );

        // A user permission block keeps the built-in defaults in front of it.
        std::fs::write(repo.join("freedas.json"), "{}").unwrap();
        std::fs::write(
            paths.project_root.join("freedas.json"),
            r#"{"permission":{"edit":"allow","bash":{"git push":"ask","*":"allow"}}}"#,
        )
        .unwrap();
        let rules = load(&paths, false).unwrap().permission.rules;
        assert_eq!(rules[0].action, "*");
        assert!(
            rules
                .iter()
                .any(|r| r.action == "read" && r.resource == "*.env")
        );
        let user = rules.iter().position(|r| r.action == "edit").unwrap();
        assert!(user > 0);

        // FREEDAS_CONFIG is one file that replaces every other layer.
        let one = dir.path().join("one.json");
        std::fs::write(&one, r#"{"model":"google/gem"}"#).unwrap();
        unsafe { std::env::set_var("FREEDAS_CONFIG", &one) };
        let config = load(&paths, false);
        unsafe { std::env::remove_var("FREEDAS_CONFIG") };
        assert_eq!(config.unwrap().model.as_deref(), Some("google/gem"));
        assert_eq!(paths.global_config(), paths.config_dir.join("freedas.json"));

        // MIDAS_CONFIG is the migration alias for the same single-file mode.
        let two = dir.path().join("two.json");
        std::fs::write(&two, r#"{"model":"google/gem2"}"#).unwrap();
        unsafe { std::env::set_var("MIDAS_CONFIG", &two) };
        let config = load(&paths, false);
        unsafe { std::env::remove_var("MIDAS_CONFIG") };
        assert_eq!(config.unwrap().model.as_deref(), Some("google/gem2"));
    }

    #[test]
    fn substitution() {
        unsafe {
            std::env::set_var("FREEDAS_TEST_VAR", "hi");
        }
        let base = Path::new(".");
        assert_eq!(
            substitute("a {env:FREEDAS_TEST_VAR} b", base).unwrap(),
            "a hi b"
        );
        unsafe {
            std::env::remove_var("FREEDAS_TEST_VAR");
        }
    }

    #[test]
    fn permission_rules_keep_file_order() {
        let pc: PermissionConfig =
            serde_json::from_str(r#"{"bash":{"git push":"ask","*":"allow"},"edit":"allow"}"#)
                .unwrap();
        let got: Vec<(&str, &str, &str)> = pc
            .rules
            .iter()
            .map(|r| (r.action.as_str(), r.resource.as_str(), r.effect.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("bash", "git push", "ask"),
                ("bash", "*", "allow"),
                ("edit", "*", "allow"),
            ]
        );

        // The real load path parses JSONC first; order must survive that too.
        let v = parse_jsonc(
            r#"{"permission":{"bash":{"git push":"ask","*":"allow"}}}"#,
            Path::new("freedas.jsonc"),
        )
        .unwrap();
        let pc: PermissionConfig = serde_json::from_value(v["permission"].clone()).unwrap();
        assert_eq!(pc.rules[0].resource, "git push");
        assert_eq!(pc.rules[1].resource, "*");
    }

    #[test]
    fn unknown_effects_are_rejected() {
        assert!(serde_json::from_str::<PermissionConfig>(r#"{"edit":"block"}"#).is_err());
        assert!(serde_json::from_str::<PermissionConfig>(r#"{"bash":{"git push":true}}"#).is_err());
        assert!(
            serde_json::from_str::<PermissionConfig>(
                r#"{"rules":[{"action":"edit","resource":"*","effect":"nope"}]}"#
            )
            .is_err()
        );
    }

    #[test]
    fn sandbox_network_is_validated_and_fail_closed() {
        assert_eq!(normalize_network(" Allow ").unwrap(), "allow");
        assert_eq!(normalize_network("deny").unwrap(), "deny");
        assert!(normalize_network("none").is_err());
        assert!(normalize_network("").is_err());
    }

    #[test]
    fn file_substitution_stays_inside_config_dir() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        std::fs::create_dir_all(base.join("sub")).unwrap();
        std::fs::write(base.join("sub").join("ok.txt"), " hello ").unwrap();
        assert_eq!(
            substitute("a {file:sub/ok.txt} b", base).unwrap(),
            "a hello b"
        );
        assert!(substitute("{file:/etc/passwd}", base).is_err());
        assert!(substitute("{file:../secret.txt}", base).is_err());
    }

    #[test]
    fn remember_rule_targets_loaded_jsonc_and_preserves_corrupt_files() {
        let dir = tempfile::tempdir().unwrap();
        let paths = temp_paths(dir.path());
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        let jsonc = paths.config_dir.join("freedas.jsonc");
        std::fs::write(&jsonc, "// keep me\n{\"permission\":{\"edit\":\"ask\"}}\n").unwrap();
        remember_rule(&paths, "read", "*.env").unwrap();
        assert!(
            !paths.global_config().exists(),
            "must not create freedas.json"
        );
        let text = std::fs::read_to_string(&jsonc).unwrap();
        let v: serde_json::Value =
            jsonc_parser::parse_to_serde_value(&text, &Default::default()).unwrap();
        let rules = v["permission"]["rules"].as_array().unwrap();
        assert!(
            rules
                .iter()
                .any(|r| r["action"] == "read" && r["effect"] == "allow")
        );

        let dir = tempfile::tempdir().unwrap();
        let paths = temp_paths(dir.path());
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        std::fs::write(paths.global_config(), "{ broken").unwrap();
        assert!(remember_rule(&paths, "read", "*.env").is_err());
        assert_eq!(
            std::fs::read_to_string(paths.global_config()).unwrap(),
            "{ broken"
        );
    }

    #[test]
    fn permission_mode_defaults_to_bypass() {
        assert_eq!(Config::default().permission_mode, PermissionMode::Bypass);
        assert!(Config::default().variant.is_none());
    }

    #[test]
    fn permission_mode_parses_from_config() {
        let config: Config =
            serde_json::from_str(r#"{"permission_mode":"ask","variant":"max"}"#).unwrap();
        assert_eq!(config.permission_mode, PermissionMode::Ask);
        assert_eq!(config.variant.as_deref(), Some("max"));
    }

    #[test]
    fn permission_mode_parse_accepts_aliases_and_rejects_junk() {
        for (raw, want) in [
            ("bypass", PermissionMode::Bypass),
            ("AUTO", PermissionMode::Auto),
            (" ask ", PermissionMode::Ask),
            ("ask-every-time", PermissionMode::Ask),
            ("Manual", PermissionMode::Ask),
        ] {
            assert_eq!(PermissionMode::parse(raw), Some(want), "{raw}");
        }
        for junk in ["", "yolo", "auto-approve"] {
            assert!(PermissionMode::parse(junk).is_none(), "{junk}");
        }
    }

    #[test]
    fn permission_mode_flags_match_contract() {
        assert_eq!(PermissionMode::Bypass.flags(), (true, false));
        assert_eq!(PermissionMode::Auto.flags(), (false, false));
        assert_eq!(PermissionMode::Ask.flags(), (false, true));
        assert_eq!(PermissionMode::Bypass.as_str(), "bypass");
        assert_eq!(PermissionMode::Ask.as_str(), "ask");
    }

    #[test]
    fn invalid_permission_mode_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedas.json");
        std::fs::write(&path, r#"{"permission_mode":"yolo"}"#).unwrap();
        let mut merged = serde_json::json!({});
        load_into(&path, &mut merged).unwrap();
        assert!(serde_json::from_value::<Config>(merged).is_err());
    }
}
