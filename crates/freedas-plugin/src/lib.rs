//! Plugin host: WASM, JS, and process plugins.
//!
//! Plugins are discovered under `<project>/.freedas/plugins/` and
//! `~/.config/freedas/plugins/`. A plugin is a `.wasm`, `.js`/`.ts` file, a directory
//! containing one, or a `freedas-plugin.json` manifest that names the entry file.
//!
//! # Safety boundary
//!
//! WASM plugins run in a wasmtime store with no WASI and no host imports, so they cannot
//! read the filesystem, open sockets, or inspect the environment. Each call is bounded by
//! a fuel budget and a linear-memory cap. JS plugins run in a QuickJS context with only the
//! `freedas` global, under a memory cap and a wall-clock interrupt.
//!
//! Process plugins are executables and are therefore trusted code once started. A process
//! plugin runs only when its file hash is recorded in `<data>/trusted_plugins.json`; the
//! first run requires `FREEDAS_PLUGIN_TRUST=1`, which records the hash and asks again
//! whenever the file changes. Path-based WASM/JS entries need the same approval before
//! they load. Processes are spawned with a cleared environment plus a small
//! allowlist, and get a single JSON-RPC line before being stopped.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Component as PathComponent, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex, mpsc};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use wasmtime::component::{Component, Linker as ComponentLinker};
use wasmtime::{Engine, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder};

const MANIFEST_FILE: &str = "freedas-plugin.json";
const NO_INIT: &str = "plugin has no init export";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const WASM_FUEL: u64 = 200_000_000;
const WASM_MEMORY_LIMIT: usize = 64 * 1024 * 1024;
const JS_MEMORY_LIMIT: usize = 64 * 1024 * 1024;
const JS_TIME_LIMIT: Duration = Duration::from_secs(2);
const MAX_HOOK_FAILURES: u32 = 3;
const TRUST_FILE: &str = "trusted_plugins.json";
const TRUST_ENV: &str = "FREEDAS_PLUGIN_TRUST";
/// Explicit headless/CI opt-in mirroring `Config::trust_project_code`.
const TRUST_PROJECT_ENV: &str = "FREEDAS_TRUST_PROJECT_CODE";

/// Variables a process plugin inherits. Provider keys, tokens, and the rest of the
/// host environment are deliberately absent.
const PROCESS_ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TMPDIR",
    "TERM",
    "SYSTEMROOT",
    "COMSPEC",
];

/// How a plugin is executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginKind {
    /// WebAssembly module or component. Sandboxed, no filesystem or network access.
    Wasm,
    /// JavaScript running in QuickJS.
    Js,
    /// Executable sidecar speaking JSON-RPC over stdio.
    Process,
}

impl PluginKind {
    /// Detect a kind from a file extension, with or without a leading dot.
    ///
    /// `.json` is not a plugin kind; only a manifest names a process plugin.
    pub fn from_extension(extension: &str) -> Option<Self> {
        match extension.trim_start_matches('.') {
            "wasm" => Some(Self::Wasm),
            "js" | "ts" | "mjs" | "cjs" => Some(Self::Js),
            _ => None,
        }
    }

    /// Parse the `kind` value of a manifest.
    pub fn from_name(kind: &str) -> Option<Self> {
        match kind {
            "wasm" => Some(Self::Wasm),
            "js" | "ts" | "javascript" => Some(Self::Js),
            "process" | "sidecar" => Some(Self::Process),
            _ => None,
        }
    }

    /// Canonical manifest name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wasm => "wasm",
            Self::Js => "js",
            Self::Process => "process",
        }
    }
}

/// A plugin found on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginInfo {
    pub id: String,
    pub kind: PluginKind,
    pub path: PathBuf,
}

/// Contents of `freedas-plugin.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginManifest {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub entry: String,
    #[serde(default)]
    pub options: Map<String, Value>,
    /// A required plugin's hook failures are logged loudly instead of skipped.
    #[serde(default)]
    pub required: bool,
}

/// Scan the project and global plugin directories, plus npm-installed plugins
/// under `<data>/plugins/`.
///
/// The project directory wins when both define the same plugin ID.
pub fn discover(project_root: &Path) -> Vec<PluginInfo> {
    let paths = freedas_core::Paths::resolve(project_root.to_path_buf());
    let project = project_root.join(".freedas").join("plugins");
    let global = paths.config_dir.join("plugins");
    let installed = paths.data_dir.join("plugins");

    let mut seen = HashSet::new();
    let mut plugins = Vec::new();
    for info in scan_plugins(&project)
        .into_iter()
        .chain(scan_plugins(&global))
        .chain(scan_installed(&installed))
    {
        if seen.insert(info.id.clone()) {
            plugins.push(info);
        }
    }
    plugins
}

/// A plugin from the `plugin` config array together with its `options`, which
/// are passed to [`Plugin::initialize`] as the config JSON.
#[derive(Debug, Clone)]
pub struct ConfiguredPlugin {
    pub plugin: Plugin,
    pub options: Value,
}

impl ConfiguredPlugin {
    pub fn initialize(&self) -> Result<String, String> {
        self.plugin.initialize(&self.options.to_string())
    }
}

/// Resolve the `plugin` config array into loadable plugins.
///
/// Entries are a bare package/path (`"@acme/freedas-plugin"`,
/// `"./plugins/x.wasm"`) or the tuple/map form with `options`. Relative paths
/// resolve against the project's `.freedas/` directory, then the global config
/// directory, then the project root. npm names resolve to the newest
/// `<data>/plugins/<name>@<version>` directory.
pub fn discover_from_config(
    specs: &[freedas_core::config::PluginSpec],
    data_dir: &Path,
    project_root: &Path,
    global_root: &Path,
) -> Vec<ConfiguredPlugin> {
    discover_from_config_with_approval(
        specs,
        data_dir,
        project_root,
        global_root,
        trust_project_code_opt_in(),
    )
}

/// Resolve the `plugin` config array, requiring the same explicit hash trust
/// as process plugins for path-based WASM/JS entries (project-sourced code
/// fails closed: unapproved entries are skipped with instructions instead of
/// loaded). Registry packages skip the check; they were explicitly installed.
/// `allow_project_code` mirrors `Config::trust_project_code`.
pub fn discover_from_config_with_approval(
    specs: &[freedas_core::config::PluginSpec],
    data_dir: &Path,
    project_root: &Path,
    global_root: &Path,
    allow_project_code: bool,
) -> Vec<ConfiguredPlugin> {
    let mut seen = HashSet::new();
    let mut plugins = Vec::new();
    for spec in specs {
        let (package, options) = match spec {
            freedas_core::config::PluginSpec::Simple(package) => {
                (package.as_str(), serde_json::json!({}))
            }
            freedas_core::config::PluginSpec::WithOptions { package, options } => {
                (package.as_str(), options.clone())
            }
        };
        let expanded = expand_tilde(package, project_root);
        let from_path = expanded.starts_with('.')
            || expanded.starts_with('/')
            || Path::new(&expanded).is_absolute();
        let Some(info) = resolve_spec(package, data_dir, project_root, global_root) else {
            eprintln!("plugin {package}: not found");
            continue;
        };
        // shortcut: non-registry WASM/JS is repo-controlled until approved.
        if from_path
            && matches!(info.kind, PluginKind::Wasm | PluginKind::Js)
            && let Err(e) = ensure_config_plugin_trusted(&info, allow_project_code)
        {
            eprintln!("plugin {package}: {e}");
            continue;
        }
        if seen.insert(info.id.clone()) {
            plugins.push(ConfiguredPlugin {
                plugin: info.into(),
                options,
            });
        }
    }
    plugins
}

fn resolve_spec(
    package: &str,
    data_dir: &Path,
    project_root: &Path,
    global_root: &Path,
) -> Option<PluginInfo> {
    let package = expand_tilde(package, project_root);
    let is_path =
        package.starts_with('.') || package.starts_with('/') || Path::new(&package).is_absolute();
    if is_path {
        let candidates = if Path::new(&package).is_absolute() {
            vec![PathBuf::from(&package)]
        } else {
            vec![
                project_root.join(".freedas").join(&package),
                global_root.join(&package),
                project_root.join(&package),
            ]
        };
        let path = candidates.into_iter().find(|path| path.exists())?;
        return plugin_at(&path);
    }
    let dir = installed_package_dir(&package, data_dir)?;
    installed_plugin(&dir)
}

/// Expand a leading `~` to the user's home directory.
fn expand_tilde(spec: &str, project_root: &Path) -> String {
    let Some(rest) = spec.strip_prefix('~') else {
        return spec.to_owned();
    };
    if !rest.is_empty() && !rest.starts_with('/') {
        return spec.to_owned();
    }
    let home = freedas_core::Paths::resolve(project_root.to_path_buf()).home;
    format!("{}{rest}", home.display())
}

fn plugin_at(path: &Path) -> Option<PluginInfo> {
    if path.is_dir() {
        return installed_plugin(path);
    }
    let kind = kind_of_file(path)?;
    let id = match load_manifest(path) {
        Some(manifest) => manifest.id,
        None => path.file_stem()?.to_str()?.to_owned(),
    };
    Some(PluginInfo {
        id,
        kind,
        path: path.to_path_buf(),
    })
}

/// Newest installed `<name>@<version>` directory for an npm package name.
fn installed_package_dir(name: &str, data_dir: &Path) -> Option<PathBuf> {
    let root = data_dir.join("plugins");
    match name.strip_prefix('@') {
        Some(scoped) => {
            let (scope, package) = scoped.split_once('/')?;
            newest_version(&root.join(format!("@{scope}")), package)
        }
        None => newest_version(&root, name),
    }
}

fn newest_version(dir: &Path, name: &str) -> Option<PathBuf> {
    let mut best: Option<(String, PathBuf)> = None;
    for entry in fs::read_dir(dir).ok()?.flatten() {
        let file_name = entry.file_name().to_string_lossy().to_string();
        let Some(version) = file_name
            .strip_prefix(name)
            .and_then(|rest| rest.strip_prefix('@'))
        else {
            continue;
        };
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|(current, _)| version_cmp(version, current).is_gt())
        {
            best = Some((version.to_owned(), path));
        }
    }
    best.map(|(_, path)| path)
}

/// Semver ordering, falling back to a plain string comparison for tags that do not
/// parse. Prerelease identifiers order after the release (`1.0.0 > 1.0.0-rc.1`) and
/// numeric identifiers compare numerically.
fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    fn parse(version: &str) -> Option<(Vec<u64>, Vec<&str>)> {
        let (core, pre) = match version.split_once('-') {
            Some((core, pre)) => (core, pre.split('.').collect()),
            None => (version, Vec::new()),
        };
        let numbers = core
            .split('.')
            .map(|part| part.parse::<u64>().ok())
            .collect::<Option<Vec<u64>>>()?;
        Some((numbers, pre))
    }

    let (Some((a_core, a_pre)), Some((b_core, b_pre))) = (parse(a), parse(b)) else {
        return a.cmp(b);
    };
    for (left, right) in a_core.iter().zip(&b_core) {
        match left.cmp(right) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    match a_core.len().cmp(&b_core.len()) {
        Ordering::Equal => {}
        other => return other,
    }
    match (a_pre.is_empty(), b_pre.is_empty()) {
        (true, true) => return Ordering::Equal,
        (true, false) => return Ordering::Greater,
        (false, true) => return Ordering::Less,
        (false, false) => {}
    }
    for (left, right) in a_pre.iter().zip(&b_pre) {
        let ordering = match (left.parse::<u64>(), right.parse::<u64>()) {
            (Ok(left), Ok(right)) => left.cmp(&right),
            (Ok(_), Err(_)) => Ordering::Less,
            (Err(_), Ok(_)) => Ordering::Greater,
            (Err(_), Err(_)) => left.cmp(right),
        };
        match ordering {
            Ordering::Equal => {}
            other => return other,
        }
    }
    a_pre.len().cmp(&b_pre.len())
}

/// Entry point of an installed package: its `package.json` `freedas` field,
/// else the usual index files.
fn installed_plugin(dir: &Path) -> Option<PluginInfo> {
    if let Some(info) = package_entry(dir) {
        return Some(info);
    }
    plugin_in_dir(dir)
}

fn package_entry(dir: &Path) -> Option<PluginInfo> {
    let text = fs::read_to_string(dir.join("package.json")).ok()?;
    let package: Value = serde_json::from_str(&text).ok()?;
    let id = package
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            let name = dir.file_name()?.to_str()?;
            Some(name.split('@').next()?.to_owned())
        })?;
    let entry = match package.get("freedas")? {
        Value::String(entry) => entry.clone(),
        Value::Object(map) => map.get("entry")?.as_str()?.to_owned(),
        _ => return None,
    };
    let path = contained_join(dir, &entry)?;
    let kind = kind_of_file(&path)?;
    Some(PluginInfo { id, kind, path })
}

/// Join a manifest- or package-declared relative entry onto `dir`, refusing paths that
/// escape it. Returns `None` when the entry is absolute, traverses upward, or resolves
/// outside `dir`.
fn contained_join(dir: &Path, entry: &str) -> Option<PathBuf> {
    let rel = Path::new(entry);
    if rel.is_absolute()
        || rel
            .components()
            .any(|part| !matches!(part, PathComponent::Normal(_) | PathComponent::CurDir))
    {
        return None;
    }
    let base = fs::canonicalize(dir).ok()?;
    let path = fs::canonicalize(base.join(rel)).ok()?;
    path.starts_with(&base).then_some(path)
}

fn scan_installed(dir: &Path) -> Vec<PluginInfo> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut plugins = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if !path.is_dir() || name.starts_with('.') {
            continue;
        }
        if name.starts_with('@') {
            if let Ok(scoped) = fs::read_dir(&path) {
                for package in scoped.flatten() {
                    if package.path().is_dir()
                        && let Some(info) = installed_plugin(&package.path())
                    {
                        plugins.push(info);
                    }
                }
            }
        } else if let Some(info) = installed_plugin(&path) {
            plugins.push(info);
        }
    }
    plugins.sort_by(|a, b| a.id.cmp(&b.id));
    plugins
}

/// Load a manifest from a file or from `freedas-plugin.json` inside a directory.
///
/// Returns `None` for a missing file, invalid JSON, or a manifest missing `id`, `kind`,
/// or `entry`.
pub fn load_manifest(path: &Path) -> Option<PluginManifest> {
    let file = if path.is_dir() {
        path.join(MANIFEST_FILE)
    } else {
        path.to_path_buf()
    };
    let text = fs::read_to_string(file).ok()?;
    let manifest: PluginManifest = serde_json::from_str(&text).ok()?;
    if manifest.id.is_empty() || manifest.kind.is_empty() || manifest.entry.is_empty() {
        return None;
    }
    Some(manifest)
}

/// Hook names a plugin may subscribe to.
pub fn hooks_available() -> Vec<&'static str> {
    vec![
        "session.start",
        "session.end",
        "prompt",
        "tool.before",
        "tool.after",
        "model.request",
        "model.response",
        "permission.ask",
        "gate.result",
    ]
}

/// An initialized-capable plugin handle.
#[derive(Debug, Clone)]
pub struct Plugin {
    pub id: String,
    pub kind: PluginKind,
    /// Entry file, or a directory holding a `freedas-plugin.json` manifest.
    pub path: PathBuf,
}

impl From<PluginInfo> for Plugin {
    fn from(info: PluginInfo) -> Self {
        Self {
            id: info.id,
            kind: info.kind,
            path: info.path,
        }
    }
}

impl Plugin {
    /// Run the plugin's init entry point with `config_json`.
    ///
    /// Every failure is returned as `Err`; bad files, bad JSON, missing exports, and
    /// traps never panic.
    pub fn initialize(&self, config_json: &str) -> Result<String, String> {
        let entry = self.resolve_entry()?;
        match self.kind {
            PluginKind::Wasm => wasm_init(&entry, config_json),
            PluginKind::Js => js_init(&entry, config_json),
            PluginKind::Process => process_init(&entry, config_json),
        }
    }

    /// Run one lifecycle hook. Returns the plugin's replacement payload, or
    /// `None` when the plugin does not handle the event or leaves it unchanged.
    ///
    /// Failures are logged. A plugin that fails three hooks in a row is disabled for the
    /// rest of the process. A manifest marked `required` fails closed: its hook
    /// errors (including the disabled-plugin error) are returned as `Err` so the
    /// caller blocks instead of proceeding without the hook. Other plugins
    /// degrade to `Ok(None)`.
    pub fn hook(&self, event: &str, payload: &str) -> Result<Option<String>, String> {
        match self.try_hook(event, payload) {
            Ok(out) => Ok(out),
            Err(error) => {
                if self.is_required() {
                    eprintln!(
                        "plugin {} is required and failed hook {event}: {error}",
                        self.id
                    );
                    Err(error)
                } else {
                    eprintln!("plugin {}: hook {event} failed: {error}", self.id);
                    Ok(None)
                }
            }
        }
    }

    /// [`Plugin::hook`] with errors surfaced, including the disabled-plugin error.
    pub fn try_hook(&self, event: &str, payload: &str) -> Result<Option<String>, String> {
        if hook_disabled(&self.id) {
            return Err(format!(
                "plugin {} disabled after {MAX_HOOK_FAILURES} consecutive hook failures",
                self.id
            ));
        }
        match self.dispatch_hook(event, payload) {
            Ok(out) => {
                reset_hook_failures(&self.id);
                Ok(out)
            }
            Err(error) => {
                record_hook_failure(&self.id);
                Err(error)
            }
        }
    }

    fn dispatch_hook(&self, event: &str, payload: &str) -> Result<Option<String>, String> {
        let entry = self.resolve_entry()?;
        let out = match self.kind {
            PluginKind::Wasm => wasm_hook(&entry, event, payload)?,
            PluginKind::Js => js_hook(&entry, event, payload)?,
            PluginKind::Process => process_hook(&entry, event, payload)?,
        };
        Ok(if out.trim().is_empty() || out == "null" {
            None
        } else {
            Some(out)
        })
    }

    fn is_required(&self) -> bool {
        load_manifest(&self.path).is_some_and(|manifest| manifest.required)
    }

    fn resolve_entry(&self) -> Result<PathBuf, String> {
        let manifest_path = if self.path.is_dir() {
            self.path.join(MANIFEST_FILE)
        } else if self.path.extension().is_some_and(|e| e == "json") {
            // Any JSON file that parses as a manifest is one. The canonical
            // name is `freedas-plugin.json`, but treating another name as the
            // executable entry would spawn a manifest as a binary.
            self.path.clone()
        } else {
            return Ok(self.path.clone());
        };
        let manifest = load_manifest(&manifest_path)
            .ok_or_else(|| format!("invalid plugin manifest: {}", manifest_path.display()))?;
        let base = manifest_path.parent().unwrap_or(Path::new("."));
        contained_join(base, &manifest.entry).ok_or_else(|| {
            format!(
                "plugin entry {} is missing or escapes the plugin directory",
                manifest.entry
            )
        })
    }
}

static HOOK_FAILURES: LazyLock<Mutex<HashMap<String, u32>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn hook_disabled(id: &str) -> bool {
    HOOK_FAILURES
        .lock()
        .map(|failures| {
            failures
                .get(id)
                .is_some_and(|count| *count >= MAX_HOOK_FAILURES)
        })
        .unwrap_or(false)
}

fn record_hook_failure(id: &str) {
    let Ok(mut failures) = HOOK_FAILURES.lock() else {
        return;
    };
    let count = failures.entry(id.to_owned()).or_insert(0);
    *count += 1;
    if *count == MAX_HOOK_FAILURES {
        eprintln!("plugin {id}: disabled after {MAX_HOOK_FAILURES} consecutive hook failures");
    }
}

fn reset_hook_failures(id: &str) {
    if let Ok(mut failures) = HOOK_FAILURES.lock() {
        failures.remove(id);
    }
}

fn scan_plugins(dir: &Path) -> Vec<PluginInfo> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut plugins = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with('.'))
        {
            continue;
        }
        if path.is_dir() {
            if let Some(info) = plugin_in_dir(&path) {
                plugins.push(info);
            }
        } else if let Some(kind) = kind_of_file(&path)
            && let Some(stem) = path.file_stem().and_then(|stem| stem.to_str())
        {
            plugins.push(PluginInfo {
                id: stem.to_owned(),
                kind,
                path,
            });
        }
    }
    plugins.sort_by(|a, b| a.id.cmp(&b.id));
    plugins
}

fn plugin_in_dir(dir: &Path) -> Option<PluginInfo> {
    if let Some(manifest) = load_manifest(dir) {
        let kind = PluginKind::from_name(&manifest.kind)?;
        return Some(PluginInfo {
            id: manifest.id,
            kind,
            path: dir.to_path_buf(),
        });
    }
    let id = dir.file_name()?.to_str()?.to_owned();
    for name in [
        "index.wasm",
        "index.js",
        "index.ts",
        "index.mjs",
        "index.cjs",
    ] {
        let path = dir.join(name);
        if path.is_file()
            && let Some(kind) = kind_of_file(&path)
        {
            return Some(PluginInfo { id, kind, path });
        }
    }
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .collect();
    files.sort();
    for path in files {
        if !path.is_file() || path.file_name().is_some_and(|name| name == MANIFEST_FILE) {
            continue;
        }
        if let Some(kind) = kind_of_file(&path) {
            return Some(PluginInfo { id, kind, path });
        }
    }
    None
}

fn kind_of_file(path: &Path) -> Option<PluginKind> {
    if path.file_name().is_some_and(|name| name == MANIFEST_FILE) {
        return PluginKind::from_name(&load_manifest(path)?.kind);
    }
    PluginKind::from_extension(path.extension()?.to_str()?)
}

fn wasm_engine() -> Result<Engine, String> {
    let mut config = wasmtime::Config::new();
    config.consume_fuel(true);
    config.wasm_component_model(true);
    Engine::new(&config).map_err(|e| format!("wasm engine: {e}"))
}

/// Every store gets the memory cap and a fresh fuel budget, so a plugin that loops or
/// allocates without bound traps instead of hanging the host.
fn wasm_store(engine: &Engine) -> Result<Store<StoreLimits>, String> {
    let limits = StoreLimitsBuilder::new()
        .memory_size(WASM_MEMORY_LIMIT)
        .build();
    let mut store = Store::new(engine, limits);
    store.limiter(|limits| limits);
    store
        .set_fuel(WASM_FUEL)
        .map_err(|e| format!("wasm fuel: {e}"))?;
    Ok(store)
}

/// Which WIT entry point to call on a component.
enum ComponentCall<'a> {
    Init(&'a str),
    Hook { event: &'a str, payload: &'a str },
}

fn wasm_init(path: &Path, config_json: &str) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let engine = wasm_engine()?;
    if looks_like_component(&engine, &bytes) {
        wasm_component_call(&engine, &bytes, ComponentCall::Init(config_json))
    } else {
        wasm_core_init(&engine, &bytes, config_json)
    }
}

fn wasm_hook(path: &Path, event: &str, payload: &str) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let engine = wasm_engine()?;
    if looks_like_component(&engine, &bytes) {
        wasm_component_call(&engine, &bytes, ComponentCall::Hook { event, payload })
    } else {
        let input = serde_json::json!({"event": event, "payload": payload}).to_string();
        wasm_core_call(&engine, &bytes, "hook", &input)
    }
}

fn looks_like_component(engine: &Engine, bytes: &[u8]) -> bool {
    if bytes.starts_with(b"\0asm") {
        // Component binaries carry version 0x0d; core modules carry 0x01.
        bytes.len() >= 8
            && bytes[4] == 0x0d
            && bytes[5] == 0x00
            && bytes[6] == 0x01
            && bytes[7] == 0x00
    } else {
        // WAT text: let wasmtime decide which shape it is.
        Component::new(engine, bytes).is_ok()
    }
}

/// Core modules use a small ABI because wasm has no string type:
/// `init(input_ptr: i32, input_len: i32) -> i64` returns `(output_ptr << 32) | output_len`
/// pointing at UTF-8 bytes in the exported `memory`. Input is written through the
/// optional `freedas_alloc(len: i32) -> i32` export, or at offset 0 when absent.
fn wasm_core_init(engine: &Engine, bytes: &[u8], config_json: &str) -> Result<String, String> {
    wasm_core_call(engine, bytes, "init", config_json)
}

/// Call a component following the documented WIT world (`init`, `hooks`) with a
/// compatibility fallback to the earlier `(string) -> string` shapes and the legacy
/// single-argument `hook` export.
fn wasm_component_call(
    engine: &Engine,
    bytes: &[u8],
    call: ComponentCall<'_>,
) -> Result<String, String> {
    let component =
        Component::new(engine, bytes).map_err(|e| format!("invalid wasm component: {e}"))?;
    let linker: ComponentLinker<StoreLimits> = ComponentLinker::new(engine);
    let mut store = wasm_store(engine)?;
    let instance = linker
        .instantiate(&mut store, &component)
        .map_err(|e| format!("instantiate wasm component: {e}"))?;
    match call {
        ComponentCall::Init(config) => {
            if let Ok(func) =
                instance.get_typed_func::<(String,), (Result<(), String>,)>(&mut store, "init")
            {
                let (result,) = func
                    .call(&mut store, (config.to_owned(),))
                    .map_err(|e| format!("plugin init failed: {e:#}"))?;
                return result
                    .map(|()| String::new())
                    .map_err(|e| format!("plugin init failed: {e:#}"));
            }
            let func = instance
                .get_typed_func::<(String,), (String,)>(&mut store, "init")
                .map_err(|e| format!("plugin init has an unsupported signature: {e}"))?;
            let (out,) = func
                .call(&mut store, (config.to_owned(),))
                .map_err(|e| format!("plugin init failed: {e:#}"))?;
            Ok(out)
        }
        ComponentCall::Hook { event, payload } => {
            if let Ok(func) = instance
                .get_typed_func::<(String, String), (Result<String, String>,)>(&mut store, "hooks")
            {
                let (result,) = func
                    .call(&mut store, (event.to_owned(), payload.to_owned()))
                    .map_err(|e| format!("plugin hooks failed: {e:#}"))?;
                return result.map_err(|e| format!("plugin hooks failed: {e:#}"));
            }
            if let Ok(func) =
                instance.get_typed_func::<(String, String), (String,)>(&mut store, "hooks")
            {
                let (out,) = func
                    .call(&mut store, (event.to_owned(), payload.to_owned()))
                    .map_err(|e| format!("plugin hooks failed: {e:#}"))?;
                return Ok(out);
            }
            let input = serde_json::json!({"event": event, "payload": payload}).to_string();
            let func = instance
                .get_typed_func::<(String,), (String,)>(&mut store, "hook")
                .map_err(|e| format!("plugin has no hooks export: {e}"))?;
            let (out,) = func
                .call(&mut store, (input,))
                .map_err(|e| format!("plugin hook failed: {e:#}"))?;
            Ok(out)
        }
    }
}

fn wasm_core_call(
    engine: &Engine,
    bytes: &[u8],
    func: &str,
    input_text: &str,
) -> Result<String, String> {
    let module = Module::new(engine, bytes).map_err(|e| format!("invalid wasm module: {e}"))?;
    let mut store = wasm_store(engine)?;
    let instance = Linker::new(engine)
        .instantiate(&mut store, &module)
        .map_err(|e| format!("instantiate wasm module: {e}"))?;
    if instance.get_func(&mut store, func).is_none() {
        return Err(NO_INIT.to_owned());
    }
    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or("plugin has no memory export")?;
    let input = input_text.as_bytes();
    let len = i32::try_from(input.len()).map_err(|_| "plugin config exceeds 2 GiB")?;
    let ptr = match instance.get_typed_func::<i32, i32>(&mut store, "freedas_alloc") {
        Ok(alloc) => alloc
            .call(&mut store, len)
            .map_err(|e| format!("plugin alloc failed: {e:#}"))?,
        Err(_) => {
            grow_for(&memory, &mut store, input.len())?;
            0
        }
    };
    let offset = usize::try_from(ptr).map_err(|_| "plugin alloc returned a negative pointer")?;
    memory
        .write(&mut store, offset, input)
        .map_err(|e| format!("write plugin memory: {e}"))?;

    let call = instance
        .get_typed_func::<(i32, i32), i64>(&mut store, func)
        .map_err(|e| format!("plugin {func} has an unsupported signature: {e}"))?;
    let packed = call
        .call(&mut store, (ptr, len))
        .map_err(|e| format!("plugin {func} failed: {e:#}"))? as u64;
    let start =
        usize::try_from(packed >> 32).map_err(|_| "plugin init returned an invalid pointer")?;
    let out_len = usize::try_from(packed & 0xffff_ffff)
        .map_err(|_| "plugin init returned an invalid length")?;
    let end = start
        .checked_add(out_len)
        .ok_or("plugin init returned an invalid range")?;
    let data = memory.data(&store);
    let output = data
        .get(start..end)
        .ok_or("plugin init returned a range outside its memory")?;
    String::from_utf8(output.to_vec())
        .map_err(|e| format!("plugin init returned invalid UTF-8: {e}"))
}

fn grow_for(memory: &Memory, store: &mut Store<StoreLimits>, len: usize) -> Result<(), String> {
    let current = memory.data_size(&*store);
    if current < len {
        let pages = (len - current).div_ceil(0x1_0000) as u64;
        memory
            .grow(&mut *store, pages)
            .map_err(|e| format!("grow plugin memory: {e}"))?;
    }
    Ok(())
}

/// Minimal globals available to a JS plugin. Host-backed behaviour lands in a later
/// milestone; nothing here touches the filesystem or network.
const JS_GLOBALS: &str = r#"
globalThis.freedas = {
  log(message) {},
  config(key) { return null; },
  toast(message) {},
  prompt(text) { return null; },
};
"#;

const JS_INIT_CALL: &str = r#"
(function () {
  const init = globalThis.freedasInit;
  if (typeof init !== "function") return "{}";
  const result = init(globalThis.__freedasConfig);
  if (result === undefined || result === null) return "{}";
  return typeof result === "string" ? result : JSON.stringify(result);
})()
"#;

/// A QuickJS runtime capped at [`JS_MEMORY_LIMIT`] and interrupted once
/// [`JS_TIME_LIMIT`] has elapsed, so a runaway plugin cannot hang the host.
fn js_runtime() -> Result<rquickjs::Runtime, String> {
    let runtime = rquickjs::Runtime::new().map_err(|e| format!("quickjs runtime: {e}"))?;
    runtime.set_memory_limit(JS_MEMORY_LIMIT);
    let deadline = Instant::now() + JS_TIME_LIMIT;
    runtime.set_interrupt_handler(Some(Box::new(move || Instant::now() >= deadline)));
    Ok(runtime)
}

fn js_init(path: &Path, config_json: &str) -> Result<String, String> {
    let source = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let runtime = js_runtime()?;
    let context = rquickjs::Context::full(&runtime).map_err(|e| format!("quickjs context: {e}"))?;
    context.with(|ctx| {
        ctx.globals()
            .set("__freedasConfig", config_json)
            .map_err(|e| format!("set plugin config: {e}"))?;
        ctx.eval::<(), _>(JS_GLOBALS)
            .map_err(|e| format!("install freedas global: {e}"))?;
        ctx.eval::<(), _>(source)
            .map_err(|e| format!("evaluate {}: {e}", path.display()))?;
        ctx.eval::<String, _>(JS_INIT_CALL)
            .map_err(|e| format!("plugin freedasInit failed: {e}"))
    })
}

const JS_HOOK_CALL: &str = r#"
(function () {
  const hook = globalThis.freedasHook;
  if (typeof hook !== "function") return null;
  const result = hook(globalThis.__freedasEvent, globalThis.__freedasPayload);
  if (result === undefined || result === null) return null;
  return typeof result === "string" ? result : JSON.stringify(result);
})()
"#;

fn js_hook(path: &Path, event: &str, payload: &str) -> Result<String, String> {
    let source = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let runtime = js_runtime()?;
    let context = rquickjs::Context::full(&runtime).map_err(|e| format!("quickjs context: {e}"))?;
    context.with(|ctx| {
        ctx.globals()
            .set("__freedasEvent", event)
            .map_err(|e| format!("set plugin event: {e}"))?;
        ctx.globals()
            .set("__freedasPayload", payload)
            .map_err(|e| format!("set plugin payload: {e}"))?;
        ctx.eval::<(), _>(JS_GLOBALS)
            .map_err(|e| format!("install freedas global: {e}"))?;
        ctx.eval::<(), _>(source)
            .map_err(|e| format!("evaluate {}: {e}", path.display()))?;
        ctx.eval::<Option<String>, _>(JS_HOOK_CALL)
            .map(|v| v.unwrap_or_default())
            .map_err(|e| format!("plugin freedasHook failed: {e}"))
    })
}

fn process_hook(path: &Path, event: &str, payload: &str) -> Result<String, String> {
    process_request(
        path,
        "hook",
        serde_json::json!({ "event": event, "payload": payload }),
    )
}

fn process_init(path: &Path, config_json: &str) -> Result<String, String> {
    let config =
        serde_json::from_str(config_json).unwrap_or_else(|_| Value::String(config_json.to_owned()));
    process_request(path, "initialize", serde_json::json!({ "config": config }))
}

/// Run one JSON-RPC request against a process plugin and parse the reply.
///
/// The process is killed and reaped on every path, including a write or read error, so
/// no zombie survives. A reply that does not arrive within [`HANDSHAKE_TIMEOUT`] fails
/// the call.
fn process_request(path: &Path, method: &str, params: Value) -> Result<String, String> {
    // Spawn the same canonical file whose hash was approved.
    let (path, expected) = ensure_process_trusted(path)?;
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let mut command = Command::new(&path);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_clear();
    for key in PROCESS_ENV_ALLOWLIST {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    // Best-effort TOCTOU narrowing: re-hash just before spawn and refuse when
    // the file changed after the trust check. A swap between this read and
    // exec is still possible; process plugins remain trusted code regardless.
    let actual = hash_file(&path)?;
    if actual != expected {
        return Err(format!(
            "process plugin {} changed after the trust check; refusing to spawn",
            path.display()
        ));
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("spawn {}: {e}", path.display()))?;

    let mut line = request.to_string().into_bytes();
    line.push(b'\n');
    let written: Result<(), String> = match child.stdin.take() {
        Some(mut stdin) => stdin
            .write_all(&line)
            .and_then(|()| stdin.flush())
            .map_err(|e| format!("write to plugin: {e}")),
        None => Err("plugin stdin is unavailable".to_owned()),
    };
    let read = written.and_then(|()| {
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => return Err("plugin stdout is unavailable".to_owned()),
        };
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut response = String::new();
            let _ = BufReader::new(stdout).read_line(&mut response);
            let _ = tx.send(response);
        });
        rx.recv_timeout(HANDSHAKE_TIMEOUT)
            .map_err(|_| "plugin handshake timed out".to_owned())
    });
    // One request per process: the sidecar stops once it answers.
    let _ = child.kill();
    let _ = child.wait();
    parse_process_response(&read?)
}

/// Process plugins run with the host's privileges, so each file hash must be approved
/// once. `FREEDAS_PLUGIN_TRUST=1` approves and records the current hash.
///
/// Returns the canonical path and its approved hash so the caller spawns the
/// file that was approved and can re-hash just before spawn.
fn ensure_process_trusted(path: &Path) -> Result<(PathBuf, String), String> {
    check_or_record_trust(path, "process plugin")
}

/// Path-based WASM/JS entries run repo-controlled code, so they need the same
/// hash approval as process plugins before they load. Fails closed (skipped
/// with instructions) until approved; a changed file needs re-approval.
/// `allow_project_code` mirrors `Config::trust_project_code` and bypasses the
/// per-file check without recording.
fn ensure_config_plugin_trusted(info: &PluginInfo, allow_project_code: bool) -> Result<(), String> {
    if allow_project_code || trust_project_code_opt_in() {
        return Ok(());
    }
    let entry = plugin_code_path(info)?;
    check_or_record_trust(&entry, "project plugin")?;
    Ok(())
}

/// Entry file whose bytes run for a configured plugin: the file itself, or
/// the manifest entry for a directory. Unresolvable entries fail closed.
fn plugin_code_path(info: &PluginInfo) -> Result<PathBuf, String> {
    if !info.path.is_dir() {
        return Ok(info.path.clone());
    }
    Plugin::from(info.clone()).resolve_entry()
}

fn check_or_record_trust(path: &Path, label: &str) -> Result<(PathBuf, String), String> {
    check_or_record_trust_in(&trust_file(), path, label)
}

fn check_or_record_trust_in(
    store: &Path,
    path: &Path,
    label: &str,
) -> Result<(PathBuf, String), String> {
    let path = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let hash = hash_file(&path)?;
    let key = path.to_string_lossy().into_owned();
    let mut trusted = read_trust(store);
    if trusted.get(&key).is_some_and(|known| known == &hash) {
        return Ok((path, hash));
    }
    if !trust_opt_in() {
        return Err(format!(
            "{label} {} is not trusted (sha256 {hash}); re-run with {TRUST_ENV}=1 to approve it",
            path.display()
        ));
    }
    trusted.insert(key, hash.clone());
    write_trust(store, &trusted)?;
    Ok((path, hash))
}

fn hash_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|e| format!("read plugin {}: {e}", path.display()))?;
    use sha2::Digest;
    Ok(sha2::Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>())
}

fn trust_file() -> PathBuf {
    freedas_core::Paths::resolve(PathBuf::new())
        .data_dir
        .join(TRUST_FILE)
}

fn trust_opt_in() -> bool {
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

fn read_trust(file: &Path) -> BTreeMap<String, String> {
    fs::read_to_string(file)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn write_trust(file: &Path, trusted: &BTreeMap<String, String>) -> Result<(), String> {
    if let Some(parent) = file.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let text = serde_json::to_string_pretty(trusted).map_err(|e| e.to_string())?;
    fs::write(file, text).map_err(|e| format!("write {}: {e}", file.display()))
}

fn parse_process_response(line: &str) -> Result<String, String> {
    let line = line.trim();
    if line.is_empty() {
        return Err("plugin exited without a response".to_owned());
    }
    let response: Value =
        serde_json::from_str(line).map_err(|e| format!("plugin response is not JSON: {e}"))?;
    if let Some(error) = response.get("error") {
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| error.to_string());
        return Err(message);
    }
    match response.get("result") {
        Some(Value::String(result)) => Ok(result.clone()),
        Some(result) => Ok(result.to_string()),
        None => Err("plugin response has no result".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hooks_match_the_contract() {
        let hooks = hooks_available();
        for expected in [
            "session.start",
            "session.end",
            "prompt",
            "tool.before",
            "tool.after",
            "model.request",
            "model.response",
            "permission.ask",
            "gate.result",
        ] {
            assert!(hooks.contains(&expected), "missing {expected}");
        }
    }

    #[test]
    fn js_plugin_runs_freedas_init() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.js");
        std::fs::write(
            &path,
            "globalThis.freedasInit = (cfg) => JSON.stringify({ ok: true, cfg });",
        )
        .unwrap();
        let plugin = Plugin {
            id: "p".into(),
            kind: PluginKind::Js,
            path,
        };
        let out = plugin.initialize("{}").unwrap();
        assert!(out.contains("\"ok\":true"), "{out}");
    }

    #[test]
    fn wasm_plugin_without_init_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.wasm");
        std::fs::write(&path, b"\0asm\x01\0\0\0").unwrap();
        let plugin = Plugin {
            id: "p".into(),
            kind: PluginKind::Wasm,
            path,
        };
        assert!(plugin.initialize("{}").is_err());
    }

    const JS_INIT: &str = "globalThis.freedasInit = (cfg) => JSON.stringify({ ok: true, cfg });";

    #[test]
    fn discover_from_config_resolves_paths_and_passes_options() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        let plugins = project.join(".freedas").join("plugins");
        std::fs::create_dir_all(&plugins).unwrap();
        std::fs::write(plugins.join("plain.js"), JS_INIT).unwrap();
        std::fs::write(plugins.join("opt.js"), JS_INIT).unwrap();
        let specs: Vec<freedas_core::config::PluginSpec> =
            serde_json::from_value(serde_json::json!([
                "./plugins/plain.js",
                ["./plugins/opt.js", { "issuer": "acme" }]
            ]))
            .unwrap();

        let found = discover_from_config_with_approval(
            &specs,
            &dir.path().join("data"),
            &project,
            &dir.path().join("config"),
            true,
        );
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[0].plugin.id, "plain");
        assert_eq!(found[0].options, serde_json::json!({}));
        assert_eq!(found[1].options, serde_json::json!({"issuer": "acme"}));
        let out = found[1].initialize().unwrap();
        assert!(out.contains("acme"), "options must reach initialize: {out}");
    }

    #[test]
    fn project_path_entries_fail_closed_without_trust() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        let plugins = project.join(".freedas").join("plugins");
        std::fs::create_dir_all(&plugins).unwrap();
        std::fs::write(plugins.join("plain.js"), JS_INIT).unwrap();
        let specs: Vec<freedas_core::config::PluginSpec> =
            serde_json::from_value(serde_json::json!(["./plugins/plain.js"])).unwrap();
        // Default entry point: an unapproved project file must not load.
        let found = discover_from_config(
            &specs,
            &dir.path().join("data"),
            &project,
            &dir.path().join("config"),
        );
        assert!(found.is_empty(), "{found:?}");
        // Explicit flag bypass loads it without touching the trust store.
        let found = discover_from_config_with_approval(
            &specs,
            &dir.path().join("data"),
            &project,
            &dir.path().join("config"),
            true,
        );
        assert_eq!(found.len(), 1, "{found:?}");
    }

    #[test]
    fn trust_pin_requires_reapproval_after_change() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("trusted_plugins.json");
        let file = dir.path().join("p.js");
        std::fs::write(&file, JS_INIT).unwrap();
        let canon = file.canonicalize().unwrap();
        let key = canon.to_string_lossy().into_owned();
        let hash = hash_file(&canon).unwrap();
        write_trust(&store, &BTreeMap::from([(key.clone(), hash)])).unwrap();
        assert!(check_or_record_trust_in(&store, &file, "project plugin").is_ok());
        std::fs::write(&file, "globalThis.freedasInit = () => \"changed\";").unwrap();
        let err = check_or_record_trust_in(&store, &file, "project plugin").unwrap_err();
        assert!(err.contains("is not trusted"), "{err}");
    }

    #[test]
    fn discover_finds_npm_installed_packages() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let package = data.join("plugins").join("@acme").join("reviewer@1.2.0");
        std::fs::create_dir_all(package.join("dist")).unwrap();
        std::fs::write(
            package.join("package.json"),
            serde_json::json!({"name": "@acme/reviewer", "freedas": "dist/plugin.js"}).to_string(),
        )
        .unwrap();
        std::fs::write(package.join("dist").join("plugin.js"), JS_INIT).unwrap();

        let scanned = scan_installed(&data.join("plugins"));
        assert_eq!(scanned.len(), 1, "{scanned:?}");
        assert_eq!(scanned[0].id, "@acme/reviewer");
        assert_eq!(scanned[0].kind, PluginKind::Js);

        let project = dir.path().join("proj");
        let found = discover_from_config(
            &[freedas_core::config::PluginSpec::Simple(
                "@acme/reviewer".into(),
            )],
            &data,
            &project,
            &dir.path().join("config"),
        );
        assert_eq!(found.len(), 1, "{found:?}");
        found[0].initialize().unwrap();
    }

    #[test]
    fn expand_tilde_expands_only_a_leading_home() {
        let home = freedas_core::Paths::resolve(PathBuf::new()).home;
        assert_eq!(
            expand_tilde("~/plugins/x.wasm", Path::new(".")),
            format!("{}/plugins/x.wasm", home.display())
        );
        assert_eq!(
            expand_tilde("~", Path::new(".")),
            home.display().to_string()
        );
        assert_eq!(expand_tilde("@acme/x", Path::new(".")), "@acme/x");
        assert_eq!(expand_tilde("~other/x", Path::new(".")), "~other/x");
    }

    #[test]
    fn versions_order_numerically_and_by_prerelease() {
        use std::cmp::Ordering;

        assert_eq!(version_cmp("1.10.0", "1.9.0"), Ordering::Greater);
        assert_eq!(version_cmp("1.0.0", "1.0.0-rc.1"), Ordering::Greater);
        assert_eq!(version_cmp("1.0.0-alpha", "1.0.0-alpha.1"), Ordering::Less);
        assert_eq!(version_cmp("1.0.0-alpha.1", "1.0.0-beta"), Ordering::Less);
        assert_eq!(version_cmp("1.0.0-1", "1.0.0-alpha"), Ordering::Less);
        assert_eq!(version_cmp("2.0", "2.0.0"), Ordering::Less);
        // Tags that are not semver fall back to a string comparison.
        assert_eq!(version_cmp("v2", "v1"), Ordering::Greater);
    }

    #[test]
    fn newest_version_prefers_semver_order() {
        let dir = tempfile::tempdir().unwrap();
        for version in ["1.2.0", "1.10.0", "1.9.0"] {
            std::fs::create_dir(dir.path().join(format!("pkg@{version}"))).unwrap();
        }
        let newest = newest_version(dir.path(), "pkg").unwrap();
        assert_eq!(newest.file_name().unwrap().to_string_lossy(), "pkg@1.10.0");
    }

    #[test]
    fn installed_packages_includes_scoped_directories() {
        let dir = tempfile::tempdir().unwrap();
        let plugins = dir.path().join("plugins");
        let plain = plugins.join("plain@1.0.0");
        let scoped = plugins.join("@acme").join("reviewer@1.2.0");
        for package in [&plain, &scoped] {
            std::fs::create_dir_all(package).unwrap();
            std::fs::write(package.join("freedas-install.json"), "{}").unwrap();
        }
        std::fs::create_dir_all(plugins.join(".unpack-1")).unwrap();

        assert_eq!(installed_packages(dir.path()), vec![scoped, plain]);
    }

    #[test]
    fn staging_dir_names_the_package_and_is_unique() {
        let root = Path::new("/tmp/plugins");
        let first = staging_dir(root, "@acme/reviewer");
        let second = staging_dir(root, "@acme/reviewer");
        assert_ne!(first, second);
        for dir in [&first, &second] {
            let name = dir.file_name().unwrap().to_string_lossy();
            assert!(name.starts_with(".unpack-_acme_reviewer-"), "{name}");
            assert!(!name.contains('/'), "{name}");
        }
    }

    #[test]
    fn installed_version_reads_the_install_record() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("plugins").join("pkg@2.0.0");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(
            package.join("freedas-install.json"),
            serde_json::json!({"name": "pkg", "version": "2.0.0"}).to_string(),
        )
        .unwrap();
        assert_eq!(
            installed_version("pkg", dir.path()).as_deref(),
            Some("2.0.0")
        );
        // A registry answer older than the installed build is a downgrade.
        assert!(version_cmp("1.9.0", "2.0.0").is_lt());
    }

    #[test]
    fn manifest_entry_cannot_escape_the_plugin_directory() {
        let dir = tempfile::tempdir().unwrap();
        let plugin_dir = dir.path().join("evil");
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(dir.path().join("outside.js"), JS_INIT).unwrap();
        std::fs::write(
            plugin_dir.join(MANIFEST_FILE),
            serde_json::json!({"id": "evil", "kind": "js", "entry": "../outside.js"}).to_string(),
        )
        .unwrap();

        let plugin = Plugin {
            id: "evil".into(),
            kind: PluginKind::Js,
            path: plugin_dir,
        };
        let error = plugin.initialize("{}").unwrap_err();
        assert!(error.contains("escapes"), "{error}");
    }

    #[test]
    fn manifest_entry_inside_the_plugin_directory_loads() {
        let dir = tempfile::tempdir().unwrap();
        let plugin_dir = dir.path().join("good");
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(plugin_dir.join("index.js"), JS_INIT).unwrap();
        std::fs::write(
            plugin_dir.join(MANIFEST_FILE),
            serde_json::json!({"id": "acme.reviewer", "kind": "js", "entry": "index.js"})
                .to_string(),
        )
        .unwrap();

        assert_eq!(plugin_in_dir(&plugin_dir).unwrap().id, "acme.reviewer");
        let plugin = Plugin {
            id: "acme.reviewer".into(),
            kind: PluginKind::Js,
            path: plugin_dir,
        };
        assert!(plugin.initialize("{}").unwrap().contains("\"ok\":true"));
    }

    #[test]
    fn json_files_are_not_process_plugins() {
        assert_eq!(PluginKind::from_extension("json"), None);
        assert_eq!(PluginKind::from_extension("package.json"), None);

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();
        assert!(plugin_in_dir(dir.path()).is_none());
        assert!(scan_plugins(dir.path()).is_empty());
    }

    #[test]
    fn host_hook_disables_a_plugin_after_three_failures() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boom.js");
        std::fs::write(
            &path,
            "globalThis.freedasHook = () => { throw new Error('boom'); };",
        )
        .unwrap();
        let plugin = Plugin {
            id: "failing-hook-plugin".into(),
            kind: PluginKind::Js,
            path,
        };
        for _ in 0..MAX_HOOK_FAILURES {
            assert!(plugin.try_hook("prompt", "{}").is_err());
        }
        let error = plugin.try_hook("prompt", "{}").unwrap_err();
        assert!(error.contains("disabled"), "{error}");
        assert!(plugin.hook("prompt", "{}").unwrap().is_none());
    }

    #[test]
    fn js_hook_is_interrupted_after_the_time_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spin.js");
        std::fs::write(&path, "globalThis.freedasHook = () => { for (;;) {} };").unwrap();
        let plugin = Plugin {
            id: "spinning-js-plugin".into(),
            kind: PluginKind::Js,
            path,
        };
        let started = std::time::Instant::now();
        assert!(plugin.try_hook("prompt", "{}").is_err());
        assert!(started.elapsed() < JS_TIME_LIMIT + Duration::from_secs(2));
    }

    #[test]
    fn wasm_hook_traps_on_exhausted_fuel() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spin.wasm");
        std::fs::write(
            &path,
            r#"(module
  (memory (export "memory") 1)
  (func (export "hook") (param i32 i32) (result i64)
    (loop $spin (br $spin))
    (i64.const 0)))"#,
        )
        .unwrap();
        let plugin = Plugin {
            id: "spinning-wasm-plugin".into(),
            kind: PluginKind::Wasm,
            path,
        };
        let error = plugin.try_hook("prompt", "{}").unwrap_err();
        assert!(error.contains("fuel"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn process_plugins_require_trust() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sidecar");
        std::fs::write(
            &path,
            "#!/bin/sh\necho '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"{}\"}'\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let plugin = Plugin {
            id: "untrusted-sidecar".into(),
            kind: PluginKind::Process,
            path,
        };
        let error = plugin.initialize("{}").unwrap_err();
        assert!(error.contains("not trusted"), "{error}");
    }
}

#[cfg(test)]
mod hook_tests {
    use super::*;

    #[test]
    fn js_hook_rewrites_the_prompt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.js");
        std::fs::write(
            &path,
            r#"globalThis.freedasHook = (event, payload) => {
  if (event !== "prompt") return null;
  return JSON.stringify({ text: JSON.parse(payload).text.toUpperCase() });
};"#,
        )
        .unwrap();
        let plugin = Plugin {
            id: "p".into(),
            kind: PluginKind::Js,
            path,
        };
        let out = plugin.hook("prompt", r#"{"text":"hi"}"#).unwrap().unwrap();
        assert_eq!(out, r#"{"text":"HI"}"#);
        assert!(plugin.hook("tool.after", "{}").unwrap().is_none());
    }

    #[test]
    fn js_hook_accepts_any_event_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.js");
        std::fs::write(
            &path,
            "globalThis.freedasHook = (event) => JSON.stringify({ event });",
        )
        .unwrap();
        let plugin = Plugin {
            id: "p".into(),
            kind: PluginKind::Js,
            path,
        };
        assert_eq!(
            plugin.hook("gate.result", "{}").unwrap().unwrap(),
            r#"{"event":"gate.result"}"#
        );
        assert_eq!(
            plugin.hook("permission.ask", "{}").unwrap().unwrap(),
            r#"{"event":"permission.ask"}"#
        );
    }

    #[test]
    fn required_hook_failures_are_errors_not_silent_skips() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("boom.js"),
            "globalThis.freedasHook = () => { throw new Error('boom'); };",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("freedas-plugin.json"),
            serde_json::json!({"id": "req", "kind": "js", "entry": "boom.js", "required": true})
                .to_string(),
        )
        .unwrap();
        let plugin = Plugin {
            id: "required-hook-fails-closed".into(),
            kind: PluginKind::Js,
            path: dir.path().to_path_buf(),
        };
        let error = plugin.hook("prompt", "{}").unwrap_err();
        assert!(error.contains("failed"), "{error}");
        // A disabled required plugin stays an error instead of degrading to None.
        for _ in 0..MAX_HOOK_FAILURES {
            let _ = plugin.try_hook("prompt", "{}");
        }
        let error = plugin.hook("prompt", "{}").unwrap_err();
        assert!(error.contains("disabled"), "{error}");
    }
}

/// Install a plugin: an npm package, or a local `.ts`/`.js`/`.wasm` file or
/// directory. Returns the value to add to the `plugin` config array.
pub async fn install(spec: &str, data_dir: &Path) -> Result<serde_json::Value, String> {
    let looks_like_path = spec.starts_with('.')
        || spec.starts_with('/')
        || spec.starts_with('~')
        || spec.ends_with(".ts")
        || spec.ends_with(".js")
        || spec.ends_with(".wasm");
    if looks_like_path {
        let cwd = std::env::current_dir().unwrap_or_default();
        if !Path::new(&expand_tilde(spec, &cwd)).exists() {
            return Err(format!("{spec} does not exist"));
        }
        return Ok(serde_json::json!(spec));
    }
    install_npm(spec, data_dir).await
}

/// Registry override from `FREEDAS_NPM_REGISTRY`, trimmed of trailing slashes.
fn npm_registry() -> Option<String> {
    std::env::var("FREEDAS_NPM_REGISTRY")
        .ok()
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
}

async fn install_npm(name: &str, data_dir: &Path) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;
    let registry = npm_registry();
    let base = registry.as_deref().unwrap_or("https://registry.npmjs.org");
    let meta_url = format!("{base}/{name}/latest");
    let meta: Value = client
        .get(&meta_url)
        .send()
        .await
        .map_err(|e| format!("registry: {e}"))?
        .json()
        .await
        .map_err(|e| format!("registry response: {e}"))?;
    let version = meta["version"]
        .as_str()
        .ok_or("no version in registry response")?;
    let tarball = meta["dist"]["tarball"]
        .as_str()
        .ok_or("no tarball in registry response")?;
    let integrity = meta["dist"]["integrity"]
        .as_str()
        .filter(|integrity| !integrity.is_empty())
        .ok_or("registry response has no integrity; refusing an unverified plugin")?;
    // Both values become path components under `<data>/plugins/`.
    if !safe_path_part(name) || !safe_path_part(version) || version.contains(['/', '@']) {
        return Err(format!(
            "registry returned an unsafe name/version: {name}@{version}"
        ));
    }
    // A registry that answers `latest` with an older build than the installed
    // one never silently downgrades: refuse unless explicitly allowed.
    if let Some(installed) = installed_version(name, data_dir)
        && version_cmp(version, &installed).is_lt()
        && !downgrade_allowed()
    {
        return Err(format!(
            "refusing to downgrade {name} from {installed} to {version}; set FREEDAS_PLUGIN_ALLOW_DOWNGRADE=1 to allow it"
        ));
    }
    let url = if tarball.starts_with("http://") || tarball.starts_with("https://") {
        tarball.to_string()
    } else {
        format!("{base}/{}", tarball.trim_start_matches('/'))
    };
    // Without an explicit mirror, only https from the npm registry itself is allowed, so
    // registry metadata cannot redirect the download to an arbitrary host.
    if registry.is_none() {
        let parsed = reqwest::Url::parse(&url).map_err(|e| format!("tarball url: {e}"))?;
        if parsed.scheme() != "https" || parsed.host_str() != Some("registry.npmjs.org") {
            return Err(format!(
                "registry returned tarball {url}; set FREEDAS_NPM_REGISTRY for a local mirror"
            ));
        }
    }
    let bytes = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("download: {e}"))?
        .bytes()
        .await
        .map_err(|e| format!("download: {e}"))?;
    let expected = integrity
        .split_whitespace()
        .find_map(|token| token.strip_prefix("sha512-"))
        .ok_or("registry integrity is not sha512")?;
    use sha2::Digest;
    let digest = sha2::Sha512::digest(&bytes);
    let b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        digest.as_slice(),
    );
    if b64 != expected {
        return Err("integrity check failed".into());
    }

    let plugins_root = data_dir.join("plugins");
    std::fs::create_dir_all(&plugins_root).map_err(|e| e.to_string())?;
    let dir = plugins_root.join(format!("{name}@{version}"));
    // Unpack into a staging directory so a rejected archive never lands in the install
    // location, then move the tarball's `package/` tree into place.
    let staging = staging_dir(&plugins_root, name);
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| e.to_string())?;
    let package = match unpack_package(&bytes, &staging) {
        Ok(package) => package,
        Err(error) => {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(error);
        }
    };
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|e| e.to_string())?;
    }
    std::fs::rename(&package, &dir).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::write(
        dir.join("freedas-install.json"),
        serde_json::json!({"name": name, "version": version, "integrity": integrity}).to_string(),
    )
    .map_err(|e| e.to_string())?;
    Ok(serde_json::json!(dir.to_string_lossy()))
}

/// Unpack staging directory for one install: the package name keeps concurrent
/// installs of different packages apart, and the pid/time/counter suffix keeps
/// the name unpredictable so a pre-created path cannot divert the unpack.
/// The leading dot keeps scanners on `installed_packages` ignoring it.
static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

fn staging_dir(plugins_root: &Path, name: &str) -> PathBuf {
    let safe: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let unique = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    plugins_root.join(format!(
        ".unpack-{safe}-{}-{nanos:x}-{unique:x}",
        std::process::id()
    ))
}

/// Newest installed version recorded for `name`, if any.
fn installed_version(name: &str, data_dir: &Path) -> Option<String> {
    let dir = installed_package_dir(name, data_dir)?;
    if let Ok(text) = fs::read_to_string(dir.join("freedas-install.json"))
        && let Ok(record) = serde_json::from_str::<Value>(&text)
        && let Some(version) = record["version"].as_str()
    {
        return Some(version.to_owned());
    }
    dir.file_name()?
        .to_str()?
        .rsplit('@')
        .next()
        .map(str::to_owned)
}

/// Explicit opt-in to install an older build over a newer one.
fn downgrade_allowed() -> bool {
    matches!(
        std::env::var("FREEDAS_PLUGIN_ALLOW_DOWNGRADE")
            .ok()
            .as_deref(),
        Some("1" | "true" | "yes")
    )
}

/// Registry-supplied name and version become path components: no separators, no `..`.
fn safe_path_part(value: &str) -> bool {
    !value.is_empty()
        && !value.contains("..")
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+' | '@' | '/'))
}

/// Unpack an npm tarball into `staging` and return its `package/` directory.
///
/// Link and special entries are rejected, every entry must stay under `package/` with
/// normal path components only, and `unpack_in` enforces containment a second time.
fn unpack_package(tarball: &[u8], staging: &Path) -> Result<PathBuf, String> {
    let mut archive =
        tar::Archive::new(flate2::read::GzDecoder::new(std::io::Cursor::new(tarball)));
    for entry in archive.entries().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir()) {
            return Err(format!(
                "tarball entry {} is a link or special file",
                entry
                    .path()
                    .map(|path| path.display().to_string())
                    .unwrap_or_default()
            ));
        }
        let path = entry
            .path()
            .map_err(|e| format!("tarball entry path: {e}"))?
            .into_owned();
        if !path.starts_with("package")
            || path
                .components()
                .any(|part| !matches!(part, PathComponent::Normal(_)))
        {
            return Err(format!(
                "tarball entry escapes the package: {}",
                path.display()
            ));
        }
        entry
            .unpack_in(staging)
            .map_err(|e| format!("unpack {}: {e}", path.display()))?;
    }
    let package = staging.join("package");
    if !package.is_dir() {
        return Err("tarball has no package/ directory".into());
    }
    Ok(package)
}

/// Installed package directories recorded by [`install`], scoped packages included.
fn installed_packages(data_dir: &Path) -> Vec<PathBuf> {
    let root = data_dir.join("plugins");
    let Ok(entries) = std::fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut packages = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if !path.is_dir() || name.starts_with('.') {
            continue;
        }
        // Scoped packages live one level deeper: `<root>/@scope/<name>@<version>`.
        if name.starts_with('@') {
            if let Ok(scoped) = std::fs::read_dir(&path) {
                packages.extend(
                    scoped
                        .flatten()
                        .map(|entry| entry.path())
                        .filter(|path| path.is_dir()),
                );
            }
        } else {
            packages.push(path);
        }
    }
    packages.sort();
    packages
}

/// Re-install npm plugins recorded by [`install`].
pub async fn update(data_dir: &Path) -> Result<Vec<String>, String> {
    let mut updated = Vec::new();
    for dir in installed_packages(data_dir) {
        let manifest = dir.join("freedas-install.json");
        let Ok(text) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let Some(name) = v["name"].as_str() else {
            continue;
        };
        install_npm(name, data_dir).await?;
        updated.push(name.to_string());
    }
    Ok(updated)
}

#[cfg(test)]
mod npm_tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn package_tgz() -> Vec<u8> {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        {
            let mut tar = tar::Builder::new(&mut gz);
            for (name, data) in [
                (
                    "package/freedas-plugin.json",
                    &br#"{"id":"acme.test","kind":"wasm","entry":"index.wasm"}"#[..],
                ),
                ("package/index.wasm", &b"\0asm"[..]),
            ] {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                tar.append_data(&mut header, name, data).unwrap();
            }
            tar.finish().unwrap();
        }
        gz.finish().unwrap()
    }

    /// `dist.integrity` for a tarball, in the registry's `sha512-<base64>` form.
    fn integrity(tarball: &[u8]) -> String {
        use sha2::Digest;
        let digest = sha2::Sha512::digest(tarball);
        format!(
            "sha512-{}",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                digest.as_slice()
            )
        )
    }

    fn tarball_with(name: &str, data: &[u8], kind: tar::EntryType, link: Option<&str>) -> Vec<u8> {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        {
            let mut tar = tar::Builder::new(&mut gz);
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(kind);
            if let Some(link) = link {
                header.set_link_name(link).unwrap();
            }
            // `Header::set_path` refuses `..` and absolute paths, so write the raw name:
            // the point of the test is that the reader rejects them.
            assert!(name.len() <= 100);
            header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
            header.set_cksum();
            tar.append(&header, data).unwrap();
            tar.finish().unwrap();
        }
        gz.finish().unwrap()
    }

    #[test]
    fn unpack_rejects_entries_outside_the_package() {
        for entry in ["../x.wasm", "/etc/x.wasm", "package/../../x.wasm"] {
            let tarball = tarball_with(entry, b"\0asm", tar::EntryType::Regular, None);
            let dir = tempfile::tempdir().unwrap();
            let staging = dir.path().join("staging");
            std::fs::create_dir_all(&staging).unwrap();

            let error = unpack_package(&tarball, &staging).unwrap_err();
            assert!(error.contains("escapes"), "{entry}: {error}");
            assert!(!dir.path().join("x.wasm").exists(), "{entry}");
            assert!(!dir.path().join("etc").exists(), "{entry}");
        }
    }

    #[test]
    fn unpack_rejects_link_entries() {
        let tarball = tarball_with(
            "package/x.wasm",
            b"",
            tar::EntryType::Symlink,
            Some("/etc/passwd"),
        );
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("staging");
        std::fs::create_dir_all(&staging).unwrap();

        let error = unpack_package(&tarball, &staging).unwrap_err();
        assert!(error.contains("link"), "{error}");
        assert!(!staging.join("package").join("x.wasm").exists());
    }

    #[test]
    fn unpack_accepts_a_package_root() {
        let tarball = tarball_with(
            "package/index.wasm",
            b"\0asm",
            tar::EntryType::Regular,
            None,
        );
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("staging");
        std::fs::create_dir_all(&staging).unwrap();

        let package = unpack_package(&tarball, &staging).unwrap();
        assert!(package.join("index.wasm").is_file());
    }

    #[tokio::test]
    async fn npm_install_honours_registry_override() {
        let tgz = package_tgz();
        let sum = integrity(&tgz);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/acme-plugin/latest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "acme-plugin",
                "version": "1.0.0",
                "dist": {
                    "tarball": format!("{}/acme-plugin/-/acme-plugin-1.0.0.tgz", server.uri()),
                    "integrity": sum.clone(),
                },
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/acme-plugin/-/acme-plugin-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tgz.clone()))
            .mount(&server)
            .await;
        // A relative tarball resolves against the configured registry base.
        Mock::given(method("GET"))
            .and(path("/acme-rel/latest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "acme-rel",
                "version": "1.0.0",
                "dist": { "tarball": "acme-rel/-/acme-rel-1.0.0.tgz", "integrity": sum },
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/acme-rel/-/acme-rel-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tgz))
            .mount(&server)
            .await;

        let data = tempfile::tempdir().unwrap();
        // SAFETY: this is the only test that touches the variable.
        unsafe { std::env::set_var("FREEDAS_NPM_REGISTRY", server.uri()) };

        let dir = data.path().join("plugins").join("acme-plugin@1.0.0");
        let installed = install("acme-plugin", data.path()).await.unwrap();
        assert_eq!(installed, serde_json::json!(dir.to_string_lossy()));
        assert!(dir.join("freedas-plugin.json").is_file());
        assert!(dir.join("index.wasm").is_file());

        // Second install is idempotent: same path, no duplicate version directory.
        assert_eq!(
            install("acme-plugin", data.path()).await.unwrap(),
            installed
        );
        assert_eq!(
            std::fs::read_dir(data.path().join("plugins"))
                .unwrap()
                .count(),
            1
        );

        let rel = data.path().join("plugins").join("acme-rel@1.0.0");
        assert_eq!(
            install("acme-rel", data.path()).await.unwrap(),
            serde_json::json!(rel.to_string_lossy())
        );
        assert!(rel.join("freedas-plugin.json").is_file());

        unsafe { std::env::remove_var("FREEDAS_NPM_REGISTRY") };
    }
}
