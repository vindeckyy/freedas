//! Built-in file/shell tools.

mod patch;

use async_trait::async_trait;
use freedas_core::config::Config;
use freedas_core::{FreedasError, Result};
use freedas_permission::{Effect, combine, scan_shell};
pub use patch::{ApplyPatchTool, PatchTool};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Content hashes from successful reads, shared across tool calls and steps so
/// `write`/`edit` can reject a file that changed on disk after it was read.
/// An empty map means "never read"; the first write is allowed.
pub type ReadHashes = Arc<Mutex<HashMap<PathBuf, String>>>;

/// How the caller answered a permission prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionReply {
    Once,
    Always,
    Reject,
}

/// Interactive approver: the UI layer supplies one; headless runs leave it
/// `None` and `ask` resolves to a blocked/rejected path instead of a prompt.
/// `remember` persists an "always" answer (global config, session rules).
pub trait PermissionApprover: Send + Sync + std::fmt::Debug {
    fn ask(&self, action: &str, resource: &str) -> PermissionReply;
    /// Like `ask`, but carries an optional preview of the proposed change so
    /// the UI can show it before the answer. Defaults to ignoring the preview.
    fn ask_preview(&self, action: &str, resource: &str, _preview: Option<&str>) -> PermissionReply {
        self.ask(action, resource)
    }
    fn remember(&self, _action: &str, _resource: &str) {}
}

#[derive(Debug, Clone)]
pub struct ToolContext {
    pub session_id: String,
    pub project_root: PathBuf,
    pub cwd: PathBuf,
    pub config: Config,
    pub agent_rules: Vec<freedas_core::config::PermissionRule>,
    /// Rules remembered with "allow always" during this run; appended after
    /// agent rules so they win for the rest of the session.
    pub session_rules: std::sync::Arc<std::sync::Mutex<Vec<freedas_core::config::PermissionRule>>>,
    pub auto: bool,
    pub manual: bool,
    pub read_hashes: ReadHashes,
    pub sandbox: bool,
    /// Skip all permission checks for one re-executed call after a "once"
    /// grant.
    pub bypass: bool,
    /// Plan agents may write under this directory.
    pub plans_dir: Option<PathBuf>,
    /// Interactive approver; `None` means no human is answering (headless).
    pub approver: Option<std::sync::Arc<dyn PermissionApprover>>,
    /// Memory store, when the caller has one.
    pub db: Option<std::sync::Arc<freedas_db::Db>>,
    /// Project scope for memory writes and recall.
    pub project_id: Option<String>,
    /// Speculative read cache filled while the model streams; `read` serves a
    /// hit only when the file's mtime and length still match.
    pub prefetch: Option<std::sync::Arc<ReadPrefetch>>,
}

#[derive(Debug, Clone)]
pub struct ToolOutput {
    pub content: String,
    pub metadata: Value,
    pub truncated: bool,
}

#[async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn schema(&self) -> Value;
    fn permission_action(&self) -> &str;
    fn parallel_safe(&self) -> bool {
        false
    }
    async fn execute(&self, input: &Value, ctx: &ToolContext) -> Result<ToolOutput>;
}

/// Single-hunk unified diff `old` → `new` for TUI display, capped at `max_lines`
/// output lines. Empty when the contents are equal. Display only: it omits
/// `\ No newline at end of file` markers and lumps distant changes into one
/// hunk, so it must never be fed to `patch`.
pub fn unified_diff(path: &str, old: &str, new: &str, max_lines: usize) -> String {
    if old == new {
        return String::new();
    }
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let mut pre = 0;
    while pre < a.len() && pre < b.len() && a[pre] == b[pre] {
        pre += 1;
    }
    let mut suf = 0;
    while suf < a.len() - pre && suf < b.len() - pre && a[a.len() - 1 - suf] == b[b.len() - 1 - suf]
    {
        suf += 1;
    }
    let ctx = 3;
    let start = pre.saturating_sub(ctx);
    let tail = ctx.min(suf);
    let a_end = a.len() - suf;
    let b_end = b.len() - suf;
    let old_start = if a.is_empty() { 0 } else { start + 1 };
    let old_len = (a_end - start) + tail;
    let new_start = if b.is_empty() { 0 } else { start + 1 };
    let new_len = (b_end - start) + tail;
    let mut out = vec![
        format!("--- a/{path}"),
        format!("+++ b/{path}"),
        format!("@@ -{old_start},{old_len} +{new_start},{new_len} @@"),
    ];
    for l in &a[start..pre] {
        out.push(format!(" {l}"));
    }
    for l in &a[pre..a_end] {
        out.push(format!("-{l}"));
    }
    for l in &b[pre..b_end] {
        out.push(format!("+{l}"));
    }
    for l in &a[a_end..a_end + tail] {
        out.push(format!(" {l}"));
    }
    cap_lines(&out.join("\n"), max_lines)
}

/// First `max` lines of `text`, with a marker line when anything was dropped.
pub(crate) fn cap_lines(text: &str, max: usize) -> String {
    let mut lines = text.lines();
    let head: Vec<&str> = lines.by_ref().take(max).collect();
    let extra = lines.count();
    let mut out = head.join("\n");
    if extra > 0 {
        out.push_str(&format!("\n... ({extra} more lines)"));
    }
    out
}

/// Attach `diff` to tool metadata, skipping empty diffs.
fn with_diff(mut metadata: Value, diff: String) -> Value {
    if !diff.is_empty() {
        metadata["diff"] = Value::String(diff);
    }
    metadata
}

/// Cap a preview at 20 lines and 2000 chars for the approval dialog.
pub(crate) fn preview_cap(text: &str) -> String {
    let mut out = text.lines().take(20).collect::<Vec<_>>().join("\n");
    if out.len() > 2000 {
        let mut cut = 2000;
        while cut > 0 && !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
    }
    out
}

/// Prefix every line of `text`, used to mark added (`+`) and removed (`-`)
/// lines in an edit preview.
fn prefixed(text: &str, prefix: char) -> String {
    text.lines()
        .map(|l| format!("{prefix}{l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn truncate_text(text: &str, max_bytes: usize) -> (String, bool) {
    if text.len() <= max_bytes {
        (text.to_string(), false)
    } else {
        let mut cut = max_bytes;
        while cut > 0 && !text.is_char_boundary(cut) {
            cut -= 1;
        }
        (format!("{}\n[truncated]", &text[..cut]), true)
    }
}

pub fn hash_bytes(b: &[u8]) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    b.hash(&mut h);
    format!("{:x}", h.finish())
}

/// True when `abs` was read before and its bytes changed since.
fn is_stale(ctx: &ToolContext, abs: &Path, hash: &str) -> bool {
    ctx.read_hashes
        .lock()
        .ok()
        .and_then(|m| m.get(abs).cloned())
        .is_some_and(|prev| prev != hash)
}

fn record_hash(ctx: &ToolContext, abs: &Path, hash: String) {
    if let Ok(mut map) = ctx.read_hashes.lock() {
        map.insert(abs.to_path_buf(), hash);
    }
}

/// Temp-file + rename with the original mode copied over, fsynced file and
/// parent, and the temp removed when anything fails. `root` is the canonical
/// project root used for the post-rename containment re-check.
async fn atomic_write(abs: &Path, bytes: &[u8], root: &Path) -> Result<()> {
    let parent = abs
        .parent()
        .ok_or_else(|| FreedasError::Tool("path has no parent directory".into()))?;
    tokio::fs::create_dir_all(parent).await?;
    let name = abs.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = parent.join(format!(".{name}.freedas-tmp-{}", ulid::Ulid::new()));
    let result = async {
        tokio::fs::write(&tmp, bytes).await?;
        if let Ok(meta) = tokio::fs::metadata(abs).await {
            tokio::fs::set_permissions(&tmp, meta.permissions()).await?;
        }
        let file = tokio::fs::OpenOptions::new().write(true).open(&tmp).await?;
        file.sync_all().await?;
        tokio::fs::rename(&tmp, abs).await?;
        // TOCTOU: a symlink swap between resolve and rename could redirect the
        // write outside the project; re-canonicalize the landed path and
        // re-verify containment before reporting success.
        let canon = canonicalize_lenient(abs);
        if !canon.starts_with(root) {
            return Err(FreedasError::PermissionDenied {
                action: "edit".into(),
                resource: abs.to_string_lossy().to_string(),
            });
        }
        if let Ok(dir) = tokio::fs::File::open(parent).await {
            let _ = dir.sync_all().await;
        }
        Ok::<(), FreedasError>(())
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&tmp).await;
    }
    result
}

/// All byte offsets of `needle` in `hay`.
fn find_occurrences(hay: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    if needle.is_empty() || needle.len() > hay.len() {
        return out;
    }
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        if &hay[i..i + needle.len()] == needle {
            out.push(i);
            i += needle.len();
        } else {
            i += 1;
        }
    }
    out
}

/// Replace `old` with `new` in raw bytes; `all` or the first occurrence only.
fn replace_bytes(hay: &[u8], old: &[u8], new: &[u8], all: bool) -> Vec<u8> {
    let hits = find_occurrences(hay, old);
    let hits = if all {
        hits
    } else {
        hits.into_iter().take(1).collect()
    };
    let mut out = Vec::with_capacity(hay.len());
    let mut last = 0;
    for at in hits {
        out.extend_from_slice(&hay[last..at]);
        out.extend_from_slice(new);
        last = at + old.len();
    }
    out.extend_from_slice(&hay[last..]);
    out
}

pub fn resolve_path(ctx: &ToolContext, input: &str) -> Result<PathBuf> {
    resolve_path_as(ctx, input, "read")
}

/// Resolve `input` and enforce containment for `action`. `action` decides
/// whether the plans-dir `bypass` applies: only file tools (`read`, `write`,
/// `edit`) may use it, never `bash`.
pub(crate) fn resolve_path_as(ctx: &ToolContext, input: &str, action: &str) -> Result<PathBuf> {
    let canon = resolve_abs(&ctx.cwd, input)?;
    // `.git` is denied for every tool action: writes would forge hooks (RCE
    // on next commit) and reads leak remotes/credentials/object contents.
    if has_git_component(&canon) {
        return Err(FreedasError::PermissionDenied {
            action: action.into(),
            resource: input.into(),
        });
    }
    let root = canonical_root(ctx);
    if !canon.starts_with(&root) {
        if bypassed(ctx, action) {
            return Ok(canon);
        }
        let resource = canon.to_string_lossy().to_string();
        let effect = combine(
            &[("external_directory".into(), resource.clone())],
            &ctx.config,
            &rules_for(ctx),
        );
        finish(
            ctx,
            effect,
            ("external_directory".into(), resource),
            None,
            false,
            false,
        )?;
    }
    Ok(canon)
}

/// Join `input` onto `cwd`, normalize `.`/`..` lexically, then canonicalize the
/// nearest existing ancestor and re-append the missing tail. This makes a
/// non-existent `../x` land where it will actually be created instead of
/// falling back to the raw path and passing `starts_with(project_root)`.
fn resolve_abs(cwd: &Path, input: &str) -> Result<PathBuf> {
    let p = Path::new(input);
    let joined = if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    };
    let Some(normalized) = normalize_lexical(&joined) else {
        return Err(FreedasError::PermissionDenied {
            action: "external_directory".into(),
            resource: input.into(),
        });
    };
    let canon = canonicalize_lenient(&normalized);
    if canon.components().any(|c| c == Component::ParentDir) {
        return Err(FreedasError::PermissionDenied {
            action: "external_directory".into(),
            resource: input.into(),
        });
    }
    Ok(canon)
}

fn canonical_root(ctx: &ToolContext) -> PathBuf {
    ctx.project_root
        .canonicalize()
        .unwrap_or_else(|_| ctx.project_root.clone())
}

fn normalize_lexical(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            other => out.push(other),
        }
    }
    Some(out)
}

fn canonicalize_lenient(abs: &Path) -> PathBuf {
    let mut existing = abs.to_path_buf();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(mut canon) = existing.canonicalize() {
            for part in tail.iter().rev() {
                canon.push(part);
            }
            return canon;
        }
        match (existing.parent(), existing.file_name()) {
            (Some(parent), Some(name)) => {
                tail.push(name.to_os_string());
                existing = parent.to_path_buf();
            }
            _ => return abs.to_path_buf(),
        }
    }
}
/// Re-verify an absolute path still lands inside the project after it was
/// created or modified (symlink-swap detection for write and patch paths).
/// `display` is the user-supplied spelling reported on failure — never the
/// canonical absolute path, which leaks the host layout to the model.
pub(crate) fn reverify_abs(ctx: &ToolContext, abs: &Path, display: &str) -> Result<()> {
    let root = canonical_root(ctx);
    let canon = canonicalize_lenient(abs);
    if !canon.starts_with(&root) {
        return Err(FreedasError::PermissionDenied {
            action: "edit".into(),
            resource: display.to_string(),
        });
    }
    Ok(())
}

/// Re-resolve raw diff/patch targets against the post-apply filesystem and
/// verify each still lands inside the project root.
pub(crate) fn verify_targets_contained(ctx: &ToolContext, targets: &[String]) -> Result<()> {
    let root = canonical_root(ctx);
    for t in targets {
        let abs = resolve_abs(&ctx.project_root, t)?;
        let canon = canonicalize_lenient(&abs);
        if !canon.starts_with(&root) {
            return Err(FreedasError::PermissionDenied {
                action: "edit".into(),
                resource: t.clone(),
            });
        }
    }
    Ok(())
}

/// `allow always` must not persist a `*`-style pattern as a global allow:
/// glob/grep patterns, skill IDs, task agents, and question text are matched
/// as globs, so a remembered pattern would over-grant later calls. Only
/// narrow literals persist; patterns degrade to allow-once.
fn persistable_remember(action: &str, resource: &str) -> bool {
    if matches!(action, "read" | "skill" | "task" | "question") && has_glob(resource) {
        return false;
    }
    true
}

fn has_git_component(path: &Path) -> bool {
    path.components()
        .any(|c| c.as_os_str() == std::ffi::OsStr::new(".git"))
}

/// `bypass` is set by the plan-agent plans-dir exception. Only file tools may
/// use it; `bash` (and anything else) still runs the full permission check.
fn bypassed(ctx: &ToolContext, action: &str) -> bool {
    ctx.bypass && matches!(action, "read" | "edit" | "write")
}

/// All rules that apply to this context: config, then agent rules, then rules
/// remembered during the session ("allow always").
fn rules_for(ctx: &ToolContext) -> Vec<freedas_core::config::PermissionRule> {
    let mut rules = ctx.agent_rules.clone();
    if let Ok(session) = ctx.session_rules.lock() {
        rules.extend(session.iter().cloned());
    }
    rules
}

/// Apply manual/sandbox/auto shaping and the interactive approver to a
/// resolved effect. `ask_for` describes the prompt to show (action, resource);
/// `preview` is the proposed change, when there is one. `dynamic` marks a call
/// the shell scanner could not fully resolve, which must ask rather than be
/// absorbed by a sandbox's write containment.
fn finish(
    ctx: &ToolContext,
    effect: Effect,
    ask_for: (String, String),
    preview: Option<&str>,
    dynamic: bool,
    nonbash_ask: bool,
) -> Result<()> {
    // The OS sandbox only bounds subprocess actions (bash and anything it
    // spawns), and only when it also denies the network; an `ask` for a fully
    // contained command is redundant. Unresolved (dynamic) commands keep their
    // ask because the sandbox cannot vouch for what they will touch. The
    // upgrade applies only when a backend exists; otherwise the later
    // `wrap_command` fallback runs unsandboxed and the prompt must stand.
    // `nonbash_ask` marks Asks raised by read/edit/external_directory
    // sub-resources — the sandbox cannot vouch for what a command reads, so
    // those asks survive the upgrade.
    let contained = ctx.sandbox
        && ctx.config.sandbox.network == "deny"
        && !dynamic
        && !nonbash_ask
        && freedas_sandbox::available();
    let effect = if contained && ask_for.0 == "bash" && effect == Effect::Ask {
        Effect::Allow
    } else {
        effect
    };
    let effect = if ctx.manual && effect == Effect::Allow {
        Effect::Ask
    } else {
        effect
    };
    match effect {
        Effect::Allow => Ok(()),
        Effect::Deny => Err(FreedasError::PermissionDenied {
            action: ask_for.0,
            resource: ask_for.1,
        }),
        Effect::Ask => {
            if ctx.auto {
                return Ok(());
            }
            if let Some(approver) = &ctx.approver {
                return match approver.ask_preview(&ask_for.0, &ask_for.1, preview) {
                    PermissionReply::Once => Ok(()),
                    PermissionReply::Always => {
                        // Broad patterns never become global allows; treat as once.
                        if !persistable_remember(&ask_for.0, &ask_for.1) {
                            return Ok(());
                        }
                        if let Ok(mut session) = ctx.session_rules.lock() {
                            session.push(freedas_core::config::PermissionRule {
                                action: ask_for.0.clone(),
                                resource: ask_for.1.clone(),
                                effect: "allow".into(),
                                source: Some("remembered".into()),
                            });
                        }
                        approver.remember(&ask_for.0, &ask_for.1);
                        Ok(())
                    }
                    PermissionReply::Reject => Err(FreedasError::PermissionDenied {
                        action: ask_for.0,
                        resource: ask_for.1,
                    }),
                };
            }
            Err(FreedasError::PermissionAsked {
                action: ask_for.0,
                resource: ask_for.1,
            })
        }
    }
}

pub fn check_perm(ctx: &ToolContext, action: &str, resource: Option<&str>) -> Result<()> {
    check_perm_with_preview(ctx, action, resource, None)
}

/// Like `check_perm`, but the approval prompt can show a preview of the
/// proposed change.
pub(crate) fn check_perm_with_preview(
    ctx: &ToolContext,
    action: &str,
    resource: Option<&str>,
    preview: Option<&str>,
) -> Result<()> {
    if bypassed(ctx, action) {
        return Ok(());
    }
    let res = resource.unwrap_or("*").to_string();
    let effect = combine(
        &[(action.to_string(), res.clone())],
        &ctx.config,
        &rules_for(ctx),
    );
    finish(
        ctx,
        effect,
        (action.to_string(), res),
        preview,
        false,
        false,
    )
}
/// Check both the user-supplied spelling and the canonical absolute path, so a
/// rule matching either form (`*.env`, an absolute allow, `..` tricks) still
/// applies after `resolve_path` normalization.
pub(crate) fn check_perm_path(
    ctx: &ToolContext,
    action: &str,
    input: &str,
    abs: &std::path::Path,
    preview: Option<&str>,
) -> Result<()> {
    if bypassed(ctx, action) {
        return Ok(());
    }
    let canon = abs.to_string_lossy().to_string();
    if canon == input {
        let effect = combine(
            &[(action.to_string(), input.to_string())],
            &ctx.config,
            &rules_for(ctx),
        );
        return finish(
            ctx,
            effect,
            (action.to_string(), input.to_string()),
            preview,
            false,
            false,
        );
    }
    let effect = combine(
        &[
            (action.to_string(), input.to_string()),
            (action.to_string(), canon),
        ],
        &ctx.config,
        &rules_for(ctx),
    );
    finish(
        ctx,
        effect,
        (action.to_string(), input.to_string()),
        preview,
        false,
        false,
    )
}

/// Like `check_perm`, but `ask` passes: only an explicit `deny` blocks. Used
/// for operations that read the page without interacting with it. `--manual`
/// still turns every allow into a prompt.
pub fn check_perm_readonly(ctx: &ToolContext, action: &str, resource: Option<&str>) -> Result<()> {
    if bypassed(ctx, action) {
        return Ok(());
    }
    let res = resource.unwrap_or("*").to_string();
    let effect = combine(
        &[(action.to_string(), res.clone())],
        &ctx.config,
        &rules_for(ctx),
    );
    let effect = if ctx.manual || effect != Effect::Ask {
        effect
    } else {
        Effect::Allow
    };
    finish(ctx, effect, (action.to_string(), res), None, false, false)
}

/// Cap speculative reads: at most this many files and this many bytes each.
pub const PREFETCH_MAX_FILES: usize = 8;
const PREFETCH_MAX_BYTES: u64 = 1024 * 1024;

/// (mtime, len, bytes) captured at prefetch time.
type Prefetched = (Option<std::time::SystemTime>, u64, std::sync::Arc<Vec<u8>>);

/// Speculative read cache: files fetched in the background while the model
/// streams. A `read` call serves cached bytes only when the on-disk file is
/// unchanged — verified by mtime and length at call time — so a prefetch can
/// never hand the model stale content.

#[derive(Default, Debug)]
pub struct ReadPrefetch {
    inner: std::sync::Mutex<std::collections::HashMap<PathBuf, Prefetched>>,
}

impl ReadPrefetch {
    /// Read `candidates` (canonical absolute paths) in the background. Tasks
    /// die with the run's runtime, so a cancelled run leaves nothing behind.
    pub fn spawn(candidates: Vec<PathBuf>) -> std::sync::Arc<Self> {
        let cache = std::sync::Arc::new(Self::default());
        for path in candidates.into_iter().take(PREFETCH_MAX_FILES) {
            let cache = cache.clone();
            tokio::spawn(async move {
                let Ok(meta) = tokio::fs::metadata(&path).await else {
                    return;
                };
                if !meta.is_file() || meta.len() > PREFETCH_MAX_BYTES {
                    return;
                }
                let Ok(bytes) = tokio::fs::read(&path).await else {
                    return;
                };
                cache.inner.lock().expect("prefetch cache").insert(
                    path,
                    (meta.modified().ok(), meta.len(), std::sync::Arc::new(bytes)),
                );
            });
        }
        cache
    }

    /// Fresh bytes for `abs` when a prefetch captured them and `meta` — just
    /// stat'ed by the caller — shows the file unchanged since.
    pub fn lookup(&self, abs: &Path, meta: &std::fs::Metadata) -> Option<std::sync::Arc<Vec<u8>>> {
        let map = self.inner.lock().expect("prefetch cache");
        let (mtime, len, bytes) = map.get(abs)?;
        (*mtime == meta.modified().ok() && *len == meta.len()).then(|| bytes.clone())
    }
}

pub struct Read;
#[async_trait]
impl Tool for Read {
    fn name(&self) -> &str {
        "read"
    }
    fn description(&self) -> &str {
        "Read a file with line ranges"
    }
    fn schema(&self) -> Value {
        json!({"type":"object","properties":{"path":{"type":"string"},"offset":{"type":"integer"},"limit":{"type":"integer"}},"required":["path"],"additionalProperties":false})
    }
    fn permission_action(&self) -> &str {
        "read"
    }
    fn parallel_safe(&self) -> bool {
        true
    }
    async fn execute(&self, input: &Value, ctx: &ToolContext) -> Result<ToolOutput> {
        use tokio::io::AsyncReadExt;
        const CAP: u64 = 1024 * 1024;
        let path = input["path"]
            .as_str()
            .ok_or_else(|| FreedasError::Tool("path required".into()))?;
        let abs = resolve_path(ctx, path)?;
        check_perm_path(ctx, "read", path, &abs, None)?;
        let meta = tokio::fs::metadata(&abs).await?;
        if !meta.is_file() {
            return Err(FreedasError::Tool(format!("not a regular file: {path}")));
        }
        // Speculative hit: bytes prefetched while the model streamed, served
        // only when `meta` proves the file is unchanged since the prefetch.
        let mut bytes = match ctx.prefetch.as_ref().and_then(|p| p.lookup(&abs, &meta)) {
            Some(bytes) => (*bytes).clone(),
            None => {
                let mut bytes = Vec::new();
                let mut file = tokio::fs::File::open(&abs).await?;
                // Take one byte past the cap so truncation is detectable while
                // the read stays bounded.
                let mut bounded = (&mut file).take(CAP + 1);
                bounded.read_to_end(&mut bytes).await?;
                bytes
            }
        };
        let truncated_read = bytes.len() as u64 > CAP;
        if truncated_read {
            bytes.truncate(CAP as usize);
        }
        let hash = hash_bytes(&bytes);
        // A truncated read cannot vouch for the whole file; recording its hash
        // would make every later edit of a large file look stale.
        if !truncated_read {
            record_hash(ctx, &abs, hash.clone());
        }
        if bytes.is_empty() {
            return Ok(ToolOutput {
                content: String::new(),
                metadata: json!({"path": path, "hash": hash}),
                truncated: false,
            });
        }
        // Binary heuristic: NUL byte in first 8KiB.
        if bytes.iter().take(8192).any(|&b| b == 0) {
            return Ok(ToolOutput {
                content: format!("[binary file: {} bytes]", bytes.len()),
                metadata: json!({"binary": true, "size": bytes.len(), "hash": hash}),
                truncated: false,
            });
        }
        let mut text = String::from_utf8_lossy(&bytes).to_string();
        let offset = input.get("offset").and_then(|v| v.as_u64());
        let limit = input.get("limit").and_then(|v| v.as_u64());
        if offset.is_some() || limit.is_some() {
            // 1-based first line; `limit` caps how many lines are returned.
            let start = offset.unwrap_or(1).saturating_sub(1) as usize;
            let lines: Vec<&str> = text.lines().collect();
            let start = start.min(lines.len());
            let end = limit
                .map(|l| start.saturating_add(l as usize).min(lines.len()))
                .unwrap_or(lines.len());
            text = lines[start..end].join("\n");
        }
        let (text, truncated_text) = truncate_text(&text, CAP as usize);
        Ok(ToolOutput {
            content: text,
            metadata: json!({"path": path, "hash": hash}),
            truncated: truncated_read || truncated_text,
        })
    }
}

pub struct Write;
#[async_trait]
impl Tool for Write {
    fn name(&self) -> &str {
        "write"
    }
    fn description(&self) -> &str {
        "Create or overwrite a file atomically"
    }
    fn schema(&self) -> Value {
        json!({"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"},"force":{"type":"boolean"}},"required":["path","content"],"additionalProperties":false})
    }
    fn permission_action(&self) -> &str {
        "edit"
    }
    async fn execute(&self, input: &Value, ctx: &ToolContext) -> Result<ToolOutput> {
        let path = input["path"]
            .as_str()
            .ok_or_else(|| FreedasError::Tool("path required".into()))?;
        let content = input["content"]
            .as_str()
            .ok_or_else(|| FreedasError::Tool("content required".into()))?;
        let abs = resolve_path_as(ctx, path, "edit")?;
        let preview = if abs.exists() {
            let old_len = std::fs::metadata(&abs).map(|m| m.len()).unwrap_or(0);
            format!(
                "overwrite {path} ({old_len} → {} bytes)\n{}",
                content.len(),
                prefixed(content, '+')
            )
        } else {
            prefixed(content, '+')
        };
        check_perm_path(ctx, "edit", path, &abs, Some(&preview_cap(&preview)))?;
        let old_bytes = if abs.exists() {
            tokio::fs::read(&abs).await?
        } else {
            Vec::new()
        };
        if abs.exists() {
            let force = input
                .get("force")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let h = hash_bytes(&old_bytes);
            if !force && is_stale(ctx, &abs, &h) {
                return Err(FreedasError::StaleRead(path.into()));
            }
        }
        let old = String::from_utf8_lossy(&old_bytes).into_owned();
        atomic_write(&abs, content.as_bytes(), &canonical_root(ctx)).await?;
        record_hash(ctx, &abs, hash_bytes(content.as_bytes()));
        Ok(ToolOutput {
            content: format!("wrote {path} ({} bytes)", content.len()),
            metadata: with_diff(
                json!({"path": path}),
                unified_diff(path, &old, content, 200),
            ),
            truncated: false,
        })
    }
}

pub struct Edit;
#[async_trait]
impl Tool for Edit {
    fn name(&self) -> &str {
        "edit"
    }
    fn description(&self) -> &str {
        "Exact string replace in a file"
    }
    fn schema(&self) -> Value {
        json!({"type":"object","properties":{"path":{"type":"string"},"old":{"type":"string"},"new":{"type":"string"},"replace_all":{"type":"boolean"}},"required":["path","old","new"],"additionalProperties":false})
    }
    fn permission_action(&self) -> &str {
        "edit"
    }
    async fn execute(&self, input: &Value, ctx: &ToolContext) -> Result<ToolOutput> {
        let path = input["path"]
            .as_str()
            .ok_or_else(|| FreedasError::Tool("path required".into()))?;
        let old = input["old"]
            .as_str()
            .ok_or_else(|| FreedasError::Tool("old required".into()))?;
        let new = input["new"]
            .as_str()
            .ok_or_else(|| FreedasError::Tool("new required".into()))?;
        let replace_all = input
            .get("replace_all")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let abs = resolve_path_as(ctx, path, "edit")?;
        let preview = preview_cap(&format!("{}\n{}", prefixed(old, '-'), prefixed(new, '+')));
        check_perm_path(ctx, "edit", path, &abs, Some(&preview))?;
        let bytes = tokio::fs::read(&abs).await?;
        let h = hash_bytes(&bytes);
        if is_stale(ctx, &abs, &h) {
            return Err(FreedasError::StaleRead(format!("{path} changed on disk")));
        }
        let hits = find_occurrences(&bytes, old.as_bytes());
        if hits.is_empty() {
            return Err(FreedasError::Tool(format!(
                "edit: pattern not found in {path}"
            )));
        }
        if hits.len() > 1 && !replace_all {
            return Err(FreedasError::Tool(format!(
                "edit: {} matches in {path}; set replace_all",
                hits.len()
            )));
        }
        let updated = replace_bytes(&bytes, old.as_bytes(), new.as_bytes(), replace_all);
        atomic_write(&abs, &updated, &canonical_root(ctx)).await?;
        record_hash(ctx, &abs, hash_bytes(&updated));
        let old_text = String::from_utf8_lossy(&bytes);
        let new_text = String::from_utf8_lossy(&updated);
        Ok(ToolOutput {
            content: format!("edited {path}"),
            metadata: with_diff(
                json!({"path": path, "replacements": hits.len()}),
                unified_diff(path, &old_text, &new_text, 200),
            ),
            truncated: false,
        })
    }
}

/// Environment a tool subprocess may inherit: a small allowlist plus
/// `environment` from config `extra` (top-level config has no dedicated field).
pub(crate) fn env_allowlist(config: &Config) -> Vec<(String, String)> {
    const KEYS: &[&str] = &[
        "PATH", "HOME", "TMPDIR", "TMP", "TEMP", "LANG", "TERM", "SHELL", "USER", "LOGNAME", "PWD",
    ];
    let mut out = Vec::new();
    for (k, v) in std::env::vars() {
        if KEYS.contains(&k.as_str()) || k.starts_with("LC_") {
            out.push((k, v));
        }
    }
    if let Some(Value::Object(map)) = config.extra.get("environment") {
        for (k, v) in map {
            if let Some(v) = v.as_str()
                && is_safe_env_key(k)
            {
                out.push((k.clone(), v.to_string()));
            }
        }
    }
    out
}

/// Config-provided env keys must be plain names without linker/loader or
/// interpreter hooks (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES` and friends).
fn is_safe_env_key(k: &str) -> bool {
    if k.is_empty() || k.len() > 128 {
        return false;
    }
    if !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return false;
    }
    if k.starts_with("LD_") || k.starts_with("DYLD_") {
        return false;
    }
    !matches!(
        k,
        "BASH_ENV"
            | "ENV"
            | "SHELLOPTS"
            | "IFS"
            | "PYTHONPATH"
            | "PYTHONHOME"
            | "NODE_OPTIONS"
            | "NODE_PATH"
            | "PERL5LIB"
            | "RUBYOPT"
            | "JAVA_TOOL_OPTIONS"
            | "JDK_JAVA_OPTIONS"
    )
}

fn looks_secret(path: &str) -> bool {
    let low = path.to_lowercase();
    low.contains(".env")
        || low.ends_with(".pem")
        || low.ends_with(".key")
        || low.contains("id_rsa")
        || low.contains("credentials")
        || low.contains(".aws")
}

/// A target the shell scanner left as a pattern, so its real reads are
/// unknowable before execution.
fn has_glob(path: &str) -> bool {
    path.contains(['*', '?', '[', '{'])
}

/// In-order commands with the cwd in effect for each, after applying `cd`
/// targets. Duplicates are dropped because the scanner repeats `cd` lines.
fn track_commands(commands: &[String], start: &Path) -> (Vec<(String, PathBuf)>, PathBuf) {
    let mut cwd = start.to_path_buf();
    let mut seen: Vec<&str> = Vec::new();
    let mut out = Vec::new();
    for command in commands {
        if seen.contains(&command.as_str()) {
            continue;
        }
        seen.push(command);
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.first() == Some(&"cd") {
            if let Some(target) = parts.get(1) {
                let p = Path::new(target);
                let joined = if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    cwd.join(p)
                };
                cwd = normalize_lexical(&joined).unwrap_or(joined);
            }
            continue;
        }
        out.push((command.clone(), cwd.clone()));
    }
    (out, cwd)
}

/// Strip quotes and collapse whitespace for deny-list matching.
fn normalize_command(command: &str) -> String {
    command
        .chars()
        .filter(|c| *c != '\'' && *c != '"')
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Catastrophic deny list. The shared parser handles wrappers, `mkfs.*`,
/// `dd of=/dev/` and `bash -c`; `rm -rf ~` is the one form it still misses.
fn catastrophic_hit(command: &str) -> Option<String> {
    if let Some(hit) = freedas_permission::catastrophic_match(command) {
        return Some(hit);
    }
    let flat = normalize_command(command);
    for segment in flat.split([';', '|', '&']) {
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
        if words.first() != Some(&"rm") {
            continue;
        }
        let recursive = words.iter().any(|w| {
            *w == "--recursive"
                || (w.starts_with('-') && !w.starts_with("--") && w.contains(['r', 'R']))
        });
        let force = words
            .iter()
            .any(|w| *w == "--force" || (w.starts_with('-') && w.contains('f')));
        let home = words.iter().any(|w| *w == "~" || *w == "~/");
        if recursive && force && home {
            return Some("rm -rf ~".into());
        }
    }
    None
}

pub struct Bash;
#[async_trait]
impl Tool for Bash {
    fn name(&self) -> &str {
        "bash"
    }
    fn description(&self) -> &str {
        "Run a shell command"
    }
    fn schema(&self) -> Value {
        json!({"type":"object","properties":{"command":{"type":"string"},"cwd":{"type":"string"},"timeout_ms":{"type":"integer"}},"required":["command"],"additionalProperties":false})
    }
    fn permission_action(&self) -> &str {
        "bash"
    }
    async fn execute(&self, input: &Value, ctx: &ToolContext) -> Result<ToolOutput> {
        let command = input["command"]
            .as_str()
            .ok_or_else(|| FreedasError::Tool("command required".into()))?;
        // Catastrophic commands are denied outright unless an explicit
        // (non-`*`) bash rule allows this exact command — `--auto`, `* allow`
        // and the plans-dir bypass never cover them.
        if let Some(hit) = catastrophic_hit(command)
            && !freedas_permission::explicit_bash_allow(&ctx.config, command, &rules_for(ctx))
        {
            return Err(FreedasError::PermissionDenied {
                action: "bash".into(),
                resource: hit,
            });
        }
        let scan = scan_shell(command);
        // The caller-supplied cwd goes through the same containment rules as
        // any other path; relative values resolve against ctx.cwd.
        let cwd = match input.get("cwd").and_then(|v| v.as_str()) {
            Some(c) => resolve_path_as(ctx, c, "bash")?,
            None => ctx.cwd.clone(),
        };
        let (sequenced, final_cwd) = track_commands(&scan.commands, &cwd);
        let root = canonical_root(ctx);
        // Resolve every extracted subcommand, read target and write target:
        // any deny denies, any ask asks. Writes become `edit` checks inside
        // the project and `external_directory` checks outside it. File targets
        // resolve against every cwd observed for this command (initial, each
        // sequenced step, final): the scanner strips redirects/`cd` so a
        // target's originating step is unknowable, and checking all cwds is
        // fail-closed when `cd` moves the resolution.
        let mut resources: Vec<(String, String)> = scan
            .commands
            .iter()
            .map(|c| ("bash".to_string(), c.clone()))
            .collect();
        let mut cwds = vec![cwd.clone()];
        for (_, c) in &sequenced {
            if !cwds.contains(c) {
                cwds.push(c.clone());
            }
        }
        if !cwds.contains(&final_cwd) {
            cwds.push(final_cwd.clone());
        }
        for w in &scan.writes {
            for base in &cwds {
                let abs = resolve_abs(base, w)?;
                // Same hard-deny as write/edit/patch: a bash redirect into
                // .git (hooks → RCE) must never degrade to a generic edit.
                if has_git_component(&abs) {
                    return Err(FreedasError::PermissionDenied {
                        action: "edit".into(),
                        resource: w.clone(),
                    });
                }
                if abs.starts_with(&root) {
                    // Check both spellings: the raw input (e.g. `*.env`) and the
                    // canonical absolute path, so a rule matching either form
                    // still applies after resolution.
                    resources.push(("edit".into(), w.clone()));
                    let canon = abs.to_string_lossy().to_string();
                    if canon != *w {
                        resources.push(("edit".into(), canon));
                    }
                } else {
                    resources.push((
                        "external_directory".into(),
                        abs.to_string_lossy().to_string(),
                    ));
                }
            }
        }
        let mut unresolved_reads = false;
        for target in &scan.reads {
            if has_glob(target) {
                unresolved_reads = true;
                // A glob that would sweep secret files is not something
                // `--auto` may silently approve.
                if ctx.auto && looks_secret(target) {
                    return Err(FreedasError::PermissionDenied {
                        action: "read".into(),
                        resource: target.clone(),
                    });
                }
                resources.push(("read".into(), target.clone()));
                continue;
            }
            for base in &cwds {
                let abs = resolve_abs(base, target)?;
                if has_git_component(&abs) {
                    return Err(FreedasError::PermissionDenied {
                        action: "read".into(),
                        resource: target.clone(),
                    });
                }
                if abs.starts_with(&root) {
                    resources.push(("read".into(), target.clone()));
                    let canon = abs.to_string_lossy().to_string();
                    if canon != *target {
                        resources.push(("read".into(), canon));
                    }
                } else {
                    resources.push((
                        "external_directory".into(),
                        abs.to_string_lossy().to_string(),
                    ));
                }
            }
        }
        let rules = rules_for(ctx);
        let mut effect = combine(&resources, &ctx.config, &rules);
        // Dynamic constructs the scanner cannot resolve statically always ask
        // unless a rule already denied the command.
        let dynamic = scan.needs_ask || unresolved_reads;
        if dynamic && effect == Effect::Allow {
            effect = Effect::Ask;
        }
        // The sandbox containment upgrade covers only the subprocess's own
        // action; an Ask raised by a read/edit/external_directory operand is
        // about host files the sandbox cannot vouch for and must survive.
        let nonbash_ask = resources.iter().any(|(a, r)| {
            a != "bash" && freedas_permission::resolve(&ctx.config, a, r, &rules) == Effect::Ask
        });
        finish(
            ctx,
            effect,
            ("bash".into(), command.to_string()),
            None,
            dynamic,
            nonbash_ask,
        )?;
        let timeout_ms = input
            .get("timeout_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(120_000);
        // The all-reads hatch is a debug escape and must never apply under
        // `sandbox.mode = "on"`, which is the strict isolation contract.
        let allow_all_reads = ctx.config.sandbox.mode != "on"
            && std::env::var("FREEDAS_SANDBOX_ALLOW_ALL_READS")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
        // Per-run scratch: keeps staged secrets and build artifacts out of
        // the host-shared /tmp so other runs (sandboxed or not) cannot see
        // them. Added as a write root so both backends grant access.
        let private_tmp = {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let dir =
                std::env::temp_dir().join(format!("freedas-run-{}-{nanos:x}", std::process::id()));
            std::fs::create_dir_all(&dir).ok().map(|()| dir)
        };
        let mut write_roots = vec![root.clone()];
        if let Some(t) = &private_tmp {
            write_roots.push(t.clone());
        }
        let policy = freedas_sandbox::SandboxPolicy {
            read: vec![root.clone()],
            write: write_roots,
            network: ctx.config.sandbox.network.clone(),
            env_allowlist: Vec::new(),
            timeout_ms,
            cwd: Some(final_cwd.clone()),
            allow_all_reads,
        };
        let sandbox_off = !ctx.sandbox
            || std::env::var("FREEDAS_EXPERIMENTAL_SANDBOX")
                .map(|v| v == "false" || v == "0")
                .unwrap_or(false);
        let no_backend_err = |ctx: &ToolContext| -> FreedasError {
            if ctx.config.sandbox.mode == "on" {
                FreedasError::SandboxUnavailable(
                    "sandbox.mode = \"on\" but no sandbox backend (sandbox-exec/bwrap) is installed".into(),
                )
            } else {
                FreedasError::SandboxUnavailable(
                    "no sandbox backend and no interactive approver; refusing unsandboxed exec \
                     (set FREEDAS_EXPERIMENTAL_SANDBOX=false to opt out explicitly)"
                        .into(),
                )
            }
        };
        let direct = || {
            vec![
                "/bin/bash".to_string(),
                "-lc".to_string(),
                command.to_string(),
            ]
        };
        let wrapped = if sandbox_off {
            direct()
        } else {
            // Single-check containment: the wrap result below is what actually
            // runs, so a backend that vanishes between the permission check
            // and spawn fails closed instead of silently running unsandboxed.
            match freedas_sandbox::wrap_command(&policy, "/bin/bash", &["-lc", command]) {
                Some(wrapped) => wrapped,
                None if ctx.config.sandbox.mode == "on" || ctx.approver.is_none() => {
                    return Err(no_backend_err(ctx));
                }
                None => {
                    eprintln!(
                        "freedas: sandbox: no backend available; running bash without OS sandbox"
                    );
                    direct()
                }
            }
        };
        let (program, args) = wrapped.split_first().expect("non-empty");
        let mut cmd = tokio::process::Command::new(program);
        // Dropping the future on cancellation kills the process group.
        cmd.kill_on_drop(true);
        cmd.args(args)
            .current_dir(&final_cwd)
            // Never inherit the parent environment: provider keys and tokens
            // must not reach a shell the model wrote.
            .env_clear()
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        for (k, v) in env_allowlist(&ctx.config) {
            cmd.env(k, v);
        }
        cmd.env("TERM", "dumb").env("NO_COLOR", "1").env("CI", "1");
        if let Some(t) = &private_tmp {
            cmd.env("TMPDIR", t).env("TMP", t).env("TEMP", t);
        }
        #[cfg(unix)]
        cmd.process_group(0);
        let mut child = cmd
            .spawn()
            .map_err(|e| FreedasError::Tool(format!("spawn: {e}")))?;
        let mut stdout_pipe = child
            .stdout
            .take()
            .ok_or_else(|| FreedasError::Tool("no stdout pipe".into()))?;
        let mut stderr_pipe = child
            .stderr
            .take()
            .ok_or_else(|| FreedasError::Tool("no stderr pipe".into()))?;
        // Drain both pipes while the process runs; writing a large patch or
        // log to a full pipe would otherwise deadlock.
        let stdout_task = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut buf = Vec::new();
            let _ = stdout_pipe.read_to_end(&mut buf).await;
            buf
        });
        let stderr_task = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut buf = Vec::new();
            let _ = stderr_pipe.read_to_end(&mut buf).await;
            buf
        });
        let status =
            match tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), child.wait())
                .await
            {
                Ok(res) => res?,
                Err(_) => {
                    kill_group(&child).await;
                    stdout_task.abort();
                    stderr_task.abort();
                    return Err(FreedasError::Tool("command timed out".into()));
                }
            };
        let stdout = String::from_utf8_lossy(&stdout_task.await.unwrap_or_default()).to_string();
        let stderr = String::from_utf8_lossy(&stderr_task.await.unwrap_or_default()).to_string();
        if let Some(t) = &private_tmp {
            let _ = std::fs::remove_dir_all(t);
        }
        let (out, t1) = truncate_text(&stdout, 1024 * 1024);
        let (err, t2) = truncate_text(&stderr, 1024 * 1024);
        let mut content = String::new();
        if !out.is_empty() {
            content.push_str(&out);
        }
        if !err.is_empty() {
            if !content.is_empty() {
                content.push_str("\n--- stderr ---\n");
            }
            content.push_str(&err);
        }
        if content.is_empty() {
            content.push_str("(no output)");
        }
        content.push_str(&format!("\nexit={}", status.code().unwrap_or(-1)));
        Ok(ToolOutput {
            content,
            metadata: json!({"command": command, "exit": status.code(), "success": status.success()}),
            truncated: t1 || t2,
        })
    }
}

/// Kill the whole process group; killing only the shell leaves its children running.
#[cfg(unix)]
async fn kill_group(child: &tokio::process::Child) {
    if let Some(pid) = child.id() {
        // Direct killpg syscall: no /bin/kill dependency, no extra process.
        // ESRCH (already reaped) is fine; the group is gone either way.
        unsafe { killpg(pid as i32, 15) };
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        unsafe { killpg(pid as i32, 9) };
    }
}

#[cfg(unix)]
unsafe extern "C" {
    fn killpg(pgrp: i32, sig: i32) -> i32;
}

#[cfg(not(unix))]
async fn kill_group(_child: &tokio::process::Child) {}

pub struct Glob;
#[async_trait]
impl Tool for Glob {
    fn name(&self) -> &str {
        "glob"
    }
    fn description(&self) -> &str {
        "Find files by glob"
    }
    fn schema(&self) -> Value {
        json!({"type":"object","properties":{"pattern":{"type":"string"}},"required":["pattern"],"additionalProperties":false})
    }
    fn permission_action(&self) -> &str {
        "read"
    }
    fn parallel_safe(&self) -> bool {
        true
    }
    async fn execute(&self, input: &Value, ctx: &ToolContext) -> Result<ToolOutput> {
        let pattern = input["pattern"]
            .as_str()
            .ok_or_else(|| FreedasError::Tool("pattern required".into()))?;
        check_perm(ctx, "read", Some(pattern))?;
        let matcher = globset::GlobBuilder::new(pattern)
            .literal_separator(true)
            .build()
            .map_err(|e| FreedasError::Tool(format!("glob: {e}")))?
            .compile_matcher();
        let root = canonical_root(ctx);
        let mut out = Vec::new();
        for entry in ignore::WalkBuilder::new(&ctx.project_root)
            .hidden(false)
            .filter_entry(|e| e.file_name() != std::ffi::OsStr::new(".git"))
            .build()
            .take(5000)
        {
            if let Ok(entry) = entry {
                let p = entry.path();
                if !p.is_file() {
                    continue;
                }
                // Canonicalize before matching: a symlink like `link -> /etc`
                // must not pass containment as `link/passwd`.
                let canon = canonicalize_lenient(p);
                if !canon.starts_with(&root) {
                    continue;
                }
                // Size cap before any read: skip huge files here; `read`
                // truncates them on demand instead of enumerating bytes.
                if std::fs::metadata(&canon).map(|m| m.len()).unwrap_or(0) > 1024 * 1024 {
                    continue;
                }
                let rel = canon
                    .strip_prefix(&root)
                    .unwrap_or(&canon)
                    .to_string_lossy()
                    .to_string();
                if matcher.is_match(&rel) {
                    out.push(rel);
                }
            }
            if out.len() >= 200 {
                break;
            }
        }
        // The pattern is not the resource; every returned file is read.
        for rel in &out {
            check_perm(ctx, "read", Some(rel))?;
        }
        Ok(ToolOutput {
            content: out.join("\n"),
            metadata: json!({"count": out.len()}),
            truncated: false,
        })
    }
}

pub struct Grep;
#[async_trait]
impl Tool for Grep {
    fn name(&self) -> &str {
        "grep"
    }
    fn description(&self) -> &str {
        "Regex search in files"
    }
    fn schema(&self) -> Value {
        json!({"type":"object","properties":{"pattern":{"type":"string"},"path":{"type":"string"}},"required":["pattern"],"additionalProperties":false})
    }
    fn permission_action(&self) -> &str {
        "read"
    }
    fn parallel_safe(&self) -> bool {
        true
    }
    async fn execute(&self, input: &Value, ctx: &ToolContext) -> Result<ToolOutput> {
        let pattern = input["pattern"]
            .as_str()
            .ok_or_else(|| FreedasError::Tool("pattern required".into()))?;
        let re =
            regex::Regex::new(pattern).map_err(|e| FreedasError::Tool(format!("regex: {e}")))?;
        check_perm(ctx, "read", Some(pattern))?;
        let root = canonical_root(ctx);
        let mut lines = Vec::new();
        let mut matched: Vec<String> = Vec::new();
        for entry in ignore::WalkBuilder::new(&ctx.project_root)
            .hidden(false)
            .filter_entry(|e| e.file_name() != std::ffi::OsStr::new(".git"))
            .build()
            .take(5000)
        {
            if let Ok(entry) = entry {
                let p = entry.path();
                if !p.is_file() {
                    continue;
                }
                let canon = canonicalize_lenient(p);
                if !canon.starts_with(&root) {
                    continue;
                }
                // Size cap before reading: skip huge files instead of loading
                // them fully; `read` truncates on demand.
                if std::fs::metadata(&canon).map(|m| m.len()).unwrap_or(0) > 1024 * 1024 {
                    continue;
                }
                if let Ok(bytes) = tokio::fs::read(&canon).await {
                    if bytes.iter().take(8192).any(|&b| b == 0) {
                        continue;
                    }
                    let text = String::from_utf8_lossy(&bytes);
                    let rel = canon
                        .strip_prefix(&root)
                        .unwrap_or(&canon)
                        .to_string_lossy()
                        .to_string();
                    let mut hit = false;
                    for (i, line) in text.lines().enumerate() {
                        if re.is_match(line) {
                            lines.push(format!("{rel}:{}: {}", i + 1, line.trim()));
                            hit = true;
                        }
                    }
                    if hit && !matched.contains(&rel) {
                        matched.push(rel);
                    }
                }
            }
            if lines.len() >= 200 {
                break;
            }
        }
        // Permission is per file, not per pattern: a search must not surface a
        // file the `read` tool would refuse.
        for rel in &matched {
            check_perm(ctx, "read", Some(rel))?;
        }
        Ok(ToolOutput {
            content: lines.join("\n"),
            metadata: json!({"count": lines.len()}),
            truncated: false,
        })
    }
}

pub struct SkillTool;
#[async_trait]
impl Tool for SkillTool {
    fn name(&self) -> &str {
        "skill"
    }
    fn description(&self) -> &str {
        "Load a skill's instructions"
    }
    fn schema(&self) -> Value {
        json!({"type":"object","properties":{"id":{"type":"string"}},"required":["id"],"additionalProperties":false})
    }
    fn permission_action(&self) -> &str {
        "skill"
    }
    async fn execute(&self, input: &Value, ctx: &ToolContext) -> Result<ToolOutput> {
        let id = input["id"]
            .as_str()
            .ok_or_else(|| FreedasError::Tool("id required".into()))?;
        check_perm(ctx, "skill", Some(id))?;
        let skills = freedas_skill::discover_with(&ctx.project_root, &ctx.config.skills);
        let Some(skill) = skills.iter().find(|s| s.id == id || s.name == id) else {
            return Err(FreedasError::Tool(format!("skill not found: {id}")));
        };
        // Load via `source` so flat `*.md` skills work; `base_dir/SKILL.md`
        // is wrong for them. Direct loads bypass `autoinvoke: false` hiding.
        // Treat repo-supplied skill bodies as data, not system instructions.
        let body = &skill.body;
        let wrapped = format!("<untrusted skill body from {id}>\n{body}\n</untrusted skill body>");
        Ok(ToolOutput {
            content: wrapped,
            metadata: json!({"id": id}),
            truncated: false,
        })
    }
}

pub struct TodoTool;
#[async_trait]
impl Tool for TodoTool {
    fn name(&self) -> &str {
        "todo"
    }
    fn description(&self) -> &str {
        "Manage the session todo list"
    }
    fn schema(&self) -> Value {
        json!({"type":"object","properties":{"action":{"type":"string","enum":["add","update","list"]},"id":{"type":"string"},"content":{"type":"string"},"status":{"type":"string"}},"required":["action"],"additionalProperties":false})
    }
    fn permission_action(&self) -> &str {
        "read"
    }
    async fn execute(&self, input: &Value, ctx: &ToolContext) -> Result<ToolOutput> {
        let action = input["action"]
            .as_str()
            .ok_or_else(|| FreedasError::Tool("action required".into()))?;
        check_perm(ctx, "read", Some("todo"))?;
        let _ = ctx;
        let content = match action {
            "add" => format!(
                "added todo {}",
                input.get("content").and_then(|v| v.as_str()).unwrap_or("")
            ),
            "update" => format!(
                "updated todo {}",
                input.get("id").and_then(|v| v.as_str()).unwrap_or("")
            ),
            "list" => "todo list requires session storage; see server API".to_string(),
            other => format!("unknown action: {other}"),
        };
        Ok(ToolOutput {
            content,
            metadata: json!({}),
            truncated: false,
        })
    }
}

pub struct MemoryTool;
#[async_trait]
impl Tool for MemoryTool {
    fn name(&self) -> &str {
        "memory"
    }
    fn description(&self) -> &str {
        "Add a durable memory or search past memories"
    }
    fn schema(&self) -> Value {
        json!({"type":"object","properties":{"action":{"type":"string","enum":["add","search"]},"kind":{"type":"string"},"text":{"type":"string"},"query":{"type":"string"}},"required":["action"],"additionalProperties":false})
    }
    fn permission_action(&self) -> &str {
        "read"
    }
    async fn execute(&self, input: &Value, ctx: &ToolContext) -> Result<ToolOutput> {
        let action = input["action"]
            .as_str()
            .ok_or_else(|| FreedasError::Tool("action required".into()))?;
        check_perm(ctx, "read", Some("memory"))?;
        let content = match action {
            "add" => {
                let text = input
                    .get("text")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim();
                let kind = input.get("kind").and_then(|v| v.as_str()).unwrap_or("fact");
                // Explicit adds allow short prefs; distillation keeps its own 12-char floor.
                if text.len() < 3 || text.len() > 500 {
                    return Err(FreedasError::Tool(
                        "memory text must be 3..500 chars".into(),
                    ));
                }
                // Redact before insert so secrets never reach SQLite; a hit
                // means the input held a secret and must not be stored.
                let redacted = freedas_core::redact::redact(text);
                if redacted.contains("[REDACTED]") {
                    return Err(FreedasError::Tool(
                        "memory contains secret; not stored".into(),
                    ));
                }
                if let (Some(db), Some(project_id)) = (&ctx.db, &ctx.project_id) {
                    db.add_memory("project", Some(project_id.as_str()), kind, &redacted, 0.8)?;
                }
                format!("remembered ({kind}): {redacted}")
            }
            "search" => {
                let query = input.get("query").and_then(|v| v.as_str()).unwrap_or("");
                match (&ctx.db, &ctx.project_id) {
                    (Some(db), Some(project_id)) => {
                        let rows = db.recall_memory_fts(Some(project_id.as_str()), query, 10)?;
                        if rows.is_empty() {
                            format!("no memories match: {query}")
                        } else {
                            rows.iter()
                                .map(|(kind, text)| format!("[{kind}] {text}"))
                                .collect::<Vec<_>>()
                                .join("\n")
                        }
                    }
                    _ => format!("searching memory for: {query}"),
                }
            }
            other => format!("unknown action: {other}"),
        };
        Ok(ToolOutput {
            content,
            metadata: json!({}),
            truncated: false,
        })
    }
}

pub struct QuestionTool;
#[async_trait]
impl Tool for QuestionTool {
    fn name(&self) -> &str {
        "question"
    }
    fn description(&self) -> &str {
        "Ask the user a structured question"
    }
    fn schema(&self) -> Value {
        json!({"type":"object","properties":{"question":{"type":"string"},"options":{"type":"array","items":{"type":"string"}}},"required":["question"],"additionalProperties":false})
    }
    fn permission_action(&self) -> &str {
        "question"
    }
    async fn execute(&self, input: &Value, ctx: &ToolContext) -> Result<ToolOutput> {
        let q = input["question"]
            .as_str()
            .ok_or_else(|| FreedasError::Tool("question required".into()))?;
        check_perm(ctx, "question", Some(q))?;
        Ok(ToolOutput {
            content: format!("Question for user: {q}"),
            metadata: json!({}),
            truncated: false,
        })
    }
}

pub struct TaskTool;
#[async_trait]
impl Tool for TaskTool {
    fn name(&self) -> &str {
        "task"
    }
    fn description(&self) -> &str {
        "Spawn a subagent for one part of the task"
    }
    fn schema(&self) -> Value {
        json!({"type":"object","properties":{"agent":{"type":"string"},"prompt":{"type":"string"}},"required":["prompt"],"additionalProperties":false})
    }
    fn permission_action(&self) -> &str {
        "task"
    }
    async fn execute(&self, input: &Value, ctx: &ToolContext) -> Result<ToolOutput> {
        let prompt = input["prompt"]
            .as_str()
            .ok_or_else(|| FreedasError::Tool("prompt required".into()))?;
        // Permission is on the agent being spawned, not the prompt text: the
        // prompt is free-form and must never become a remembered rule.
        let agent = input
            .get("agent")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("default");
        check_perm(ctx, "task", Some(agent))?;
        Ok(ToolOutput {
            content: format!("subagent requested: {prompt}"),
            metadata: json!({}),
            truncated: false,
        })
    }
}

pub struct WebFetch;
#[async_trait]
impl Tool for WebFetch {
    fn name(&self) -> &str {
        "webfetch"
    }
    fn description(&self) -> &str {
        "Fetch a URL and convert it to Markdown"
    }
    fn schema(&self) -> Value {
        json!({"type":"object","properties":{"url":{"type":"string"}},"required":["url"],"additionalProperties":false})
    }
    fn permission_action(&self) -> &str {
        "webfetch"
    }
    async fn execute(&self, input: &Value, ctx: &ToolContext) -> Result<ToolOutput> {
        let url = input["url"]
            .as_str()
            .ok_or_else(|| FreedasError::Tool("url required".into()))?;
        check_perm(ctx, "webfetch", Some(url))?;
        check_ssrf(url).await?;
        // No redirect following: each hop must be re-checked, so resolve them
        // manually (bounded) instead of letting reqwest follow blindly. The
        // resolver validates the addresses reqwest actually connects to.
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .dns_resolver(std::sync::Arc::new(SsrfResolver))
            .build()
            .map_err(|e| FreedasError::Tool(format!("http client: {e}")))?;
        let mut next_url = url.to_string();
        let mut resp = client
            .get(&next_url)
            .send()
            .await
            .map_err(|e| FreedasError::Tool(format!("fetch: {e}")))?;
        for _ in 0..5 {
            if !resp.status().is_redirection() {
                break;
            }
            let Some(loc) = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
            else {
                break;
            };
            next_url = resp
                .url()
                .join(loc)
                .map(|u| u.to_string())
                .unwrap_or_else(|_| loc.to_string());
            check_ssrf(&next_url).await?;
            resp = client
                .get(&next_url)
                .send()
                .await
                .map_err(|e| FreedasError::Tool(format!("fetch: {e}")))?;
        }
        if resp.status().is_redirection() {
            return Err(FreedasError::Tool("too many redirects".into()));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| FreedasError::Tool(format!("read: {e}")))?;
        let (text, truncated) = truncate_text(&String::from_utf8_lossy(&bytes), 5 * 1024 * 1024);
        let content = html2md::parse_html(&text);
        Ok(ToolOutput {
            content,
            metadata: json!({"url": url}),
            truncated,
        })
    }
}

pub struct WebSearch;
#[async_trait]
impl Tool for WebSearch {
    fn name(&self) -> &str {
        "websearch"
    }
    fn description(&self) -> &str {
        "Search the web (DuckDuckGo)"
    }
    fn schema(&self) -> Value {
        json!({"type":"object","properties":{"query":{"type":"string"}},"required":["query"],"additionalProperties":false})
    }
    fn permission_action(&self) -> &str {
        "websearch"
    }
    async fn execute(&self, input: &Value, ctx: &ToolContext) -> Result<ToolOutput> {
        let query = input["query"]
            .as_str()
            .ok_or_else(|| FreedasError::Tool("query required".into()))?;
        check_perm(ctx, "websearch", Some(query))?;
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .dns_resolver(std::sync::Arc::new(SsrfResolver))
            .build()
            .map_err(|e| FreedasError::Tool(format!("http client: {e}")))?;
        let url = format!(
            "https://html.duckduckgo.com/html/?q={}",
            query.replace(' ', "+")
        );
        check_ssrf(&url).await?;
        let mut next_url = url.clone();
        let mut resp = client
            .get(&next_url)
            .header("user-agent", "Freedas")
            .send()
            .await
            .map_err(|e| FreedasError::Tool(format!("search: {e}")))?;
        for _ in 0..5 {
            if !resp.status().is_redirection() {
                break;
            }
            let Some(loc) = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
            else {
                break;
            };
            next_url = resp
                .url()
                .join(loc)
                .map(|u| u.to_string())
                .unwrap_or_else(|_| loc.to_string());
            check_ssrf(&next_url).await?;
            resp = client
                .get(&next_url)
                .header("user-agent", "Freedas")
                .send()
                .await
                .map_err(|e| FreedasError::Tool(format!("search: {e}")))?;
        }
        if resp.status().is_redirection() {
            return Err(FreedasError::Tool("too many redirects".into()));
        }
        let text = resp
            .text()
            .await
            .map_err(|e| FreedasError::Tool(format!("read: {e}")))?;
        let md = html2md::parse_html(&text);
        let (content, truncated) = truncate_text(&md, 100_000);
        Ok(ToolOutput {
            content,
            metadata: json!({"query": query}),
            truncated,
        })
    }
}

pub struct LspTool;

/// First installed language server that speaks for this file extension.
fn lsp_server_for(ext: &str) -> Option<&'static str> {
    let candidates: &[&str] = match ext {
        "rs" => &["rust-analyzer"],
        "ts" | "tsx" | "js" => &["typescript-language-server"],
        "py" => &["pylsp"],
        "go" => &["gopls"],
        "c" | "cpp" | "h" => &["clangd"],
        _ => &[],
    };
    let installed = freedas_lsp::servers_available();
    candidates
        .iter()
        .find(|c| installed.iter().any(|a| a.as_str() == **c))
        .copied()
}

#[async_trait]
impl Tool for LspTool {
    fn name(&self) -> &str {
        "lsp"
    }
    fn description(&self) -> &str {
        "Query a language server for diagnostics, hover, or definitions"
    }
    fn schema(&self) -> Value {
        json!({"type":"object","properties":{
            "operation":{"type":"string","enum":["diagnostics","hover","definition"]},
            "path":{"type":"string"},
            "line":{"type":"integer","description":"1-based line"},
            "col":{"type":"integer","description":"1-based column"}
        },"required":["operation","path"],"additionalProperties":false})
    }
    fn permission_action(&self) -> &str {
        "read"
    }
    fn parallel_safe(&self) -> bool {
        true
    }
    async fn execute(&self, input: &Value, ctx: &ToolContext) -> Result<ToolOutput> {
        let operation = input["operation"]
            .as_str()
            .ok_or_else(|| FreedasError::Tool("operation required".into()))?;
        let path = input["path"]
            .as_str()
            .ok_or_else(|| FreedasError::Tool("path required".into()))?;
        let abs = resolve_path(ctx, path)?;
        check_perm(ctx, "read", Some(path))?;
        let ext = abs
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_string();
        let Some(server) = lsp_server_for(&ext) else {
            return Ok(ToolOutput {
                content: format!("no LSP server for {ext}"),
                metadata: json!({"server": null, "ext": ext}),
                truncated: false,
            });
        };
        let line = input["line"].as_u64().unwrap_or(1).saturating_sub(1) as u32;
        let col = input["col"].as_u64().unwrap_or(1).saturating_sub(1) as u32;
        let (content, metadata) = match operation {
            "diagnostics" => {
                let diags = freedas_lsp::diagnostics(server, &abs, &ctx.project_root)
                    .await
                    .map_err(|e| FreedasError::Tool(format!("lsp diagnostics: {e}")))?;
                let lines: Vec<String> = diags
                    .iter()
                    .map(|d| {
                        let sev = match d.severity {
                            1 => "error",
                            2 => "warning",
                            3 => "info",
                            _ => "hint",
                        };
                        let start = &d.range["start"];
                        format!(
                            "{path}:{}:{}: {sev}: {}{}",
                            start["line"].as_u64().unwrap_or(0) + 1,
                            start["character"].as_u64().unwrap_or(0) + 1,
                            d.message,
                            d.source
                                .as_ref()
                                .map(|s| format!(" [{s}]"))
                                .unwrap_or_default()
                        )
                    })
                    .collect();
                let content = if lines.is_empty() {
                    "no diagnostics".to_string()
                } else {
                    lines.join("\n")
                };
                (content, json!({"server": server, "count": diags.len()}))
            }
            "hover" | "definition" => {
                let found = if operation == "hover" {
                    freedas_lsp::hover(server, &abs, &ctx.project_root, line, col).await
                } else {
                    freedas_lsp::definition(server, &abs, &ctx.project_root, line, col).await
                }
                .map_err(|e| FreedasError::Tool(format!("lsp {operation}: {e}")))?;
                let located = found.is_some();
                let content = found
                    .map(|v| serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string()))
                    .unwrap_or_else(|| format!("no {operation} information"));
                (content, json!({"server": server, "found": located}))
            }
            other => {
                return Err(FreedasError::Tool(format!(
                    "unknown lsp operation: {other}"
                )));
            }
        };
        let (content, truncated) = truncate_text(&content, 20_000);
        Ok(ToolOutput {
            content,
            metadata,
            truncated,
        })
    }
}

// ------------------------------------------------------------------ browser

const BROWSER_NAMES: &[&str] = &[
    "chromium",
    "google-chrome",
    "chrome",
    "brave-browser",
    "microsoft-edge",
];
const DEVTOOLS_PREFIX: &str = "DevTools listening on ";
const BROWSER_LAUNCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Where to look for a browser binary.
#[derive(Debug, Default)]
struct BrowserDirs {
    path_dirs: Vec<PathBuf>,
    /// Fully qualified executables inside macOS app bundles.
    exe_paths: Vec<PathBuf>,
}

fn browser_dirs() -> BrowserDirs {
    let path_dirs = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    let mut exe_paths = Vec::new();
    #[cfg(target_os = "macos")]
    {
        let mut apps = vec![PathBuf::from("/Applications")];
        if let Some(home) = std::env::var_os("HOME") {
            apps.push(PathBuf::from(home).join("Applications"));
        }
        for base in apps {
            exe_paths.push(base.join("Google Chrome.app/Contents/MacOS/Google Chrome"));
            exe_paths.push(base.join("Chromium.app/Contents/MacOS/Chromium"));
        }
    }
    BrowserDirs {
        path_dirs,
        exe_paths,
    }
}

fn is_executable(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        p.is_file()
    }
}

fn browser_candidates(dirs: &BrowserDirs) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for name in BROWSER_NAMES {
        for dir in &dirs.path_dirs {
            let p = dir.join(name);
            if is_executable(&p) {
                out.push(p);
            }
        }
    }
    for p in &dirs.exe_paths {
        if is_executable(p) {
            out.push(p.clone());
        }
    }
    out
}

/// Start one headless browser, returning the child (kill it when done), its
/// DevTools websocket URL, and the profile dir that must outlive it.
async fn spawn_devtools(
    exe: &Path,
) -> std::result::Result<(tokio::process::Child, String, tempfile::TempDir), String> {
    let profile = tempfile::TempDir::new().map_err(|e| format!("profile dir: {e}"))?;
    let mut child = tokio::process::Command::new(exe)
        .args([
            "--headless",
            "--remote-debugging-port=0",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-gpu",
            "--disable-extensions",
            "--disable-background-networking",
        ])
        .arg(format!("--user-data-dir={}", profile.path().display()))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("spawn: {e}"))?;
    let stderr = child.stderr.take().ok_or("no stderr pipe")?;
    // Drain stderr for the life of the process: closing it early kills the
    // browser on SIGPIPE.
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        use tokio::io::AsyncBufReadExt;
        let mut lines = tokio::io::BufReader::new(stderr).lines();
        let mut tx = Some(tx);
        while let Ok(Some(line)) = lines.next_line().await {
            if let Some(i) = line.find(DEVTOOLS_PREFIX)
                && let Some(tx) = tx.take()
            {
                let _ = tx.send(line[i + DEVTOOLS_PREFIX.len()..].trim().to_string());
            }
        }
    });
    match tokio::time::timeout(BROWSER_LAUNCH_TIMEOUT, rx).await {
        Ok(Ok(ws)) if !ws.is_empty() => Ok((child, ws, profile)),
        Ok(_) => Err("exited before reporting a DevTools endpoint".into()),
        Err(_) => Err("no DevTools endpoint within 10s".into()),
    }
}

async fn launch_browser_in(
    dirs: &BrowserDirs,
) -> Result<(tokio::process::Child, String, tempfile::TempDir)> {
    let candidates = browser_candidates(dirs);
    if candidates.is_empty() {
        return Err(FreedasError::Tool("no browser found on PATH".into()));
    }
    let mut errors = Vec::new();
    for exe in candidates {
        match spawn_devtools(&exe).await {
            Ok(found) => return Ok(found),
            Err(e) => errors.push(format!("{}: {e}", exe.display())),
        }
    }
    Err(FreedasError::Tool(format!(
        "no browser could be started: {}",
        errors.join("; ")
    )))
}

/// One browser process shared by every browser call in this process, so a
/// `navigate` followed by `click`/`snapshot` sees the same DOM. Serialized by
/// the async mutex; the mutex is never held by the UI.
struct LiveBrowser {
    /// Owns the CDP command channel; dropping it ends the handler stream.
    #[allow(dead_code)]
    browser: chromiumoxide::Browser,
    child: tokio::process::Child,
    driver: tokio::task::JoinHandle<()>,
    page: chromiumoxide::Page,
    _profile: tempfile::TempDir,
}

impl Drop for LiveBrowser {
    fn drop(&mut self) {
        self.driver.abort();
        let _ = self.child.start_kill();
    }
}

async fn connect_live(
    ws: &str,
    child: tokio::process::Child,
    profile: tempfile::TempDir,
) -> Result<LiveBrowser> {
    let (browser, mut handler) = chromiumoxide::Browser::connect(ws.to_string())
        .await
        .map_err(|e| FreedasError::Tool(format!("browser connect: {e}")))?;
    let driver = tokio::spawn(async move {
        use futures::StreamExt;
        while let Some(step) = handler.next().await {
            if step.is_err() {
                break;
            }
        }
    });
    let page = browser
        .new_page("about:blank")
        .await
        .map_err(|e| FreedasError::Tool(format!("open page: {e}")))?;
    Ok(LiveBrowser {
        browser,
        child,
        driver,
        page,
        _profile: profile,
    })
}

async fn browser_operation(
    page: &chromiumoxide::Page,
    input: &Value,
    operation: &str,
) -> Result<ToolOutput> {
    let (content, metadata, truncated) = match operation {
        "navigate" => {
            let url = input["url"].as_str().unwrap_or_default();
            check_ssrf(url).await?;
            page.goto(url)
                .await
                .map_err(|e| FreedasError::Tool(format!("navigate {url}: {e}")))?;
            let title = page.get_title().await.ok().flatten().unwrap_or_default();
            let final_url = page
                .url()
                .await
                .ok()
                .flatten()
                .unwrap_or_else(|| url.to_string());
            // A navigation may redirect; the final hop is checked too. The
            // page has already loaded by then, so a blocked target closes the
            // page instead of leaving attacker content in the shared browser.
            // CDP request interception is the upgrade path for a pre-connect
            // block.
            if let Err(e) = check_ssrf(&final_url).await {
                let _ = page.clone().close().await;
                return Err(e);
            }
            (
                format!("{title}\n{final_url}"),
                json!({"title": title, "url": final_url}),
                false,
            )
        }
        "snapshot" => {
            let text: String = page
                .evaluate("(document.body ?? document.documentElement).innerText ?? ''")
                .await
                .map_err(|e| FreedasError::Tool(format!("snapshot: {e}")))?
                .into_value()
                .map_err(|e| FreedasError::Tool(format!("snapshot: {e}")))?;
            let (content, truncated) = truncate_text(&text, 64 * 1024);
            let url = page.url().await.ok().flatten();
            (content, json!({"url": url}), truncated)
        }
        // Network-unsafe: click/type/evaluate can trigger arbitrary JS fetch
        // inside the page, which CDP navigation checks cannot intercept.
        // Callers must treat these as network egress.
        "click" => {
            let selector = input["selector"].as_str().unwrap_or_default();
            page.find_element(selector)
                .await
                .map_err(|e| FreedasError::Tool(format!("element {selector}: {e}")))?
                .click()
                .await
                .map_err(|e| FreedasError::Tool(format!("click {selector}: {e}")))?;
            (
                format!("clicked {selector}"),
                json!({"selector": selector}),
                false,
            )
        }
        "type" => {
            let selector = input["selector"].as_str().unwrap_or_default();
            let text = input["text"].as_str().unwrap_or_default();
            page.find_element(selector)
                .await
                .map_err(|e| FreedasError::Tool(format!("element {selector}: {e}")))?
                .click()
                .await
                .map_err(|e| FreedasError::Tool(format!("focus {selector}: {e}")))?
                .type_str(text)
                .await
                .map_err(|e| FreedasError::Tool(format!("type {selector}: {e}")))?;
            (
                format!("typed {} chars into {selector}", text.chars().count()),
                json!({"selector": selector}),
                false,
            )
        }
        "evaluate" => {
            let script = input["script"].as_str().unwrap_or_default();
            let value = page
                .evaluate(script)
                .await
                .map_err(|e| FreedasError::Tool(format!("evaluate: {e}")))?
                .value()
                .cloned()
                .unwrap_or(Value::Null);
            let text = serde_json::to_string(&value).unwrap_or_else(|_| value.to_string());
            let (content, truncated) = truncate_text(&text, 64 * 1024);
            (content, json!({}), truncated)
        }
        other => {
            return Err(FreedasError::Tool(format!(
                "unknown browser operation: {other}"
            )));
        }
    };
    Ok(ToolOutput {
        content,
        metadata,
        truncated,
    })
}

pub struct BrowserTool {
    /// Lazy browser, started on the first call and reused after that.
    live: tokio::sync::Mutex<Option<LiveBrowser>>,
}

impl BrowserTool {
    pub fn new() -> Self {
        Self {
            live: tokio::sync::Mutex::new(None),
        }
    }
}

impl Default for BrowserTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for BrowserTool {
    fn name(&self) -> &str {
        "browser"
    }
    fn description(&self) -> &str {
        "Drive a headless Chromium: navigate, snapshot, click, type, evaluate"
    }
    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "operation": {"type": "string", "enum": ["navigate", "snapshot", "click", "type", "evaluate"]},
                "url": {"type": "string"},
                "selector": {"type": "string"},
                "text": {"type": "string"},
                "script": {"type": "string"},
                "timeout_ms": {"type": "integer"}
            },
            "required": ["operation"],
            "additionalProperties": false
        })
    }
    fn permission_action(&self) -> &str {
        "browser"
    }
    async fn execute(&self, input: &Value, ctx: &ToolContext) -> Result<ToolOutput> {
        let operation = input["operation"].as_str().unwrap_or_default();
        // Validate before prompting: a malformed call must never ask.
        let resource = match operation {
            "navigate" => input["url"]
                .as_str()
                .filter(|u| !u.is_empty())
                .ok_or_else(|| FreedasError::Tool("url required".into()))?,
            "snapshot" => "*",
            "click" | "type" => input["selector"]
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| FreedasError::Tool("selector required".into()))?,
            "evaluate" => input["script"]
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| FreedasError::Tool("script required".into()))?,
            other => {
                return Err(FreedasError::Tool(format!(
                    "unknown browser operation: {other}"
                )));
            }
        };
        if operation == "type" && input["text"].as_str().is_none() {
            return Err(FreedasError::Tool("text required".into()));
        }
        if operation == "navigate" {
            let parsed = reqwest::Url::parse(resource)
                .map_err(|e| FreedasError::Tool(format!("invalid url: {e}")))?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err(FreedasError::Tool(format!(
                    "browser: unsupported url scheme `{}`",
                    parsed.scheme()
                )));
            }
            check_ssrf(resource).await?;
        }
        // Reading the page is not interacting with it: `ask` is treated as
        // allowed for those, matching the documented prompt set.
        if matches!(operation, "navigate" | "snapshot") {
            check_perm_readonly(ctx, "browser", Some(resource))?;
        } else {
            check_perm(ctx, "browser", Some(resource))?;
        }
        let timeout_ms = input["timeout_ms"].as_u64().unwrap_or(30_000).max(1);
        let mut guard = self.live.lock().await;
        let dead = match guard.as_mut() {
            Some(live) => matches!(live.child.try_wait(), Ok(Some(_))),
            None => true,
        };
        if dead {
            *guard = None;
            let (child, ws, profile) = launch_browser_in(&browser_dirs()).await?;
            *guard = Some(connect_live(&ws, child, profile).await?);
        }
        let Some(page) = guard.as_ref().map(|live| live.page.clone()) else {
            return Err(FreedasError::Tool("browser unavailable".into()));
        };
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(timeout_ms),
            browser_operation(&page, input, operation),
        )
        .await;
        match result {
            Ok(Ok(out)) => Ok(out),
            // A failed or hung command usually means the browser or CDP session
            // is wedged; drop it and start clean on the next call.
            Ok(Err(e)) => {
                *guard = None;
                Err(e)
            }
            Err(_) => {
                *guard = None;
                Err(FreedasError::Tool(format!(
                    "browser timed out after {timeout_ms} ms"
                )))
            }
        }
    }
}

/// Resolver that validates every address it returns, so the address checked
/// is the address reqwest connects to (no second lookup / rebinding window).
#[derive(Debug, Default, Clone, Copy)]
struct SsrfResolver;

fn dns_error(msg: &str) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(std::io::Error::other(msg.to_string()))
}

impl reqwest::dns::Resolve for SsrfResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let host = name.as_str().to_string();
            if is_ssrf_host(&host) {
                return Err(dns_error("blocked host"));
            }
            let addrs = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            let mut out = Vec::new();
            for addr in addrs {
                if is_ssrf_ip(addr.ip()) {
                    return Err(dns_error("blocked address"));
                }
                out.push(addr);
            }
            if out.is_empty() {
                return Err(dns_error("no addresses"));
            }
            Ok(Box::new(out.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// DNS-resolve the host and reject private/loopback/link-local addresses;
/// literal IPs skip resolution. Every redirect hop re-runs this check.
async fn check_ssrf(url: &str) -> Result<()> {
    // `Url` parsing handles IPv6 (`[::1]:8080`), userinfo, and default ports;
    // string splits misparsed both and could let a blocked host through.
    let parsed = reqwest::Url::parse(url).map_err(|_| FreedasError::PermissionDenied {
        action: "webfetch".into(),
        resource: url.into(),
    })?;
    let hostname = parsed.host_str().unwrap_or("");
    if hostname.is_empty() {
        return Err(FreedasError::PermissionDenied {
            action: "webfetch".into(),
            resource: url.into(),
        });
    }
    let bare = hostname.trim_matches(['[', ']']);
    // Literal IP: check directly. Hostname: resolve and check every address.
    if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
        if is_ssrf_ip(ip) {
            return Err(FreedasError::PermissionDenied {
                action: "webfetch".into(),
                resource: url.into(),
            });
        }
    } else {
        if is_ssrf_host(bare) {
            return Err(FreedasError::PermissionDenied {
                action: "webfetch".into(),
                resource: url.into(),
            });
        }
        let port = parsed.port_or_known_default().unwrap_or(80);
        match tokio::net::lookup_host(format!("{bare}:{port}")).await {
            Ok(addrs) => {
                for addr in addrs {
                    if is_ssrf_ip(addr.ip()) {
                        return Err(FreedasError::PermissionDenied {
                            action: "webfetch".into(),
                            resource: url.into(),
                        });
                    }
                }
            }
            Err(_) => {
                return Err(FreedasError::Tool(format!("dns: cannot resolve {bare}")));
            }
        }
    }
    Ok(())
}

fn is_ssrf_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                // Stable octet equivalents of the nightly `ip`-gated helpers:
                // documentation (RFC 5737), broadcast, reserved 240/4.
                || (o[0] == 192 && o[1] == 0 && o[2] == 2)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)
                || o == [255, 255, 255, 255]
                || o[0] >= 240
        }
        std::net::IpAddr::V6(v6) => {
            // Check the V6 value itself first: `to_ipv4` would map `::1` to
            // `0.0.0.1` (allowed) and return `None` for the SIIT translated
            // form `::ffff:0:a.b.c.d`, so it must never run before these.
            let seg = v6.segments();
            if v6.is_loopback()
                || v6.is_unspecified()
                || (seg[0] & 0xffc0) == 0xfe80 // link-local
                || (seg[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                || v6 == std::net::Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)
            {
                return true;
            }
            // Embedded V4 without `to_ipv4()`: mapped `::ffff:a.b.c.d` plus
            // the SIIT translated shape `::ffff:0:a.b.c.d`.
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_ssrf_ip(std::net::IpAddr::V4(mapped));
            }
            if seg[0] == 0
                && seg[1] == 0
                && seg[2] == 0
                && seg[3] == 0
                && seg[4] == 0xffff
                && seg[5] == 0
            {
                let v4 = std::net::Ipv4Addr::new(
                    (seg[6] >> 8) as u8,
                    seg[6] as u8,
                    (seg[7] >> 8) as u8,
                    seg[7] as u8,
                );
                return is_ssrf_ip(std::net::IpAddr::V4(v4));
            }
            false
        }
    }
}

fn is_ssrf_host(host: &str) -> bool {
    let host = host.to_lowercase();
    host == "localhost"
        || host == "169.254.169.254"
        || host == "fd00:ec2::254"
        // Cloud metadata services and private-only names are blocked by name,
        // not just by the address they resolve to.
        || host == "metadata.google.internal"
        || host == "metadata.goog"
        || host == "instance-data"
        || host == "instance-data.ec2.internal"
        || host.ends_with(".internal")
        || host.ends_with(".local")
        || host.starts_with("127.")
        || host.starts_with("10.")
        || host.starts_with("192.168.")
        || host.starts_with("172.16.")
        || host.starts_with("172.17.")
        || host.starts_with("172.18.")
        || host.starts_with("172.19.")
        || host.starts_with("172.20.")
        || host.starts_with("172.21.")
        || host.starts_with("172.22.")
        || host.starts_with("172.23.")
        || host.starts_with("172.24.")
        || host.starts_with("172.25.")
        || host.starts_with("172.26.")
        || host.starts_with("172.27.")
        || host.starts_with("172.28.")
        || host.starts_with("172.29.")
        || host.starts_with("172.30.")
        || host.starts_with("172.31.")
        || host == "0.0.0.0"
        || host == "::1"
}

pub fn registry() -> Vec<Box<dyn Tool>> {
    vec![
        Box::new(Read),
        Box::new(Write),
        Box::new(Edit),
        Box::new(Bash),
        Box::new(Glob),
        Box::new(Grep),
        Box::new(SkillTool),
        Box::new(TodoTool),
        Box::new(MemoryTool),
        Box::new(QuestionTool),
        Box::new(TaskTool),
        Box::new(WebFetch),
        Box::new(WebSearch),
        Box::new(LspTool),
        Box::new(PatchTool),
        Box::new(ApplyPatchTool),
        Box::new(BrowserTool::new()),
    ]
}

pub fn tool_schemas() -> Vec<freedas_provider::ToolSchema> {
    registry()
        .iter()
        .map(|t| freedas_provider::ToolSchema {
            name: t.name().into(),
            description: t.description().into(),
            schema: t.schema(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssrf_blocks_private_and_metadata_targets() {
        for target in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "[::1]",
            "fd00:ec2::254",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            let ip: std::net::IpAddr = target.trim_matches(['[', ']']).parse().unwrap();
            assert!(is_ssrf_ip(ip), "{target} should be blocked");
        }
        for target in ["8.8.8.8", "1.1.1.1", "2606:4700::1111"] {
            let ip: std::net::IpAddr = target.parse().unwrap();
            assert!(!is_ssrf_ip(ip), "{target} should be allowed");
        }
        for host in ["localhost", "metadata.google.internal", "instance-data"] {
            assert!(is_ssrf_host(host), "{host} should be blocked");
        }
        assert!(!is_ssrf_host("example.com"));
    }

    #[test]
    fn preview_caps_lines_and_bytes() {
        let text = (0..30)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let capped = preview_cap(&text);
        assert_eq!(capped.lines().count(), 20);
        assert!(capped.ends_with("line 19"));
        assert!(preview_cap(&"x".repeat(5000)).len() <= 2000);
    }

    #[test]
    fn truncate_keeps_boundary() {
        let (t, trunc) = truncate_text("hello world", 5);
        assert!(trunc);
        assert!(t.starts_with("hello"));
    }

    fn test_ctx(root: &Path, auto: bool) -> ToolContext {
        ToolContext {
            session_id: "ses_1".into(),
            project_root: root.to_path_buf(),
            cwd: root.to_path_buf(),
            config: Config::default(),
            agent_rules: vec![],
            auto,
            manual: false,
            read_hashes: Default::default(),
            sandbox: false,
            session_rules: Default::default(),
            bypass: false,
            plans_dir: None,
            approver: None,
            db: None,
            project_id: None,
            prefetch: None,
        }
    }

    #[tokio::test]
    async fn traversal_through_missing_target_is_asked() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("project");
        std::fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap();
        std::fs::write(dir.path().join("secret.txt"), "x").unwrap();
        let ctx = test_ctx(&root, false);
        for target in ["../secret.txt", "../missing.txt"] {
            let err = Read
                .execute(&json!({"path": target}), &ctx)
                .await
                .unwrap_err();
            assert!(
                matches!(err, FreedasError::PermissionAsked { .. }),
                "{target}: {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn edit_rejects_stale_read() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::write(root.join("a.txt"), "one").unwrap();
        let ctx = test_ctx(&root, true);
        Read.execute(&json!({"path": "a.txt"}), &ctx).await.unwrap();
        // Changed outside the tool after the read.
        std::fs::write(root.join("a.txt"), "two").unwrap();
        let err = Edit
            .execute(
                &json!({"path": "a.txt", "old": "two", "new": "three"}),
                &ctx,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, FreedasError::StaleRead(_)), "{err:?}");
    }

    #[tokio::test]
    async fn edit_is_byte_safe_on_non_utf8() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::write(root.join("a.bin"), b"\xffhello\xff").unwrap();
        let ctx = test_ctx(&root, true);
        Edit.execute(
            &json!({"path": "a.bin", "old": "hello", "new": "bye"}),
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(root.join("a.bin")).unwrap(), b"\xffbye\xff");
    }

    #[test]
    fn env_allowlist_keeps_only_safe_names() {
        let mut config = Config::default();
        config.extra.insert(
            "environment".into(),
            json!({"EXTRA_TOKEN": "x", "PATH": "/override", "LD_PRELOAD": "evil", "DYLD_INSERT_LIBRARIES": "evil", "PYTHONPATH": "evil"}),
        );
        let env = env_allowlist(&config);
        let names: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"EXTRA_TOKEN"));
        assert!(!names.contains(&"LD_PRELOAD"));
        assert!(!names.contains(&"DYLD_INSERT_LIBRARIES"));
        assert!(!names.contains(&"PYTHONPATH"));
        assert!(
            names.iter().all(|k| {
                matches!(
                    *k,
                    "PATH"
                        | "HOME"
                        | "TMPDIR"
                        | "TMP"
                        | "TEMP"
                        | "LANG"
                        | "TERM"
                        | "SHELL"
                        | "USER"
                        | "LOGNAME"
                        | "PWD"
                        | "EXTRA_TOKEN"
                ) || k.starts_with("LC_")
            }),
            "{names:?}"
        );
        // Config-provided values are appended last, so they win at spawn.
        assert_eq!(
            env.iter().rev().find(|(k, _)| k == "PATH").unwrap().1,
            "/override"
        );
    }

    #[test]
    fn scanner_extracts_read_targets_and_cd() {
        let scan = scan_shell("cat .env && grep -r token src/lib.rs");
        assert!(scan.reads.iter().any(|r| r == ".env"), "{:?}", scan.reads);
        assert!(
            scan.reads.iter().any(|r| r == "src/lib.rs"),
            "{:?}",
            scan.reads
        );
        assert!(!scan.reads.iter().any(|r| r == "token"));
        // Globs stay unresolved and are flagged as such.
        assert!(has_glob(".env*"));
        assert!(!has_glob("src/.env"));
        assert!(looks_secret(".env*"));

        // The scanner repeats `cd` lines; tracking must apply it once.
        let commands = vec![
            "cd sub".to_string(),
            "make".to_string(),
            "cd sub".to_string(),
        ];
        let (sequenced, cwd) = track_commands(&commands, Path::new("/p"));
        assert_eq!(cwd, Path::new("/p/sub"));
        assert_eq!(sequenced.len(), 1);
        assert_eq!(sequenced[0].1, Path::new("/p/sub"));
    }

    #[tokio::test]
    async fn write_into_git_is_denied() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let ctx = test_ctx(&root, true);
        let err = Write
            .execute(&json!({"path": ".git/config", "content": "x"}), &ctx)
            .await
            .unwrap_err();
        assert!(
            matches!(err, FreedasError::PermissionDenied { ref action, .. } if action == "edit"),
            "{err:?}"
        );
    }

    #[test]
    fn catastrophes_survive_wrappers() {
        for command in [
            "sudo rm -rf /",
            "rm -rf ~",
            "mkfs.ext4 /dev/sda",
            "dd of=/dev/sda",
            "bash -c 'rm -rf /'",
            "env FOO=1 rm -rf /",
        ] {
            assert!(catastrophic_hit(command).is_some(), "{command}");
        }
        for command in ["rm -rf ./target", "git status", "echo mkfs.ext4 /dev/sda"] {
            assert!(catastrophic_hit(command).is_none(), "{command}");
        }
    }

    #[tokio::test]
    async fn read_slices_lines_and_rejects_directories() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::write(root.join("a.txt"), "1\n2\n3\n4\n").unwrap();
        let ctx = test_ctx(&root, true);
        let out = Read
            .execute(&json!({"path": "a.txt", "offset": 2, "limit": 2}), &ctx)
            .await
            .unwrap();
        assert_eq!(out.content, "2\n3");
        let err = Read.execute(&json!({"path": "."}), &ctx).await.unwrap_err();
        assert!(err.to_string().contains("not a regular file"), "{err}");
    }

    #[tokio::test]
    async fn edit_requires_exact_match() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let f = root.join("a.txt");
        std::fs::write(&f, "hello").unwrap();
        let ctx = ToolContext {
            session_id: "ses_1".into(),
            project_root: root.clone(),
            cwd: root.clone(),
            config: Config::default(),
            agent_rules: vec![],
            auto: true,
            manual: false,
            read_hashes: Default::default(),
            sandbox: false,
            session_rules: Default::default(),
            bypass: false,
            plans_dir: None,
            approver: None,
            db: None,
            project_id: None,
            prefetch: None,
        };
        let out = Edit
            .execute(&json!({"path": "a.txt", "old": "hello", "new": "hi"}), &ctx)
            .await
            .unwrap();
        assert!(out.metadata["replacements"] == 1);
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "hi");
    }

    fn browser_ctx(config: Config) -> (ToolContext, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let ctx = ToolContext {
            session_id: "ses_1".into(),
            project_root: root.clone(),
            cwd: root,
            config,
            agent_rules: vec![],
            auto: false,
            manual: false,
            read_hashes: Default::default(),
            sandbox: false,
            session_rules: Default::default(),
            bypass: false,
            plans_dir: None,
            approver: None,
            db: None,
            project_id: None,
            prefetch: None,
        };
        (ctx, dir)
    }

    /// Default config asks for `browser`; reading the page must not prompt.
    #[tokio::test]
    async fn browser_navigate_does_not_prompt() {
        let (ctx, _dir) = browser_ctx(Config::default());
        check_perm_readonly(&ctx, "browser", Some("https://8.8.8.8/")).unwrap();
    }

    #[tokio::test]
    async fn browser_navigate_denied_by_explicit_rule() {
        let mut config = Config::default();
        config
            .permission
            .rules
            .push(freedas_core::config::PermissionRule::new(
                "browser", "*", "deny",
            ));
        let (ctx, _dir) = browser_ctx(config);
        let err = BrowserTool::new()
            .execute(
                &json!({
                    "operation": "navigate",
                    "url": "https://8.8.8.8/",
                    "timeout_ms": 1000
                }),
                &ctx,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            FreedasError::PermissionDenied { action, .. } if action == "browser"
        ));
    }

    #[tokio::test]
    async fn browser_rejects_file_scheme_and_private_hosts() {
        let (ctx, _dir) = browser_ctx(Config::default());
        let tool = BrowserTool::new();
        let err = tool
            .execute(
                &json!({"operation": "navigate", "url": "file:///etc/passwd"}),
                &ctx,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unsupported url scheme"), "{err}");
        let err = tool
            .execute(
                &json!({"operation": "navigate", "url": "http://169.254.169.254/latest"}),
                &ctx,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, FreedasError::PermissionDenied { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn browser_tool_is_registered() {
        let tool = registry()
            .into_iter()
            .find(|t| t.name() == "browser")
            .expect("browser tool registered");
        assert_eq!(tool.permission_action(), "browser");
        let schema = tool.schema();
        assert!(
            schema["required"]
                .as_array()
                .unwrap()
                .contains(&json!("operation"))
        );
        assert_eq!(
            schema["properties"]["operation"]["enum"]
                .as_array()
                .unwrap()
                .len(),
            5
        );
    }

    #[tokio::test]
    async fn browser_without_binary_reports_path_error() {
        let empty = BrowserDirs::default();
        assert!(browser_candidates(&empty).is_empty());
        let err = launch_browser_in(&empty).await.unwrap_err();
        assert_eq!(err.to_string(), "tool error: no browser found on PATH");
    }

    #[tokio::test]
    async fn browser_rejects_unknown_operation() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let ctx = ToolContext {
            session_id: "ses_1".into(),
            project_root: root.clone(),
            cwd: root,
            config: Config::default(),
            agent_rules: vec![],
            auto: true,
            manual: false,
            read_hashes: Default::default(),
            sandbox: false,
            session_rules: Default::default(),
            bypass: false,
            plans_dir: None,
            approver: None,
            db: None,
            project_id: None,
            prefetch: None,
        };
        let err = BrowserTool::new()
            .execute(&json!({"operation": "scroll"}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "tool error: unknown browser operation: scroll"
        );
    }
}

#[cfg(test)]
mod parity_tests {
    use super::*;

    fn ctx(root: &std::path::Path) -> ToolContext {
        ToolContext {
            session_id: "ses_1".into(),
            project_root: root.to_path_buf(),
            cwd: root.to_path_buf(),
            config: Config::default(),
            agent_rules: vec![],
            auto: false,
            manual: false,
            read_hashes: Default::default(),
            sandbox: false,
            session_rules: Default::default(),
            bypass: false,
            plans_dir: None,
            approver: None,
            db: None,
            project_id: None,
            prefetch: None,
        }
    }

    #[tokio::test]
    async fn memory_add_then_search() {
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(freedas_db::Db::memory().unwrap());
        let project_id = db.ensure_project(dir.path()).unwrap();
        let mut c = ctx(dir.path());
        c.db = Some(db);
        c.project_id = Some(project_id);
        MemoryTool
            .execute(
                &json!({"action": "add", "kind": "preference", "text": "prefer tabs"}),
                &c,
            )
            .await
            .unwrap();
        let out = MemoryTool
            .execute(&json!({"action": "search", "query": "prefer tabs"}), &c)
            .await
            .unwrap();
        assert!(out.content.contains("prefer tabs"), "{}", out.content);
    }

    #[tokio::test]
    async fn prefetch_serves_only_unchanged_files() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.txt");
        std::fs::write(&f, "hello").unwrap();
        let canon = f.canonicalize().unwrap();
        let cache = ReadPrefetch::spawn(vec![canon.clone()]);
        // The prefetch task is in flight; poll briefly for it to land.
        let mut hit = None;
        for _ in 0..50 {
            let meta = std::fs::metadata(&canon).unwrap();
            if let Some(bytes) = cache.lookup(&canon, &meta) {
                hit = Some(bytes);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(
            hit.as_deref().map(|b| b.as_slice()),
            Some(b"hello".as_slice())
        );
        // A change since the prefetch (new length) must miss, never serve stale.
        std::fs::write(&canon, "changed!").unwrap();
        let meta = std::fs::metadata(&canon).unwrap();
        assert!(cache.lookup(&canon, &meta).is_none());
        // And an end-to-end read through the tool agrees.
        let mut c = ctx(dir.path());
        c.prefetch = Some(cache);
        let out = Read.execute(&json!({"path": "a.txt"}), &c).await.unwrap();
        assert_eq!(out.content, "changed!");
    }

    #[tokio::test]
    async fn env_read_asks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), "A=1").unwrap();
        let err = Read
            .execute(&json!({"path": ".env"}), &ctx(dir.path()))
            .await
            .unwrap_err();
        assert!(
            matches!(err, FreedasError::PermissionAsked { .. }),
            "{err:?}"
        );
        let err = Read
            .execute(&json!({"path": ".env.example"}), &ctx(dir.path()))
            .await;
        assert!(err.is_err());
    }

    #[test]
    fn lsp_tool_registered() {
        let tools = registry();
        let lsp = tools.iter().find(|t| t.name() == "lsp").unwrap();
        assert_eq!(lsp.permission_action(), "read");
        assert_eq!(lsp.schema()["type"], "object");
        assert_eq!(lsp.schema()["required"][0], "operation");
    }

    #[tokio::test]
    async fn lsp_tool_without_server_for_extension() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::write(root.join("a.txt"), "hi").unwrap();
        let out = LspTool
            .execute(
                &json!({"operation": "diagnostics", "path": "a.txt"}),
                &ctx(&root),
            )
            .await
            .unwrap();
        assert_eq!(out.content, "no LSP server for txt");
    }

    #[test]
    fn diff_new_file() {
        let d = unified_diff("x.txt", "", "a\nb", 200);
        assert_eq!(d, "--- a/x.txt\n+++ b/x.txt\n@@ -0,0 +1,2 @@\n+a\n+b");
    }

    #[test]
    fn diff_one_line_change() {
        let d = unified_diff("x.txt", "a\nb\nc\nd\ne", "a\nb\nX\nd\ne", 200);
        assert!(d.contains("@@ -1,5 +1,5 @@"), "{d}");
        assert!(d.contains("\n-c\n"), "{d}");
        assert!(d.contains("\n+X\n"), "{d}");
    }

    #[test]
    fn diff_unchanged_is_empty() {
        assert_eq!(unified_diff("x.txt", "same", "same", 200), "");
    }

    #[test]
    fn diff_truncation_marker() {
        let old = (0..50)
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let new = old.replace("\n25\n", "\nX\n");
        let d = unified_diff("x.txt", &old, &new, 4);
        assert_eq!(d.lines().count(), 5, "{d}");
        assert!(d.ends_with("more lines)"), "{d}");
    }
}
