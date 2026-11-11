//! `patch` (unified diff) and `apply_patch` (Codex-style) tools.
//!
//! Both resolve every target path through `resolve_path`/`check_perm` first,
//! then delegate the actual application to the platform `patch` binary so
//! malformed hunks are rejected by a battle-tested parser instead of ours.
//! A failed dry-run leaves files untouched.
//!
//! Application is NOT atomic across files: `patch` applies file-by-file, and
//! a mid-run failure (or a tree change during the dry-run→apply window) can
//! leave a partial result. Containment is re-verified post-apply and every
//! existing target is hash-checked before and after, but there is no
//! rollback — treat `patch`/`apply_patch` output as best-effort and re-check
//! the tree on failure.

use async_trait::async_trait;
use freedas_core::{FreedasError, Result};
use serde_json::{Value, json};

use crate::{Tool, ToolContext, ToolOutput, check_perm_with_preview, resolve_path_as};
use std::path::{Path, PathBuf};

/// `patch`: apply a unified diff. Input: `{diff}` (required) or `{path, diff}`
/// to pin a single file. `-p1` strips `a/`/`b/` prefixes; `-d` scopes to the
/// project root.
pub struct PatchTool;

#[async_trait]
impl Tool for PatchTool {
    fn name(&self) -> &str {
        "patch"
    }
    fn description(&self) -> &str {
        "Apply a unified diff atomically (dry-run first)"
    }
    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "diff": {"type": "string", "description": "unified diff text"},
                "path": {"type": "string", "description": "single target file (optional; restricts the diff to it)"}
            },
            "required": ["diff"],
            "additionalProperties": false
        })
    }
    fn permission_action(&self) -> &str {
        "edit"
    }
    async fn execute(&self, input: &Value, ctx: &ToolContext) -> Result<ToolOutput> {
        let diff = input["diff"]
            .as_str()
            .ok_or_else(|| FreedasError::Tool("diff required".into()))?;
        let pinned = input["path"].as_str();
        // Permission is checked for every path the diff touches, plus the
        // pinned path. `edit` on the diff text would match nothing useful, so
        // extract the targets first.
        let mut targets = diff_targets(diff);
        if let Some(p) = pinned
            && !targets.iter().any(|t| t == p)
        {
            targets.insert(0, p.to_string());
        }
        if targets.is_empty() {
            return Err(FreedasError::Tool("diff names no target files".into()));
        }
        // A target starting with `-` would be parsed as a flag by the `patch`
        // binary; reject it before it reaches `apply_via_patch_bin`.
        for t in &targets {
            if t.starts_with('-') {
                return Err(FreedasError::Tool(format!(
                    "patch target must not start with '-': {t}"
                )));
            }
        }
        let preview = crate::preview_cap(diff);
        // Resolve once and hash each existing target: the stale-read guard
        // write/edit enforce applies here too — a file changed since the last
        // `read` fails instead of being silently clobbered.
        let mut target_hashes: Vec<(PathBuf, String)> = Vec::new();
        for t in &targets {
            let abs = resolve_path_as(ctx, t, "edit")?;
            check_perm_with_preview(ctx, "edit", Some(t), Some(&preview))?;
            if let Ok(bytes) = tokio::fs::read(&abs).await {
                let h = crate::hash_bytes(&bytes);
                if crate::is_stale(ctx, &abs, &h) {
                    return Err(FreedasError::StaleRead(format!("{t} changed on disk")));
                }
                target_hashes.push((abs, h));
            }
        }
        // Re-compare right before the real `patch` run: drift between the
        // permission check and the spawn is a lost-update, not a patch
        // conflict the binary can see.
        for (abs, h) in &target_hashes {
            if let Ok(bytes) = tokio::fs::read(abs).await {
                let now = crate::hash_bytes(&bytes);
                if now != *h {
                    return Err(FreedasError::StaleRead(
                        "patch target changed before apply".into(),
                    ));
                }
            }
        }
        let out = apply_via_patch_bin(ctx, diff, pinned).await?;
        for (abs, _) in &target_hashes {
            if let Ok(bytes) = tokio::fs::read(abs).await {
                crate::record_hash(ctx, abs, crate::hash_bytes(&bytes));
            }
        }
        // TOCTOU: a symlink swap during the external `patch` run could redirect
        // writes outside the project; re-canonicalize each target post-apply and
        // re-verify containment.
        crate::verify_targets_contained(ctx, &targets)?;
        Ok(out)
    }
}

/// `apply_patch`: Codex-style multi-hunk patch — `*** Begin Patch` ... blocks of
/// `*** Update File: <path>` / `*** Add File:` / `*** Delete File:` with
/// `@@` context lines and `+`/`-`/` ` lines. We translate it to a unified diff
/// and feed it through `patch` for atomicity.
pub struct ApplyPatchTool;

#[async_trait]
impl Tool for ApplyPatchTool {
    fn name(&self) -> &str {
        "apply_patch"
    }
    fn description(&self) -> &str {
        "Apply a Codex-style patch atomically"
    }
    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "patch": {"type": "string", "description": "Codex patch text (*** Begin Patch ... *** End Patch)"}
            },
            "required": ["patch"],
            "additionalProperties": false
        })
    }
    fn permission_action(&self) -> &str {
        "edit"
    }
    async fn execute(&self, input: &Value, ctx: &ToolContext) -> Result<ToolOutput> {
        let text = input["patch"]
            .as_str()
            .ok_or_else(|| FreedasError::Tool("patch required".into()))?;
        let ops =
            parse_codex_patch(text).map_err(|e| FreedasError::Tool(format!("apply_patch: {e}")))?;
        if ops.is_empty() {
            return Err(FreedasError::Tool("patch has no file operations".into()));
        }
        let mut delete_paths: Vec<(String, PathBuf)> = Vec::new();
        let preview = crate::preview_cap(text);
        // Stale-read parity with write/edit: hash each existing target at
        // resolve time and fail on drift since the last `read`.
        let mut target_hashes: Vec<(PathBuf, String)> = Vec::new();
        for op in &ops {
            let path = op.path();
            if std::path::Path::new(path).is_absolute() {
                return Err(FreedasError::Tool(format!(
                    "apply_patch: absolute path rejected: {path}"
                )));
            }
            let abs = resolve_path_as(ctx, path, "edit")?;
            check_perm_with_preview(ctx, "edit", Some(path), Some(&preview))?;
            if let Ok(bytes) = tokio::fs::read(&abs).await {
                let h = crate::hash_bytes(&bytes);
                if crate::is_stale(ctx, &abs, &h) {
                    return Err(FreedasError::StaleRead(format!("{path} changed on disk")));
                }
                target_hashes.push((abs.clone(), h));
            }
            if matches!(op, CodexOp::Delete { .. }) {
                delete_paths.push((path.to_string(), abs));
            }
        }
        // Validate deletes before touching anything: a missing target must not
        // surface after the edits already landed.
        for (path, abs) in &delete_paths {
            let exists = tokio::fs::metadata(abs)
                .await
                .map(|m| m.is_file())
                .unwrap_or(false);
            if !exists {
                return Err(FreedasError::Tool(format!("delete target missing: {path}")));
            }
        }
        // Drift between permission checks and the real `patch` spawn is a
        // lost-update the binary cannot see; fail like a stale read.
        for (abs, h) in &target_hashes {
            if let Ok(bytes) = tokio::fs::read(abs).await {
                if crate::hash_bytes(&bytes) != *h {
                    return Err(FreedasError::StaleRead(
                        "patch target changed before apply".into(),
                    ));
                }
            }
        }
        let unified = codex_to_unified(&ops, &ctx.project_root)?;
        let target_strs: Vec<String> = ops.iter().map(|op| op.path().to_string()).collect();
        // Empty deletes contribute headers only (no hunks); `patch` skips
        // hunk-less files, so the removal below does the actual delete.
        let has_hunks = unified.lines().any(|l| l.starts_with("@@"));
        let out = if unified.trim().is_empty() || !has_hunks {
            None
        } else {
            // Non-empty deletes are part of `unified`, so the `--dry-run`
            // in `apply_via_patch_bin` validates them atomically.
            Some(apply_via_patch_bin(ctx, &unified, None).await?)
        };
        // TOCTOU: re-verify containment after the external `patch` run before
        // touching deletes natively.
        crate::verify_targets_contained(ctx, &target_strs)?;
        for (abs, _) in &target_hashes {
            if let Ok(bytes) = tokio::fs::read(abs).await {
                crate::record_hash(ctx, abs, crate::hash_bytes(&bytes));
            }
        }
        // macOS BSD patch exits 0 on `--- a/f +++ /dev/null` deletes but
        // leaves the file behind emptied, not unlinked: complete every
        // delete natively. Missing means GNU patch already unlinked it.
        for (path, abs) in &delete_paths {
            // Re-canonicalize right before the native delete: a symlink swap
            // since resolve must not redirect the unlink outside the project.
            crate::reverify_abs(ctx, abs, path)?;
            match tokio::fs::metadata(abs).await {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    return Err(FreedasError::Tool(format!(
                        "delete target unreadable: {path}: {e}"
                    )));
                }
                Ok(_) => {}
            }
            let content = tokio::fs::read(abs).await.map_err(|e| {
                FreedasError::Tool(format!("delete target unreadable: {path}: {e}"))
            })?;
            if content.is_empty() {
                tokio::fs::remove_file(abs)
                    .await
                    .map_err(|e| FreedasError::Tool(format!("delete failed: {path}: {e}")))?;
            } else {
                return Err(FreedasError::Tool(format!("delete did not remove {path}")));
            }
        }
        Ok(out.unwrap_or(ToolOutput {
            content: "patch applied".to_string(),
            metadata: json!({}),
            truncated: false,
        }))
    }
}

/// Run `patch` with `--dry-run` then for real. Returns combined output.
async fn apply_via_patch_bin(
    ctx: &ToolContext,
    diff: &str,
    pinned_path: Option<&str>,
) -> Result<ToolOutput> {
    let mut base = vec![
        "patch".to_string(),
        "--forward".to_string(),
        "-p1".to_string(),
        "-d".to_string(),
        ctx.project_root.to_string_lossy().to_string(),
    ];
    if let Some(p) = pinned_path {
        if p.starts_with('-') {
            return Err(FreedasError::Tool(format!(
                "patch target must not start with '-': {p}"
            )));
        }
        base.push("--".to_string());
        base.push(p.to_string());
    }
    // Confine `patch` to the project with network denied; the permission gate
    // already refused to upgrade `ask` when no backend exists, so the direct
    // fallback below runs only after an explicit approval.
    let wrap = |args: &[String]| -> Result<Vec<String>> {
        let off = !ctx.sandbox
            || std::env::var("FREEDAS_EXPERIMENTAL_SANDBOX")
                .map(|v| v == "false" || v == "0")
                .unwrap_or(false);
        if off {
            return Ok(args.to_vec());
        }
        let root = ctx.project_root.clone();
        let policy = freedas_sandbox::SandboxPolicy {
            read: vec![root.clone()],
            write: vec![root.clone()],
            network: "deny".to_string(),
            env_allowlist: Vec::new(),
            timeout_ms: 60_000,
            cwd: Some(root),
            allow_all_reads: false,
        };
        let prog = args[0].clone();
        let rest: Vec<&str> = args[1..].iter().map(|s| s.as_str()).collect();
        match freedas_sandbox::wrap_command(&policy, &prog, &rest) {
            Some(wrapped) => Ok(wrapped),
            None if ctx.config.sandbox.mode == "on" || ctx.approver.is_none() => {
                Err(FreedasError::SandboxUnavailable(
                    "no sandbox backend; refusing to run external patch unsandboxed".into(),
                ))
            }
            None => {
                eprintln!(
                    "freedas: sandbox: no backend available; running patch without OS sandbox"
                );
                Ok(args.to_vec())
            }
        }
    };
    let mut dry = base.clone();
    dry.insert(1, "--dry-run".to_string());
    let dry = wrap(&dry)?;
    let (ok, stdout, stderr) = run_patch(ctx, &dry, diff).await?;
    if !ok {
        return Err(FreedasError::Tool(format!(
            "patch rejected (dry-run):\n{stdout}{stderr}"
        )));
    }
    let base = wrap(&base)?;
    let (ok, stdout, stderr) = run_patch(ctx, &base, diff).await?;
    if !ok {
        return Err(FreedasError::Tool(format!(
            "patch failed:\n{stdout}{stderr}"
        )));
    }
    Ok(ToolOutput {
        content: if stdout.is_empty() {
            "patch applied".to_string()
        } else {
            stdout
        },
        metadata: json!({"diff": crate::cap_lines(diff, 200)}),
        truncated: false,
    })
}

/// Feed `diff` to the patch binary on stdin while draining its output, with a
/// hard timeout; blocking writes can otherwise deadlock on a large patch.
async fn run_patch(
    ctx: &ToolContext,
    args: &[String],
    diff: &str,
) -> Result<(bool, String, String)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut cmd = tokio::process::Command::new(&args[0]);
    cmd.args(&args[1..])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        // Never inherit provider keys/tokens into the patch subprocess.
        .env_clear()
        .kill_on_drop(true);
    for (k, v) in crate::env_allowlist(&ctx.config) {
        cmd.env(k, v);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| FreedasError::Tool(format!("patch binary unavailable: {e}")))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| FreedasError::Tool("patch stdin unavailable".into()))?;
    let data = diff.as_bytes().to_vec();
    let writer = tokio::spawn(async move {
        let _ = stdin.write_all(&data).await;
        let _ = stdin.shutdown().await;
    });
    let mut out_pipe = child
        .stdout
        .take()
        .ok_or_else(|| FreedasError::Tool("patch stdout unavailable".into()))?;
    let mut err_pipe = child
        .stderr
        .take()
        .ok_or_else(|| FreedasError::Tool("patch stderr unavailable".into()))?;
    let out_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = out_pipe.read_to_end(&mut buf).await;
        buf
    });
    let err_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = err_pipe.read_to_end(&mut buf).await;
        buf
    });
    let status = match tokio::time::timeout(std::time::Duration::from_secs(60), child.wait()).await
    {
        Ok(status) => status?,
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            let _ = writer.await;
            out_task.abort();
            err_task.abort();
            return Err(FreedasError::Tool("patch timed out".into()));
        }
    };
    let _ = writer.await;
    let stdout = String::from_utf8_lossy(&out_task.await.unwrap_or_default()).to_string();
    let stderr = String::from_utf8_lossy(&err_task.await.unwrap_or_default()).to_string();
    Ok((status.success(), stdout, stderr))
}

/// File paths a unified diff touches: both `---` and `+++` sides, so
/// deletions (`+++ /dev/null`) and renames are still checked.
fn diff_targets(diff: &str) -> Vec<String> {
    let lines: Vec<&str> = diff.lines().collect();
    let mut out = Vec::new();
    let push = |raw: &str, out: &mut Vec<String>| {
        if let Some(path) = strip_diff_path(raw)
            && !out.contains(&path)
        {
            out.push(path);
        }
    };
    let mut i = 0;
    while i + 1 < lines.len() {
        if let (Some(old), Some(new)) = (
            lines[i].strip_prefix("--- "),
            lines[i + 1].strip_prefix("+++ "),
        ) {
            for raw in [old, new] {
                push(raw, &mut out);
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    // Some producers emit only the `+++` side.
    if out.is_empty() {
        for line in &lines {
            if let Some(raw) = line.strip_prefix("+++ ") {
                push(raw, &mut out);
            }
        }
    }
    // Git rename headers bypass the `---`/`+++` pair, so check them too;
    // resolve_path downstream rejects any traversal they name.
    for line in &lines {
        if let Some(raw) = line
            .strip_prefix("rename from ")
            .or_else(|| line.strip_prefix("rename to "))
        {
            push(raw, &mut out);
        }
    }
    out
}

/// One header path: cut git/timestamp suffixes, drop `/dev/null`, unquote one
/// surrounding `"..."` pair (GNU patch unquotes), strip exactly one `a/` or
/// `b/` prefix.
fn strip_diff_path(raw: &str) -> Option<String> {
    let p = raw.split('\t').next().unwrap_or(raw).trim();
    if p.is_empty() || p == "/dev/null" {
        return None;
    }
    // GNU patch strips one surrounding quote pair and unescapes `\\`/`\"`.
    let p = p
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(p);
    let mut unescaped = String::with_capacity(p.len());
    let mut chars = p.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('\\') => unescaped.push('\\'),
                Some('"') => unescaped.push('"'),
                Some(next) => {
                    unescaped.push('\\');
                    unescaped.push(next);
                }
                None => unescaped.push('\\'),
            }
        } else {
            unescaped.push(c);
        }
    }
    let p = unescaped
        .strip_prefix("b/")
        .or_else(|| unescaped.strip_prefix("a/"))
        .unwrap_or(&unescaped)
        .trim();
    if p.is_empty() {
        None
    } else {
        Some(p.to_string())
    }
}

#[derive(Debug)]
enum CodexOp {
    Update { path: String, hunks: Vec<CodexHunk> },
    Add { path: String, lines: Vec<String> },
    Delete { path: String },
}

impl CodexOp {
    fn path(&self) -> &str {
        match self {
            Self::Update { path, .. } | Self::Add { path, .. } | Self::Delete { path } => path,
        }
    }
}

#[derive(Debug)]
struct CodexHunk {
    /// `-` lines must match the original file; ` ` lines are kept; `+` added.
    /// Each element is (kind, text) with kind in {' ', '-', '+'}.
    lines: Vec<(char, String)>,
}

fn parse_codex_patch(text: &str) -> std::result::Result<Vec<CodexOp>, String> {
    let mut ops = Vec::new();
    let mut lines = text.lines().peekable();
    // Skip to the Begin marker; tolerate missing marker by starting at the
    // first `*** ` op line.
    if !text.contains("*** Begin Patch") {
        // Best effort: the model may emit just the ops.
    }
    while let Some(line) = lines.next() {
        let line = line.trim_end();
        if line == "*** End Patch" {
            break;
        }
        if let Some(path) = line.strip_prefix("*** Update File:") {
            let path = path.trim().to_string();
            let mut hunks = Vec::new();
            let mut current: Option<CodexHunk> = None;
            while let Some(&next) = lines.peek() {
                let next = next.trim_end();
                if next.starts_with("*** ") {
                    break;
                }
                lines.next();
                if next.starts_with("@@") {
                    if let Some(h) = current.take() {
                        hunks.push(h);
                    }
                    current = Some(CodexHunk { lines: Vec::new() });
                    continue;
                }
                let h = current.get_or_insert_with(|| CodexHunk { lines: Vec::new() });
                if let Some(body) = next.strip_prefix('-') {
                    h.lines.push(('-', body.to_string()));
                } else if let Some(body) = next.strip_prefix('+') {
                    h.lines.push(('+', body.to_string()));
                } else if let Some(body) = next.strip_prefix(' ') {
                    h.lines.push((' ', body.to_string()));
                } else if next.is_empty() {
                    // Blank context line in Codex format is a space-less empty line.
                    h.lines.push((' ', String::new()));
                } else {
                    return Err(format!("update {path}: bad hunk line `{next}`"));
                }
            }
            if let Some(h) = current.take() {
                hunks.push(h);
            }
            ops.push(CodexOp::Update { path, hunks });
        } else if let Some(path) = line.strip_prefix("*** Add File:") {
            let path = path.trim().to_string();
            let mut body = Vec::new();
            while let Some(&next) = lines.peek() {
                if next.trim_end().starts_with("*** ") {
                    break;
                }
                lines.next();
                let n = next.trim_end();
                if let Some(l) = n.strip_prefix('+') {
                    body.push(l.to_string());
                } else if n.is_empty() {
                    body.push(String::new());
                } else {
                    return Err(format!("add {path}: bad line `{n}`"));
                }
            }
            ops.push(CodexOp::Add { path, lines: body });
        } else if let Some(path) = line.strip_prefix("*** Delete File:") {
            ops.push(CodexOp::Delete {
                path: path.trim().to_string(),
            });
        }
    }
    Ok(ops)
}

/// Translate Codex ops into a unified diff `patch -p1` can consume. Update
/// hunk headers use the real start line found from the hunk's context/removed
/// lines in the target file, so context occurring earlier in the file cannot
/// misplace the hunk.
fn codex_to_unified(ops: &[CodexOp], root: &Path) -> Result<String> {
    let mut out = String::new();
    for op in ops {
        if std::path::Path::new(op.path()).is_absolute() {
            return Err(FreedasError::Tool(format!(
                "absolute path rejected: {}",
                op.path()
            )));
        }
        match op {
            CodexOp::Delete { path } => {
                // Emit the delete as a unified diff so `patch --dry-run`
                // validates it atomically instead of a native `remove_file`.
                let content = std::fs::read_to_string(root.join(path)).unwrap_or_default();
                let lines: Vec<&str> = content.lines().collect();
                out.push_str(&format!("--- a/{path}\n+++ /dev/null\n"));
                // No hunk for empty files: `@@ -0,0 +0,0 @@` is rejected
                // by GNU patch; the caller completes the delete natively.
                if !lines.is_empty() {
                    out.push_str(&format!("@@ -1,{} +0,0 @@\n", lines.len()));
                    for l in lines {
                        out.push('-');
                        out.push_str(l);
                        out.push('\n');
                    }
                }
            }
            CodexOp::Add { path, lines } => {
                out.push_str(&format!("--- /dev/null\n+++ b/{path}\n"));
                out.push_str(&format!("@@ -0,0 +1,{} @@\n", lines.len()));
                for l in lines {
                    out.push('+');
                    out.push_str(l);
                    out.push('\n');
                }
            }
            CodexOp::Update { path, hunks } => {
                out.push_str(&format!("--- a/{path}\n+++ b/{path}\n"));
                let file = std::fs::read_to_string(root.join(path)).unwrap_or_default();
                let file_lines: Vec<&str> = file.lines().collect();
                let mut cursor = 0;
                for h in hunks {
                    let old_lines: Vec<&str> = h
                        .lines
                        .iter()
                        .filter(|(k, _)| *k != '+')
                        .map(|(_, l)| l.as_str())
                        .collect();
                    let start = match locate(&file_lines, &old_lines, cursor) {
                        Some(i) => {
                            cursor = i + old_lines.len();
                            i + 1
                        }
                        None => 1,
                    };
                    let old = old_lines.len();
                    let new = h.lines.iter().filter(|(k, _)| *k != '-').count();
                    out.push_str(&format!("@@ -{start},{old} +{start},{new} @@\n"));
                    for (k, l) in &h.lines {
                        out.push(*k);
                        out.push_str(l);
                        out.push('\n');
                    }
                }
            }
        }
    }
    Ok(out)
}

fn locate(lines: &[&str], needle: &[&str], from: usize) -> Option<usize> {
    if needle.is_empty() || needle.len() > lines.len() || from > lines.len() - needle.len() {
        return None;
    }
    (from..=lines.len() - needle.len()).find(|&i| lines[i..i + needle.len()] == *needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_from_diff() {
        let d = "--- a/src/a.rs\n+++ b/src/a.rs\n@@ -1 +1 @@\n-x\n+y\n--- /dev/null\n+++ b/new.rs\n@@\n+z";
        let t = diff_targets(d);
        assert!(t.contains(&"src/a.rs".to_string()));
        assert!(t.contains(&"new.rs".to_string()));
        assert!(!t.iter().any(|p| p.contains("/dev/null")));
    }

    #[test]
    fn targets_include_deletions_renames_and_timestamps() {
        let d = "--- a/gone.rs\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n--- a/old.rs\t2024-01-01 00:00:00\n+++ b/new.rs\t2024-01-01 00:00:01\n@@\n+file\n";
        let t = diff_targets(d);
        assert!(t.contains(&"gone.rs".to_string()), "{t:?}");
        assert!(t.contains(&"old.rs".to_string()), "{t:?}");
        assert!(t.contains(&"new.rs".to_string()), "{t:?}");
        // Exactly one prefix is stripped, so `b/a/x.rs` keeps its `a/`.
        let d = "--- a/a/x.rs\n+++ b/a/x.rs\n@@\n+x\n";
        assert!(diff_targets(d).contains(&"a/x.rs".to_string()));
    }

    #[test]
    fn codex_update_uses_real_start_line() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/main.rs"),
            "fn helper() {}\n\nfn main() {\n    old\n}\n",
        )
        .unwrap();
        let p = "*** Begin Patch\n*** Update File: src/main.rs\n@@\n fn main() {\n-    old\n+    new\n }\n*** End Patch\n";
        let ops = parse_codex_patch(p).unwrap();
        let u = codex_to_unified(&ops, root).unwrap();
        assert!(u.contains("@@ -3,3 +3,3 @@"), "{u}");
        assert!(u.contains("--- a/src/main.rs"));
        assert!(u.contains("-    old"));
        assert!(u.contains("+    new"));
    }

    #[test]
    fn codex_add_rejects_malformed_line() {
        let p = "*** Begin Patch\n*** Add File: foo.txt\n+hello\nnot-a-plus\n*** End Patch\n";
        let err = parse_codex_patch(p).unwrap_err();
        assert!(err.contains("bad line"), "{err}");
    }

    fn ctx(root: &std::path::Path) -> ToolContext {
        ToolContext {
            session_id: "ses_1".into(),
            project_root: root.to_path_buf(),
            cwd: root.to_path_buf(),
            config: freedas_core::config::Config::default(),
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
        }
    }

    #[tokio::test]
    async fn applies_unified_diff_and_rejects_bad_hunk() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("a.txt"), "hello\n").unwrap();
        let good = "--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-hello\n+world\n";
        PatchTool
            .execute(&json!({ "diff": good }), &ctx(root))
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("a.txt")).unwrap(),
            "world\n"
        );

        // A hunk that does not match must fail and leave the file untouched.
        let bad = "--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-nope\n+other\n";
        assert!(
            PatchTool
                .execute(&json!({ "diff": bad }), &ctx(root))
                .await
                .is_err()
        );
        assert_eq!(
            std::fs::read_to_string(root.join("a.txt")).unwrap(),
            "world\n"
        );
    }

    #[tokio::test]
    async fn codex_patch_adds_updates_and_deletes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("keep.txt"), "old\n").unwrap();
        std::fs::write(root.join("gone.txt"), "bye\n").unwrap();
        let patch = "*** Begin Patch\n\
*** Add File: new.txt\n\
+added\n\
*** Update File: keep.txt\n\
@@\n\
-old\n\
+new\n\
*** Delete File: gone.txt\n\
*** End Patch\n";
        ApplyPatchTool
            .execute(&json!({ "patch": patch }), &ctx(root))
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("new.txt")).unwrap(),
            "added\n"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("keep.txt")).unwrap(),
            "new\n"
        );
        assert!(!root.join("gone.txt").exists());
    }

    #[tokio::test]
    async fn codex_delete_only_patch_applies() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("gone.txt"), "bye\n").unwrap();
        ApplyPatchTool
            .execute(
                &json!({"patch": "*** Begin Patch\n*** Delete File: gone.txt\n*** End Patch\n"}),
                &ctx(root),
            )
            .await
            .unwrap();
        assert!(!root.join("gone.txt").exists());

        // A missing delete target is rejected before anything is written.
        std::fs::write(root.join("keep.txt"), "old\n").unwrap();
        let patch = "*** Begin Patch\n*** Update File: keep.txt\n@@\n-old\n+new\n*** Delete File: missing.txt\n*** End Patch\n";
        assert!(
            ApplyPatchTool
                .execute(&json!({ "patch": patch }), &ctx(root))
                .await
                .is_err()
        );
        assert_eq!(
            std::fs::read_to_string(root.join("keep.txt")).unwrap(),
            "old\n"
        );
    }

    #[test]
    fn codex_add() {
        let dir = tempfile::tempdir().unwrap();
        let p = "*** Begin Patch\n*** Add File: foo.txt\n+hello\n+world\n*** End Patch\n";
        let ops = parse_codex_patch(p).unwrap();
        let u = codex_to_unified(&ops, dir.path()).unwrap();
        assert!(u.contains("--- /dev/null"));
        assert!(u.contains("+hello"));
    }
}
