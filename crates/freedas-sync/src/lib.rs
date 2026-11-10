//! Sync/import of instructions and skills from other agents.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct PlanEntry {
    pub source: String,
    pub target: String,
    pub kind: String,
}

/// Skill names become a path component under `.freedas/skills/`. Only
/// `[a-z0-9-_]+` is accepted so `..`, `/`, and absolute names cannot escape.
pub fn is_valid_skill_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}
/// Frontmatter `name` with the same semantics as the skill/agent loader:
/// CRLF-normalized, requires a leading `---` line, splits on the first
/// closing `---`, first-colon split, unquote+trim. `None` when absent so the
/// caller falls back to the directory id.
fn frontmatter_name(text: &str) -> Option<String> {
    let owned;
    let text: &str = if text.contains('\r') {
        owned = text.replace("\r\n", "\n");
        &owned
    } else {
        text
    };
    let rest = text.strip_prefix("---\n")?;
    let (front, _) = rest.split_once("\n---")?;
    for line in front.lines() {
        if let Some((k, v)) = line.split_once(':')
            && k.trim() == "name"
        {
            return Some(
                v.trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .trim()
                    .to_string(),
            );
        }
    }
    None
}

/// Slash commands owned by the product; mirrors
/// `freedas-skill::is_reserved_name` so detect skips the same ids the loader
/// would refuse instead of creating stray skill dirs.
fn is_reserved_name(id: &str) -> bool {
    const RESERVED: &[&str] = &[
        "new",
        "clear",
        "sessions",
        "resume",
        "continue",
        "rename",
        "fork",
        "compact",
        "summarize",
        "undo",
        "redo",
        "editor",
        "move",
        "export",
        "copy",
        "timestamps",
        "thinking",
        "status",
        "debug",
        "changelog",
        "help",
        "exit",
        "quit",
        "q",
        "init",
        "sync",
        "adopt",
        "agents",
        "variants",
        "mcps",
        "login",
        "credits",
        "usage",
        "workspace",
        "billing",
        "org",
        "orgs",
        "switch-org",
        "remote",
        "rc",
        "update",
        "code-standards",
        "ui-standards",
        "review",
        "standards-review",
        "standards-audit",
        "ui-review",
        "ui-audit",
        "quick-plan",
        "plan-quick",
        "deep-plan",
        "plan-deep",
    ];
    let name = id.trim_start_matches('/');
    RESERVED.iter().any(|b| b.eq_ignore_ascii_case(name))
}

/// True when `target` (a plan-relative path) stays inside `project_root` once
/// joined: rejects absolute paths and any `..` component.
fn target_within_root(project_root: &Path, target: &str) -> bool {
    let rel = Path::new(target);
    if rel.is_absolute() {
        return false;
    }
    if rel.components().any(|c| {
        matches!(
            c,
            std::path::Component::ParentDir
                | std::path::Component::RootDir
                | std::path::Component::Prefix(_)
        )
    }) {
        return false;
    }
    project_root.join(rel).starts_with(project_root)
}

pub fn detect(project_root: &Path) -> Vec<PlanEntry> {
    let mut entries = Vec::new();
    for src in [
        "CLAUDE.md",
        "GEMINI.md",
        ".cursorrules",
        ".windsurfrules",
        ".clinerules",
        ".github/copilot-instructions.md",
    ] {
        if project_root.join(src).exists() {
            entries.push(PlanEntry {
                source: src.into(),
                target: "AGENTS.md".into(),
                kind: "merge".into(),
            });
        }
    }
    let cursor_dir = project_root.join(".cursor").join("rules");
    if cursor_dir.exists() {
        for e in walk_md(&cursor_dir)
            .into_iter()
            .filter(|p| p.extension().map(|x| x == "mdc").unwrap_or(false))
        {
            let rel = e.strip_prefix(project_root).unwrap_or(&e);
            entries.push(PlanEntry {
                source: rel.to_string_lossy().to_string(),
                target: "AGENTS.md".into(),
                kind: "merge".into(),
            });
        }
    }
    for base in [".claude/skills", ".agents/skills"] {
        let dir = project_root.join(base);
        if dir.exists() {
            for e in walk_md(&dir) {
                if e.file_name().map(|n| n == "SKILL.md").unwrap_or(false) {
                    // Copy the whole skill directory, not just SKILL.md.
                    let src_dir = e.parent().map(|p| p.to_path_buf()).unwrap_or_default();
                    // Frontmatter `name` wins over the directory name.
                    let name = std::fs::read_to_string(&e)
                        .ok()
                        .and_then(|t| frontmatter_name(&t))
                        .filter(|n| !n.is_empty())
                        .or_else(|| src_dir.file_name().map(|n| n.to_string_lossy().to_string()))
                        .unwrap_or_default();
                    // Reject `..`, `/`, absolute, anything outside `[a-z0-9-_]+`,
                    // and reserved slash-command names the loader would skip.
                    if !is_valid_skill_name(&name) || is_reserved_name(&name) {
                        continue;
                    }
                    entries.push(PlanEntry {
                        source: src_dir
                            .strip_prefix(project_root)
                            .unwrap_or(&src_dir)
                            .to_string_lossy()
                            .to_string(),
                        target: format!(".freedas/skills/{name}"),
                        kind: "copydir".into(),
                    });
                }
            }
        }
    }
    entries
}

/// Depth cap for tree walks; a symlink-free tree this deep is not a skill.
const MAX_DEPTH: u8 = 32;

/// Copy a directory tree recursively. Symlinks are skipped: following them
/// copies files from outside the skill directory and can loop forever.
pub fn copy_dir(src: &Path, dest: &Path) -> std::io::Result<()> {
    copy_dir_at(src, dest, 0)
}

fn copy_dir_at(src: &Path, dest: &Path, depth: u8) -> std::io::Result<()> {
    if depth > MAX_DEPTH {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("copy depth limit exceeded at {}", src.display()),
        ));
    }
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        let target = dest.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_at(&entry.path(), &target, depth + 1)?;
        } else if file_type.is_file() {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

/// SHA-256 hex of a file's contents (or of the directory file list+contents).
/// Directory hashes use paths relative to the hashed root plus file bytes,
/// so a copy in a different location hashes the same.
pub fn content_hash(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    if path.is_dir() {
        let mut files = Vec::new();
        collect_files(path, &mut files);
        files.sort();
        for f in files {
            let rel = f.strip_prefix(path).unwrap_or(&f);
            h.update(rel.to_string_lossy().as_bytes());
            h.update([0]);
            if let Ok(b) = std::fs::read(&f) {
                h.update(b);
            }
            h.update([0]);
        }
    } else if let Ok(b) = std::fs::read(path) {
        h.update(b);
    }
    hex::encode(h.finalize())
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    collect_files_at(dir, out, 0)
}

fn collect_files_at(dir: &Path, out: &mut Vec<PathBuf>, depth: u8) {
    if depth > MAX_DEPTH {
        return;
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let Ok(file_type) = e.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            let p = e.path();
            if file_type.is_dir() {
                collect_files_at(&p, out, depth + 1);
            } else if file_type.is_file() {
                out.push(p);
            }
        }
    }
}

/// Content equality for files and directories; directory comparison uses
/// paths relative to the root so a copy in a different location still matches.
fn same_contents(a: &Path, b: &Path) -> bool {
    if a.is_dir() != b.is_dir() {
        return false;
    }
    if !a.is_dir() {
        return std::fs::read(a).ok() == std::fs::read(b).ok();
    }
    let (mut left, mut right) = (Vec::new(), Vec::new());
    collect_files(a, &mut left);
    collect_files(b, &mut right);
    let relative = |files: &[PathBuf], root: &Path| -> Vec<(PathBuf, Vec<u8>)> {
        let mut out: Vec<(PathBuf, Vec<u8>)> = files
            .iter()
            .filter_map(|file| {
                Some((
                    file.strip_prefix(root).ok()?.to_path_buf(),
                    std::fs::read(file).ok()?,
                ))
            })
            .collect();
        out.sort_by(|x, y| x.0.cmp(&y.0));
        out
    };
    relative(&left, a) == relative(&right, b)
}

/// Ledger entries in the `{version:1, entries:[...]}` shape, reading the
/// pre-version flat map once.
fn ledger_entries(project_root: &Path) -> Vec<serde_json::Value> {
    let ledger = project_root.join(".freedas").join("sync.json");
    let existing: serde_json::Value = std::fs::read_to_string(&ledger)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    if let Some(arr) = existing.get("entries").and_then(|e| e.as_array()) {
        return arr.clone();
    }
    // Legacy flat map: { "<source>": {target,hash,time} }.
    existing
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(src, e)| {
                    Some(serde_json::json!({
                        "source": src,
                        "target": e.get("target")?.as_str()?,
                        "hash": e.get("hash")?.as_str()?,
                        "importedAt": e.get("time").and_then(|t| t.as_i64()).unwrap_or(0),
                    }))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Read-only: true when `source` has no recorded entry matching `hash`, so the
/// source still needs to be applied. `record_apply` advances the ledger only
/// after the write succeeds.
pub fn record_needed(project_root: &Path, source: &str, hash: &str) -> bool {
    !ledger_entries(project_root).iter().any(|e| {
        e.get("source").and_then(|s| s.as_str()) == Some(source)
            && e.get("hash").and_then(|h| h.as_str()) == Some(hash)
    })
}

/// Record successful imports in `.freedas/sync.json` in one write.
pub fn record_apply_all(project_root: &Path, entries: &[(String, String, String)]) {
    if entries.is_empty() {
        return;
    }
    let mut ledger = ledger_entries(project_root);
    let now = freedas_core::paths::now_ms();
    for (source, target, hash) in entries {
        if let Some(e) = ledger
            .iter_mut()
            .find(|e| e.get("source").and_then(|s| s.as_str()) == Some(source.as_str()))
        {
            e["target"] = serde_json::json!(target);
            e["hash"] = serde_json::json!(hash);
            e["importedAt"] = serde_json::json!(now);
        } else {
            ledger.push(serde_json::json!({
                "source": source,
                "target": target,
                "hash": hash,
                "importedAt": now,
            }));
        }
    }
    let ledger_path = project_root.join(".freedas").join("sync.json");
    if let Some(parent) = ledger_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(
        &ledger_path,
        serde_json::to_string_pretty(&serde_json::json!({"version": 1, "entries": ledger}))
            .unwrap_or_default(),
    );
}

/// Record a successful import in `.freedas/sync.json`.
pub fn record_apply(project_root: &Path, source: &str, target: &str, hash: &str) {
    record_apply_all(
        project_root,
        &[(source.to_string(), target.to_string(), hash.to_string())],
    );
}

/// Byte span of the managed section: `Ok(None)` when `source` has no section,
/// `Err` when the markers are malformed (missing end, stray end before begin,
/// or duplicates) — replacing those would truncate or grow the file.
fn marker_span(existing: &str, source: &str) -> Result<Option<std::ops::Range<usize>>, ()> {
    let begin = format!("<!-- freedas:sync:begin source=\"{source}\" -->");
    let end = format!("<!-- freedas:sync:end source=\"{source}\" -->");
    let mut begins = existing.match_indices(&begin);
    let Some((start, _)) = begins.next() else {
        return Ok(None);
    };
    if begins.next().is_some() || existing.matches(&end).count() != 1 {
        return Err(());
    }
    let end_idx = existing.find(&end).ok_or(())?;
    if end_idx < start {
        return Err(());
    }
    Ok(Some(start..end_idx + end.len()))
}

/// True when every begin marker for `source` has a matching end marker.
fn markers_intact(existing: &str, source: &str) -> bool {
    marker_span(existing, source).is_ok()
}

/// Ledger key for `source`: relative to the project root when possible, so a
/// moved checkout keeps the same key for identical contents.
fn ledger_key(project_root: &Path, source: &str) -> String {
    let p = Path::new(source);
    if p.is_absolute()
        && let Ok(rel) = p.strip_prefix(project_root)
    {
        return rel.to_string_lossy().to_string();
    }
    source.to_string()
}

/// Resolve a plan source to a filesystem path. Absolute entries (from older
/// scans) still resolve; relative entries join under the root.
fn resolve_src(project_root: &Path, source: &str) -> PathBuf {
    let p = Path::new(source);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        project_root.join(p)
    }
}

/// Backup path that never clobbers an existing backup: `<target>.bak`,
/// then `<target>.bak.1`, `<target>.bak.2`, ...
fn unique_backup(target: &Path) -> PathBuf {
    let base = format!("{}.bak", target.display());
    let first = PathBuf::from(&base);
    if !first.exists() {
        return first;
    }
    let mut n = 1u32;
    loop {
        let q = PathBuf::from(format!("{base}.{n}"));
        if !q.exists() {
            return q;
        }
        n += 1;
    }
}

/// Sibling temp path for atomic replacement.
fn unique_tmp(target: &Path) -> PathBuf {
    let base = format!(
        "{}.tmp.{}-{}",
        target.display(),
        std::process::id(),
        freedas_core::paths::now_ms()
    );
    let first = PathBuf::from(&base);
    if !first.exists() {
        return first;
    }
    let mut n = 1u32;
    loop {
        let q = PathBuf::from(format!("{base}.{n}"));
        if !q.exists() {
            return q;
        }
        n += 1;
    }
}

/// Copy a skill directory via a temp dir then rename, so a failed or killed
/// copy never leaves a half-written target. Existing backups are never
/// deleted; a fresh unique `.bak` name is used per conflict. The target must
/// stay within `project_root`; absolute or `..` targets are refused.
fn copy_dir_atomic(
    src: &Path,
    target: &Path,
    project_root: &Path,
) -> std::io::Result<Option<PathBuf>> {
    // Belt and suspenders: the caller checks `target_within_root`, and this
    // asserts it again so a future caller cannot silently escape the project.
    assert!(
        target.starts_with(project_root),
        "copy target escapes project root"
    );
    if !target.starts_with(project_root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("copy target escapes project root: {}", target.display()),
        ));
    }
    // `project_root.join("..")` still `starts_with` lexically, so reject any
    // `..` outright: a canonical root never contains one.
    if target
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("copy target escapes project root: {}", target.display()),
        ));
    }
    let mut backup: Option<PathBuf> = None;
    if target.exists() && !same_contents(target, src) {
        // Never lose local edits silently and never destroy a prior backup.
        let bak = unique_backup(target);
        let backed_up = if target.is_dir() {
            copy_dir(target, &bak).is_ok()
        } else {
            std::fs::copy(target, &bak).is_ok()
        };
        if !backed_up {
            return Err(std::io::Error::other(format!(
                "backup of {} failed",
                target.display()
            )));
        }
        backup = Some(bak);
    } else if target.exists() {
        return Ok(None);
    }
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = unique_tmp(target);
    // Copy first; only touch the live target once the copy landed.
    let copied = copy_dir(src, &tmp).is_ok();
    if !copied {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(std::io::Error::other(format!(
            "copy of {} failed",
            src.display()
        )));
    }
    if target.exists() {
        if target.is_dir() {
            std::fs::remove_dir_all(target)?;
        } else {
            std::fs::remove_file(target)?;
        }
    }
    match std::fs::rename(&tmp, target) {
        Ok(()) => Ok(backup),
        Err(e) => {
            let _ = std::fs::remove_dir_all(&tmp);
            Err(e)
        }
    }
}

/// Apply a stored plan list: merge instructions into AGENTS.md and copy skill
/// directories. Returns `(applied, skipped)`. The TUI passes the offered list
/// it showed so files added or removed between offer and confirm cannot change
/// what gets applied.
pub fn apply_plan(project_root: &Path, entries: &[PlanEntry]) -> std::io::Result<(usize, usize)> {
    let agents = project_root.join("AGENTS.md");
    let mut content = std::fs::read_to_string(&agents).unwrap_or_default();
    let (mut applied, mut skipped) = (0usize, 0usize);
    // Defer ledger writes until the file changes have landed; recording first
    // would mark content imported even if the write then failed.
    let mut pending: Vec<(String, String, String)> = Vec::new();
    for e in entries {
        // A crafted `PlanEntry` must not escape the project: refuse absolute
        // paths and any `..`, and re-check the joined path stays inside.
        if !target_within_root(project_root, &e.target) {
            skipped += 1;
            continue;
        }
        let src = resolve_src(project_root, &e.source);
        let key = ledger_key(project_root, &e.source);
        let hash = content_hash(&src);
        if !record_needed(project_root, &key, &hash) {
            skipped += 1;
            continue;
        }
        if e.kind == "merge" {
            let Ok(c) = std::fs::read_to_string(&src) else {
                skipped += 1;
                continue;
            };
            // A malformed marker pair would otherwise silently truncate
            // everything after the begin marker; refuse instead.
            if !markers_intact(&content, &key) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "malformed sync markers for {key} in AGENTS.md: missing or misplaced end marker"
                    ),
                ));
            }
            content = merge_agents_md(&content, &key, &c);
            pending.push((key, e.target.clone(), hash));
            applied += 1;
        } else if e.kind == "copydir" {
            // Defense in depth: `detect` only emits `[a-z0-9-_]+` names, but a
            // stored plan could predate validation.
            if let Some(name) = e.target.strip_prefix(".freedas/skills/")
                && !is_valid_skill_name(name)
            {
                skipped += 1;
                continue;
            }
            let target = project_root.join(&e.target);
            assert!(
                target.starts_with(project_root),
                "copy target escapes project root"
            );
            match copy_dir_atomic(&src, &target, project_root) {
                Ok(backup) => {
                    if let Some(bak) = backup {
                        eprintln!(
                            "conflict: {} exists and differs; backed up to {}",
                            e.target,
                            bak.display()
                        );
                    }
                    pending.push((key, e.target.clone(), hash));
                    applied += 1;
                }
                Err(_) => {
                    eprintln!("conflict: {} exists and differs; left in place", e.target);
                    skipped += 1;
                }
            }
        }
    }
    // Write the merged instructions before recording them.
    std::fs::write(&agents, &content)?;
    record_apply_all(project_root, &pending);
    Ok((applied, skipped))
}

/// Apply every detected source: merge instructions into AGENTS.md and copy
/// skill directories. Returns `(applied, skipped)`.
pub fn apply(project_root: &Path) -> std::io::Result<(usize, usize)> {
    let entries = detect(project_root);
    apply_plan(project_root, &entries)
}

fn walk_md(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let Ok(file_type) = e.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            let p = e.path();
            if file_type.is_dir() {
                out.extend(walk_md(&p));
            } else if p
                .extension()
                .map(|x| x == "md" || x == "mdc")
                .unwrap_or(false)
            {
                out.push(p);
            }
        }
    }
    out
}

pub fn merge_agents_md(existing: &str, source: &str, content: &str) -> String {
    let section = format!(
        "<!-- freedas:sync:begin source=\"{source}\" -->\n{content}\n<!-- freedas:sync:end source=\"{source}\" -->\n"
    );
    match marker_span(existing, source) {
        Ok(Some(span)) => {
            let mut out = existing[..span.start].to_string();
            out.push_str(&section);
            out.push_str(existing[span.end..].trim_start_matches('\n'));
            out
        }
        Ok(None) => {
            let mut out = existing.to_string();
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&section);
            out
        }
        // Malformed markers: leave the file alone; `apply` reports the error.
        Err(()) => existing.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn merge_adds_and_replaces() {
        let first = merge_agents_md("# Mine\n", "CLAUDE.md", "hello");
        assert!(first.contains("hello"));
        let second = merge_agents_md(&first, "CLAUDE.md", "world");
        assert!(second.contains("world") && !second.contains("hello"));
        assert_eq!(second.matches("freedas:sync:begin").count(), 1);
    }

    #[test]
    fn record_needed_is_read_only_until_apply() {
        let dir = tempfile::tempdir().unwrap();
        assert!(record_needed(dir.path(), "CLAUDE.md", "sha256:1"));
        assert!(!dir.path().join(".freedas/sync.json").exists());
        record_apply(dir.path(), "CLAUDE.md", "AGENTS.md", "sha256:1");
        assert!(!record_needed(dir.path(), "CLAUDE.md", "sha256:1"));
        assert!(record_needed(dir.path(), "CLAUDE.md", "sha256:2"));
        let text = std::fs::read_to_string(dir.path().join(".freedas/sync.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["version"], 1);
        assert_eq!(value["entries"][0]["target"], "AGENTS.md");
    }

    #[test]
    fn identical_skill_copy_needs_no_backup() {
        let dir = tempfile::tempdir().unwrap();
        let skill = dir.path().join(".claude/skills/release");
        std::fs::create_dir_all(&skill).unwrap();
        std::fs::write(skill.join("SKILL.md"), "---\nname: release\n---\nbody").unwrap();
        let target = dir.path().join(".freedas/skills/release");
        copy_dir(&skill, &target).unwrap();
        assert!(same_contents(&skill, &target));
        std::fs::write(target.join("SKILL.md"), "different").unwrap();
        assert!(!same_contents(&skill, &target));
    }

    #[test]
    fn malformed_markers_refuse_instead_of_truncating() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("CLAUDE.md"), "hello").unwrap();
        let broken = "<!-- freedas:sync:begin source=\"CLAUDE.md\" -->\nkeep me\n";
        std::fs::write(dir.path().join("AGENTS.md"), broken).unwrap();
        let err = apply(dir.path()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("AGENTS.md")).unwrap(),
            broken
        );
    }

    #[test]
    fn stray_end_before_begin_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("CLAUDE.md"), "hello").unwrap();
        let broken = "<!-- freedas:sync:end source=\"CLAUDE.md\" -->\nkeep me\n<!-- freedas:sync:begin source=\"CLAUDE.md\" -->\ntail\n";
        std::fs::write(dir.path().join("AGENTS.md"), broken).unwrap();
        assert!(apply(dir.path()).is_err());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("AGENTS.md")).unwrap(),
            broken
        );
    }

    #[test]
    fn duplicate_begin_markers_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("CLAUDE.md"), "hello").unwrap();
        let broken = "<!-- freedas:sync:begin source=\"CLAUDE.md\" -->\na\n<!-- freedas:sync:begin source=\"CLAUDE.md\" -->\nb\n<!-- freedas:sync:end source=\"CLAUDE.md\" -->\n";
        std::fs::write(dir.path().join("AGENTS.md"), broken).unwrap();
        assert!(apply(dir.path()).is_err());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("AGENTS.md")).unwrap(),
            broken
        );
    }

    #[test]
    fn ledger_is_written_only_after_agents_md() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("CLAUDE.md"), "hello").unwrap();
        // A directory where the file should be makes the final write fail.
        std::fs::create_dir_all(dir.path().join("AGENTS.md")).unwrap();
        assert!(apply(dir.path()).is_err());
        assert!(!dir.path().join(".freedas/sync.json").exists());
    }

    #[test]
    fn successful_apply_records_ledger() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("CLAUDE.md"), "hello").unwrap();
        let (applied, _) = apply(dir.path()).unwrap();
        assert_eq!(applied, 1);
        assert!(
            std::fs::read_to_string(dir.path().join("AGENTS.md"))
                .unwrap()
                .contains("hello")
        );
        let text = std::fs::read_to_string(dir.path().join(".freedas/sync.json")).unwrap();
        assert!(text.contains("CLAUDE.md"));
        let (applied, skipped) = apply(dir.path()).unwrap();
        assert_eq!((applied, skipped), (0, 1));
    }

    #[cfg(unix)]
    #[test]
    fn copy_dir_skips_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("skill");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("SKILL.md"), "body").unwrap();
        let secret = dir.path().join("secret.txt");
        std::fs::write(&secret, "token").unwrap();
        std::os::unix::fs::symlink(&secret, src.join("leak")).unwrap();
        std::os::unix::fs::symlink(dir.path(), src.join("loop")).unwrap();

        let dest = dir.path().join("out");
        copy_dir(&src, &dest).unwrap();
        assert!(dest.join("SKILL.md").exists());
        assert!(!dest.join("leak").exists());
        assert!(!dest.join("loop").exists());
    }
}
