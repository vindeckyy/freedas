//! Benchmark harness: run tasks in sandboxes and measure accuracy/cost.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Task {
    pub id: String,
    pub prompt: String,
    pub repo: String,
    pub base_branch: String,
    pub timeout_minutes: u32,
}

#[derive(Debug, Serialize)]
pub struct BenchResult {
    pub task_id: String,
    /// Only sandboxed runs count toward the pass total.
    pub verified: bool,
    pub passed: bool,
    pub cost_usd: f64,
    pub tokens: u64,
}

pub fn load_task(dir: &Path) -> Result<Task, String> {
    let path = dir.join("task.yaml");
    let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    parse_task_yaml(&text)
}

/// Minimal YAML reader for flat `task.yaml` files: comments, quoted and plain
/// scalars, plain-scalar continuations, and `|` / `>` block scalars.
pub fn parse_task_yaml(text: &str) -> Result<Task, String> {
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let raw = lines[i];
        let trimmed = raw.trim();
        i += 1;
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        if indent > 0 {
            // Nested mapping outside a block scalar; task.yaml is flat.
            continue;
        }
        let Some((key, rest)) = trimmed.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let rest = rest.trim();
        if rest.starts_with('|') || rest.starts_with('>') {
            let folded = rest.starts_with('>');
            let strip = rest.contains('-');
            let mut body: Vec<String> = Vec::new();
            let mut body_indent: Option<usize> = None;
            while i < lines.len() {
                let line = lines[i];
                if !line.trim().is_empty() {
                    let line_indent = line.len() - line.trim_start().len();
                    if line_indent <= indent {
                        break;
                    }
                    body_indent.get_or_insert(line_indent);
                }
                body.push(line.to_string());
                i += 1;
            }
            while body.last().is_some_and(|line| line.trim().is_empty()) {
                body.pop();
            }
            let body_indent = body_indent.unwrap_or(0);
            let dedented: Vec<&str> = body
                .iter()
                .map(|line| {
                    if line.len() >= body_indent {
                        &line[body_indent..]
                    } else {
                        ""
                    }
                })
                .collect();
            let mut value = if folded {
                dedented.join(" ")
            } else {
                dedented.join("\n")
            };
            if !strip {
                value.push('\n');
            }
            fields.insert(key.to_string(), value);
            continue;
        }

        let mut value = if let Some(quote) = rest.chars().next().filter(|c| *c == '"' || *c == '\'')
        {
            match rest[1..].find(quote) {
                Some(end) => rest[1..1 + end].to_string(),
                None => rest[1..].to_string(),
            }
        } else {
            strip_comment(rest).to_string()
        };
        // Plain scalars fold continuation lines indented under the key.
        while i < lines.len() {
            let next = lines[i];
            let next_indent = next.len() - next.trim_start().len();
            if next.trim().is_empty() || next_indent <= indent {
                break;
            }
            value.push(' ');
            value.push_str(strip_comment(next.trim()));
            i += 1;
        }
        fields.insert(key.to_string(), value.trim().to_string());
    }

    let id = fields.remove("id").ok_or("task.yaml missing id")?;
    // The id becomes a filesystem component and a log token: a tight charset
    // rejects traversal, absolute paths, and control-character forgery.
    let id_ok = !id.is_empty()
        && id.len() <= 64
        && !id.contains("..")
        && id.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));
    if !id_ok {
        return Err(format!("task.yaml id {id:?} must match [A-Za-z0-9_-]"));
    }
    for leftover in fields.keys() {
        eprintln!("freedas-bench: ignoring unknown task.yaml key {leftover:?}");
    }
    Ok(Task {
        id,
        prompt: fields.remove("prompt").ok_or("task.yaml missing prompt")?,
        repo: fields.remove("repo").ok_or("task.yaml missing repo")?,
        base_branch: fields
            .remove("base_branch")
            .ok_or("task.yaml missing base_branch")?,
        timeout_minutes: match fields.remove("timeout_minutes") {
            Some(value) => value
                .parse::<u32>()
                .map_err(|e| format!("task.yaml timeout_minutes: {e}"))?,
            None => 30,
        },
    })
}

fn strip_comment(value: &str) -> &str {
    for (i, ch) in value.char_indices() {
        if ch == '#' && (i == 0 || value.as_bytes()[i - 1].is_ascii_whitespace()) {
            return value[..i].trim_end();
        }
    }
    value.trim_end()
}

pub fn list_tasks(suite: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let root = suite
        .canonicalize()
        .unwrap_or_else(|_| suite.to_path_buf());
    if let Ok(entries) = std::fs::read_dir(suite) {
        for e in entries.flatten() {
            // Symlinked entries would pull task content from outside the suite.
            if e.file_type().map(|t| t.is_symlink()).unwrap_or(true) {
                continue;
            }
            let p = e.path();
            if !p.is_dir() || !p.join("task.yaml").exists() {
                continue;
            }
            if let Ok(canon) = p.canonicalize()
                && canon.starts_with(&root)
            {
                out.push(canon);
            }
        }
    }
    out.sort();
    out
}

/// Run one task's tests; convenience wrapper that drops the sandbox flag.
/// Test-only: production callers must see `verified`, not just `passed`.
#[cfg(test)]
async fn run_task_tests(repo: &Path, task_dir: &Path) -> bool {
    run_task_tests_verified(repo, task_dir).await.passed
}

/// Outcome of one task's tests: pass/fail plus whether an OS sandbox
/// contained the run. A run without a sandbox backend is unverified; record
/// it as such (benchmark validity gate).
pub struct TaskOutcome {
    pub passed: bool,
    pub verified: bool,
}

/// Run one task's tests in a checked-out repo, bounded by the task's
/// `timeout_minutes` (clamped to 1..=60 so a bad task.yaml cannot hang a
/// bench run). A task with no runner fails: a missing check is not a pass.
pub async fn run_task_tests_verified(repo: &Path, task_dir: &Path) -> TaskOutcome {
    let fail = |verified: bool| TaskOutcome {
        passed: false,
        verified,
    };
    let timeout_minutes = load_task(task_dir)
        .map(|task| task.timeout_minutes)
        .unwrap_or(30)
        .clamp(1, 60);
    let tests_dir = task_dir.join("tests");
    let script = tests_dir.join("run.sh");
    // A symlinked run.sh (or tests dir) would execute content outside the
    // suite; require the resolved path to stay inside the task directory.
    let task_root = task_dir
        .canonicalize()
        .unwrap_or_else(|_| task_dir.to_path_buf());
    let script_ok = script
        .canonicalize()
        .map(|c| c.starts_with(&task_root))
        .unwrap_or(false);
    let (program, args, task_env): (String, Vec<String>, Vec<(String, String)>) = if script.exists()
        && script_ok
    {
        (
            "/bin/bash".to_string(),
            vec![script.to_string_lossy().into_owned()],
            vec![(
                "TASK_DIR".to_string(),
                tests_dir.to_string_lossy().into_owned(),
            )],
        )
    } else if repo.join("Cargo.toml").exists() {
        ("cargo".to_string(), vec!["test".to_string()], Vec::new())
    } else if repo.join("package.json").exists() {
        ("npm".to_string(), vec!["test".to_string()], Vec::new())
    } else if repo.join("pyproject.toml").exists() {
        ("pytest".to_string(), Vec::new(), Vec::new())
    } else {
        return fail(true);
    };
    let policy = freedas_sandbox::SandboxPolicy {
        read: vec![repo.to_path_buf(), task_dir.to_path_buf()],
        write: vec![repo.to_path_buf()],
        network: "deny".to_string(),
        env_allowlist: Vec::new(),
        timeout_ms: u64::from(timeout_minutes) * 60_000,
        cwd: Some(repo.to_path_buf()),
        allow_all_reads: false,
    };
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (argv, verified) = match freedas_sandbox::wrap_command(&policy, &program, &arg_refs) {
        Some(wrapped) => (wrapped, true),
        None => {
            // Untrusted test code without a sandbox is a fail, not a pass —
            // opt in explicitly for trusted suites on bare-metal machines.
            if std::env::var("FREEDAS_BENCH_ALLOW_UNSANDBOXED").as_deref() != Ok("1") {
                eprintln!(
                    "freedas: sandbox: no backend; refusing untrusted bench tests                      (set FREEDAS_BENCH_ALLOW_UNSANDBOXED=1 to override)"
                );
                return fail(false);
            }
            eprintln!("freedas: sandbox: no backend available; running bench without OS sandbox");
            let mut v = vec![program.clone()];
            v.extend(args.clone());
            (v, false)
        }
    };
    let (prog, rest) = argv.split_first().expect("non-empty sandbox argv");
    let mut command = tokio::process::Command::new(prog);
    command
        .args(rest)
        .current_dir(repo)
        .kill_on_drop(true)
        .env_clear()
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for (k, v) in bench_env(repo) {
        command.env(k, v);
    }
    for (k, v) in task_env {
        command.env(k, v);
    }
    #[cfg(unix)]
    command.process_group(0);
    let child = match command.spawn() {
        Ok(c) => c,
        Err(_) => return fail(verified),
    };
    let pid = child.id();
    let limit = Duration::from_secs(u64::from(timeout_minutes) * 60);
    match tokio::time::timeout(limit, child.wait_with_output()).await {
        Ok(Ok(output)) => TaskOutcome {
            passed: output.status.success(),
            verified,
        },
        Ok(Err(_)) => fail(verified),
        Err(_) => {
            kill_group(pid);
            fail(verified)
        }
    }
}

/// Minimal environment for bench test subprocesses: PATH/TMP plus locale.
/// Provider keys, tokens, and the user's real HOME never reach the task's
/// tests; HOME is the checked-out repo so writes stay in the workspace.
fn bench_env(repo: &Path) -> Vec<(String, String)> {
    const KEYS: &[&str] = &["PATH", "TMPDIR", "TMP", "TEMP", "LANG"];
    let mut out: Vec<(String, String)> = std::env::vars()
        .filter(|(k, _)| KEYS.contains(&k.as_str()) || k.starts_with("LC_"))
        .collect();
    out.push(("HOME".to_string(), repo.to_string_lossy().into_owned()));
    out.push(("USER".to_string(), "freedas-bench".to_string()));
    out
}

/// Kill the whole process group via killpg; no /bin/kill dependency.
fn kill_group(pid: Option<u32>) {
    #[cfg(unix)]
    if let Some(pid) = pid {
        unsafe { killpg(pid as i32, 9) };
    }
    #[cfg(not(unix))]
    let _ = pid;
}

#[cfg(unix)]
unsafe extern "C" {
    fn killpg(pgrp: i32, sig: i32) -> i32;
}

pub fn summarize(results: &[BenchResult]) -> String {
    // An unsandboxed PASS proves nothing; only verified runs count.
    let passed = results.iter().filter(|r| r.passed && r.verified).count();
    let total_cost: f64 = results.iter().map(|r| r.cost_usd).sum();
    let total_tokens: u64 = results.iter().map(|r| r.tokens).sum();
    let mean_cost = if results.is_empty() {
        0.0
    } else {
        total_cost / results.len() as f64
    };
    format!(
        "passed {passed}/{} · mean cost ${mean_cost:.4}/task · {total_tokens} tokens",
        results.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_task_yaml() {
        let t = parse_task_yaml(
            "id: t1\nprompt: \"add tests\"\nrepo: o/r\nbase_branch: main\ntimeout_minutes: 10\n",
        )
        .unwrap();
        assert_eq!(t.id, "t1");
        assert_eq!(t.timeout_minutes, 10);
    }

    #[test]
    fn parses_block_scalars_comments_and_continuations() {
        let text = r#"# benchmark task
id: 't2' # quoted
prompt: |
  add tests for the parser

  and fix the docs
repo: o/r  # trailing comment
base_branch: main
  continued
timeout_minutes: 5
"#;
        let t = parse_task_yaml(text).unwrap();
        assert_eq!(t.id, "t2");
        assert_eq!(t.prompt, "add tests for the parser\n\nand fix the docs\n");
        assert_eq!(t.repo, "o/r");
        assert_eq!(t.base_branch, "main continued");
        assert_eq!(t.timeout_minutes, 5);
    }

    #[test]
    fn parses_folded_block_scalar() {
        let t = parse_task_yaml("id: t3\nprompt: >-\n  one\n  two\nrepo: o/r\nbase_branch: dev\n")
            .unwrap();
        assert_eq!(t.prompt, "one two");
    }

    #[tokio::test]
    async fn missing_test_runner_fails() {
        let dir = tempfile::tempdir().unwrap();
        let task = tempfile::tempdir().unwrap();
        assert!(!run_task_tests(dir.path(), task.path()).await);
    }

    #[test]
    fn summarize_counts() {
        let results = vec![
            BenchResult {
                task_id: "a".into(),
                verified: true,
                passed: true,
                cost_usd: 0.10,
                tokens: 100,
            },
            BenchResult {
                task_id: "b".into(),
                verified: true,
                passed: false,
                cost_usd: 0.20,
                tokens: 200,
            },
        ];
        assert!(summarize(&results).contains("passed 1/2"));
    }
}
