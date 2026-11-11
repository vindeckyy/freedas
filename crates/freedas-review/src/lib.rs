//! PR review engine and GitHub App service.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub mod github;

pub use github::{
    GithubApp, create_check_run, installation_token, post_review, request_reviewers,
    should_approve, submit_approval,
};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub file: String,
    /// New-file line. Zero (or absent) means the finding cannot be inline.
    #[serde(default)]
    pub line: u32,
    pub severity: String,
    pub confidence: u8,
    pub title: String,
    pub body: String,
    pub suggestion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewResult {
    pub confidence: f32,
    pub risk: f32,
    pub summary: String,
    pub findings: Vec<Finding>,
}

/// Verify a GitHub `X-Hub-Signature-256` header (`sha256=<hex>`) in constant time.
/// An empty secret never verifies: HMAC accepts an empty key, which would let a
/// forged signature pass. Callers must enforce one-time delivery IDs —
/// GitHub signs no timestamp, so a valid signature alone permits replay.
pub fn verify_webhook(body: &[u8], signature_header: &str, secret: &str) -> bool {
    if secret.is_empty() {
        return false;
    }
    let Some(hex) = signature_header.strip_prefix("sha256=") else {
        return false;
    };
    let Some(expected) = hex_decode(hex) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.is_ascii() || !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// One review per (workspace, repo, PR, head SHA). Installation is deliberately
/// absent: a manual review (installation 0) and a webhook review of the same
/// head would otherwise both be billed to the same workspace.
pub fn dedupe_key(workspace_id: &str, repo: &str, pr_number: i64, head_sha: &str) -> String {
    format!("{workspace_id}:{repo}:{pr_number}:{head_sha}")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewPolicy {
    pub automatic: String,
    pub include_drafts: bool,
    pub strictness: String,
    #[serde(default)]
    pub filters: Vec<serde_json::Value>,
    #[serde(default)]
    pub custom_rules: Vec<serde_json::Value>,
    #[serde(default)]
    pub context_files: Vec<String>,
    #[serde(default)]
    pub linked_repositories: Vec<String>,
    #[serde(default = "default_summary")]
    pub summary: serde_json::Value,
    pub status_check: Option<serde_json::Value>,
    pub auto_approve: Option<AutoApprove>,
}

/// Thresholds for the optional approval. An absent threshold is not a limit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoApprove {
    #[serde(default, alias = "minConfidence")]
    pub min_confidence: Option<f32>,
    #[serde(default, alias = "maxRisk")]
    pub max_risk: Option<f32>,
}

fn default_summary() -> serde_json::Value {
    serde_json::json!({ "target": "comment", "confidence": true, "findings": true })
}

pub fn policy_default() -> ReviewPolicy {
    ReviewPolicy {
        automatic: "opened".into(),
        include_drafts: false,
        strictness: "medium".into(),
        filters: Vec::new(),
        custom_rules: Vec::new(),
        context_files: Vec::new(),
        linked_repositories: Vec::new(),
        summary: default_summary(),
        status_check: None,
        auto_approve: None,
    }
}

/// low: everything; medium: skip nits; high: only confident high/blocker defects.
/// Unknown strictness falls back to medium.
pub fn strictness_allows(strictness: &str, severity: &str, confidence: u8) -> bool {
    match strictness {
        "low" => true,
        "high" => confidence >= 3 && matches!(severity, "high" | "blocker"),
        _ => severity != "nit",
    }
}

/// Run the review agent over the working-tree diff, keeping only findings that
/// lands on a line the diff actually touched.
pub async fn run_local_review(
    project_root: &Path,
    model_fn: impl Fn(&str) -> String,
) -> ReviewResult {
    run_local_review_target(project_root, None, model_fn).await
}

/// Review a chosen target:
///
/// - `None`: uncommitted work — `git diff HEAD` plus untracked files as new-file diffs.
/// - `Some("<branch>")`: `git diff <branch>...HEAD`.
/// - `Some("<sha>")`: that commit's diff (`git show`).
/// - `Some("<number|URL>")`: the PR diff via `gh pr diff`, else the GitHub API.
pub async fn run_local_review_target(
    project_root: &Path,
    target: Option<&str>,
    model_fn: impl Fn(&str) -> String,
) -> ReviewResult {
    match run_review(project_root, target, None, model_fn).await {
        Ok(result) => result,
        Err(error) => failed_result(error),
    }
}

fn failed_result(summary: String) -> ReviewResult {
    ReviewResult {
        confidence: 0.0,
        risk: 0.0,
        summary,
        findings: Vec::new(),
    }
}

/// Workspace policy inputs for a worker review.
struct ReviewJob<'a> {
    policy: &'a ReviewPolicy,
    repo: &'a str,
    token: Option<&'a str>,
    /// When present, the PR diff is pinned to this commit instead of the PR's
    /// current head.
    head_sha: Option<&'a str>,
}

/// Worker entry: reviews with the workspace policy's full-file context,
/// context files, custom rules, linked repositories, and summary options.
/// A review is `Err` when the diff is unreadable or the model reply is not
/// findings JSON; such a review must never be reported as clean.
pub async fn run_worker_review_target(
    project_root: &Path,
    target: Option<&str>,
    policy: &ReviewPolicy,
    repo: &str,
    token: Option<&str>,
    head_sha: Option<&str>,
    model_fn: impl Fn(&str) -> String,
) -> Result<ReviewResult, String> {
    run_review(
        project_root,
        target,
        Some(ReviewJob {
            policy,
            repo,
            token,
            head_sha,
        }),
        model_fn,
    )
    .await
}

async fn run_review(
    project_root: &Path,
    target: Option<&str>,
    job: Option<ReviewJob<'_>>,
    model_fn: impl Fn(&str) -> String,
) -> Result<ReviewResult, String> {
    let pin = job.as_ref().and_then(|job| job.head_sha);
    let token = job.as_ref().and_then(|job| job.token);
    let diff = collect_diff(project_root, target, pin, token)
        .await
        .map_err(|error| format!("could not read diff: {error}"))?;
    let (extra, _linked) = match job {
        Some(job) => review_sections(project_root, &diff, job.policy, job.repo, job.token).await,
        None => (String::new(), Vec::new()),
    };
    let prompt = review_prompt(&diff, &extra);
    let ranges = diff_ranges(&diff);
    let Some(parsed) = parse_findings(&model_fn(&prompt)) else {
        return Err("review model reply was not valid findings JSON".into());
    };
    let findings: Vec<Finding> = parsed
        .into_iter()
        .filter(|f| in_diff(&ranges, &f.file, f.line))
        .collect();
    if findings.is_empty() {
        return Ok(failed_result("no actionable findings".into()));
    }
    let (confidence, risk, summary) = score(&findings);
    Ok(ReviewResult {
        confidence,
        risk,
        summary,
        findings,
    })
}

/// Confidence, risk, and a one-line summary for a non-empty finding list.
fn score(findings: &[Finding]) -> (f32, f32, String) {
    let total: u32 = findings.iter().map(|f| u32::from(f.confidence)).sum();
    let files: BTreeSet<&str> = findings.iter().map(|f| f.file.as_str()).collect();
    (
        total as f32 / findings.len() as f32,
        findings
            .iter()
            .map(|f| severity_risk(&f.severity))
            .fold(0.0, f32::max),
        format!("{} finding(s) in {} file(s)", findings.len(), files.len()),
    )
}

/// The model prompt: rubric, diff, policy sections, then the JSON instruction.
fn review_prompt(diff: &str, extra: &str) -> String {
    let mut prompt = format!("{REVIEW_RUBRIC}\n\n{diff}");
    if !prompt.ends_with('\n') {
        prompt.push('\n');
    }
    if !extra.is_empty() {
        prompt.push('\n');
        prompt.push_str(extra);
        if !prompt.ends_with('\n') {
            prompt.push('\n');
        }
    }
    prompt.push('\n');
    prompt.push_str(REVIEW_FORMAT);
    prompt
}

/// Full-file, context-file, rule, linked-repository, and sequence-diagram
/// sections, plus the linked-repo temp dirs kept alive until the model call.
async fn review_sections(
    root: &Path,
    diff: &str,
    policy: &ReviewPolicy,
    repo: &str,
    token: Option<&str>,
) -> (String, Vec<tempfile::TempDir>) {
    let changed = diff_files(diff);
    let mut sections = file_sections(root, &changed, 10, 400);
    sections.push_str(&context_sections(root, &policy.context_files, 5, 200));
    if let Some(rules) = rules_section(&policy.custom_rules, repo, &changed) {
        sections.push_str(&rules);
    }
    let (linked, dirs) = linked_sections(&policy.linked_repositories, token).await;
    sections.push_str(&linked);
    if let Some(instruction) = sequence_diagram_instruction(&policy.summary) {
        sections.push_str(instruction);
        sections.push('\n');
    }
    (sections, dirs)
}

/// Path from the text after `+++ `/`--- `: drops a trailing tab-separated
/// timestamp, surrounding quotes (paths with spaces), and the `b/` prefix.
fn diff_path(rest: &str) -> Option<String> {
    let rest = rest.split('\t').next().unwrap_or(rest).trim();
    let rest = rest.trim_matches('"');
    let path = rest.strip_prefix("b/").unwrap_or(rest);
    (!path.is_empty() && path != "/dev/null").then(|| path.to_string())
}

/// New-side file paths in diff order. A `+++` line is only a header when it
/// directly follows `---`, because hunk content can also start with `+++ `.
fn diff_files(diff: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut files = Vec::new();
    let mut after_old_header = false;
    for line in diff.lines() {
        if line.starts_with("--- ") {
            after_old_header = true;
            continue;
        }
        if after_old_header {
            after_old_header = false;
            if let Some(path) = line.strip_prefix("+++ ").and_then(diff_path)
                && seen.insert(path.clone())
            {
                files.push(path);
            }
        }
    }
    files
}

/// The file at `entry` under `root`, resolved so `..` and symlinks cannot
/// leave the checkout.
fn safe_path(root: &Path, entry: &str) -> Option<PathBuf> {
    let root = root.canonicalize().ok()?;
    let resolved = root.join(entry).canonicalize().ok()?;
    (resolved.starts_with(&root) && resolved.is_file()).then_some(resolved)
}

/// Largest slice of a file sent to the model, in bytes.
const MAX_READ_BYTES: u64 = 1024 * 1024;

/// First `max_lines` lines of at most [`MAX_READ_BYTES`] bytes, with whether
/// the file continued. Binary files are rejected rather than dumped into the
/// prompt.
fn read_capped(path: &Path, max_lines: usize) -> std::io::Result<(String, bool)> {
    use std::io::Read;

    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_READ_BYTES)
        .read_to_end(&mut bytes)?;
    if bytes.iter().take(8192).any(|&byte| byte == 0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "binary file",
        ));
    }
    let byte_truncated = bytes.len() as u64 == MAX_READ_BYTES;
    let text = String::from_utf8_lossy(&bytes);
    let mut out = String::new();
    let mut truncated = false;
    for (index, line) in text.lines().enumerate() {
        if index == max_lines {
            truncated = true;
            break;
        }
        out.push_str(line);
        out.push('\n');
    }
    Ok((out, truncated || byte_truncated))
}

fn file_sections(root: &Path, changed: &[String], max_files: usize, max_lines: usize) -> String {
    let mut out = String::new();
    for file in changed.iter().take(max_files) {
        let Some(path) = safe_path(root, file) else {
            out.push_str(&format!("## File: {file} (skipped: not readable)\n"));
            continue;
        };
        match read_capped(&path, max_lines) {
            Ok((text, truncated)) => {
                out.push_str(&format!("## File: {file}\n```\n{text}"));
                if !text.is_empty() && !text.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str("```\n");
                if truncated {
                    out.push_str(&format!("[truncated after {max_lines} lines]\n"));
                }
            }
            Err(_) => out.push_str(&format!("## File: {file} (skipped: not readable)\n")),
        }
    }
    out
}

fn context_sections(root: &Path, entries: &[String], max_files: usize, max_lines: usize) -> String {
    let mut out = String::new();
    for entry in entries.iter().take(max_files) {
        let Some(path) = safe_path(root, entry) else {
            out.push_str(&format!(
                "## Context: {entry} (skipped: outside checkout or missing)\n"
            ));
            continue;
        };
        match read_capped(&path, max_lines) {
            Ok((text, truncated)) => {
                out.push_str(&format!("## Context: {entry}\n{text}"));
                if !text.is_empty() && !text.ends_with('\n') {
                    out.push('\n');
                }
                if truncated {
                    out.push_str(&format!("[truncated after {max_lines} lines]\n"));
                }
            }
            Err(_) => out.push_str(&format!("## Context: {entry} (skipped: not readable)\n")),
        }
    }
    out
}

/// Whole-string glob: `*` matches any run (including `/`), `?` one character.
fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while ti < text.len() {
        if pi < pattern.len() && (pattern[pi] == '?' || pattern[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(star) = star {
            pi = star + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < pattern.len() && pattern[pi] == '*' {
        pi += 1;
    }
    pi == pattern.len()
}

struct Rule {
    text: String,
    paths: Vec<String>,
    repos: Vec<String>,
}

/// A rule is a plain string or `{text, paths, repos}`.
fn parse_rule(value: &serde_json::Value) -> Option<Rule> {
    match value {
        serde_json::Value::String(text) => {
            let text = text.trim().to_owned();
            (!text.is_empty()).then_some(Rule {
                text,
                paths: Vec::new(),
                repos: Vec::new(),
            })
        }
        serde_json::Value::Object(map) => {
            let text = map.get("text")?.as_str()?.trim().to_owned();
            if text.is_empty() {
                return None;
            }
            let list = |key: &str| {
                map.get(key)
                    .and_then(|value| serde_json::from_value::<Vec<String>>(value.clone()).ok())
                    .unwrap_or_default()
            };
            Some(Rule {
                text,
                paths: list("paths"),
                repos: list("repos"),
            })
        }
        _ => None,
    }
}

fn rule_applies(rule: &Rule, repo: &str, changed: &[String]) -> bool {
    let repo_matches =
        rule.repos.is_empty() || rule.repos.iter().any(|scope| glob_match(scope, repo));
    let path_matches = rule.paths.is_empty()
        || rule.paths.iter().any(|pattern| {
            changed
                .iter()
                .any(|file| glob_match(pattern, file) || file.ends_with(pattern.as_str()))
        });
    repo_matches && path_matches
}

fn rules_section(rules: &[serde_json::Value], repo: &str, changed: &[String]) -> Option<String> {
    let mut lines = Vec::new();
    for rule in rules.iter().filter_map(parse_rule) {
        if !rule_applies(&rule, repo, changed) {
            continue;
        }
        let mut text = rule.text;
        if !rule.paths.is_empty() {
            text.push_str(&format!(" (paths: {})", rule.paths.join(", ")));
        }
        if !rule.repos.is_empty() {
            text.push_str(&format!(" (repos: {})", rule.repos.join(", ")));
        }
        lines.push(format!("- {text}"));
    }
    (!lines.is_empty()).then(|| format!("## Project rules\n{}\n", lines.join("\n")))
}

fn sequence_diagram_instruction(summary: &serde_json::Value) -> Option<&'static str> {
    let enabled = match summary.get("sequenceDiagram")? {
        serde_json::Value::Bool(enabled) => *enabled,
        serde_json::Value::String(text) => {
            matches!(text.to_ascii_lowercase().as_str(), "true" | "1" | "yes")
        }
        serde_json::Value::Number(number) => number.as_i64().is_some_and(|value| value != 0),
        _ => false,
    };
    enabled.then_some(
        "If this change alters request flow, include a mermaid `sequenceDiagram` in the summary.",
    )
}

/// Shallow-clone linked repositories (cap 3) and list their tree and README.
async fn linked_sections(
    entries: &[String],
    token: Option<&str>,
) -> (String, Vec<tempfile::TempDir>) {
    let mut out = String::new();
    let mut dirs = Vec::new();
    for entry in entries {
        if dirs.len() == 3 {
            break;
        }
        let repo = entry.trim();
        if !is_repo_slug(repo) {
            continue;
        }
        match clone_linked(repo, token).await {
            Ok((dir, body)) => {
                out.push_str(&format!("## Linked: {repo}\n{body}\n"));
                dirs.push(dir);
            }
            Err(error) => out.push_str(&format!("## Linked: {repo} (unavailable: {error})\n")),
        }
    }
    (out, dirs)
}

async fn clone_linked(
    repo: &str,
    token: Option<&str>,
) -> Result<(tempfile::TempDir, String), String> {
    let dir = tempfile::tempdir().map_err(|error| format!("temp dir: {error}"))?;
    let url = format!("https://github.com/{repo}.git");
    let redact = |text: String| match token {
        Some(token) => text.replace(token, "***"),
        None => text,
    };
    let mut clone_cmd = tokio::process::Command::new("git");
    clone_cmd
        .args(["clone", "--depth", "1", "--quiet", &url])
        .arg(dir.path());
    // Never pass the token on the command line: it is visible in `ps`.
    // Scrub helpers/prompts so the clone cannot hang or read unrelated creds.
    clone_cmd.env("GIT_TERMINAL_PROMPT", "0");
    clone_cmd.env_remove("GIT_ASKPASS");
    clone_cmd.env_remove("SSH_ASKPASS");
    clone_cmd.env_remove("GIT_HTTP_EXTRAHEADER");
    if let Some(token) = token {
        clone_cmd.env(
            "GIT_HTTP_EXTRAHEADER",
            format!("Authorization: Bearer {token}"),
        );
    }
    let clone = tokio::time::timeout(std::time::Duration::from_secs(60), clone_cmd.output()).await;
    match clone {
        Ok(Ok(output)) if output.status.success() => {}
        Ok(Ok(output)) => {
            return Err(redact(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ));
        }
        Ok(Err(error)) => return Err(redact(format!("git clone: {error}"))),
        Err(_) => return Err("git clone timed out".into()),
    }

    let listing = tokio::process::Command::new("git")
        .arg("-C")
        .arg(dir.path())
        .arg("ls-files")
        .output()
        .await
        .map_err(|error| format!("git ls-files: {error}"))?;
    let listing = String::from_utf8_lossy(&listing.stdout);
    let paths: Vec<&str> = listing
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    let mut body = String::new();
    for path in paths.iter().take(200) {
        body.push_str(path);
        body.push('\n');
    }
    if paths.len() > 200 {
        body.push_str(&format!("[{} more paths]\n", paths.len() - 200));
    }

    for name in ["README.md", "readme.md", "README"] {
        let path = dir.path().join(name);
        if !path.is_file() {
            continue;
        }
        if let Ok((text, truncated)) = read_capped(&path, 100) {
            body.push_str(&format!("### {name}\n{text}"));
            if truncated {
                body.push_str("[truncated after 100 lines]\n");
            }
        }
        break;
    }
    Ok((dir, body))
}

/// `path:line: severity: problem. fix.` per finding, one per line.
pub fn format_finding(finding: &Finding) -> String {
    format!(
        "{}:{}: {}: {}. {}",
        finding.file, finding.line, finding.severity, finding.title, finding.body
    )
}

impl ReviewResult {
    pub fn format_findings(&self) -> String {
        self.findings
            .iter()
            .map(format_finding)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

async fn collect_diff(
    root: &Path,
    target: Option<&str>,
    pin: Option<&str>,
    token: Option<&str>,
) -> Result<String, String> {
    match target.map(str::trim).filter(|t| !t.is_empty()) {
        None => uncommitted_diff(root).await,
        Some(target) => targeted_diff(root, target, pin, token).await,
    }
}

async fn uncommitted_diff(root: &Path) -> Result<String, String> {
    // `HEAD` covers staged and unstaged tracked changes; without a commit the
    // plain diff against the empty tree is the whole working tree.
    let mut diff = match git_out(root, &["diff", "--no-color", "HEAD"]).await {
        Ok(diff) => diff,
        Err(_) => git_out(root, &["diff", "--no-color"]).await?,
    };
    if let Ok(list) = git_out(root, &["ls-files", "--others", "--exclude-standard"]).await {
        for file in list
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .take(200)
        {
            let Some(bytes) = read_untracked(&root.join(file)).await else {
                continue;
            };
            // Binary files have no reviewable text; skip them.
            if bytes.iter().take(8192).any(|&b| b == 0) {
                continue;
            }
            diff.push_str(&synthetic_new_file_diff(
                file,
                &String::from_utf8_lossy(&bytes),
            ));
        }
    }
    if diff.trim().is_empty() {
        return Err("no uncommitted changes".into());
    }
    Ok(diff)
}

/// Untracked files are capped like tracked ones; a multi-gigabyte build artifact
/// must not be read into memory.
async fn read_untracked(path: &Path) -> Option<Vec<u8>> {
    use tokio::io::AsyncReadExt;

    let file = tokio::fs::File::open(path).await.ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_READ_BYTES)
        .read_to_end(&mut bytes)
        .await
        .ok()?;
    Some(bytes)
}

/// A new-file diff for an untracked path, in the same shape `git diff` emits.
fn synthetic_new_file_diff(file: &str, text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = format!(
        "diff --git a/{file} b/{file}\nnew file mode 100644\n--- /dev/null\n+++ b/{file}\n@@ -0,0 +1,{} @@\n",
        lines.len()
    );
    for line in lines {
        out.push('+');
        out.push_str(line);
        out.push('\n');
    }
    out
}

async fn targeted_diff(
    root: &Path,
    target: &str,
    pin: Option<&str>,
    token: Option<&str>,
) -> Result<String, String> {
    if let Some(number) = pr_number(target) {
        return pr_diff(root, number, pin, token).await;
    }
    // A branch name reviews branch...HEAD; anything else is a commit.
    let is_branch = git_out(
        root,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("refs/heads/{target}"),
        ],
    )
    .await
    .is_ok()
        || git_out(
            root,
            &[
                "rev-parse",
                "--verify",
                "--quiet",
                &format!("refs/remotes/{target}"),
            ],
        )
        .await
        .is_ok()
        || git_out(
            root,
            &[
                "rev-parse",
                "--verify",
                "--quiet",
                &format!("refs/remotes/origin/{target}"),
            ],
        )
        .await
        .is_ok();
    if is_branch {
        git_out(root, &["diff", "--no-color", &format!("{target}...HEAD")]).await
    } else {
        git_out(root, &["show", "--no-color", "--format=", target]).await
    }
}

/// A PR number, or the trailing number of a PR URL.
fn pr_number(target: &str) -> Option<u64> {
    if let Ok(number) = target.parse::<u64>() {
        return Some(number);
    }
    let path = target.trim_end_matches('/');
    if !path.contains("/pull/") && !path.contains("/pulls/") {
        return None;
    }
    path.rsplit('/').next()?.parse().ok()
}

/// GitHub API base for diff fetches: the configured base, never a hardcoded
/// host — the installation token must not leave for the wrong audience.
fn diff_api_base() -> String {
    std::env::var("FREEDAS_GITHUB_API_BASE")
        .ok()
        .filter(|base| !base.trim().is_empty())
        .unwrap_or_else(|| github::DEFAULT_API_BASE.to_owned())
}

/// `head_sha` values land in API paths and `commit_id` fields; only real
/// object ids pass (SHA-1 or SHA-256 hex).
fn valid_head_sha(sha: &str) -> bool {
    matches!(sha.len(), 40 | 64) && sha.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Prefer the diff at `pin` so a review posts against the commit it was run on;
/// fall back to the PR's current head when that commit cannot be fetched.
async fn pr_diff(
    root: &Path,
    number: u64,
    pin: Option<&str>,
    token: Option<&str>,
) -> Result<String, String> {
    if let Some(head_sha) = pin {
        // A pinned review must never silently describe the floating head —
        // the verdict posts against `head_sha` either way.
        if !valid_head_sha(head_sha) {
            return Err(format!("pinned head_sha {head_sha:?} is not a git object id"));
        }
        return pinned_pr_diff(root, number, head_sha, token).await;
    }
    let gh = tokio::process::Command::new("gh")
        .args(["pr", "diff", &number.to_string()])
        .current_dir(root)
        .output()
        .await;
    if let Ok(out) = gh
        && out.status.success()
    {
        return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
    }
    github_pr_diff(root, number).await
}

/// Diff `base...head_sha` through the GitHub API, so the result is independent
/// of later pushes to the pull request.
async fn pinned_pr_diff(
    root: &Path,
    number: u64,
    head_sha: &str,
    token: Option<&str>,
) -> Result<String, String> {
    let api_base = diff_api_base();
    let token = match token {
        Some(token) => token.to_owned(),
        None => github_token(root)?,
    };
    let remote = git_out(root, &["remote", "get-url", "origin"]).await?;
    let repo = github_repo(&remote).ok_or_else(|| format!("not a GitHub remote: {remote}"))?;
    let client = reqwest::Client::new();
    let pull: serde_json::Value = client
        .get(format!(
            "{api_base}/repos/{repo}/pulls/{number}"
        ))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "freedas")
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| format!("github: {e}"))?
        .json()
        .await
        .map_err(|e| format!("github: {e}"))?;
    let base = pull
        .pointer("/base/sha")
        .and_then(|sha| sha.as_str())
        .ok_or("github: pull request has no base sha")?;
    let response = client
        .get(format!(
            "{api_base}/repos/{repo}/compare/{base}...{head_sha}"
        ))
        .header("Accept", "application/vnd.github.v3.diff")
        .header("User-Agent", "freedas")
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| format!("github: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("github: HTTP {}", response.status()));
    }
    response.text().await.map_err(|e| format!("github: {e}"))
}

/// Stored GitHub token, else `GITHUB_TOKEN`/`GH_TOKEN`.
fn github_token(root: &Path) -> Result<String, String> {
    let paths = freedas_core::Paths::resolve(root.to_path_buf());
    freedas_provider::credentials::api_key_for(&paths.data_dir, "github")
        .or_else(|| std::env::var("GITHUB_TOKEN").ok())
        .or_else(|| std::env::var("GH_TOKEN").ok())
        .ok_or_else(|| "gh unavailable and no GitHub token stored".to_owned())
}

/// Fallback when `gh` is missing or unauthenticated: fetch the diff with the
/// stored GitHub token.
async fn github_pr_diff(root: &Path, number: u64) -> Result<String, String> {
    let api_base = diff_api_base();
    let token = github_token(root)?;
    let remote = git_out(root, &["remote", "get-url", "origin"]).await?;
    let repo = github_repo(&remote).ok_or_else(|| format!("not a GitHub remote: {remote}"))?;
    let response = reqwest::Client::new()
        .get(format!(
            "{api_base}/repos/{repo}/pulls/{number}"
        ))
        .header("Accept", "application/vnd.github.v3.diff")
        .header("User-Agent", "freedas")
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| format!("github: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("github: HTTP {}", response.status()));
    }
    response.text().await.map_err(|e| format!("github: {e}"))
}

/// `owner/repo` from an HTTPS or SSH GitHub remote.
fn github_repo(remote: &str) -> Option<String> {
    let path = remote.trim().trim_end_matches(".git");
    let tail = path.rsplit_once("github.com").map(|(_, tail)| tail)?;
    let tail = tail.trim_start_matches([':', '/']);
    let mut parts = tail.split('/');
    let owner = parts.next()?;
    let repo = parts.next()?;
    (!owner.is_empty() && !repo.is_empty()).then(|| format!("{owner}/{repo}"))
}

async fn git_out(root: &Path, args: &[&str]) -> Result<String, String> {
    let out = tokio::process::Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[derive(Deserialize)]
struct Reply {
    findings: Vec<Finding>,
}

/// Accept either `{"findings": [...]}` or a bare array, optionally inside a
/// code fence. `None` means the reply could not be parsed as findings, which is
/// an error rather than a clean review; an object without a `findings` key is
/// not a findings reply.
fn parse_findings(response: &str) -> Option<Vec<Finding>> {
    let start = response.find(['{', '['])?;
    let end = response.rfind(['}', ']'])?;
    if start > end {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(&response[start..=end]).ok()?;
    if value.is_array() {
        return serde_json::from_value(value).ok();
    }
    serde_json::from_value::<Reply>(value)
        .ok()
        .map(|reply| reply.findings)
}

/// New-side hunk ranges as (path, first line, line count). A `+++` line is only
/// a header when it directly follows `---`; hunk content can also start with
/// `+++ `.
fn diff_ranges(diff: &str) -> Vec<(String, u32, u32)> {
    let mut out = Vec::new();
    let mut file: Option<String> = None;
    let mut after_old_header = false;
    for line in diff.lines() {
        if line.starts_with("--- ") {
            after_old_header = true;
            continue;
        }
        if after_old_header {
            after_old_header = false;
            if let Some(rest) = line.strip_prefix("+++ ") {
                file = diff_path(rest);
                continue;
            }
        }
        if let Some(hunk) = line.strip_prefix("@@ -")
            && let (Some(path), Some((start, count))) = (file.as_ref(), parse_hunk(hunk))
        {
            out.push((path.clone(), start, count));
        }
    }
    out
}

/// `@@ -a,b +c,d @@` arrives as `a,b +c,d @@`.
fn parse_hunk(rest: &str) -> Option<(u32, u32)> {
    let spec = rest.split(" +").nth(1)?.split_whitespace().next()?;
    let (start, count) = match spec.split_once(',') {
        Some((start, count)) => (start, count),
        None => (spec, "1"),
    };
    Some((start.parse().ok()?, count.parse().ok()?))
}

/// `line == 0` is a whole-file finding: it needs a path the diff touched but no
/// specific hunk line.
fn in_diff(ranges: &[(String, u32, u32)], file: &str, line: u32) -> bool {
    ranges.iter().any(|(path, start, count)| {
        path == file && *count > 0 && (line == 0 || (line >= *start && line < start + count))
    })
}

fn severity_risk(severity: &str) -> f32 {
    match severity {
        "blocker" => 5.0,
        "high" => 4.0,
        "medium" => 3.0,
        "low" => 2.0,
        _ => 1.0,
    }
}

// ---------------------------------------------------------------------------
// Review worker
// ---------------------------------------------------------------------------

/// `reviews` may already exist from the control plane, so the worker creates it
/// if missing and adds its own columns idempotently.
const WORKER_SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS reviews (id TEXT PRIMARY KEY, workspace_id TEXT, installation_id BIGINT, repo TEXT, pr_number BIGINT, head_sha TEXT, status TEXT, confidence NUMERIC(4,2), risk NUMERIC(4,2), review_url TEXT, findings JSONB, summary TEXT, customer_cost_usd NUMERIC(12,6) NOT NULL DEFAULT 0, upstream_cost_usd NUMERIC(12,6) NOT NULL DEFAULT 0, error TEXT, retry_count INTEGER NOT NULL DEFAULT 0, retryable BOOLEAN NOT NULL DEFAULT TRUE, created_at BIGINT, updated_at BIGINT)",
    "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS confidence NUMERIC(4,2)",
    "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS risk NUMERIC(4,2)",
    "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS review_url TEXT",
    "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS findings JSONB",
    "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS summary TEXT",
    "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS customer_cost_usd NUMERIC(12,6) NOT NULL DEFAULT 0",
    "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS upstream_cost_usd NUMERIC(12,6) NOT NULL DEFAULT 0",
    "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS error TEXT",
    "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS retry_count INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS retryable BOOLEAN NOT NULL DEFAULT TRUE",
    // The installation-scoped key misses manual reviews (`installation_id = 0`),
    // so the same head SHA could be billed twice. Scope by workspace: manual
    // and webhook rows dedupe against each other, while two tenants reviewing
    // the same public PR stay independent. Control's schema agrees.
    "ALTER TABLE reviews DROP CONSTRAINT IF EXISTS reviews_installation_id_repo_pr_number_head_sha_key",
    "DROP INDEX IF EXISTS reviews_repo_pr_head",
    "DROP INDEX IF EXISTS reviews_installation_head",
    "DROP INDEX IF EXISTS reviews_manual_head",
    // Legacy rows can repeat a workspace/repo/PR/head under the old key; keep
    // the most advanced row before the unique index would reject them.
    "DELETE FROM reviews r WHERE r.workspace_id IS NOT NULL AND r.id <> (SELECT x.id FROM reviews x WHERE x.workspace_id = r.workspace_id AND x.repo = r.repo AND x.pr_number = r.pr_number AND x.head_sha = r.head_sha ORDER BY (x.review_url IS NOT NULL) DESC, (x.status = 'completed') DESC, x.created_at DESC, x.id DESC LIMIT 1)",
    "CREATE UNIQUE INDEX IF NOT EXISTS reviews_workspace_head ON reviews (workspace_id, repo, pr_number, head_sha)",
];

/// Run the review worker forever with `concurrency` leasing tasks. The model
/// endpoint comes from `FREEDAS_GATEWAY_URL`; GitHub App settings come from the
/// `FREEDAS_GITHUB_*` environment variables. Missing configuration fails
/// startup instead of producing a worker that can never post.
pub async fn run_worker(pool: &sqlx::PgPool, concurrency: usize) -> sqlx::Result<()> {
    let gateway = std::env::var("FREEDAS_GATEWAY_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
        .ok_or_else(|| sqlx::Error::Configuration("FREEDAS_GATEWAY_URL is required".into()))?;
    let github = github_from_env().ok_or_else(|| {
        sqlx::Error::Configuration(
            "FREEDAS_GITHUB_APP_ID and FREEDAS_GITHUB_PRIVATE_KEY_PATH are required".into(),
        )
    })?;
    run_worker_with(pool, concurrency, Some(gateway), Some(github)).await
}

/// Same as [`run_worker`] with explicit settings (`None`: no posting). An empty
/// gateway is rejected rather than turned into a relative request URL.
pub async fn run_worker_with(
    pool: &sqlx::PgPool,
    concurrency: usize,
    gateway: Option<String>,
    github: Option<GithubApp>,
) -> sqlx::Result<()> {
    if let Some(url) = gateway.as_deref()
        && url.trim().is_empty()
    {
        return Err(sqlx::Error::Configuration(
            "FREEDAS_GATEWAY_URL is empty".into(),
        ));
    }
    for statement in WORKER_SCHEMA {
        sqlx::query(statement).execute(pool).await?;
    }
    let mut workers = Vec::with_capacity(concurrency.max(1));
    for _ in 0..concurrency.max(1) {
        let pool = pool.clone();
        let gateway = gateway.clone();
        let github = github.clone();
        workers.push(tokio::spawn(async move {
            worker_loop(pool, gateway, github).await
        }));
    }
    for worker in workers {
        if let Err(error) = worker.await {
            eprintln!("freedas-review: worker task failed: {error}");
        }
    }
    Ok(())
}

/// Build the app config from the environment, keeping `--flag` values out of it.
fn github_from_env() -> Option<GithubApp> {
    let app_id = std::env::var("FREEDAS_GITHUB_APP_ID").ok()?;
    let path = std::env::var("FREEDAS_GITHUB_PRIVATE_KEY_PATH").ok()?;
    let private_key_pem = std::fs::read_to_string(path).ok()?;
    let api_base = std::env::var("FREEDAS_GITHUB_API_BASE")
        .ok()
        .filter(|base| !base.trim().is_empty())
        .unwrap_or_else(|| github::DEFAULT_API_BASE.to_owned());
    Some(GithubApp {
        app_id,
        private_key_pem,
        api_base,
    })
}

async fn worker_loop(pool: sqlx::PgPool, gateway: Option<String>, github: Option<GithubApp>) {
    loop {
        match lease(&pool).await {
            Ok(Some((id, repo, pr_number, head_sha))) => {
                process(
                    &pool,
                    gateway.as_deref(),
                    github.as_ref(),
                    id,
                    repo,
                    pr_number,
                    head_sha,
                )
                .await;
            }
            Ok(None) => tokio::time::sleep(std::time::Duration::from_millis(500)).await,
            Err(error) => {
                eprintln!("freedas-review: lease failed: {error}");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    }
}

/// A `running` row older than this lost its worker and is reclaimed.
const LEASE_MS: i64 = 15 * 60 * 1000;

/// Lease one review.
///
/// - `queued` rows are claimed immediately.
/// - `failed` rows are reclaimed after a backoff that grows with `retry_count`,
///   for at most two retries. Rows that failed on configuration
///   (`retryable = FALSE`) wait the backoff but do not consume a retry.
/// - `running` rows older than [`LEASE_MS`] are reclaimed from a lost worker.
pub async fn lease(
    pool: &sqlx::PgPool,
) -> Result<Option<(String, Option<String>, Option<i64>, Option<String>)>, sqlx::Error> {
    sqlx::query_as(
        "UPDATE reviews
            SET status = 'running',
                updated_at = $1,
                retry_count = retry_count
                    + CASE WHEN status = 'failed' AND retryable THEN 1 ELSE 0 END
          WHERE id = (
                SELECT id FROM reviews
                 WHERE status = 'queued'
                    OR (status = 'failed'
                        AND (retry_count < 2 OR retryable = FALSE)
                        AND updated_at
                            + (CASE retry_count
                                 WHEN 0 THEN 60000
                                 WHEN 1 THEN 300000
                                 ELSE 900000
                               END) <= $1)
                    OR (status = 'running' AND updated_at < $1 - $2)
                 ORDER BY created_at
                 LIMIT 1
                 FOR UPDATE SKIP LOCKED
          )
          RETURNING id, repo, pr_number, head_sha",
    )
    .bind(now_ms())
    .bind(LEASE_MS)
    .fetch_optional(pool)
    .await
}

#[allow(clippy::too_many_arguments)]
async fn process(
    pool: &sqlx::PgPool,
    gateway: Option<&str>,
    github: Option<&GithubApp>,
    id: String,
    repo: Option<String>,
    pr_number: Option<i64>,
    head_sha: Option<String>,
) {
    let repo = repo.unwrap_or_default();
    // A queued head_sha must be a real object id before it reaches API paths;
    // a malformed row fails closed rather than reviewing unpinned.
    if let Some(sha) = head_sha.as_deref()
        && !valid_head_sha(sha)
    {
        return record_failure(pool, &id, "malformed head_sha", false).await;
    }
    let policy = policy_of(pool, &id).await;
    // Manual reviews (installation 0) still post through the installation that
    // owns the repository.
    let installation_id = match review_target(pool, &id).await.0.filter(|id| *id > 0) {
        Some(id) => Some(id),
        None => resolve_installation(pool, &id, &repo).await,
    };
    let token = match github {
        Some(app) => installation_token_for(app, installation_id).await,
        None => None,
    };
    match review(
        gateway,
        &repo,
        pr_number,
        head_sha.as_deref(),
        &policy,
        token.as_deref(),
    )
    .await
    {
        Ok(mut result) => {
            apply_strictness(&mut result, &policy.strictness);
            if let Some(app) = github.filter(|_| is_repo_slug(&repo)) {
                // Posting is retryable: a failed post must not look like a
                // completed review.
                if let Err(error) = post_to_github(
                    pool,
                    app,
                    &id,
                    &repo,
                    pr_number,
                    installation_id,
                    head_sha.as_deref(),
                    &result,
                )
                .await
                {
                    return record_failure(pool, &id, &error, true).await;
                }
            }
            if let Err(error) = complete(pool, &id, &result).await {
                eprintln!("freedas-review: could not update {id}: {error}");
            }
        }
        Err(error) => {
            let retryable = !is_config_error(&error);
            record_failure(pool, &id, &error, retryable).await;
        }
    }
}

async fn record_failure(pool: &sqlx::PgPool, id: &str, error: &str, retryable: bool) {
    let updated = if retryable {
        fail(pool, id, error).await
    } else {
        fail_config(pool, id, error).await
    };
    if let Err(error) = updated {
        eprintln!("freedas-review: could not update {id}: {error}");
    }
}

/// Errors that a retry cannot fix; they must not consume the retry budget.
fn is_config_error(error: &str) -> bool {
    error.starts_with("no local checkout for")
        || error.starts_with("review model is not configured")
}

/// Post the review, check run, reviewer request, and approval. `Err` means the
/// review itself was not posted and the row should be retried; ancillary
/// failures are recorded without blocking completion.
#[allow(clippy::too_many_arguments)]
async fn post_to_github(
    pool: &sqlx::PgPool,
    app: &GithubApp,
    id: &str,
    repo: &str,
    pr_number: Option<i64>,
    installation_id: Option<i64>,
    head_sha: Option<&str>,
    result: &ReviewResult,
) -> Result<(), String> {
    let Some(pr) = pr_number else {
        return Ok(());
    };
    let Some(head_sha) = head_sha else {
        return Err(format!("review has no head_sha; cannot post {repo}#{pr}"));
    };
    let Some(installation_id) = installation_id else {
        return Err(format!(
            "no GitHub App installation owns {repo}; cannot post review"
        ));
    };
    let client = reqwest::Client::new();
    let token = installation_token(
        &client,
        &app.api_base,
        &app.app_id,
        &app.private_key_pem,
        installation_id,
    )
    .await?;

    let review_url = post_review(
        &client,
        &app.api_base,
        &token,
        repo,
        pr,
        head_sha,
        &freedas_core::redact::redact(&result.summary),
        &result.findings,
    )
    .await?;
    let mut errors = Vec::new();
    if let Err(error) =
        sqlx::query("UPDATE reviews SET review_url = $1, updated_at = $2 WHERE id = $3")
            .bind(&review_url)
            .bind(now_ms())
            .bind(id)
            .execute(pool)
            .await
    {
        errors.push(format!("review url: {error}"));
    }
    let conclusion = if result
        .findings
        .iter()
        .any(|f| matches!(f.severity.as_str(), "blocker" | "high"))
    {
        "failure"
    } else {
        "success"
    };
    if let Err(error) = create_check_run(
        &client,
        &app.api_base,
        &token,
        repo,
        head_sha,
        conclusion,
        &freedas_core::redact::redact(&result.summary),
    )
    .await
    {
        errors.push(error);
    }
    match app_bot_login(&client, &app.api_base, &app.app_id, &app.private_key_pem).await {
        Ok(login) => {
            if let Err(error) =
                request_reviewers(&client, &app.api_base, &token, repo, pr, &login).await
            {
                errors.push(error);
            }
        }
        Err(error) => errors.push(error),
    }
    let policy = policy_of(pool, id).await;
    let clean = !result
        .findings
        .iter()
        .any(|f| matches!(f.severity.as_str(), "blocker" | "high"));
    if clean
        && should_approve(&policy, result.confidence, result.risk)
        && let Err(error) = submit_approval(
            &client,
            &app.api_base,
            &token,
            repo,
            pr,
            head_sha,
            result.confidence,
            result.risk,
            &policy,
        )
        .await
    {
        errors.push(error);
    }
    if !errors.is_empty() {
        record_error(pool, id, &errors.join("; ")).await;
    }
    Ok(())
}

/// The GitHub App's own bot login (`<slug>[bot]`), the only reviewer a bot can
/// request.
async fn app_bot_login(
    client: &reqwest::Client,
    api_base: &str,
    app_id: &str,
    key_pem: &str,
) -> Result<String, String> {
    let slug = github::app_slug(client, api_base, app_id, key_pem).await?;
    Ok(format!("{slug}[bot]"))
}

/// `installation_id` and `head_sha` for the post step.
async fn review_target(pool: &sqlx::PgPool, id: &str) -> (Option<i64>, Option<String>) {
    sqlx::query_as::<_, (Option<i64>, Option<String>)>(
        "SELECT installation_id, head_sha FROM reviews WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .unwrap_or((None, None))
}

/// The workspace's installation that owns `repo`; manual review rows carry 0.
/// Scoped to the row's workspace so one tenant can never post with another
/// tenant's installation token.
async fn resolve_installation(pool: &sqlx::PgPool, id: &str, repo: &str) -> Option<i64> {
    sqlx::query_scalar(
        "SELECT r.installation_id FROM github_repositories r
           JOIN github_installations i ON i.id = r.installation_id
          WHERE r.repo = $1 AND r.enabled
            AND i.workspace_id = (SELECT workspace_id FROM reviews WHERE id = $2)
          ORDER BY r.installation_id DESC
          LIMIT 1",
    )
    .bind(repo)
    .bind(id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
}

/// The workspace policy, or defaults when the row is missing. Unparseable
/// columns keep their default.
async fn policy_of(pool: &sqlx::PgPool, id: &str) -> ReviewPolicy {
    type Row = (
        Option<String>,
        Option<bool>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let row = sqlx::query_as::<_, Row>(
        "SELECT strictness, include_drafts, custom_rules::text, context_files::text,
                linked_repositories::text, summary::text, auto_approve::text
           FROM review_policies
          WHERE workspace_id = (SELECT workspace_id FROM reviews WHERE id = $1)",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();
    let mut policy = policy_default();
    let Some((strictness, include_drafts, rules, context, linked, summary, auto_approve)) = row
    else {
        return policy;
    };
    if let Some(strictness) = strictness {
        policy.strictness = strictness;
    }
    if let Some(include_drafts) = include_drafts {
        policy.include_drafts = include_drafts;
    }
    if let Some(rules) = decode::<Vec<serde_json::Value>>(rules) {
        policy.custom_rules = rules;
    }
    if let Some(context) = decode::<Vec<String>>(context) {
        policy.context_files = context;
    }
    if let Some(linked) = decode::<Vec<String>>(linked) {
        policy.linked_repositories = linked;
    }
    if let Some(summary) = decode::<serde_json::Value>(summary) {
        policy.summary = summary;
    }
    policy.auto_approve = decode::<AutoApprove>(auto_approve);
    policy
}

fn decode<T: serde::de::DeserializeOwned>(text: Option<String>) -> Option<T> {
    text.and_then(|text| serde_json::from_str(&text).ok())
}

/// Installation token for linked-repository clones and pinned diffs; absent
/// without a GitHub App or installation.
async fn installation_token_for(app: &GithubApp, installation_id: Option<i64>) -> Option<String> {
    installation_token(
        &reqwest::Client::new(),
        &app.api_base,
        &app.app_id,
        &app.private_key_pem,
        installation_id?,
    )
    .await
    .ok()
}

async fn record_error(pool: &sqlx::PgPool, id: &str, error: &str) {
    if let Err(error) = sqlx::query("UPDATE reviews SET error = $1, updated_at = $2 WHERE id = $3")
        .bind(bound_error(error))
        .bind(now_ms())
        .bind(id)
        .execute(pool)
        .await
    {
        eprintln!("freedas-review: could not record posting error: {error}");
    }
}

/// `owner/name` only; local checkout paths are not postable. Each segment is
/// restricted to `[A-Za-z0-9_.-]+` so `..`, absolute paths, and shell/URL
/// metacharacters never pass as a slug.
fn is_repo_slug(repo: &str) -> bool {
    let mut parts = repo.split('/');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(owner), Some(name), None) => is_slug_segment(owner) && is_slug_segment(name),
        _ => false,
    }
}

fn is_slug_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
}

/// Drop findings the review policy excludes, then recompute confidence/risk so
/// the stored scores (and any auto-approval decision) describe what remains.
fn apply_strictness(result: &mut ReviewResult, strictness: &str) {
    let before = result.findings.len();
    result
        .findings
        .retain(|f| strictness_allows(strictness, &f.severity, f.confidence));
    if result.findings.len() == before {
        return;
    }
    if result.findings.is_empty() {
        result.confidence = 0.0;
        result.risk = 0.0;
        result.summary = format!("no findings met the {strictness} strictness bar");
        return;
    }
    let (confidence, risk, summary) = score(&result.findings);
    result.confidence = confidence;
    result.risk = risk;
    result.summary = summary;
}

async fn complete(pool: &sqlx::PgPool, id: &str, result: &ReviewResult) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE reviews
            SET status = 'completed', confidence = $1::numeric, risk = $2::numeric,
                findings = $3, summary = $4, error = NULL, updated_at = $5
          WHERE id = $6",
    )
    .bind(result.confidence.to_string())
    .bind(result.risk.to_string())
    .bind(serde_json::to_value(&result.findings).unwrap_or(serde_json::Value::Null))
    .bind(&result.summary)
    .bind(now_ms())
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn fail(pool: &sqlx::PgPool, id: &str, error: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE reviews
            SET status = 'failed', error = $1, retryable = TRUE, updated_at = $2
          WHERE id = $3",
    )
    .bind(bound_error(error))
    .bind(now_ms())
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// A failure a retry cannot fix (missing checkout or model config): retried
/// forever on the backoff schedule, but it does not spend the retry budget.
async fn fail_config(pool: &sqlx::PgPool, id: &str, error: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE reviews
            SET status = 'failed', error = $1, retryable = FALSE, updated_at = $2
          WHERE id = $3",
    )
    .bind(bound_error(error))
    .bind(now_ms())
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

fn bound_error(message: &str) -> String {
    freedas_core::redact::redact(message)
        .chars()
        .take(500)
        .collect()
}

#[allow(clippy::too_many_arguments)]
async fn review(
    gateway: Option<&str>,
    repo: &str,
    pr_number: Option<i64>,
    head_sha: Option<&str>,
    policy: &ReviewPolicy,
    token: Option<&str>,
) -> Result<ReviewResult, String> {
    let Some(root) = checkout_for(repo) else {
        return Err(format!(
            "no local checkout for {repo}; set FREEDAS_REVIEW_CHECKOUT_DIR"
        ));
    };
    let Some(gateway) = gateway.filter(|url| !url.trim().is_empty()) else {
        return Err("review model is not configured (FREEDAS_GATEWAY_URL)".into());
    };
    let model = ReviewModel::new(gateway.to_owned());
    let target = pr_number.map(|number| number.to_string());
    let result = run_worker_review_target(
        &root,
        target.as_deref(),
        policy,
        repo,
        token,
        head_sha,
        |prompt| model.message(prompt),
    )
    .await;
    if let Some(error) = model.error() {
        return Err(error);
    }
    result
}

/// Resolve `repo` (`owner/name`) under `FREEDAS_REVIEW_CHECKOUT_DIR`. The slug
/// is untrusted row data, so an absolute path or `..` must never select a
/// directory outside the checkout root.
fn checkout_for(repo: &str) -> Option<PathBuf> {
    let root = std::env::var("FREEDAS_REVIEW_CHECKOUT_DIR").ok()?;
    checkout_in(Path::new(&root), repo)
}

fn checkout_in(root: &Path, repo: &str) -> Option<PathBuf> {
    if !is_repo_slug(repo) {
        return None;
    }
    let root = root.canonicalize().ok()?;
    let candidate = root.join(repo).canonicalize().ok()?;
    (candidate.starts_with(&root) && candidate.is_dir()).then_some(candidate)
}

const REVIEW_RUBRIC: &str = "You review a git diff and report defects. Check correctness, \
regressions, security, data loss, and missing tests. Ignore style nits.";

const REVIEW_FORMAT: &str = "Respond with only a JSON array of findings: [{\"file\":\"path\",\
\"line\":1,\"severity\":\"blocker|high|medium|low|nit\",\"confidence\":1,\"title\":\"short problem\",\
\"body\":\"fix\"}]. Line numbers are new-file lines. Return [] when nothing is wrong.";

const REVIEW_SYSTEM: &str = "You review code changes and return JSON findings.";

struct ReviewModel {
    // shortcut: blocks the runtime thread during the model call; move review
    // onto an async model call if worker concurrency starts to matter.
    client: reqwest::blocking::Client,
    url: String,
    token: Option<String>,
    model: String,
    error: std::sync::Arc<std::sync::Mutex<Option<String>>>,
}

impl ReviewModel {
    fn new(gateway: String) -> Self {
        let token = std::env::var("FREEDAS_GATEWAY_TOKEN")
            .or_else(|_| std::env::var("FREEDAS_TOKEN"))
            .ok()
            .filter(|token| !token.trim().is_empty());
        let model =
            std::env::var("FREEDAS_REVIEW_MODEL").unwrap_or_else(|_| "freedas/auto".to_owned());
        Self {
            client: reqwest::blocking::Client::new(),
            url: chat_url(&gateway),
            token,
            model,
            error: Default::default(),
        }
    }

    fn message(&self, prompt: &str) -> String {
        let body = serde_json::json!({
            "model": self.model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": REVIEW_SYSTEM},
                {"role": "user", "content": prompt},
            ],
        });
        let mut request = self.client.post(&self.url).json(&body);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        match request.send() {
            Ok(response) if response.status().is_success() => {
                let value: serde_json::Value = response.json().unwrap_or_default();
                value
                    .pointer("/choices/0/message/content")
                    .and_then(|content| content.as_str())
                    .unwrap_or_default()
                    .to_owned()
            }
            Ok(response) => {
                self.record_error(format!("gateway: HTTP {}", response.status()));
                String::new()
            }
            Err(error) => {
                self.record_error(format!("gateway: {error}"));
                String::new()
            }
        }
    }

    fn record_error(&self, message: String) {
        *self.error.lock().expect("review error lock") = Some(message);
    }

    fn error(&self) -> Option<String> {
        self.error.lock().expect("review error lock").clone()
    }
}

fn chat_url(base: &str) -> String {
    let base = base.trim_end_matches('/');
    if base.ends_with("/v1") {
        format!("{base}/chat/completions")
    } else {
        format!("{base}/v1/chat/completions")
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod worker_tests {
    use super::*;

    #[test]
    fn error_is_bounded_to_500_chars() {
        assert_eq!(bound_error("short"), "short");
        assert_eq!(bound_error(&"x".repeat(900)).chars().count(), 500);
        // Multi-byte input is truncated by characters, not bytes.
        assert_eq!(bound_error(&"é".repeat(600)).chars().count(), 500);
    }

    #[test]
    fn chat_url_appends_the_v1_prefix_once() {
        assert_eq!(
            chat_url("https://gw.example.com"),
            "https://gw.example.com/v1/chat/completions"
        );
        assert_eq!(
            chat_url("https://gw.example.com/v1/"),
            "https://gw.example.com/v1/chat/completions"
        );
    }

    #[test]
    fn checkout_stays_under_the_checkout_root() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("checkouts");
        let repo = root.join("acme").join("api");
        std::fs::create_dir_all(&repo).unwrap();
        assert_eq!(
            checkout_in(&root, "acme/api"),
            Some(repo.canonicalize().unwrap())
        );

        // Absolute paths, traversal, and non-slugs never resolve.
        let outside = base.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let absolute = outside.to_str().unwrap();
        assert!(checkout_in(&root, absolute).is_none());
        assert!(checkout_in(&root, "../outside").is_none());
        assert!(checkout_in(&root, "acme").is_none());
        assert!(checkout_in(&root, "").is_none());
        assert!(checkout_in(&root, "acme/missing").is_none());
    }

    #[test]
    fn config_errors_keep_their_retry_budget() {
        assert!(is_config_error(
            "no local checkout for acme/api; set FREEDAS_REVIEW_CHECKOUT_DIR"
        ));
        assert!(is_config_error(
            "review model is not configured (FREEDAS_GATEWAY_URL)"
        ));
        assert!(!is_config_error("gateway: HTTP 500"));
        assert!(!is_config_error(
            "review model reply was not valid findings JSON"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "Jefe";
    // RFC 4231 test case 2.
    const BODY: &[u8] = b"what do ya want for nothing?";
    const SIGNATURE: &str =
        "sha256=5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

    #[test]
    fn webhook_accepts_valid_signature() {
        assert!(verify_webhook(BODY, SIGNATURE, SECRET));
    }

    #[test]
    fn webhook_rejects_bad_input() {
        assert!(!verify_webhook(BODY, SIGNATURE, "other-secret"));
        assert!(!verify_webhook(b"tampered", SIGNATURE, SECRET));
        assert!(!verify_webhook(BODY, "5bdcc146", SECRET));
        assert!(!verify_webhook(BODY, "sha256=zz", SECRET));
        assert!(!verify_webhook(BODY, "sha256=abc", SECRET));
    }

    #[test]
    fn dedupe_key_is_installation_independent() {
        assert_eq!(
            dedupe_key("ws_1", "acme/api", 42, "abc123"),
            "ws_1:acme/api:42:abc123"
        );
    }

    #[test]
    fn webhook_rejects_empty_secret() {
        // An empty key makes HMAC verifiable by anyone; it must never pass.
        assert!(!verify_webhook(BODY, SIGNATURE, ""));
        assert!(!verify_webhook(b"", "sha256=", ""));
    }

    #[test]
    fn strictness_table() {
        assert!(strictness_allows("low", "nit", 1));
        assert!(strictness_allows("low", "high", 1));

        assert!(strictness_allows("medium", "medium", 1));
        assert!(strictness_allows("medium", "high", 5));
        assert!(!strictness_allows("medium", "nit", 5));

        assert!(strictness_allows("high", "blocker", 3));
        assert!(strictness_allows("high", "high", 4));
        assert!(!strictness_allows("high", "high", 2));
        assert!(!strictness_allows("high", "medium", 5));
        assert!(!strictness_allows("high", "low", 5));
    }

    #[test]
    fn strictness_filters_findings_and_summary() {
        fn finding(severity: &str, confidence: u8) -> Finding {
            Finding {
                file: "app.rs".into(),
                line: 2,
                severity: severity.into(),
                confidence,
                title: "problem".into(),
                body: "fix".into(),
                suggestion: None,
            }
        }
        fn result(findings: Vec<Finding>) -> ReviewResult {
            ReviewResult {
                confidence: 0.0,
                risk: 0.0,
                summary: "2 finding(s) in 1 file(s)".into(),
                findings,
            }
        }

        let both = || vec![finding("nit", 1), finding("high", 4)];

        let mut medium = result(both());
        apply_strictness(&mut medium, "medium");
        assert_eq!(medium.findings.len(), 1);
        assert_eq!(medium.findings[0].severity, "high");
        assert_eq!(medium.summary, "1 finding(s) in 1 file(s)");
        // Scores must describe the retained finding, not the original set.
        assert_eq!(medium.confidence, 4.0);
        assert_eq!(medium.risk, 4.0);

        let mut low = result(both());
        apply_strictness(&mut low, "low");
        assert_eq!(low.findings.len(), 2);

        let mut high = result(both());
        apply_strictness(&mut high, "high");
        assert_eq!(high.findings.len(), 1);
        assert_eq!(high.findings[0].confidence, 4);
        assert_eq!(high.findings[0].severity, "high");

        let mut none = result(vec![finding("nit", 1)]);
        none.confidence = 3.0;
        none.risk = 3.0;
        apply_strictness(&mut none, "medium");
        assert!(none.findings.is_empty());
        assert_eq!(none.confidence, 0.0);
        assert_eq!(none.risk, 0.0);
        assert!(none.summary.contains("strictness bar"));
    }

    #[test]
    fn policy_default_values() {
        let p = policy_default();
        assert_eq!(p.automatic, "opened");
        assert_eq!(p.strictness, "medium");
        assert!(!p.include_drafts);
        assert!(p.status_check.is_none() && p.auto_approve.is_none());
    }

    #[test]
    fn glob_match_handles_star_and_question() {
        assert!(glob_match("*.rs", "src/lib.rs"));
        assert!(glob_match("src/*.rs", "src/lib.rs"));
        // `*` spans `/`, matching the permission rule semantics.
        assert!(glob_match("src/*.rs", "src/deep/lib.rs"));
        assert!(!glob_match("src/*.rs", "src/lib.txt"));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "abbc"));
        assert!(glob_match("*", ""));
        assert!(glob_match("", ""));
        assert!(!glob_match("a", "ab"));
    }

    #[test]
    fn custom_rules_scope_by_paths_and_repos() {
        let rules = vec![
            serde_json::json!("Always use checked arithmetic."),
            serde_json::json!({"text": "Handlers must validate input.", "paths": ["src/api/*.rs"]}),
            serde_json::json!({"text": "Client changes need an API test.", "repos": ["acme/client"]}),
            serde_json::json!({
                "text": "Migrations need a rollback.",
                "paths": ["db/*.sql"],
                "repos": ["acme/server"]
            }),
        ];
        let changed = ["src/api/handler.rs".to_string(), "db/001.sql".to_string()];

        let server = rules_section(&rules, "acme/server", &changed).unwrap();
        assert!(server.starts_with("## Project rules"));
        assert!(server.contains("Always use checked arithmetic."));
        assert!(server.contains("Handlers must validate input. (paths: src/api/*.rs)"));
        assert!(!server.contains("Client changes need an API test."));
        assert!(server.contains("Migrations need a rollback."));
        assert!(server.contains("(repos: acme/server)"));

        let client = rules_section(&rules, "acme/client", &changed).unwrap();
        assert!(client.contains("Client changes need an API test."));
        assert!(!client.contains("Migrations need a rollback."));
        assert!(client.contains("Handlers must validate input."));

        let unmatched = rules_section(&rules, "acme/client", &["src/main.rs".to_string()]);
        assert!(!unmatched.unwrap().contains("Handlers must validate input."));
    }

    #[test]
    fn context_paths_cannot_escape_the_checkout() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("checkout");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("guide.md"), "inside\n").unwrap();
        let outside = base.path().join("secret.md");
        std::fs::write(&outside, "secret\n").unwrap();

        assert!(safe_path(&root, "guide.md").is_some());
        assert!(safe_path(&root, "../secret.md").is_none());
        assert!(safe_path(&root, outside.to_str().unwrap()).is_none());
        assert!(safe_path(&root, "missing.md").is_none());

        let sections = context_sections(
            &root,
            &["guide.md".to_string(), "../secret.md".to_string()],
            5,
            200,
        );
        assert!(sections.contains("## Context: guide.md\ninside"));
        assert!(sections.contains("## Context: ../secret.md (skipped:"));
        assert!(!sections.contains("secret\n"));
    }

    #[test]
    fn full_file_context_caps_lines_and_notes_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(
            root.join("app.rs"),
            (1..=401)
                .map(|line| format!("line {line}\n"))
                .collect::<String>(),
        )
        .unwrap();

        let sections = file_sections(root, &["app.rs".to_string()], 10, 400);
        assert!(sections.starts_with("## File: app.rs\n```\n"));
        assert!(sections.contains("line 400\n"));
        assert!(!sections.contains("line 401"));
        assert!(sections.contains("[truncated after 400 lines]"));

        let (_, truncated) = read_capped(&root.join("app.rs"), 400).unwrap();
        assert!(truncated);
        let (_, truncated) = read_capped(&root.join("app.rs"), 401).unwrap();
        assert!(!truncated);

        let missing = file_sections(root, &["missing.rs".to_string()], 10, 400);
        assert!(missing.contains("## File: missing.rs (skipped: not readable)"));
    }

    #[test]
    fn sequence_diagram_instruction_follows_summary_flag() {
        let on = serde_json::json!({"sequenceDiagram": true});
        assert!(
            sequence_diagram_instruction(&on)
                .unwrap()
                .contains("sequenceDiagram")
        );
        let off = serde_json::json!({"sequenceDiagram": false});
        assert!(sequence_diagram_instruction(&off).is_none());
        assert!(sequence_diagram_instruction(&serde_json::json!({})).is_none());
        assert!(
            sequence_diagram_instruction(&serde_json::json!({"sequenceDiagram": "yes"})).is_some()
        );
        assert!(
            sequence_diagram_instruction(&serde_json::json!({"sequenceDiagram": "no"})).is_none()
        );
    }

    #[test]
    fn prompt_places_context_before_the_json_instruction() {
        let prompt = review_prompt("diff --git a/a.rs b/a.rs", "## File: a.rs\nbody\n");
        let file = prompt.find("## File: a.rs").unwrap();
        let format = prompt.find("Respond with only a JSON array").unwrap();
        assert!(file < format);
        assert!(prompt.contains("diff --git a/a.rs b/a.rs"));
    }

    #[tokio::test]
    async fn local_review_drops_findings_outside_the_diff() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("app.rs"), "fn main() {}\n").unwrap();
        git(root, &["init", "-q"]);
        git(root, &["add", "."]);
        git(
            root,
            &[
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=t",
                "commit",
                "-qm",
                "init",
            ],
        );
        std::fs::write(root.join("app.rs"), "fn main() {\n    let unused = 1;\n}\n").unwrap();

        let response = serde_json::json!({
            "findings": [
                {"file": "app.rs", "line": 2, "severity": "high", "confidence": 4,
                 "title": "unused binding", "body": "remove it"},
                {"file": "app.rs", "line": 99, "severity": "high", "confidence": 5,
                 "title": "not in diff", "body": "drop"},
                {"file": "other.rs", "line": 1, "severity": "low", "confidence": 1,
                 "title": "unknown file", "body": "drop"}
            ]
        })
        .to_string();

        let result = run_local_review(root, |_| response.clone()).await;
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].file, "app.rs");
        assert_eq!(result.findings[0].line, 2);
        assert_eq!(result.confidence, 4.0);
        assert_eq!(result.risk, 4.0);
        assert!(result.summary.contains("1 finding"));
    }

    #[tokio::test]
    async fn local_review_reports_git_failure() {
        let dir = tempfile::tempdir().unwrap();
        let result = run_local_review(dir.path(), |_| "{}".into()).await;
        assert!(result.findings.is_empty());
        assert!(result.summary.contains("could not read diff"));
    }

    #[test]
    fn parse_findings_requires_findings_json() {
        // Empty, non-JSON, and JSON without the findings key are unparsed
        // reviews, not clean ones.
        assert!(parse_findings("").is_none());
        assert!(parse_findings("Looks good to me").is_none());
        assert!(parse_findings(r#"{"summary":"clean"}"#).is_none());
        assert!(parse_findings("```json\n{\"oops\":1}\n```").is_none());
        // Both documented shapes are valid, including a bare empty array.
        assert!(parse_findings(r#"{"findings":[]}"#).unwrap().is_empty());
        assert!(parse_findings("[]").unwrap().is_empty());
        assert!(parse_findings("```json\n[]\n```").unwrap().is_empty());
        let one = parse_findings(
            r#"[{"file":"a.rs","line":1,"severity":"high","confidence":4,"title":"t","body":"b"}]"#,
        )
        .unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].file, "a.rs");
    }

    #[tokio::test]
    async fn local_review_fails_when_the_reply_is_unparsed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let (_, second) = two_commit_repo(root);
        for reply in ["", "Looks good to me", r#"{"summary":"clean"}"#] {
            let result = run_local_review_target(root, Some(&second), |_| reply.to_string()).await;
            assert!(result.findings.is_empty());
            assert!(
                result.summary.contains("not valid findings JSON"),
                "{reply}: {}",
                result.summary
            );
            assert_eq!(result.confidence, 0.0);
        }

        // A valid empty array is a genuine clean review.
        let result = run_local_review_target(root, Some(&second), |_| "[]".into()).await;
        assert_eq!(result.summary, "no actionable findings");
    }

    #[test]
    fn diff_headers_are_paired_and_paths_with_spaces_parse() {
        let diff = "diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n\
@@ -1,2 +1,3 @@\n context\n+++ not\\ta\\theader\n-old\n+new\n\
--- a/dir/with space.rs\n+++ \"b/dir/with space.rs\"\n@@ -10 +11,2 @@\n";
        let ranges = diff_ranges(diff);
        assert_eq!(
            ranges,
            vec![
                ("a.rs".to_string(), 1, 3),
                ("dir/with space.rs".to_string(), 11, 2)
            ]
        );
        // A `+++` line that is not preceded by `---` is hunk content, not a path.
        let files = diff_files(diff);
        assert_eq!(files, vec!["a.rs", "dir/with space.rs"]);
    }

    #[test]
    fn whole_file_findings_need_a_touched_path() {
        let ranges = diff_ranges("--- a/a.rs\n+++ b/a.rs\n@@ -1 +1 @@\n");
        assert!(in_diff(&ranges, "a.rs", 0));
        assert!(!in_diff(&ranges, "other.rs", 0));
        assert!(in_diff(&ranges, "a.rs", 1));
        assert!(!in_diff(&ranges, "a.rs", 2));
    }

    fn finding_json(file: &str, line: u32) -> String {
        serde_json::json!({
            "findings": [
                {"file": file, "line": line, "severity": "high", "confidence": 4,
                 "title": "unused binding", "body": "remove it"}
            ]
        })
        .to_string()
    }

    /// Two commits: `base` at the first, a second commit touching `app.rs`.
    fn two_commit_repo(root: &Path) -> (String, String) {
        std::fs::write(root.join("app.rs"), "fn main() {}\n").unwrap();
        git(root, &["init", "-q"]);
        git(root, &["add", "."]);
        commit(root, "init");
        let first = git_stdout(root, &["rev-parse", "HEAD"]);
        std::fs::write(root.join("app.rs"), "fn main() {\n    let unused = 1;\n}\n").unwrap();
        git(root, &["add", "."]);
        commit(root, "second");
        let second = git_stdout(root, &["rev-parse", "HEAD"]);
        (first, second)
    }

    #[tokio::test]
    async fn local_review_commit_target_reads_that_commit() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let (_, second) = two_commit_repo(root);
        let seen = std::cell::RefCell::new(String::new());
        let response = finding_json("app.rs", 2);
        let result = run_local_review_target(root, Some(&second), |diff| {
            *seen.borrow_mut() = diff.to_string();
            response.clone()
        })
        .await;
        assert!(seen.borrow().contains("let unused"), "{}", seen.borrow());
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].line, 2);
    }

    #[tokio::test]
    async fn local_review_branch_target_diffs_branch_to_head() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let (first, _) = two_commit_repo(root);
        git(root, &["branch", "base", &first]);
        let seen = std::cell::RefCell::new(String::new());
        let response = finding_json("app.rs", 2);
        let result = run_local_review_target(root, Some("base"), |diff| {
            *seen.borrow_mut() = diff.to_string();
            response.clone()
        })
        .await;
        assert!(seen.borrow().contains("let unused"), "{}", seen.borrow());
        assert_eq!(result.findings.len(), 1);
    }

    #[tokio::test]
    async fn local_review_includes_untracked_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        two_commit_repo(root);
        std::fs::write(root.join("fresh.rs"), "fn a() {}\nfn b() {}\n").unwrap();
        let seen = std::cell::RefCell::new(String::new());
        let response = finding_json("fresh.rs", 2);
        let result = run_local_review_target(root, None, |diff| {
            *seen.borrow_mut() = diff.to_string();
            response.clone()
        })
        .await;
        assert!(
            seen.borrow().contains("+++ b/fresh.rs"),
            "{}",
            seen.borrow()
        );
        assert_eq!(result.findings.len(), 1);

        let formatted = result.format_findings();
        assert_eq!(formatted, "fresh.rs:2: high: unused binding. remove it");
    }

    fn commit(root: &Path, message: &str) {
        git(
            root,
            &[
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=t",
                "commit",
                "-qm",
                message,
            ],
        );
    }

    fn git_stdout(root: &Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(root)
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn git(root: &Path, args: &[&str]) {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(root)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
