//! Docker/Kubernetes sandbox runner (plan §26).
//!
//! One binary, N poll tasks. Each task leases one `queued` row from the shared
//! control-plane PostgreSQL database, runs it to completion, and settles
//! compute billing back into `sandboxes`/`wallet_ledger`/`audit_log`.
//!
//! Nothing here claims success the runner did not observe: a Docker/k8s
//! failure marks the row `failed` with a bounded reason, and the run's model
//! cost is billed by the gateway, not by this process.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bollard::Docker;
use bollard::exec::{CreateExecOptions, StartExecOptions, StartExecResults};
use bollard::models::{ContainerCreateBody, HostConfig};
use bollard::query_parameters::{
    CreateContainerOptionsBuilder, RemoveContainerOptionsBuilder, StopContainerOptionsBuilder,
};
use freedas_core::redact::redact;
use futures::StreamExt;
use kube::api::{Api, ApiResource, DeleteParams, DynamicObject, GroupVersionKind, PostParams};
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

/// Default image; overridable with `--image`.
pub const DEFAULT_IMAGE: &str = concat!("freedas/sandbox:", env!("CARGO_PKG_VERSION"));

/// Compute bills per second with a sixty-second minimum (plan §26.5).
pub const MIN_COMPUTE_SECONDS: i64 = 60;

/// Heartbeat cadence while a sandbox runs (plan §26.1).
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

/// Setup commands (`git clone`, checkout) get this long before they count as failed.
const SETUP_TIMEOUT: Duration = Duration::from_secs(300);

/// Exec output kept for failure reasons; larger output is truncated, not re-run.
const MAX_EXEC_OUTPUT: usize = 1 << 20;

/// Failure reasons are bounded so a hostile tool output cannot bloat the row.
const MAX_REASON_CHARS: usize = 300;

/// Sentinels from [`docker_exec`]/[`with_deadline`]; callers map them to an outcome.
pub const TIMEOUT: &str = "timeout";
pub const CANCELLED: &str = "cancelled";

/// Container limits (§26.2 step 2): 2 CPUs, 4 GiB, read-only root with a writable `/tmp`.
const SANDBOX_MEMORY_BYTES: i64 = 4 * 1024 * 1024 * 1024;
const SANDBOX_NANO_CPUS: i64 = 2_000_000_000;
const SANDBOX_TMPFS_OPTS: &str = "rw,noexec,nosuid,size=512m";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunnerBackend {
    Docker,
    K8s,
}

pub fn backend_from_str(s: &str) -> Option<RunnerBackend> {
    match s {
        "docker" => Some(RunnerBackend::Docker),
        "k8s" | "kubernetes" => Some(RunnerBackend::K8s),
        _ => None,
    }
}

/// Terminal state written to `sandboxes.status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Stopped,
    Failed,
    Cancelled,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Stopped => "stopped",
            Outcome::Failed => "failed",
            Outcome::Cancelled => "cancelled",
        }
    }
}

/// A leased row from `sandboxes`.
#[derive(Debug, Clone)]
pub struct Sandbox {
    pub id: String,
    pub workspace_id: String,
    pub repo: String,
    pub base_branch: String,
    pub task: Option<String>,
    pub branch: Option<String>,
    pub status: String,
    pub compute_rate_usd: f64,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct RunnerConfig {
    pub image: String,
    pub namespace: String,
    pub concurrency: usize,
    pub poll_interval: Duration,
    pub session_limit: Duration,
    /// Command prefix run inside the sandbox; the task text is appended as one argv.
    pub agent_cmd: Vec<String>,
    /// Push the result branch here when set (plan §26.2 step 6).
    pub push_remote: Option<String>,
    /// GitHub token used to open the draft PR (§26.2 step 6); no token, no PR.
    pub github_token: Option<String>,
    /// Control plane that mints per-sandbox model/GitHub tokens; unset disables injection.
    pub control_url: Option<String>,
    /// Runner bearer token for `control_url`; both must be set to mint tokens.
    pub runner_token: Option<String>,
    /// Only local fixture repos under this directory are bind-mounted; unset
    /// refuses every local path, so a row cannot mount an arbitrary host dir.
    pub fixture_root: Option<PathBuf>,
    pub work_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Billing {
    pub seconds: i64,
    pub cost_usd: f64,
}

/// Connected runner client for the selected backend.
#[derive(Clone)]
pub enum RunnerClient {
    Docker(Docker),
    K8s(kube::Client),
}

pub async fn connect(backend: RunnerBackend) -> Result<RunnerClient, String> {
    match backend {
        RunnerBackend::Docker => Docker::connect_with_local_defaults()
            .map(RunnerClient::Docker)
            .map_err(|e| format!("docker daemon unavailable: {e}")),
        RunnerBackend::K8s => k8s_client()
            .await
            .map(RunnerClient::K8s)
            .ok_or_else(|| "no Kubernetes configuration (kubeconfig or in-cluster)".to_string()),
    }
}

// ---------------------------------------------------------------- persistence

const SANDBOX_COLUMNS: &str = "id, workspace_id, repo, base_branch, task, branch, status, \
     compute_rate_usd::float8, created_at";

type SandboxRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    String,
    f64,
    i64,
);

impl From<SandboxRow> for Sandbox {
    fn from(
        (
            id,
            workspace_id,
            repo,
            base_branch,
            task,
            branch,
            status,
            compute_rate_usd,
            created_at,
        ): SandboxRow,
    ) -> Self {
        Sandbox {
            id,
            workspace_id,
            repo,
            base_branch,
            task,
            branch,
            status,
            compute_rate_usd,
            created_at,
        }
    }
}

/// Lease one `queued` sandbox: claim it atomically and move it to `provisioning`.
///
/// Errors are logged and reported as "no work" so a database blip backs off
/// through the poll interval instead of spinning.
pub async fn lease(pool: &PgPool) -> Option<Sandbox> {
    let sql = format!(
        "UPDATE sandboxes SET status = 'provisioning', updated_at = $1
         WHERE id = (
             SELECT id FROM sandboxes WHERE status = 'queued'
             ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED
         )
         RETURNING {SANDBOX_COLUMNS}"
    );
    match sqlx::query_as::<_, SandboxRow>(&sql)
        .bind(now_ms())
        .fetch_optional(pool)
        .await
    {
        Ok(row) => row.map(Sandbox::from),
        Err(error) => {
            tracing::error!(%error, "sandbox lease failed");
            None
        }
    }
}

/// Refresh `updated_at` so the control plane knows the row is alive.
///
/// Returns `false` when the row is no longer `provisioning`/`running`: the
/// control plane stopped it, so the run must cancel and tear down.
pub async fn heartbeat(pool: &PgPool, id: &str) -> Result<bool, String> {
    sqlx::query(
        "UPDATE sandboxes SET updated_at = $1
         WHERE id = $2 AND status IN ('provisioning', 'running')",
    )
    .bind(now_ms())
    .bind(id)
    .execute(pool)
    .await
    .map(|result| result.rows_affected() > 0)
    .map_err(|e| e.to_string())
}

/// provisioning -> running, once the workload has actually started.
pub async fn mark_running(pool: &PgPool, id: &str) -> Result<(), String> {
    let updated = sqlx::query(
        "UPDATE sandboxes SET status = 'running', updated_at = $1
         WHERE id = $2 AND status = 'provisioning'",
    )
    .bind(now_ms())
    .bind(id)
    .execute(pool)
    .await
    .map_err(|e| e.to_string())?;
    if updated.rows_affected() == 0 {
        // Stopped by the control plane between lease and start: do not run.
        return Err("sandbox is no longer leased".to_string());
    }
    Ok(())
}

/// Elapsed whole seconds, rounded up, never below the sixty-second billing minimum.
pub fn compute_seconds(started_ms: i64, finished_ms: i64) -> i64 {
    let elapsed = finished_ms.saturating_sub(started_ms);
    ((elapsed + 999) / 1000).max(MIN_COMPUTE_SECONDS)
}

/// Compute cost for a run, billed per second at the rate snapshotted at creation,
/// rounded to the ledger's six decimal places.
pub fn compute_cost(seconds: i64, rate_usd_per_second: f64) -> f64 {
    // A non-finite or negative row rate must not reach the ledger cast — NaN
    // renders as 'NaN' and fails the row, negatives silently invert billing.
    let rate = if rate_usd_per_second.is_finite() && rate_usd_per_second >= 0.0 {
        rate_usd_per_second
    } else {
        0.0
    };
    let cost = seconds.max(MIN_COMPUTE_SECONDS) as f64 * rate;
    let cost = (cost * 1e6).round() / 1e6;
    if cost.is_finite() { cost } else { 0.0 }
}

/// Flatten, redact, and bound a failure reason so it fits the database column.
pub fn bounded_reason(reason: &str) -> String {
    let flat: String = redact(reason)
        .chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect();
    flat.trim().chars().take(MAX_REASON_CHARS).collect()
}

/// Terminal transition: status, compute seconds/cost, wallet debit, audit row.
///
/// The ledger and audit rows are written in the same transaction as the status
/// update, so a crash cannot bill without recording the stop or vice versa.
/// `pr` carries the draft pull request opened by this run, if any.
pub async fn settle(
    pool: &PgPool,
    sandbox: &Sandbox,
    started_ms: i64,
    outcome: Outcome,
    failure_reason: Option<&str>,
    pr: Option<(i64, &str)>,
) -> Result<Billing, String> {
    let now = now_ms();
    let seconds = compute_seconds(started_ms, now);
    let cost = compute_cost(seconds, sandbox.compute_rate_usd);
    let status = outcome.as_str();
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    let updated = sqlx::query(
        "UPDATE sandboxes SET status = $1, updated_at = $2, finished_at = $2,
         compute_seconds = $3, compute_cost_usd = $4::numeric, failure_reason = $5,
         pr_number = $6, pr_url = $7
         WHERE id = $8 AND status IN ('provisioning', 'running')",
    )
    .bind(status)
    .bind(now)
    .bind(seconds)
    .bind(cost.to_string())
    .bind(failure_reason.map(bounded_reason))
    .bind(pr.map(|(number, _)| number))
    .bind(pr.map(|(_, url)| url))
    .bind(&sandbox.id)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    if updated.rows_affected() == 0 {
        // The control plane already terminated the row (user stop); it billed
        // compute itself, so the runner must not add a second ledger row.
        tx.rollback().await.map_err(|e| e.to_string())?;
        // Still record what the runner observed: status and compute stay the
        // control plane's, but the failure reason and draft PR are ours.
        if failure_reason.is_some() || pr.is_some() {
            let patched = sqlx::query(
                "UPDATE sandboxes SET failure_reason = COALESCE($1, failure_reason),
                 pr_number = COALESCE($2, pr_number), pr_url = COALESCE($3, pr_url)
                 WHERE id = $4",
            )
            .bind(failure_reason.map(bounded_reason))
            .bind(pr.map(|(number, _)| number))
            .bind(pr.map(|(_, url)| url))
            .bind(&sandbox.id)
            .execute(pool)
            .await
            .map_err(|e| e.to_string())?;
            tracing::info!(
                sandbox = %sandbox.id,
                rows = patched.rows_affected(),
                "sandbox already settled by the control plane; recorded the runner's outcome"
            );
        }
        let existing: Option<(Option<i64>, Option<f64>)> = sqlx::query_as(
            "SELECT compute_seconds, compute_cost_usd::float8 FROM sandboxes WHERE id = $1",
        )
        .bind(&sandbox.id)
        .fetch_optional(pool)
        .await
        .map_err(|e| e.to_string())?;
        let (seconds, cost_usd) = existing
            .map(|(s, c)| (s.unwrap_or(0), c.unwrap_or(0.0)))
            .unwrap_or((0, 0.0));
        return Ok(Billing { seconds, cost_usd });
    }
    if cost > 0.0 {
        sqlx::query(
            "INSERT INTO wallet_ledger (id, workspace_id, delta_usd, reason, ref, created_at)
             VALUES ($1, $2, $3::numeric, $4, $5, $6)",
        )
        .bind(new_id("led"))
        .bind(&sandbox.workspace_id)
        .bind((-cost).to_string())
        .bind(format!("sandbox_compute:{}", sandbox.id))
        .bind(&sandbox.id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    }
    sqlx::query(
        "INSERT INTO audit_log (id, workspace_id, user_id, action, subject, metadata, created_at)
         VALUES ($1, $2, NULL, $3, $4, $5::jsonb, $6)",
    )
    .bind(new_id("aud"))
    .bind(&sandbox.workspace_id)
    .bind(format!("sandbox.{status}"))
    .bind(&sandbox.id)
    .bind(
        serde_json::json!({
            "status": status,
            "computeSeconds": seconds,
            "computeCostUsd": cost,
            "failureReason": failure_reason.map(bounded_reason),
        })
        .to_string(),
    )
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    // Teardown revokes the sandbox's model token. Idempotent, so a control
    // plane stop that already revoked it is not an error; a revocation
    // failure is logged and never fails the settle.
    if let Err(error) = sqlx::query(
        "UPDATE api_tokens SET revoked_at = $1
         WHERE revoked_at IS NULL AND scopes IN ($2, $3)",
    )
    .bind(now)
    .bind(format!("{{sandbox:{}}}", sandbox.id))
    .bind(format!("sandbox:{}", sandbox.id))
    .execute(pool)
    .await
    {
        eprintln!("sandbox settle: revoking tokens failed: {error}");
    }
    Ok(Billing {
        seconds,
        cost_usd: cost,
    })
}

fn spawn_heartbeat(
    pool: PgPool,
    id: String,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(HEARTBEAT_INTERVAL);
        tick.tick().await;
        loop {
            tick.tick().await;
            match heartbeat(&pool, &id).await {
                Ok(true) => {}
                Ok(false) => {
                    // The control plane stopped/failed/cancelled the row: stop
                    // the workload now instead of running it to completion.
                    tracing::info!(sandbox = %id, "sandbox stopped by the control plane");
                    cancel.cancel();
                    return;
                }
                Err(error) => tracing::warn!(sandbox = %id, %error, "sandbox heartbeat failed"),
            }
        }
    })
}

/// Row ids land in host paths and Docker/K8s object names; anything outside a
/// DNS-label-ish charset can traverse `work_dir` or hijack sibling objects.
pub fn check_sandbox_id(id: &str) -> Result<(), String> {
    let ok = !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));
    if ok {
        Ok(())
    } else {
        Err(bounded_reason(&format!("invalid sandbox id: {id}")))
    }
}

/// Run one leased sandbox to completion and settle its compute billing.
pub async fn run_sandbox(
    pool: &PgPool,
    client: &RunnerClient,
    sandbox: &Sandbox,
    cfg: &RunnerConfig,
    cancel: &CancellationToken,
) -> Result<Billing, String> {
    check_sandbox_id(&sandbox.id)?;
    if !sandbox.compute_rate_usd.is_finite() || sandbox.compute_rate_usd < 0.0 {
        return Err("invalid compute rate".to_string());
    }
    let started = now_ms();
    let run_cancel = cancel.child_token();
    let tokens = fetch_tokens(cfg, &sandbox.id).await;
    let beat = spawn_heartbeat(pool.clone(), sandbox.id.clone(), run_cancel.clone());
    let result = match client {
        RunnerClient::Docker(docker) => {
            docker_run(docker, pool, sandbox, cfg, tokens.as_ref(), &run_cancel).await
        }
        RunnerClient::K8s(kube) => {
            k8s_run(
                kube,
                pool,
                sandbox,
                cfg,
                started,
                tokens.as_ref(),
                &run_cancel,
            )
            .await
        }
    };
    beat.abort();
    let (outcome, reason, pr) = match &result {
        Ok(pr) => (Outcome::Stopped, None, pr.clone()),
        Err(error) if error == CANCELLED => (Outcome::Cancelled, None, None),
        Err(error) => (Outcome::Failed, Some(error.clone()), None),
    };
    // Bill from the row's creation time, the same base the control plane uses,
    // so a stop by either side records the same compute seconds.
    let billing = settle(
        pool,
        sandbox,
        sandbox.created_at,
        outcome,
        reason.as_deref(),
        pr.as_ref().map(|(number, url)| (*number, url.as_str())),
    )
    .await?;
    tracing::info!(
        sandbox = %sandbox.id,
        status = outcome.as_str(),
        seconds = billing.seconds,
        cost_usd = billing.cost_usd,
        "sandbox finished"
    );
    result.map(|_| billing)
}

// ------------------------------------------------------------- draft pull request

/// Branch the run's result is pushed to (§26.2 step 5).
fn result_branch(sandbox: &Sandbox) -> String {
    sandbox
        .branch
        .clone()
        .unwrap_or_else(|| format!("freedas/sandbox-{}", sandbox.id))
}

/// `owner/name` from the sandbox repo field; local fixture paths are not GitHub repos.
pub fn github_repo_slug(repo: &str) -> Option<&str> {
    // Absolute paths are local fixtures; checking the raw input keeps
    // `/tmp/fixture` from trimming into a bogus `tmp/fixture` slug.
    let trimmed = repo.trim();
    if trimmed.starts_with('/') || trimmed.starts_with("file:") {
        return None;
    }
    let slug = trimmed.trim_matches('/');
    let slug = slug.strip_prefix("https://github.com/").unwrap_or(slug);
    let slug = slug.trim_matches('/');
    let slug = slug.strip_suffix(".git").unwrap_or(slug);
    let slug = slug.trim_matches('/');
    let mut parts = slug.split('/');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(owner), Some(name), None) if is_slug_component(owner) && is_slug_component(name) => {
            Some(slug)
        }
        _ => None,
    }
}

/// One `owner`/`name` component: alnum plus `-_.` only, never a dot-path or an
/// option-shaped leading `-`/`.` (parity with the git-side branch charset below).
fn is_slug_component(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && !s.starts_with('-')
        && !s.starts_with('.')
        && s != "."
        && s != ".."
}

/// Reject a repo git would parse as an option (`-x`), not a repository.
pub fn check_repo(repo: &str) -> Result<(), String> {
    if repo.starts_with('-') {
        return Err(bounded_reason(&format!("invalid repo: {repo}")));
    }
    Ok(())
}

/// Clone/push URL for the sandbox. A GitHub repo gets the installation token in
/// the URL so `git` authenticates without a credential helper; anything else
/// (local fixture, non-GitHub remote) is used as given.
pub fn authed_remote(repo: &str, token: Option<&str>) -> String {
    match (token, github_repo_slug(repo)) {
        (Some(token), Some(slug)) => {
            format!("https://x-access-token:{token}@github.com/{slug}.git")
        }
        _ => repo.to_string(),
    }
}

/// `git clone` argv; `--` keeps a hostile repo from being read as an option.
fn clone_argv(source: &str, base_branch: &str) -> Vec<String> {
    argv(&["git", "clone", "--branch", base_branch, "--", source, "."])
}

/// `git push` argv for the result branch.
fn push_argv(remote: &str, branch: &str) -> Vec<String> {
    argv(&["git", "push", "--", remote, &format!("HEAD:{branch}")])
}

/// Branch names must be safe for `git checkout -b -- <branch>` and
/// `git push HEAD:<branch>`: alnum plus `-_.`/`/` only, no option shapes
/// (`-x`), no refspec shapes (`:`, `a:b`), no `..`/`//` traversals.
pub fn check_branch(branch: &str) -> Result<(), String> {
    let bad = branch.is_empty()
        || branch.len() > 255
        || branch.starts_with('-')
        || branch.starts_with(':')
        || branch.starts_with('/')
        || branch.starts_with('.')
        || branch.contains(':')
        || !branch
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/'))
        || branch.contains("..")
        || branch.contains("//")
        || branch.ends_with('/')
        || branch.ends_with('.')
        || branch.ends_with(".lock");
    if bad {
        return Err(bounded_reason(&format!("invalid branch: {branch}")));
    }
    Ok(())
}

/// `git checkout -b -- <branch>`; `--` keeps a hostile branch from being read as
/// an option. Validate with [`check_branch`] before calling.
fn checkout_argv(branch: &str) -> Vec<String> {
    argv(&["git", "checkout", "-b", "--", branch])
}

/// GitHub token available to git: the sandbox's installation token wins over
/// the runner's own `--github-token`.
fn git_token<'a>(cfg: &'a RunnerConfig, tokens: Option<&'a SandboxTokens>) -> Option<&'a str> {
    tokens
        .and_then(|tokens| tokens.github.as_deref())
        .or(cfg.github_token.as_deref())
}

/// Repo, base branch, result branch, and task for the Job image (§26.3).
pub fn sandbox_run_env(sandbox: &Sandbox) -> Vec<(String, String)> {
    vec![
        ("FREEDAS_SANDBOX_REPO".to_string(), sandbox.repo.clone()),
        (
            "FREEDAS_SANDBOX_BASE_BRANCH".to_string(),
            sandbox.base_branch.clone(),
        ),
        ("FREEDAS_SANDBOX_BRANCH".to_string(), result_branch(sandbox)),
        (
            "FREEDAS_SANDBOX_TASK".to_string(),
            sandbox.task.clone().unwrap_or_default(),
        ),
    ]
}

/// Open a draft pull request against `base` and return `(number, html_url)`.
pub async fn create_draft_pr(
    client: &reqwest::Client,
    token: &str,
    repo: &str,
    head: &str,
    base: &str,
    title: &str,
    body: &str,
) -> Result<(i64, String), String> {
    let response = client
        .post(format!("https://api.github.com/repos/{repo}/pulls"))
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "freedas")
        .json(&serde_json::json!({
            "title": title,
            "head": head,
            "base": base,
            "body": body,
            "draft": true,
        }))
        .send()
        .await
        .map_err(|e| bounded_reason(&format!("pr create: {e}")))?;
    let status = response.status().as_u16();
    let body = response
        .text()
        .await
        .map_err(|e| bounded_reason(&format!("pr response: {e}")))?;
    parse_pr_response(status, &body)
}

/// A PR is only recorded when GitHub actually created one; every error is bounded.
pub fn parse_pr_response(status: u16, body: &str) -> Result<(i64, String), String> {
    if status != 201 {
        return Err(bounded_reason(&format!("github {status}: {body}")));
    }
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|e| bounded_reason(&format!("github response: {e}")))?;
    match (
        value.get("number").and_then(|v| v.as_i64()),
        value.get("html_url").and_then(|v| v.as_str()),
    ) {
        (Some(number), Some(url)) if !url.is_empty() => Ok((number, url.to_string())),
        _ => Err(bounded_reason(&format!(
            "github response: no number/html_url: {body}"
        ))),
    }
}

/// Does the pushed result branch exist on GitHub? 200 yes, 404 no.
pub async fn branch_exists(
    client: &reqwest::Client,
    token: &str,
    repo: &str,
    branch: &str,
) -> Result<bool, String> {
    let response = client
        .get(format!(
            "https://api.github.com/repos/{repo}/branches/{branch}"
        ))
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "freedas")
        .send()
        .await
        .map_err(|e| bounded_reason(&format!("branch check: {e}")))?;
    branch_check(response.status().as_u16())
}

/// Only a definite GitHub answer counts; every other status is an error.
pub fn branch_check(status: u16) -> Result<bool, String> {
    match status {
        200 => Ok(true),
        404 => Ok(false),
        other => Err(bounded_reason(&format!("branch check: github {other}"))),
    }
}

/// Best-effort draft PR for a pushed run. No token, no GitHub repo, or no push
/// remote means nothing is recorded and the sandbox still stops successfully.
async fn draft_pr(
    cfg: &RunnerConfig,
    sandbox: &Sandbox,
    head: &str,
    token: Option<&str>,
) -> Option<(i64, String)> {
    let token = token?;
    let repo = github_repo_slug(&sandbox.repo)?;
    cfg.push_remote.as_ref()?;
    let task = sandbox.task.clone().unwrap_or_default();
    let title: String = task.trim().chars().take(72).collect();
    let client = reqwest::Client::new();
    match create_draft_pr(
        &client,
        token,
        repo,
        head,
        &sandbox.base_branch,
        &title,
        &task,
    )
    .await
    {
        Ok(pr) => Some(pr),
        Err(error) => {
            tracing::warn!(sandbox = %sandbox.id, %error, "draft PR not created");
            None
        }
    }
}

// ------------------------------------------------------------------- tokens

/// Short-lived credentials minted by the control plane for one sandbox (§26.4).
///
/// Revocation is by expiry: the contract returns no token id, so there is no
/// `DELETE` to call at teardown; both tokens expire within the hour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxTokens {
    pub model: String,
    pub github: Option<String>,
}

/// Ask the control plane for this sandbox's tokens.
pub async fn sandbox_tokens(
    control_url: &str,
    runner_token: &str,
    sandbox_id: &str,
) -> Result<SandboxTokens, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| bounded_reason(&format!("sandbox token: {e}")))?;
    let response = client
        .post(format!(
            "{}/sandboxes/{sandbox_id}/token",
            control_url.trim_end_matches('/')
        ))
        .header("Authorization", format!("Bearer {runner_token}"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .map_err(|e| bounded_reason(&format!("sandbox token: {e}")))?;
    let status = response.status().as_u16();
    let body = response
        .text()
        .await
        .map_err(|e| bounded_reason(&format!("sandbox token: {e}")))?;
    parse_token_response(status, &body)
}

/// Only a 2xx body with a non-empty `modelToken` yields tokens.
pub fn parse_token_response(status: u16, body: &str) -> Result<SandboxTokens, String> {
    if !(200..300).contains(&status) {
        return Err(bounded_reason(&format!("sandbox token: {status} {body}")));
    }
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|e| bounded_reason(&format!("sandbox token: {e}")))?;
    let model = value
        .get("modelToken")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| bounded_reason(&format!("sandbox token: no modelToken: {body}")))?;
    let github = value
        .get("githubToken")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    Ok(SandboxTokens {
        model: model.to_string(),
        github,
    })
}

/// Mint tokens when configured; a control-plane failure never blocks the run.
async fn fetch_tokens(cfg: &RunnerConfig, sandbox_id: &str) -> Option<SandboxTokens> {
    let control = cfg.control_url.as_deref()?;
    let runner = cfg.runner_token.as_deref()?;
    match sandbox_tokens(control, runner, sandbox_id).await {
        Ok(tokens) => Some(tokens),
        Err(error) => {
            tracing::warn!(sandbox = %sandbox_id, %error, "running without sandbox tokens");
            None
        }
    }
}

/// Env handed to the clone and agent processes inside the sandbox (§26.4).
/// `FREEDAS_API_TOKEN` is the pre-rename name kept for compatibility;
/// `FREEDAS_SANDBOX_ID` is the gateway scope for a sandbox-scoped token.
pub fn sandbox_env(tokens: Option<&SandboxTokens>, sandbox_id: &str) -> Vec<(String, String)> {
    let Some(tokens) = tokens else {
        return Vec::new();
    };
    let mut env = vec![
        ("FREEDAS_API_KEY".to_string(), tokens.model.clone()),
        ("FREEDAS_API_TOKEN".to_string(), tokens.model.clone()),
        ("FREEDAS_SANDBOX_ID".to_string(), sandbox_id.to_string()),
    ];
    if let Some(github) = &tokens.github {
        env.push(("GH_TOKEN".to_string(), github.clone()));
        env.push(("GITHUB_TOKEN".to_string(), github.clone()));
    }
    env
}

/// `KEY=value` form Docker exec takes; `None` when there is nothing to inject.
fn exec_env(env: &[(String, String)]) -> Option<Vec<String>> {
    (!env.is_empty()).then(|| {
        env.iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect()
    })
}

// --------------------------------------------------------------------- docker

/// Docker name for a sandbox (`freedas-sbx-<id>`).
pub fn container_name(id: &str) -> String {
    format!("freedas-sbx-{id}")
}

/// Local fixture repos are bind-mounted read-only rather than fetched.
///
/// Only paths under the explicit `--fixture-root` are accepted: without the
/// flag a sandbox row could mount any host directory into a container.
pub fn local_repo_path(repo: &str, fixture_root: Option<&Path>) -> Option<PathBuf> {
    let root = fixture_root?.canonicalize().ok()?;
    let raw = repo.strip_prefix("file://").unwrap_or(repo);
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return None;
    }
    let path = path.canonicalize().ok()?;
    path.starts_with(&root).then_some(path)
}

/// Create a locked-down container: no capabilities, no privilege escalation,
/// non-root user. The workspace is a host bind mount so the fixture repo and
/// the result branch survive teardown for inspection.
pub async fn docker_create(
    client: &Docker,
    image: &str,
    name: &str,
    workspace: &Path,
    source: Option<&Path>,
    network: &str,
) -> Result<String, String> {
    // A crashed runner can leave the container behind; names are per sandbox,
    // so reclaim the name instead of failing to create.
    let _ = client
        .remove_container(
            name,
            Some(RemoveContainerOptionsBuilder::default().force(true).build()),
        )
        .await;
    let mut binds = vec![format!("{}:/workspace", workspace.display())];
    if let Some(source) = source {
        binds.push(format!("{}:/src:ro", source.display()));
    }
    let host_config = HostConfig {
        cap_drop: Some(vec!["ALL".to_string()]),
        security_opt: Some(vec!["no-new-privileges".to_string()]),
        network_mode: Some(network.to_string()),
        binds: Some(binds),
        // §26.2 step 2: bounded CPU/memory, read-only root with a scratch /tmp.
        memory: Some(SANDBOX_MEMORY_BYTES),
        nano_cpus: Some(SANDBOX_NANO_CPUS),
        readonly_rootfs: Some(true),
        tmpfs: Some(HashMap::from([(
            "/tmp".to_string(),
            SANDBOX_TMPFS_OPTS.to_string(),
        )])),
        ..Default::default()
    };
    let body = ContainerCreateBody {
        image: Some(image.to_string()),
        user: Some("1000".to_string()),
        // Keep the container alive for `docker exec`: the image's entrypoint is
        // `freedas`, so an ENTRYPOINT override is required (a CMD would be
        // passed to freedas as arguments and it would exit immediately).
        entrypoint: Some(vec!["sleep".to_string(), "infinity".to_string()]),
        working_dir: Some("/workspace".to_string()),
        host_config: Some(host_config),
        ..Default::default()
    };
    let options = CreateContainerOptionsBuilder::default().name(name).build();
    client
        .create_container(Some(options), body)
        .await
        .map(|created| created.id)
        .map_err(|e| e.to_string())
}

pub async fn docker_stop(client: &Docker, name: &str) -> Result<(), String> {
    let options = StopContainerOptionsBuilder::default().t(1).build();
    client
        .stop_container(name, Some(options))
        .await
        .map_err(|e| e.to_string())
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExecOutcome {
    pub code: i64,
    pub output: String,
}

/// Run `work` until it finishes, the deadline elapses, or the run is cancelled.
///
/// Both the stream drain and the exit-code inspect live inside `work`: a silent
/// agent that never exits cannot outlive the deadline.
async fn with_deadline<F, T>(
    timeout: Duration,
    cancel: &CancellationToken,
    work: F,
) -> Result<T, String>
where
    F: Future<Output = Result<T, String>>,
{
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(CANCELLED.to_string()),
        result = tokio::time::timeout(timeout, work) => {
            result.map_err(|_| TIMEOUT.to_string())?
        }
    }
}

/// Keeps the head and the tail of an over-long exec stream, dropping the middle.
#[derive(Default)]
struct OutputBuffer {
    head: String,
    tail: String,
}

impl OutputBuffer {
    fn push(&mut self, chunk: &str) {
        if self.head.len() < MAX_EXEC_OUTPUT {
            let room = MAX_EXEC_OUTPUT - self.head.len();
            if chunk.len() <= room {
                self.head.push_str(chunk);
                return;
            }
            let mut cut = room;
            while !chunk.is_char_boundary(cut) {
                cut -= 1;
            }
            self.head.push_str(&chunk[..cut]);
            self.push_tail(&chunk[cut..]);
            return;
        }
        self.push_tail(chunk);
    }

    fn push_tail(&mut self, chunk: &str) {
        self.tail.push_str(chunk);
        if self.tail.len() > MAX_EXEC_OUTPUT / 2 {
            let mut cut = self.tail.len() - MAX_EXEC_OUTPUT / 2;
            while !self.tail.is_char_boundary(cut) {
                cut += 1;
            }
            self.tail.drain(..cut);
        }
    }

    fn finish(self) -> String {
        if self.tail.is_empty() {
            self.head
        } else {
            format!("{}\n[exec output truncated]\n{}", self.head, self.tail)
        }
    }
}

/// Run one command inside a running container and wait for its exit code.
///
/// The deadline covers both draining the output stream and inspecting the exit
/// code. On timeout or cancellation the container is killed so the exec cannot
/// keep running while the row is already settled.
pub async fn docker_exec(
    client: &Docker,
    container: &str,
    cmd: &[String],
    env: &[(String, String)],
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<ExecOutcome, String> {
    let config = CreateExecOptions {
        cmd: Some(cmd.to_vec()),
        env: exec_env(env),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        ..Default::default()
    };
    let exec = client
        .create_exec(container, config)
        .await
        .map_err(|e| format!("exec create: {e}"))?;
    let start = StartExecOptions {
        output_capacity: Some(64 * 1024),
        ..Default::default()
    };
    let started = client
        .start_exec(&exec.id, Some(start))
        .await
        .map_err(|e| format!("exec start: {e}"))?;
    let result = with_deadline(timeout, cancel, async {
        let mut buffer = OutputBuffer::default();
        match started {
            StartExecResults::Attached {
                output: mut stream, ..
            } => {
                while let Some(chunk) = stream.next().await {
                    match chunk {
                        Ok(log) => buffer.push(&log.to_string()),
                        Err(e) => return Err(format!("exec stream: {e}")),
                    }
                }
            }
            StartExecResults::Detached => return Err("exec detached unexpectedly".to_string()),
        }
        // The attached stream ends when the process exits; the exit code is only
        // on inspect, so it is polled inside the same deadline.
        let code = loop {
            let inspect = client
                .inspect_exec(&exec.id)
                .await
                .map_err(|e| format!("exec inspect: {e}"))?;
            if inspect.running == Some(false) {
                break inspect.exit_code.unwrap_or(-1);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        Ok(ExecOutcome {
            code,
            output: buffer.finish(),
        })
    })
    .await;
    if matches!(&result, Err(error) if error == TIMEOUT || error == CANCELLED) {
        // Docker has no exec kill; killing the container ends the exec.
        let _ = client.kill_container(container, None).await;
    }
    result
}

fn exec_failure(cmd: &[String], out: &ExecOutcome) -> String {
    let chars: Vec<char> = out.output.chars().collect();
    let tail: String = chars[chars.len().saturating_sub(400)..].iter().collect();
    bounded_reason(&format!(
        "{} exited {}: {tail}",
        cmd.first().map(String::as_str).unwrap_or("command"),
        out.code
    ))
}

async fn exec_ok(
    client: &Docker,
    container: &str,
    cmd: &[String],
    env: &[(String, String)],
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<ExecOutcome, String> {
    let out = docker_exec(client, container, cmd, env, timeout, cancel).await?;
    if out.code != 0 {
        return Err(exec_failure(cmd, &out));
    }
    Ok(out)
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

async fn docker_run(
    client: &Docker,
    pool: &PgPool,
    sandbox: &Sandbox,
    cfg: &RunnerConfig,
    tokens: Option<&SandboxTokens>,
    cancel: &CancellationToken,
) -> Result<Option<(i64, String)>, String> {
    if cfg.agent_cmd.is_empty() {
        return Err("agent command is empty".to_string());
    }
    check_repo(&sandbox.repo)?;
    check_branch(&sandbox.base_branch)?;
    let env = sandbox_env(tokens, &sandbox.id);
    let git_token = git_token(cfg, tokens);
    let name = container_name(&sandbox.id);
    let workspace = cfg.work_dir.join(&sandbox.id);
    tokio::fs::create_dir_all(&workspace)
        .await
        .map_err(|e| bounded_reason(&format!("workspace: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // The container runs as uid 1000 on a host-owned bind mount.
        let _ = std::fs::set_permissions(&workspace, std::fs::Permissions::from_mode(0o777));
    }

    let local = local_repo_path(&sandbox.repo, cfg.fixture_root.as_deref());
    // The agent needs the gateway and GitHub. Docker has no per-destination
    // allowlist, so the deployment's egress proxy/firewall is the boundary here;
    // bridge (not host) networking is the isolation this runner can guarantee.
    let network = "bridge";

    let run = async {
        docker_create(
            client,
            &cfg.image,
            &name,
            &workspace,
            local.as_deref(),
            network,
        )
        .await?;
        client
            .start_container(&name, None)
            .await
            .map_err(|e| bounded_reason(&format!("start: {e}")))?;
        mark_running(pool, &sandbox.id).await?;

        let source = match &local {
            Some(_) => "/src".to_string(),
            None => authed_remote(&sandbox.repo, git_token),
        };
        exec_ok(
            client,
            &name,
            &clone_argv(&source, &sandbox.base_branch),
            &env,
            SETUP_TIMEOUT,
            cancel,
        )
        .await?;

        let branch = result_branch(sandbox);
        check_branch(&branch)?;
        exec_ok(
            client,
            &name,
            &checkout_argv(&branch),
            &env,
            SETUP_TIMEOUT,
            cancel,
        )
        .await?;

        let mut command = cfg.agent_cmd.clone();
        command.push(sandbox.task.clone().unwrap_or_default());
        let agent = docker_exec(client, &name, &command, &env, cfg.session_limit, cancel)
            .await
            .map_err(|e| {
                if e == TIMEOUT {
                    "session_limit".to_string()
                } else {
                    e
                }
            })?;
        if agent.code != 0 {
            return Err(exec_failure(&command, &agent));
        }

        // A no-op task leaves nothing to commit; that is not a failure.
        exec_ok(
            client,
            &name,
            &argv(&["git", "add", "-A"]),
            &env,
            SETUP_TIMEOUT,
            cancel,
        )
        .await?;
        // `-c` keeps identity out of `~/.gitconfig`, which is read-only here.
        let commit_cmd = argv(&[
            "git",
            "-c",
            "user.email=freedas-runner@localhost",
            "-c",
            "user.name=Freedas Runner",
            "commit",
            "-m",
            &format!("freedas sandbox {}", sandbox.id),
        ]);
        let commit = docker_exec(client, &name, &commit_cmd, &env, SETUP_TIMEOUT, cancel).await?;
        if commit.code != 0
            && !commit.output.contains("nothing to commit")
            && !commit.output.contains("no changes added")
        {
            return Err(exec_failure(&commit_cmd, &commit));
        }
        if let Some(remote) = &cfg.push_remote {
            let remote = authed_remote(remote, git_token);
            let push_cmd = push_argv(&remote, &branch);
            let push = docker_exec(client, &name, &push_cmd, &env, SETUP_TIMEOUT, cancel).await?;
            if push.code != 0 {
                return Err(exec_failure(&push_cmd, &push));
            }
        }
        Ok(branch)
    }
    .await;

    // Teardown failures leave a token-bearing container or a host workspace
    // behind — log them with the sandbox id so operators can reconcile.
    if let Err(error) = docker_stop(client, &name).await {
        tracing::warn!(sandbox = %sandbox.id, %error, "docker stop failed during teardown");
    }
    if let Err(error) = client
        .remove_container(
            &name,
            Some(RemoveContainerOptionsBuilder::default().force(true).build()),
        )
        .await
    {
        tracing::warn!(sandbox = %sandbox.id, %error, "docker remove failed during teardown");
    }
    if let Err(error) = tokio::fs::remove_dir_all(&workspace).await {
        tracing::warn!(sandbox = %sandbox.id, %error, "workspace cleanup failed");
    }
    match run {
        Ok(branch) => Ok(draft_pr(cfg, sandbox, &branch, git_token).await),
        Err(error) => Err(error),
    }
}

// ------------------------------------------------------------------------- k8s

pub fn job_name(id: &str) -> String {
    format!("freedas-sbx-{id}")
}

/// Job spec from plan §26.3: one Job per sandbox, no service account token.
///
/// `env` carries the sandbox's short-lived model/GitHub tokens (§26.4) plus the
/// repo/branch/task from [`sandbox_run_env`]. Credential entries (see
/// [`SECRET_ENV_KEYS`]) render as `valueFrom.secretKeyRef` into the per-run
/// [`k8s_secret_manifest`]; everything else renders as plaintext `value`. The
/// agent command plus the task is passed as container `args`: the image
/// entrypoint does checkout/push and then execs them, so the pod runs the agent
/// instead of sitting idle.
pub fn k8s_job_manifest(
    id: &str,
    image: &str,
    namespace: &str,
    env: &[(String, String)],
    agent_cmd: &[String],
    task: &str,
    session_limit_seconds: u64,
) -> serde_json::Value {
    let secret_name = k8s_secret_name(id);
    let env: Vec<serde_json::Value> = env
        .iter()
        .map(|(name, value)| {
            if SECRET_ENV_KEYS.contains(&name.as_str()) {
                serde_json::json!({"name": name, "valueFrom": {"secretKeyRef": {"name": secret_name, "key": name}}})
            } else {
                serde_json::json!({ "name": name, "value": value })
            }
        })
        .collect();
    let mut args = agent_cmd.to_vec();
    args.push(task.to_string());
    serde_json::json!({
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": { "name": job_name(id), "namespace": namespace, "labels": { "app.kubernetes.io/name": "freedas", "app.kubernetes.io/managed-by": "freedas", "app.kubernetes.io/instance": id } },
        "spec": {
            "activeDeadlineSeconds": session_limit_seconds,
            "ttlSecondsAfterFinished": 300,
            "template": {
                "metadata": { "labels": { "app.kubernetes.io/name": "freedas", "app.kubernetes.io/managed-by": "freedas", "app.kubernetes.io/instance": id } },
                "spec": {
                    "automountServiceAccountToken": false,
                    "restartPolicy": "Never",
                    "securityContext": {
                        "runAsNonRoot": true,
                        "seccompProfile": { "type": "RuntimeDefault" }
                    },
                    "containers": [{
                        "name": "agent",
                        "image": image,
                        // Mutable tags re-resolve on every run; prefer a
                        // digest-pinned image in --image for deploys.
                        "imagePullPolicy": "Always",
                        "args": args,
                        "env": env,
                        "securityContext": {
                            "allowPrivilegeEscalation": false,
                            "capabilities": { "drop": ["ALL"] },
                            "readOnlyRootFilesystem": true
                        },
                        "resources": { "limits": { "cpu": "2", "memory": "4Gi", "ephemeral-storage": "1Gi" } },
                        "volumeMounts": [
                            { "name": "workspace", "mountPath": "/workspace" },
                            { "name": "tmp", "mountPath": "/tmp" }
                        ]
                    }],
                    "volumes": [
                        { "name": "workspace", "emptyDir": { "sizeLimit": "512Mi" } },
                        { "name": "tmp", "emptyDir": { "sizeLimit": "128Mi" } }
                    ]
                }
            }
        }
    })
}

/// Env keys that carry short-lived credentials and must never render as
/// plaintext `value` in the Job spec (§26.4).
pub const SECRET_ENV_KEYS: &[&str] = &[
    "FREEDAS_API_KEY",
    "FREEDAS_API_TOKEN",
    "GH_TOKEN",
    "GITHUB_TOKEN",
];

/// Per-run Secret name holding one sandbox's tokens.
pub fn k8s_secret_name(id: &str) -> String {
    format!("{}-tokens", job_name(id))
}

/// Per-run NetworkPolicy name isolating one sandbox's pods.
pub fn k8s_network_policy_name(id: &str) -> String {
    format!("{}-egress", job_name(id))
}

/// Per-run Secret carrying only the credential env entries; non-secret entries
/// stay in the Job as plaintext `value`.
pub fn k8s_secret_manifest(
    id: &str,
    namespace: &str,
    env: &[(String, String)],
) -> serde_json::Value {
    let string_data: serde_json::Map<String, serde_json::Value> = env
        .iter()
        .filter(|(name, _)| SECRET_ENV_KEYS.contains(&name.as_str()))
        .map(|(name, value)| {
            (
                name.to_string(),
                serde_json::Value::String(value.to_string()),
            )
        })
        .collect();
    serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": { "name": k8s_secret_name(id), "namespace": namespace },
        "type": "Opaque",
        "stringData": string_data,
    })
}

/// NetworkPolicy for one sandbox run: default-deny egress except DNS (UDP/TCP
/// 53) and HTTPS (TCP 443) to GitHub and the gateway.
///
/// Expected HTTPS endpoints: `github.com`, `api.github.com`,
/// `codeload.github.com`, `objects.githubusercontent.com` (git + API), plus the
/// gateway/control-plane host from `--control-url` (the host the image uses for
/// model calls). Exact IPs shift, so vanilla `ipBlock`s cannot pin them here;
/// operators with a FQDN-aware CNI (e.g. Cilium `toFQDNs`) should tighten the
/// 443 rule's `to` to those names. Without such a CNI, 443-to-any plus no other
/// ports is the tightest portable policy.
pub fn k8s_network_policy_manifest(id: &str, namespace: &str) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": { "name": k8s_network_policy_name(id), "namespace": namespace },
        "spec": {
            "podSelector": { "matchLabels": { "app.kubernetes.io/instance": id } },
            "policyTypes": ["Egress"],
            "egress": [
                { "ports": [{ "protocol": "UDP", "port": 53 }, { "protocol": "TCP", "port": 53 }] },
                { "ports": [{ "protocol": "TCP", "port": 443 }],
                  "to": [{ "ipBlock": { "cidr": "0.0.0.0/0", "except": [
                      "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                      "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
                      "192.0.0.0/24", "198.18.0.0/15", "224.0.0.0/4"
                  ] } }] }
            ]
        }
    })
}

/// Ambient cluster client; `None` when no kubeconfig or in-cluster config exists.
pub async fn k8s_client() -> Option<kube::Client> {
    kube::Client::try_default().await.ok()
}

fn k8s_api_for(
    client: &kube::Client,
    namespace: &str,
    group: &str,
    version: &str,
    kind: &str,
) -> Api<DynamicObject> {
    let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(group, version, kind));
    Api::namespaced_with(client.clone(), namespace, &resource)
}

fn k8s_api(client: &kube::Client, namespace: &str) -> Api<DynamicObject> {
    k8s_api_for(client, namespace, "batch", "v1", "Job")
}

fn k8s_secret_api(client: &kube::Client, namespace: &str) -> Api<DynamicObject> {
    k8s_api_for(client, namespace, "", "v1", "Secret")
}

fn k8s_network_policy_api(client: &kube::Client, namespace: &str) -> Api<DynamicObject> {
    k8s_api_for(
        client,
        namespace,
        "networking.k8s.io",
        "v1",
        "NetworkPolicy",
    )
}

#[allow(clippy::too_many_arguments)]
pub async fn k8s_create(
    client: kube::Client,
    id: &str,
    image: &str,
    namespace: &str,
    env: &[(String, String)],
    agent_cmd: &[String],
    task: &str,
    session_limit_seconds: u64,
) -> Result<(), String> {
    let job_api = k8s_api(&client, namespace);
    let secret_api = k8s_secret_api(&client, namespace);
    let netpol_api = k8s_network_policy_api(&client, namespace);
    // A crashed runner can leave objects behind; names are per sandbox.
    let _ = job_api
        .delete(&job_name(id), &DeleteParams::default())
        .await;
    let _ = secret_api
        .delete(&k8s_secret_name(id), &DeleteParams::default())
        .await;
    let _ = netpol_api
        .delete(&k8s_network_policy_name(id), &DeleteParams::default())
        .await;
    let secret: DynamicObject = serde_json::from_value(k8s_secret_manifest(id, namespace, env))
        .map_err(|e| e.to_string())?;
    secret_api
        .create(&PostParams::default(), &secret)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())?;
    let netpol: DynamicObject = serde_json::from_value(k8s_network_policy_manifest(id, namespace))
        .map_err(|e| e.to_string())?;
    netpol_api
        .create(&PostParams::default(), &netpol)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())?;
    let job: DynamicObject = serde_json::from_value(k8s_job_manifest(
        id,
        image,
        namespace,
        env,
        agent_cmd,
        task,
        session_limit_seconds,
    ))
    .map_err(|e| e.to_string())?;
    job_api
        .create(&PostParams::default(), &job)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Create the Job, watch it to success/failure, then delete it.
///
/// The Job image runs the checkout/push steps itself (it has the tokens and the
/// egress policy); this process only drives status and billing. A run whose
/// push branch never appeared on GitHub is a failure, not a success.
pub async fn k8s_run(
    client: &kube::Client,
    pool: &PgPool,
    sandbox: &Sandbox,
    cfg: &RunnerConfig,
    started_ms: i64,
    tokens: Option<&SandboxTokens>,
    cancel: &CancellationToken,
) -> Result<Option<(i64, String)>, String> {
    if cfg.agent_cmd.is_empty() {
        return Err("agent command is empty".to_string());
    }
    check_repo(&sandbox.repo)?;
    check_branch(&sandbox.base_branch)?;
    check_branch(&result_branch(sandbox))?;
    let git_token = git_token(cfg, tokens);
    let mut env = sandbox_env(tokens, &sandbox.id);
    env.extend(sandbox_run_env(sandbox));
    let task = sandbox.task.clone().unwrap_or_default();
    k8s_create(
        client.clone(),
        &sandbox.id,
        &cfg.image,
        &cfg.namespace,
        &env,
        &cfg.agent_cmd,
        &task,
        cfg.session_limit.as_secs(),
    )
    .await?;
    mark_running(pool, &sandbox.id).await?;
    let api = k8s_api(client, &cfg.namespace);
    let name = job_name(&sandbox.id);
    let limit_ms = cfg.session_limit.as_millis() as i64;

    let run = async {
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return Err(CANCELLED.to_string()),
                _ = tokio::time::sleep(cfg.poll_interval) => {}
            }
            if now_ms() - started_ms > limit_ms {
                return Err("session_limit".to_string());
            }
            let job = api
                .get(&name)
                .await
                .map_err(|e| bounded_reason(&format!("job get: {e}")))?;
            let status = job.data.get("status").cloned().unwrap_or_default();
            if status
                .get("succeeded")
                .and_then(|v| v.as_i64())
                .unwrap_or(0)
                > 0
            {
                return Ok(());
            }
            if let Some(failed) = status.get("failed").and_then(|v| v.as_i64())
                && failed > 0
            {
                return Err(bounded_reason(&format!("job failed: {status}")));
            }
        }
    }
    .await;

    if let Err(error) = api.delete(&name, &DeleteParams::default()).await {
        tracing::warn!(sandbox = %sandbox.id, %error, "job delete failed during teardown");
    }
    if let Err(error) = k8s_secret_api(client, &cfg.namespace)
        .delete(&k8s_secret_name(&sandbox.id), &DeleteParams::default())
        .await
    {
        // An orphaned Secret holds short-lived model/GitHub tokens.
        tracing::warn!(sandbox = %sandbox.id, %error, "secret delete failed during teardown");
    }
    if let Err(error) = k8s_network_policy_api(client, &cfg.namespace)
        .delete(
            &k8s_network_policy_name(&sandbox.id),
            &DeleteParams::default(),
        )
        .await
    {
        tracing::warn!(sandbox = %sandbox.id, %error, "networkpolicy delete failed during teardown");
    }
    match run {
        // The Job image pushes the branch itself (§26.3); open the draft PR here.
        Ok(()) => {
            let branch = result_branch(sandbox);
            if cfg.push_remote.is_some()
                && let (Some(token), Some(slug)) = (git_token, github_repo_slug(&sandbox.repo))
            {
                let http = reqwest::Client::new();
                match branch_exists(&http, token, slug, &branch).await {
                    Ok(true) => {}
                    Ok(false) => return Err("result branch not produced".to_string()),
                    Err(error) => {
                        tracing::warn!(sandbox = %sandbox.id, %error, "branch check failed")
                    }
                }
            }
            Ok(draft_pr(cfg, sandbox, &branch, git_token).await)
        }
        Err(error) => Err(error),
    }
}

// ----------------------------------------------------------------------- time

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn new_id(prefix: &str) -> String {
    format!("{prefix}_{}", ulid::Ulid::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_parse() {
        assert_eq!(backend_from_str("docker"), Some(RunnerBackend::Docker));
        assert_eq!(backend_from_str("k8s"), Some(RunnerBackend::K8s));
        assert_eq!(backend_from_str("kubernetes"), Some(RunnerBackend::K8s));
        assert_eq!(backend_from_str("podman"), None);
        assert_eq!(backend_from_str(""), None);
    }

    #[test]
    fn manifest_shape() {
        let cmd = argv(&["freedas", "run", "--auto", "--format", "json"]);
        let m = k8s_job_manifest(
            "sbx_01",
            "freedas/sandbox:0.1.0",
            "freedas-sandboxes",
            &[("FREEDAS_SANDBOX_REPO".to_string(), "acme/repo".to_string())],
            &cmd,
            "add a test",
            900,
        );
        assert_eq!(m["apiVersion"], "batch/v1");
        assert_eq!(m["kind"], "Job");
        assert_eq!(m["metadata"]["name"], "freedas-sbx-sbx_01");
        assert_eq!(m["metadata"]["namespace"], "freedas-sandboxes");
        assert_eq!(m["spec"]["ttlSecondsAfterFinished"], 300);
        // The Job deadline follows `--session-limit-minutes`, not a fixed hour.
        assert_eq!(m["spec"]["activeDeadlineSeconds"], 900);

        let pod = &m["spec"]["template"]["spec"];
        assert_eq!(pod["automountServiceAccountToken"], false);
        assert_eq!(pod["restartPolicy"], "Never");
        assert_eq!(pod["securityContext"]["runAsNonRoot"], true);
        assert_eq!(
            pod["securityContext"]["seccompProfile"]["type"],
            "RuntimeDefault"
        );

        let c = &pod["containers"][0];
        assert_eq!(c["name"], "agent");
        assert_eq!(c["image"], "freedas/sandbox:0.1.0");
        // The image entrypoint checks out/pushes; args run the agent.
        assert_eq!(
            c["args"],
            serde_json::json!(["freedas", "run", "--auto", "--format", "json", "add a test"])
        );
        assert_eq!(
            c["env"][0],
            serde_json::json!({"name": "FREEDAS_SANDBOX_REPO", "value": "acme/repo"})
        );
        assert_eq!(c["securityContext"]["allowPrivilegeEscalation"], false);
        assert_eq!(c["securityContext"]["capabilities"]["drop"][0], "ALL");
        assert_eq!(c["securityContext"]["readOnlyRootFilesystem"], true);
        assert_eq!(c["resources"]["limits"]["cpu"], "2");
        assert_eq!(c["resources"]["limits"]["memory"], "4Gi");
        assert_eq!(c["volumeMounts"][0]["mountPath"], "/workspace");
        // A read-only root needs a writable scratch dir.
        assert_eq!(c["volumeMounts"][1]["mountPath"], "/tmp");

        assert_eq!(pod["volumes"][0]["name"], "workspace");
        assert_eq!(
            pod["volumes"][0]["emptyDir"],
            serde_json::json!({ "sizeLimit": "512Mi" })
        );
        assert_eq!(pod["volumes"][1]["name"], "tmp");
        // No service account token anywhere (K8s would inject the token at automount).
        let rendered = m.to_string();
        assert!(!rendered.contains("serviceAccountName"));
        assert!(!rendered.contains("default-token"));
    }

    #[test]
    fn manifest_without_agent_command_still_renders() {
        let m = k8s_job_manifest("sbx_01", "img", "ns", &[], &[], "", 60);
        assert_eq!(
            m["spec"]["template"]["spec"]["containers"][0]["args"],
            serde_json::json!([""])
        );
    }

    #[test]
    fn cost_has_sixty_second_minimum() {
        assert_eq!(compute_seconds(0, 1_000), 60);
        assert_eq!(compute_seconds(0, 59_999), 60);
        assert_eq!(compute_seconds(0, 60_000), 60);
        // Partial seconds round up: a run is never billed under its elapsed time.
        assert_eq!(compute_seconds(0, 60_001), 61);
        assert_eq!(compute_seconds(0, 61_000), 61);
        assert_eq!(compute_seconds(10_000, 10_000), 60);
        assert_eq!(compute_seconds(10_000, 9_000), 60);

        assert!((compute_cost(60, 0.001) - 0.06).abs() < 1e-12);
        assert!((compute_cost(90, 0.002) - 0.18).abs() < 1e-12);
        // Sub-minute runs still bill the minimum.
        assert!((compute_cost(1, 1.0) - 60.0).abs() < 1e-12);
        assert_eq!(compute_cost(3600, 0.0), 0.0);
        // Cost is rounded to the ledger's six decimal places.
        assert_eq!(compute_cost(60, 0.00000049), 0.000029);
        assert!((compute_cost(1, 0.1234567) - 7.407402).abs() < 1e-9);
    }

    #[test]
    fn reasons_are_flat_and_bounded() {
        let long = format!("line one\nline two\r\n{}", "x".repeat(1000));
        let reason = bounded_reason(&long);
        assert!(!reason.contains('\n'));
        assert!(!reason.contains('\r'));
        assert_eq!(reason.chars().count(), MAX_REASON_CHARS);
        assert_eq!(bounded_reason("  agent exit 2  "), "agent exit 2");
        // Secrets in tool output never reach the row.
        let leaked = bounded_reason(
            "fatal: unable to access 'https://x-access-token:ghs_abcdefghijklmnopqrstuvwxyz0123456789@github.com/a/b'",
        );
        assert!(
            !leaked.contains("ghs_abcdefghijklmnopqrstuvwxyz0123456789"),
            "{leaked}"
        );
        assert!(leaked.contains("[REDACTED]"), "{leaked}");
    }

    #[test]
    fn local_repo_paths_require_fixture_root() {
        let dir = std::env::temp_dir();
        let repo = dir.display().to_string();
        // Without the flag no host path is mountable.
        assert_eq!(local_repo_path(&repo, None), None);
        assert_eq!(local_repo_path(&format!("file://{repo}"), None), None);
        let root = dir.canonicalize().expect("temp dir");
        assert_eq!(local_repo_path(&repo, Some(&root)), Some(root.clone()));
        assert_eq!(
            local_repo_path(&format!("file://{repo}"), Some(&root)),
            Some(root.clone())
        );
        // Paths outside the root, relative paths, and non-paths stay rejected.
        assert_eq!(local_repo_path("/definitely/not/a/repo", Some(&root)), None);
        assert_eq!(local_repo_path("acme/repo", Some(&root)), None);
        assert_eq!(
            local_repo_path("https://github.com/acme/repo", Some(&root)),
            None
        );
    }

    #[test]
    fn git_argv_and_remote_auth() {
        // `--` keeps a repo named like a flag from being read as an option.
        assert_eq!(
            clone_argv("https://github.com/acme/repo.git", "main"),
            argv(&[
                "git",
                "clone",
                "--branch",
                "main",
                "--",
                "https://github.com/acme/repo.git",
                "."
            ])
        );
        assert_eq!(
            push_argv("origin", "freedas/sandbox-1"),
            argv(&["git", "push", "--", "origin", "HEAD:freedas/sandbox-1"])
        );

        assert_eq!(check_repo("acme/repo"), Ok(()));
        assert!(check_repo("-oProxyCommand=id").is_err());

        assert_eq!(authed_remote("acme/repo", None), "acme/repo");
        assert_eq!(
            authed_remote("https://github.com/acme/repo.git", Some("ghs_tok")),
            "https://x-access-token:ghs_tok@github.com/acme/repo.git"
        );
        assert_eq!(
            authed_remote("/tmp/fixture", Some("ghs_tok")),
            "/tmp/fixture"
        );
    }

    #[test]
    fn run_env_carries_repo_and_branch() {
        let sandbox = sandbox("sbx_1", "ws_1", 0.002);
        assert_eq!(
            sandbox_run_env(&sandbox),
            vec![
                (
                    "FREEDAS_SANDBOX_REPO".to_string(),
                    "/tmp/fixture".to_string()
                ),
                (
                    "FREEDAS_SANDBOX_BASE_BRANCH".to_string(),
                    "main".to_string()
                ),
                (
                    "FREEDAS_SANDBOX_BRANCH".to_string(),
                    "freedas/sandbox-test".to_string()
                ),
                ("FREEDAS_SANDBOX_TASK".to_string(), "add a test".to_string()),
            ]
        );
    }

    #[test]
    fn branch_check_statuses() {
        assert_eq!(branch_check(200), Ok(true));
        assert_eq!(branch_check(404), Ok(false));
        assert!(branch_check(401).is_err());
        assert!(branch_check(500).is_err());
    }

    #[test]
    fn outcome_strings() {
        assert_eq!(Outcome::Stopped.as_str(), "stopped");
        assert_eq!(Outcome::Failed.as_str(), "failed");
        assert_eq!(Outcome::Cancelled.as_str(), "cancelled");
    }

    #[test]
    fn job_names_match_manifest() {
        assert_eq!(container_name("sbx_1"), "freedas-sbx-sbx_1");
        assert_eq!(job_name("sbx_1"), "freedas-sbx-sbx_1");
    }

    #[test]
    fn pr_response_parsing() {
        let created =
            r#"{"number":42,"html_url":"https://github.com/acme/repo/pull/42","draft":true}"#;
        assert_eq!(
            parse_pr_response(201, created),
            Ok((42, "https://github.com/acme/repo/pull/42".to_string()))
        );

        // GitHub refusals surface the status and a bounded body, never a PR.
        let refused = r#"{"message":"Validation Failed","errors":[{"message":"A pull request already exists"}]}"#;
        let error = parse_pr_response(422, refused).unwrap_err();
        assert!(error.starts_with("github 422:"), "{error}");
        assert!(error.len() <= MAX_REASON_CHARS, "{error}");

        let malformed = parse_pr_response(201, "<html>not json</html>").unwrap_err();
        assert!(malformed.starts_with("github response:"), "{malformed}");
        assert!(parse_pr_response(201, r#"{"number":1}"#).is_err());
        assert!(parse_pr_response(200, created).is_err());
    }

    #[test]
    fn github_repo_slugs() {
        assert_eq!(github_repo_slug("acme/repo"), Some("acme/repo"));
        assert_eq!(
            github_repo_slug("https://github.com/acme/repo.git"),
            Some("acme/repo")
        );
        assert_eq!(github_repo_slug("acme"), None);
        assert_eq!(github_repo_slug("a/b/c"), None);
        assert_eq!(github_repo_slug("/tmp/fixture"), None);
        assert_eq!(github_repo_slug("file:///tmp/fixture"), None);
    }

    #[test]
    fn token_response_parsing() {
        let full = r#"{"modelToken":"sk-sandbox","githubToken":"ghs-install"}"#;
        assert_eq!(
            parse_token_response(200, full),
            Ok(SandboxTokens {
                model: "sk-sandbox".to_string(),
                github: Some("ghs-install".to_string()),
            })
        );

        // No GitHub App configured: model access still works.
        assert_eq!(
            parse_token_response(201, r#"{"modelToken":"sk-sandbox"}"#),
            Ok(SandboxTokens {
                model: "sk-sandbox".to_string(),
                github: None,
            })
        );
        assert_eq!(
            parse_token_response(200, r#"{"modelToken":"m","githubToken":""}"#),
            Ok(SandboxTokens {
                model: "m".to_string(),
                github: None,
            })
        );

        // Non-2xx carries the body, redacted and bounded.
        let refused = r#"{"error":"runner token revoked"}"#;
        let error = parse_token_response(403, refused).unwrap_err();
        assert!(error.starts_with("sandbox token:"), "{error}");
        assert!(error.contains("runner token revoked"), "{error}");
        assert!(error.len() <= MAX_REASON_CHARS, "{error}");
        assert!(parse_token_response(500, &"x".repeat(10_000)).is_err());

        // A 2xx without a usable model token is still a failure.
        assert!(
            parse_token_response(200, r#"{"githubToken":"g"}"#)
                .unwrap_err()
                .starts_with("sandbox token:")
        );
        assert!(parse_token_response(200, "").is_err());
    }

    #[test]
    fn sandbox_env_from_tokens() {
        let tokens = SandboxTokens {
            model: "sk-model".to_string(),
            github: Some("ghs-gh".to_string()),
        };
        let env = sandbox_env(Some(&tokens), "sbx_1");
        assert_eq!(
            env,
            vec![
                ("FREEDAS_API_KEY".to_string(), "sk-model".to_string()),
                ("FREEDAS_API_TOKEN".to_string(), "sk-model".to_string()),
                ("FREEDAS_SANDBOX_ID".to_string(), "sbx_1".to_string()),
                ("GH_TOKEN".to_string(), "ghs-gh".to_string()),
                ("GITHUB_TOKEN".to_string(), "ghs-gh".to_string()),
            ]
        );
        assert_eq!(
            exec_env(&env),
            Some(vec![
                "FREEDAS_API_KEY=sk-model".to_string(),
                "FREEDAS_API_TOKEN=sk-model".to_string(),
                "FREEDAS_SANDBOX_ID=sbx_1".to_string(),
                "GH_TOKEN=ghs-gh".to_string(),
                "GITHUB_TOKEN=ghs-gh".to_string(),
            ])
        );

        // No GitHub App: model token and its gateway scope only.
        let model_only = SandboxTokens {
            model: "sk-model".to_string(),
            github: None,
        };
        assert_eq!(sandbox_env(Some(&model_only), "sbx_1").len(), 3);
        // No configuration at all: nothing is injected.
        assert!(sandbox_env(None, "sbx_1").is_empty());
        assert_eq!(exec_env(&[]), None);
    }

    #[test]
    fn manifest_carries_token_env() {
        let tokens = SandboxTokens {
            model: "sk-model".to_string(),
            github: Some("ghs-gh".to_string()),
        };
        let env = sandbox_env(Some(&tokens), "sbx_01");
        let m = k8s_job_manifest(
            "sbx_01",
            "freedas/sandbox:0.1.0",
            "freedas-sandboxes",
            &env,
            &argv(&["freedas", "run"]),
            "task",
            3600,
        );
        let rendered = m.to_string();
        // Credentials never render as plaintext `value` in the Job spec.
        assert!(!rendered.contains("sk-model"), "{rendered}");
        assert!(!rendered.contains("ghs-gh"), "{rendered}");
        let job_env = m["spec"]["template"]["spec"]["containers"][0]["env"]
            .as_array()
            .expect("env list");
        assert_eq!(
            job_env[0],
            serde_json::json!({"name": "FREEDAS_API_KEY", "valueFrom": {"secretKeyRef": {"name": "freedas-sbx-sbx_01-tokens", "key": "FREEDAS_API_KEY"}}})
        );
        assert_eq!(
            job_env[2],
            serde_json::json!({"name": "FREEDAS_SANDBOX_ID", "value": "sbx_01"})
        );
        assert_eq!(
            job_env[3],
            serde_json::json!({"name": "GH_TOKEN", "valueFrom": {"secretKeyRef": {"name": "freedas-sbx-sbx_01-tokens", "key": "GH_TOKEN"}}})
        );
        assert_eq!(job_env.len(), 5);
        // The per-run Secret carries the credential values instead.
        let secret = k8s_secret_manifest("sbx_01", "freedas-sandboxes", &env);
        assert_eq!(secret["kind"], "Secret");
        assert_eq!(secret["metadata"]["name"], "freedas-sbx-sbx_01-tokens");
        assert_eq!(secret["stringData"]["FREEDAS_API_KEY"], "sk-model");
        assert_eq!(secret["stringData"]["GH_TOKEN"], "ghs-gh");
        // The NetworkPolicy selects the Job pods and locks egress to DNS + HTTPS.
        let netpol = k8s_network_policy_manifest("sbx_01", "freedas-sandboxes");
        assert_eq!(netpol["kind"], "NetworkPolicy");
        assert_eq!(
            netpol["spec"]["podSelector"]["matchLabels"]["app.kubernetes.io/instance"],
            "sbx_01"
        );
        assert_eq!(
            m["spec"]["template"]["metadata"]["labels"]["app.kubernetes.io/instance"],
            "sbx_01"
        );
    }

    #[tokio::test]
    async fn deadline_wraps_the_whole_work() {
        let cancel = CancellationToken::new();
        // A silent command that never finishes still hits the deadline.
        let result = with_deadline(Duration::from_millis(20), &cancel, async {
            tokio::time::sleep(Duration::from_secs(60)).await;
            Ok(())
        })
        .await;
        assert_eq!(result, Err(TIMEOUT.to_string()));

        // Completion is returned unchanged.
        let ok = with_deadline(Duration::from_secs(5), &cancel, async { Ok(7) }).await;
        assert_eq!(ok, Ok(7));

        // Cancellation ends the work immediately, before the deadline.
        let cancel = CancellationToken::new();
        cancel.cancel();
        let cancelled = with_deadline(Duration::from_secs(60), &cancel, async {
            tokio::time::sleep(Duration::from_secs(60)).await;
            Ok(())
        })
        .await;
        assert_eq!(cancelled, Err(CANCELLED.to_string()));
    }

    #[test]
    fn output_keeps_head_and_tail() {
        let mut buffer = OutputBuffer::default();
        buffer.push("first-line\n");
        for _ in 0..200 {
            buffer.push(&"x".repeat(64 * 1024));
        }
        buffer.push("\nlast-line");
        let output = buffer.finish();
        assert!(output.starts_with("first-line"), "{}", &output[..40]);
        assert!(output.ends_with("last-line"));
        assert!(output.contains("[exec output truncated]"));
        // Bounded: the head cap plus the rolling tail, never the whole stream.
        assert!(output.len() <= MAX_EXEC_OUTPUT + MAX_EXEC_OUTPUT / 2 + 64);
    }

    // ------------------------------------------------------- Postgres-backed

    /// Shared control-plane tables, matching `freedas-control`'s schema.
    const SCHEMA: &[&str] = &[
        "CREATE TABLE IF NOT EXISTS workspaces (id TEXT PRIMARY KEY, slug TEXT NOT NULL UNIQUE, name TEXT NOT NULL, kind TEXT NOT NULL, owner_id TEXT, settings JSONB NOT NULL DEFAULT '{}'::jsonb, created_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS sandboxes (id TEXT PRIMARY KEY, workspace_id TEXT, repo TEXT, base_branch TEXT, task TEXT, branch TEXT, pr_number BIGINT, pr_url TEXT, status TEXT, compute_rate_usd NUMERIC(12,6) NOT NULL DEFAULT 0, compute_seconds BIGINT, compute_cost_usd NUMERIC(12,6), failure_reason TEXT, created_at BIGINT, updated_at BIGINT, finished_at BIGINT)",
        "ALTER TABLE sandboxes ADD COLUMN IF NOT EXISTS pr_number BIGINT",
        "ALTER TABLE sandboxes ADD COLUMN IF NOT EXISTS pr_url TEXT",
        "CREATE TABLE IF NOT EXISTS wallet_ledger (id TEXT PRIMARY KEY, workspace_id TEXT, delta_usd NUMERIC(12,6) NOT NULL, reason TEXT NOT NULL, ref TEXT, created_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS audit_log (id TEXT PRIMARY KEY, workspace_id TEXT, user_id TEXT, action TEXT NOT NULL, subject TEXT, metadata JSONB NOT NULL DEFAULT '{}'::jsonb, created_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS api_tokens (id TEXT PRIMARY KEY, user_id TEXT, workspace_id TEXT, token_hash TEXT NOT NULL UNIQUE, scopes TEXT, last_used_at BIGINT, expires_at BIGINT, revoked_at BIGINT, created_at BIGINT NOT NULL)",
    ];

    async fn test_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = PgPool::connect(&url).await.expect("connect DATABASE_URL");
        // Sibling test binaries can create the same tables concurrently; retry
        // the idempotent DDL instead of failing the whole test.
        for statement in SCHEMA {
            for attempt in 0..5 {
                match sqlx::query(statement).execute(&pool).await {
                    Ok(_) => break,
                    Err(error) if attempt == 4 => panic!("schema: {error}"),
                    Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
                }
            }
        }
        Some(pool)
    }

    fn sandbox(id: &str, workspace_id: &str, rate: f64) -> Sandbox {
        Sandbox {
            id: id.to_string(),
            workspace_id: workspace_id.to_string(),
            repo: "/tmp/fixture".to_string(),
            base_branch: "main".to_string(),
            task: Some("add a test".to_string()),
            branch: Some("freedas/sandbox-test".to_string()),
            status: "provisioning".to_string(),
            compute_rate_usd: rate,
            created_at: 1,
        }
    }

    async fn seed_workspace(pool: &PgPool, id: &str) {
        sqlx::query(
            "INSERT INTO workspaces (id, slug, name, kind, created_at)
             VALUES ($1, $1, 'Sandbox Runner Test', 'organization', 1)
             ON CONFLICT DO NOTHING",
        )
        .bind(id)
        .execute(pool)
        .await
        .expect("workspace");
    }

    #[tokio::test]
    async fn lease_moves_queued_to_provisioning() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let id = new_id("sbx");
        sqlx::query(
            "INSERT INTO sandboxes (id, workspace_id, repo, base_branch, task, branch, status,
             compute_rate_usd, created_at, updated_at)
             VALUES ($1, 'ws_runner_test', '/tmp/fixture', 'main', 'task',
                     'freedas/sandbox-test', 'queued', 0.002, 1, 1)",
        )
        .bind(&id)
        .execute(&pool)
        .await
        .expect("insert queued sandbox");

        let leased = lease(&pool).await.expect("a queued sandbox");
        assert_eq!(leased.status, "provisioning");
        assert!(leased.compute_rate_usd > 0.0);
        assert!(!leased.id.is_empty());

        // Nothing is left queued for this row: a second lease sees another row
        // or nothing, never this id again.
        let again = lease(&pool).await;
        assert!(again.map(|s| s.id) != Some(id.clone()));

        let _ = sqlx::query("DELETE FROM sandboxes WHERE workspace_id = 'ws_runner_test'")
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn control_stop_ends_the_run() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let id = new_id("sbx");
        sqlx::query(
            "INSERT INTO sandboxes (id, workspace_id, repo, base_branch, task, branch, status,
             compute_rate_usd, created_at, updated_at)
             VALUES ($1, 'ws_runner_test', '/tmp/fixture', 'main', 'task',
                     'freedas/sandbox-test', 'provisioning', 0.002, 1, 1)",
        )
        .bind(&id)
        .execute(&pool)
        .await
        .expect("insert provisioning sandbox");

        // Alive: heartbeat reports true and the runner may start.
        assert_eq!(heartbeat(&pool, &id).await, Ok(true));
        mark_running(&pool, &id).await.expect("mark running");

        // The control plane stops the row while the agent runs.
        sqlx::query("UPDATE sandboxes SET status = 'stopped' WHERE id = $1")
            .bind(&id)
            .execute(&pool)
            .await
            .expect("control stop");

        // The next heartbeat sees it and the run must cancel.
        assert_eq!(heartbeat(&pool, &id).await, Ok(false));
        // A stopped row is never started.
        assert!(mark_running(&pool, &id).await.is_err());

        let _ = sqlx::query("DELETE FROM sandboxes WHERE workspace_id = 'ws_runner_test'")
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn settle_writes_status_ledger_and_audit() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let ws = new_id("ws");
        let id = new_id("sbx");
        seed_workspace(&pool, &ws).await;
        sqlx::query(
            "INSERT INTO sandboxes (id, workspace_id, repo, base_branch, task, branch, status,
             compute_rate_usd, created_at, updated_at)
             VALUES ($1, $2, '/tmp/fixture', 'main', 'task', 'freedas/sandbox-test',
                     'running', 0.002, 1, 1)",
        )
        .bind(&id)
        .bind(&ws)
        .execute(&pool)
        .await
        .expect("insert running sandbox");

        let started = now_ms() - 90_000;
        let billing = settle(
            &pool,
            &sandbox(&id, &ws, 0.002),
            started,
            Outcome::Stopped,
            None,
            None,
        )
        .await
        .expect("settle");
        assert!((89..=92).contains(&billing.seconds), "{billing:?}");
        assert!((billing.cost_usd - 0.18).abs() < 0.01, "{billing:?}");

        let row: (String, i64, f64) = sqlx::query_as(
            "SELECT status, compute_seconds, compute_cost_usd::float8 FROM sandboxes WHERE id = $1",
        )
        .bind(&id)
        .fetch_one(&pool)
        .await
        .expect("sandbox row");
        assert_eq!(row.0, "stopped");
        assert_eq!(row.1, billing.seconds);
        assert!((row.2 - billing.cost_usd).abs() < 1e-9);

        let ledger: (f64, String, Option<String>) = sqlx::query_as(
            "SELECT delta_usd::float8, reason, ref FROM wallet_ledger WHERE ref = $1",
        )
        .bind(&id)
        .fetch_one(&pool)
        .await
        .expect("ledger row");
        assert!(ledger.0 < 0.0);
        assert!((ledger.0 + billing.cost_usd).abs() < 1e-9);
        assert_eq!(ledger.1, format!("sandbox_compute:{id}"));
        assert_eq!(ledger.2.as_deref(), Some(id.as_str()));

        let audit: (String,) = sqlx::query_as("SELECT action FROM audit_log WHERE subject = $1")
            .bind(&id)
            .fetch_one(&pool)
            .await
            .expect("audit row");
        assert_eq!(audit.0, "sandbox.stopped");

        // Re-settling an already-finished row must not double-bill, but it still
        // records the runner's failure reason and draft PR.
        let again = settle(
            &pool,
            &sandbox(&id, &ws, 0.002),
            started,
            Outcome::Failed,
            Some("late duplicate"),
            Some((7, "https://github.com/acme/repo/pull/7")),
        )
        .await
        .expect("second settle");
        assert_eq!(again.seconds, billing.seconds);
        let row: (String, Option<String>, Option<i64>) =
            sqlx::query_as("SELECT status, failure_reason, pr_number FROM sandboxes WHERE id = $1")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .expect("sandbox row");
        assert_eq!(row.0, "stopped");
        assert_eq!(row.1.as_deref(), Some("late duplicate"));
        assert_eq!(row.2, Some(7));
        let ledgers: (i64,) = sqlx::query_as("SELECT count(*) FROM wallet_ledger WHERE ref = $1")
            .bind(&id)
            .fetch_one(&pool)
            .await
            .expect("ledger count");
        assert_eq!(ledgers.0, 1);
        let audits: (i64,) = sqlx::query_as("SELECT count(*) FROM audit_log WHERE subject = $1")
            .bind(&id)
            .fetch_one(&pool)
            .await
            .expect("audit count");
        assert_eq!(audits.0, 1);

        // A failed run records its bounded reason and the matching audit action.
        let id2 = new_id("sbx");
        sqlx::query(
            "INSERT INTO sandboxes (id, workspace_id, repo, base_branch, task, branch, status,
             compute_rate_usd, created_at, updated_at)
             VALUES ($1, $2, '/tmp/fixture', 'main', 'task', 'freedas/sandbox-test',
                     'running', 0.0, 1, 1)",
        )
        .bind(&id2)
        .bind(&ws)
        .execute(&pool)
        .await
        .expect("insert second sandbox");
        let failed = settle(
            &pool,
            &sandbox(&id2, &ws, 0.0),
            now_ms(),
            Outcome::Failed,
            Some("agent exited 1\nboom"),
            None,
        )
        .await
        .expect("settle failure");
        assert_eq!(failed.seconds, 60);
        assert_eq!(failed.cost_usd, 0.0);
        let reason: (String, String) =
            sqlx::query_as("SELECT status, failure_reason FROM sandboxes WHERE id = $1")
                .bind(&id2)
                .fetch_one(&pool)
                .await
                .expect("failed row");
        assert_eq!(reason.0, "failed");
        assert_eq!(reason.1, "agent exited 1 boom");
        // Zero cost means no ledger row.
        let ledgers: (i64,) = sqlx::query_as("SELECT count(*) FROM wallet_ledger WHERE ref = $1")
            .bind(&id2)
            .fetch_one(&pool)
            .await
            .expect("ledger count");
        assert_eq!(ledgers.0, 0);

        let _ = sqlx::query("DELETE FROM wallet_ledger WHERE workspace_id = $1")
            .bind(&ws)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM audit_log WHERE workspace_id = $1")
            .bind(&ws)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM sandboxes WHERE workspace_id = $1")
            .bind(&ws)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM workspaces WHERE id = $1")
            .bind(&ws)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn settle_revokes_the_sandbox_tokens() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let ws = new_id("ws");
        let id = new_id("sbx");
        seed_workspace(&pool, &ws).await;
        sqlx::query(
            "INSERT INTO sandboxes (id, workspace_id, repo, base_branch, task, branch, status,
             compute_rate_usd, created_at, updated_at)
             VALUES ($1, $2, '/tmp/fixture', 'main', 'task', 'freedas/sandbox-test',
                     'running', 0.0, 1, 1)",
        )
        .bind(&id)
        .bind(&ws)
        .execute(&pool)
        .await
        .expect("insert running sandbox");
        // Both scope shapes the control plane mints are revoked.
        for (idx, scopes) in [format!("{{sandbox:{id}}}"), format!("sandbox:{id}")]
            .into_iter()
            .enumerate()
        {
            sqlx::query(
                "INSERT INTO api_tokens (id, workspace_id, token_hash, scopes, created_at)
                 VALUES ($1, $2, $3, $4, 1)",
            )
            .bind(format!("tok_{idx}_{id}"))
            .bind(&ws)
            .bind(format!("hash_{idx}_{id}"))
            .bind(scopes)
            .execute(&pool)
            .await
            .expect("insert sandbox token");
        }

        settle(
            &pool,
            &sandbox(&id, &ws, 0.0),
            now_ms(),
            Outcome::Stopped,
            None,
            None,
        )
        .await
        .expect("settle");

        let live: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM api_tokens WHERE workspace_id = $1 AND revoked_at IS NULL",
        )
        .bind(&ws)
        .fetch_one(&pool)
        .await
        .expect("token count");
        assert_eq!(live, 0);
        let revoked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM api_tokens WHERE workspace_id = $1 AND revoked_at IS NOT NULL",
        )
        .bind(&ws)
        .fetch_one(&pool)
        .await
        .expect("revoked count");
        assert_eq!(revoked, 2);

        let _ = sqlx::query("DELETE FROM api_tokens WHERE workspace_id = $1")
            .bind(&ws)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM audit_log WHERE workspace_id = $1")
            .bind(&ws)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM sandboxes WHERE workspace_id = $1")
            .bind(&ws)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM workspaces WHERE id = $1")
            .bind(&ws)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn settle_records_draft_pr_only_when_supplied() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let ws = new_id("ws");
        seed_workspace(&pool, &ws).await;

        async fn insert_running(pool: &PgPool, id: &str, ws: &str) {
            sqlx::query(
                "INSERT INTO sandboxes (id, workspace_id, repo, base_branch, task, branch, status,
                 compute_rate_usd, created_at, updated_at)
                 VALUES ($1, $2, 'acme/repo', 'main', 'task', 'freedas/sandbox-test',
                         'running', 0.0, 1, 1)",
            )
            .bind(id)
            .bind(ws)
            .execute(pool)
            .await
            .expect("insert running sandbox");
        }

        let id = new_id("sbx");
        insert_running(&pool, &id, &ws).await;
        settle(
            &pool,
            &sandbox(&id, &ws, 0.0),
            now_ms(),
            Outcome::Stopped,
            None,
            Some((42, "https://github.com/acme/repo/pull/42")),
        )
        .await
        .expect("settle with pr");
        let row: (String, Option<i64>, Option<String>) =
            sqlx::query_as("SELECT status, pr_number, pr_url FROM sandboxes WHERE id = $1")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .expect("sandbox row");
        assert_eq!(row.0, "stopped");
        assert_eq!(row.1, Some(42));
        assert_eq!(
            row.2.as_deref(),
            Some("https://github.com/acme/repo/pull/42")
        );

        // A run that opened no PR records neither column.
        let id2 = new_id("sbx");
        insert_running(&pool, &id2, &ws).await;
        settle(
            &pool,
            &sandbox(&id2, &ws, 0.0),
            now_ms(),
            Outcome::Stopped,
            None,
            None,
        )
        .await
        .expect("settle without pr");
        let row: (Option<i64>, Option<String>) =
            sqlx::query_as("SELECT pr_number, pr_url FROM sandboxes WHERE id = $1")
                .bind(&id2)
                .fetch_one(&pool)
                .await
                .expect("sandbox row");
        assert_eq!(row, (None, None));

        let _ = sqlx::query("DELETE FROM wallet_ledger WHERE workspace_id = $1")
            .bind(&ws)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM audit_log WHERE workspace_id = $1")
            .bind(&ws)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM sandboxes WHERE workspace_id = $1")
            .bind(&ws)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM workspaces WHERE id = $1")
            .bind(&ws)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    #[ignore]
    async fn live_docker_create_start_and_stop() {
        // Requires a Docker daemon and a local image; run with `--ignored`.
        let Ok(client) = Docker::connect_with_local_defaults() else {
            return;
        };
        let workspace = std::env::temp_dir().join("freedas-sbx-live-test");
        std::fs::create_dir_all(&workspace).expect("workspace");
        let cancel = CancellationToken::new();
        let id = docker_create(
            &client,
            "alpine:latest",
            "freedas-test-sbx",
            &workspace,
            None,
            "none",
        )
        .await
        .expect("create");
        assert!(!id.is_empty());
        // A container left by a crashed run is reclaimed instead of blocking create.
        docker_create(
            &client,
            "alpine:latest",
            "freedas-test-sbx",
            &workspace,
            None,
            "none",
        )
        .await
        .expect("reclaim stale container");
        client
            .start_container("freedas-test-sbx", None)
            .await
            .expect("start");
        let out = exec_ok(
            &client,
            "freedas-test-sbx",
            &argv(&["true"]),
            &[],
            SETUP_TIMEOUT,
            &cancel,
        )
        .await
        .expect("exec true");
        assert_eq!(out.code, 0);
        // A silent command is cut off by the deadline and the container dies.
        let slow = docker_exec(
            &client,
            "freedas-test-sbx",
            &argv(&["sleep", "60"]),
            &[],
            Duration::from_millis(200),
            &cancel,
        )
        .await;
        assert_eq!(slow, Err(TIMEOUT.to_string()));
        docker_stop(&client, "freedas-test-sbx")
            .await
            .expect("stop");
        let _ = client
            .remove_container(
                "freedas-test-sbx",
                Some(RemoveContainerOptionsBuilder::default().force(true).build()),
            )
            .await;
        let _ = std::fs::remove_dir_all(&workspace);
    }
}
