//! `freedas-sandbox-runner`: lease queued sandboxes from the control-plane
//! database and run them (plan §26.7).

use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use freedas_sandbox_runner::{
    CANCELLED, DEFAULT_IMAGE, RunnerBackend, RunnerClient, RunnerConfig, connect, lease,
    run_sandbox,
};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum BackendArg {
    Docker,
    K8s,
}

impl From<BackendArg> for RunnerBackend {
    fn from(value: BackendArg) -> Self {
        match value {
            BackendArg::Docker => RunnerBackend::Docker,
            BackendArg::K8s => RunnerBackend::K8s,
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "freedas-sandbox-runner",
    version,
    about = "Run Freedas cloud sandboxes"
)]
struct Args {
    #[arg(long, value_enum, default_value_t = BackendArg::Docker)]
    backend: BackendArg,
    /// Control plane that mints per-sandbox model/GitHub tokens; unset disables injection.
    #[arg(long, env = "FREEDAS_CONTROL_URL")]
    control_url: Option<String>,
    /// Runner bearer token for `--control-url`; both must be set to mint tokens.
    #[arg(long, env = "FREEDAS_RUNNER_TOKEN")]
    runner_token: Option<String>,
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,
    #[arg(long, default_value = DEFAULT_IMAGE)]
    image: String,
    #[arg(long, default_value = "freedas-sandboxes")]
    namespace: String,
    #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u64).range(1..=64))]
    concurrency: u64,
    /// Seconds between lease/status polls.
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=3600))]
    poll_interval: u64,
    /// `sandbox.session_limit_minutes`: a run past this is failed with `session_limit`.
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=10080))]
    session_limit_minutes: u64,
    /// Command prefix for the agent inside the sandbox; the task is appended as one argument.
    #[arg(long, default_value = "freedas run --auto --format json")]
    agent_cmd: String,
    /// Push the result branch to this remote (URL or name) on success.
    #[arg(long)]
    push_remote: Option<String>,
    /// GitHub token for opening the draft PR; without it no PR is created.
    #[arg(long, env = "FREEDAS_GITHUB_TOKEN")]
    github_token: Option<String>,
    /// Directory local fixture repos must live under; unset refuses every local path.
    #[arg(long)]
    fixture_root: Option<PathBuf>,
    #[arg(long)]
    work_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();
    if args.control_url.is_some() != args.runner_token.is_some() {
        tracing::warn!(
            "control-url and runner-token must both be set; sandboxes run without tokens"
        );
    }

    let pool = PgPoolOptions::new()
        .max_connections(args.concurrency as u32 + 2)
        .connect(&args.database_url)
        .await?;
    let client = connect(args.backend.into()).await?;
    let cfg = RunnerConfig {
        image: args.image,
        namespace: args.namespace,
        concurrency: args.concurrency as usize,
        poll_interval: Duration::from_secs(args.poll_interval),
        session_limit: Duration::from_secs(
            args.session_limit_minutes
                .checked_mul(60)
                .ok_or("session limit too large")?,
        ),
        agent_cmd: args
            .agent_cmd
            .split_whitespace()
            .map(str::to_string)
            .collect(),
        push_remote: args.push_remote,
        github_token: args.github_token,
        control_url: args.control_url,
        runner_token: args.runner_token,
        fixture_root: args.fixture_root,
        work_dir: args
            .work_dir
            .unwrap_or_else(|| std::env::temp_dir().join("freedas-sandboxes")),
    };
    tokio::fs::create_dir_all(&cfg.work_dir).await?;
    tracing::info!(
        backend = ?args.backend,
        concurrency = cfg.concurrency,
        image = %cfg.image,
        "sandbox runner started"
    );

    let cancel = CancellationToken::new();
    let mut workers = Vec::new();
    for _ in 0..cfg.concurrency {
        workers.push(tokio::spawn(worker(
            pool.clone(),
            client.clone(),
            cfg.clone(),
            cancel.clone(),
        )));
    }

    tokio::signal::ctrl_c().await?;
    cancel.cancel();
    tracing::info!("shutting down: cancelling in-flight sandboxes and tearing them down");
    for handle in workers {
        let _ = handle.await;
    }
    Ok(())
}

async fn worker(pool: PgPool, client: RunnerClient, cfg: RunnerConfig, cancel: CancellationToken) {
    loop {
        if cancel.is_cancelled() {
            return;
        }
        match lease(&pool).await {
            Some(sandbox) => {
                let id = sandbox.id.clone();
                tracing::info!(sandbox = %id, repo = %sandbox.repo, "leased sandbox");
                if let Err(error) = run_sandbox(&pool, &client, &sandbox, &cfg, &cancel).await {
                    if error == CANCELLED {
                        tracing::info!(sandbox = %id, "sandbox cancelled and torn down");
                    } else {
                        tracing::error!(sandbox = %id, %error, "sandbox run failed");
                    }
                }
            }
            None => {
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(cfg.poll_interval) => {}
                }
            }
        }
    }
}
