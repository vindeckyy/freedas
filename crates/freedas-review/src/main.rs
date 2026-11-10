//! `freedas-review` — GitHub App review worker binary.
//!
//! The control plane verifies webhooks and enqueues `reviews` rows; this process
//! leases queued rows, runs the review engine, and records the outcome.

use anyhow::Context;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "freedas-review",
    version,
    about = "Freedas pull request review worker"
)]
struct Cli {
    /// Control-plane base URL.
    #[arg(
        long,
        env = "FREEDAS_BASE_URL",
        default_value = "http://127.0.0.1:8080"
    )]
    control_url: String,
    /// Postgres connection string shared with the control plane.
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,
    /// GitHub App ID.
    #[arg(long, env = "FREEDAS_GITHUB_APP_ID")]
    github_app_id: Option<String>,
    /// Path to the GitHub App private key.
    #[arg(long, env = "FREEDAS_GITHUB_PRIVATE_KEY_PATH")]
    github_private_key_path: Option<String>,
    /// GitHub REST base URL.
    #[arg(
        long,
        env = "FREEDAS_GITHUB_API_BASE",
        default_value = freedas_review::github::DEFAULT_API_BASE
    )]
    github_api_base: String,
    /// Webhook secret used to verify deliveries.
    #[arg(long, env = "FREEDAS_GITHUB_WEBHOOK_SECRET")]
    webhook_secret: Option<String>,
    /// Number of reviews processed in parallel.
    #[arg(long, env = "FREEDAS_REVIEW_CONCURRENCY", default_value_t = 4)]
    concurrency: usize,
    /// Gateway that serves review model calls.
    #[arg(long, env = "FREEDAS_GATEWAY_URL")]
    gateway_url: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let github_app_id = cli
        .github_app_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .context("--github-app-id is required")?
        .to_owned();
    let private_key_path = cli
        .github_private_key_path
        .as_deref()
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .context("--github-private-key-path is required")?;
    anyhow::ensure!(
        cli.webhook_secret
            .as_deref()
            .is_some_and(|secret| !secret.trim().is_empty()),
        "--webhook-secret is required"
    );
    let gateway_url = cli
        .gateway_url
        .as_deref()
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .context("--gateway-url is required")?
        .to_owned();

    println!("freedas-review: control {}", cli.control_url);
    println!("freedas-review: github app {github_app_id} (key configured)");
    println!("freedas-review: webhook secret set");
    println!("freedas-review: model gateway {gateway_url}");
    println!("freedas-review: concurrency {}", cli.concurrency.max(1));

    let pool = sqlx::PgPool::connect(&cli.database_url).await?;
    let github = freedas_review::GithubApp {
        app_id: github_app_id,
        private_key_pem: std::fs::read_to_string(private_key_path)
            .with_context(|| format!("reading GitHub App key at {private_key_path}"))?,
        api_base: cli.github_api_base.clone(),
    };
    freedas_review::run_worker_with(&pool, cli.concurrency, Some(gateway_url), Some(github))
        .await?;
    Ok(())
}
