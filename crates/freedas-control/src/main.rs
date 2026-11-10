//! `freedas-control` — self-hosted control plane: auth, workspaces, wallet,
//! usage, reviews, sandboxes, and GitHub webhook intake.

use clap::Parser;

/// Table DDL for a fresh control-plane database. Mirrors `SCHEMA` in the API
/// crate's tests; the gateway, review worker, and sandbox runner extend it with
/// their own tables.
const MIGRATIONS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT NOT NULL, password_hash TEXT, oidc_sub TEXT UNIQUE, active BOOLEAN NOT NULL DEFAULT TRUE, created_at BIGINT NOT NULL)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE",
    "CREATE TABLE IF NOT EXISTS workspaces (id TEXT PRIMARY KEY, slug TEXT NOT NULL UNIQUE, name TEXT NOT NULL, kind TEXT NOT NULL, owner_id TEXT REFERENCES users(id), settings JSONB NOT NULL DEFAULT '{}'::jsonb, created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS memberships (workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE, user_id TEXT REFERENCES users(id) ON DELETE CASCADE, role TEXT NOT NULL, PRIMARY KEY (workspace_id, user_id))",
    "CREATE TABLE IF NOT EXISTS wallet_ledger (id TEXT PRIMARY KEY, workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE, delta_usd NUMERIC(12,6) NOT NULL, reason TEXT NOT NULL, ref TEXT, created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS api_tokens (id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id) ON DELETE CASCADE, workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE, token_hash TEXT NOT NULL UNIQUE, scopes TEXT, last_used_at BIGINT, expires_at BIGINT, revoked_at BIGINT, created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS reviews (id TEXT PRIMARY KEY, workspace_id TEXT, installation_id BIGINT, repo TEXT, pr_number BIGINT, head_sha TEXT, status TEXT, author TEXT, confidence NUMERIC(4,2), risk NUMERIC(4,2), findings JSONB, summary TEXT, error TEXT, customer_cost_usd NUMERIC(12,6) NOT NULL DEFAULT 0, upstream_cost_usd NUMERIC(12,6) NOT NULL DEFAULT 0, review_url TEXT, created_at BIGINT, updated_at BIGINT)",
    // Manual reviews use installation_id 0, so their dedupe key is scoped to
    // the workspace; installation reviews keep the installation key.
    "ALTER TABLE reviews DROP CONSTRAINT IF EXISTS reviews_installation_id_repo_pr_number_head_sha_key",
    // The review worker dedupes by (workspace, repo, PR, head); control creates
    // the same index so both writers agree. Older global/scoped names go away.
    "DROP INDEX IF EXISTS reviews_repo_pr_head",
    "DROP INDEX IF EXISTS reviews_installation_head",
    "DROP INDEX IF EXISTS reviews_manual_head",
    // Legacy rows could repeat a workspace/repo/PR/head now that the key is
    // workspace-scoped; keep the most advanced row before indexing.
    "DELETE FROM reviews r WHERE r.workspace_id IS NOT NULL AND r.id <> (SELECT x.id FROM reviews x WHERE x.workspace_id = r.workspace_id AND x.repo = r.repo AND x.pr_number = r.pr_number AND x.head_sha = r.head_sha ORDER BY (x.review_url IS NOT NULL) DESC, (x.status = 'completed') DESC, x.created_at DESC, x.id DESC LIMIT 1)",
    "CREATE UNIQUE INDEX IF NOT EXISTS reviews_workspace_head ON reviews (workspace_id, repo, pr_number, head_sha)",
    "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS author TEXT",
    "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS confidence NUMERIC(4,2)",
    "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS risk NUMERIC(4,2)",
    "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS findings JSONB",
    // Written by freedas-review; the control plane copies them so analytics
    // works before the worker has ever started.
    "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS customer_cost_usd NUMERIC(12,6) NOT NULL DEFAULT 0",
    "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS upstream_cost_usd NUMERIC(12,6) NOT NULL DEFAULT 0",
    // The review worker records the posted review permalink here.
    "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS review_url TEXT",
    "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS summary TEXT",
    "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS error TEXT",
    "CREATE TABLE IF NOT EXISTS sandboxes (id TEXT PRIMARY KEY, workspace_id TEXT, repo TEXT, base_branch TEXT, task TEXT, branch TEXT, pr_number BIGINT, pr_url TEXT, status TEXT, compute_rate_usd NUMERIC(12,6) NOT NULL DEFAULT 0, compute_seconds BIGINT, compute_cost_usd NUMERIC(12,6), failure_reason TEXT, created_at BIGINT, updated_at BIGINT, finished_at BIGINT)",
    "ALTER TABLE sandboxes ADD COLUMN IF NOT EXISTS pr_number BIGINT",
    "ALTER TABLE sandboxes ADD COLUMN IF NOT EXISTS pr_url TEXT",
    "CREATE TABLE IF NOT EXISTS teams (id TEXT PRIMARY KEY, workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE, name TEXT NOT NULL, created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS team_members (team_id TEXT REFERENCES teams(id) ON DELETE CASCADE, user_id TEXT REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY (team_id, user_id))",
    "CREATE TABLE IF NOT EXISTS budgets (id TEXT PRIMARY KEY, workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE, scope TEXT NOT NULL CHECK (scope IN ('workspace','user','team')), subject_id TEXT, limit_usd NUMERIC(12,6) NOT NULL, period TEXT NOT NULL CHECK (period IN ('monthly','total')), created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS invoices (id TEXT PRIMARY KEY, workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE, period_start BIGINT NOT NULL, period_end BIGINT NOT NULL, lines JSONB NOT NULL, total_usd NUMERIC(12,6) NOT NULL, created_at BIGINT NOT NULL, UNIQUE (workspace_id, period_start))",
    // Older rows could repeat a month; keep the newest before the constraint.
    "DELETE FROM invoices a USING invoices b WHERE a.workspace_id = b.workspace_id AND a.period_start = b.period_start AND (a.created_at, a.id) < (b.created_at, b.id)",
    "CREATE UNIQUE INDEX IF NOT EXISTS invoices_workspace_period ON invoices (workspace_id, period_start)",
    "CREATE TABLE IF NOT EXISTS usage_events (id TEXT PRIMARY KEY, workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE, user_id TEXT REFERENCES users(id), session_id TEXT, kind TEXT NOT NULL, provider TEXT, model TEXT, input_tokens BIGINT NOT NULL DEFAULT 0, output_tokens BIGINT NOT NULL DEFAULT 0, cost_usd NUMERIC(12,6) NOT NULL DEFAULT 0, created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS audit_log (id TEXT PRIMARY KEY, workspace_id TEXT, user_id TEXT, action TEXT NOT NULL, subject TEXT, metadata JSONB NOT NULL DEFAULT '{}'::jsonb, created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS github_installations (id BIGINT PRIMARY KEY, workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE, account_login TEXT NOT NULL, account_type TEXT NOT NULL, repository_selection TEXT NOT NULL, created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS github_repositories (installation_id BIGINT REFERENCES github_installations(id) ON DELETE CASCADE, repo TEXT NOT NULL, enabled BOOLEAN NOT NULL DEFAULT TRUE, PRIMARY KEY (installation_id, repo))",
    "CREATE TABLE IF NOT EXISTS review_policies (workspace_id TEXT PRIMARY KEY REFERENCES workspaces(id) ON DELETE CASCADE, automatic TEXT NOT NULL DEFAULT 'opened', include_drafts BOOLEAN NOT NULL DEFAULT FALSE, strictness TEXT NOT NULL DEFAULT 'medium', filters JSONB NOT NULL DEFAULT '[]'::jsonb, custom_rules JSONB NOT NULL DEFAULT '[]'::jsonb, context_files JSONB NOT NULL DEFAULT '[]'::jsonb, linked_repositories JSONB NOT NULL DEFAULT '[]'::jsonb, summary JSONB NOT NULL DEFAULT '{}'::jsonb, status_check JSONB, auto_approve JSONB, updated_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS session_metadata (session_id TEXT PRIMARY KEY, workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE, user_id TEXT REFERENCES users(id), project TEXT, model TEXT, input_tokens BIGINT NOT NULL DEFAULT 0, output_tokens BIGINT NOT NULL DEFAULT 0, cost_usd NUMERIC(12,6) NOT NULL DEFAULT 0, files_read JSONB NOT NULL DEFAULT '[]'::jsonb, prompt_excerpt TEXT, started_at BIGINT NOT NULL, ended_at BIGINT)",
    "CREATE TABLE IF NOT EXISTS payment_methods (id TEXT PRIMARY KEY, workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE, provider TEXT NOT NULL, provider_customer_id TEXT, provider_payment_method_id TEXT, brand TEXT, last4 TEXT, created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS device_codes (device_code TEXT PRIMARY KEY, user_code TEXT NOT NULL, user_id TEXT, workspace_id TEXT, approved BOOLEAN NOT NULL DEFAULT FALSE, expires_at BIGINT NOT NULL, created_at BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS skills (workspace_id TEXT NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', sha256 TEXT NOT NULL, bytes BYTEA NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (workspace_id, name))",
    "CREATE TABLE IF NOT EXISTS webhook_deliveries (id TEXT PRIMARY KEY, received_at BIGINT NOT NULL)",
];

#[derive(Parser, Debug)]
#[command(
    name = "freedas-control",
    version,
    about = "Freedas self-hosted control plane"
)]
struct Cli {
    /// Postgres connection string.
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,
    /// Public base URL used in install links and callbacks.
    #[arg(
        long,
        env = "FREEDAS_BASE_URL",
        default_value = "http://127.0.0.1:8080"
    )]
    base_url: String,
    /// Bind address.
    #[arg(long, default_value = "127.0.0.1")]
    hostname: String,
    /// Bind port.
    #[arg(long, default_value_t = 8080)]
    port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let pool = sqlx::PgPool::connect(&cli.database_url).await?;
    for statement in MIGRATIONS {
        sqlx::query(statement).execute(&pool).await?;
    }
    // A sandbox that stops heartbeating for 60s is failed; this runs off the
    // request path.
    let reaper_pool = pool.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(15));
        loop {
            tick.tick().await;
            match freedas_control::reap_stale_sandboxes(&reaper_pool, 60_000).await {
                Ok(0) => {}
                Ok(n) => eprintln!("reaped {n} stale sandboxes"),
                Err(error) => eprintln!("sandbox reaper failed: {error}"),
            }
        }
    });
    let app = freedas_control::app(pool, cli.base_url.clone())
        // The dashboard is the same static SPA the local server serves; its
        // workspace, review, sandbox, and usage pages call this API. `/me` and
        // `/org/{slug}` are the personal and organization pages; the SPA
        // rewrites their pathnames to its `#/workspaces` route.
        .route("/", axum::routing::get(dashboard))
        .route("/me", axum::routing::get(dashboard))
        .route("/org/{slug}", axum::routing::get(org_dashboard));
    let listener = tokio::net::TcpListener::bind((cli.hostname.as_str(), cli.port)).await?;
    println!(
        "freedas-control listening on http://{}:{} (base {})",
        cli.hostname, cli.port, cli.base_url
    );
    axum::serve(listener, app).await?;
    Ok(())
}

async fn dashboard() -> axum::response::Html<&'static str> {
    axum::response::Html(freedas_web::INDEX_HTML)
}

/// The slug only selects a heading in the SPA, which reads it back from
/// `location.pathname`; the HTML body is identical to `/`.
async fn org_dashboard(_slug: axum::extract::Path<String>) -> axum::response::Html<&'static str> {
    axum::response::Html(freedas_web::INDEX_HTML)
}
