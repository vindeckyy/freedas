//! `freedas-control` — self-hosted control plane: auth, workspaces, wallet,
//! usage, reviews, sandboxes, and GitHub webhook intake.

use clap::Parser;

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
    freedas_control::migrate(&pool, freedas_control::MIGRATIONS).await?;
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
