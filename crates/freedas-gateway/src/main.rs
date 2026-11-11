//! `freedas-gateway` — OpenAI-compatible gateway binary.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "freedas-gateway",
    version,
    about = "Freedas OpenAI-compatible gateway"
)]
struct Cli {
    /// Upstream OpenAI-compatible base URL.
    #[arg(long)]
    upstream: Option<String>,
    /// Postgres connection string for token auth, budget checks, and usage
    /// metering. Required unless `--insecure-no-auth` is passed.
    #[arg(long, env = "DATABASE_URL")]
    database_url: Option<String>,
    /// Upstream credential as `<provider>=<key>`; may be repeated. Falls back to
    /// the provider's standard environment variable (for example
    /// `OPENAI_API_KEY`).
    #[arg(long = "provider-key", value_name = "PROVIDER=KEY")]
    provider_keys: Vec<String>,
    /// Run without a database and accept any non-empty bearer token. Local
    /// testing only: there is no authentication, budgeting, or metering.
    #[arg(long)]
    insecure_no_auth: bool,
    /// Bind address.
    #[arg(long, default_value = "127.0.0.1")]
    hostname: String,
    /// Bind port.
    #[arg(long, default_value_t = 8081)]
    port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if cli.database_url.is_none() && !cli.insecure_no_auth {
        anyhow::bail!(
            "refusing to start without --database-url: bearer tokens and budgets live in the \
             control database. Pass --insecure-no-auth for local testing."
        );
    }
    let pool = match &cli.database_url {
        Some(url) => Some(sqlx::PgPool::connect(url).await?),
        None => None,
    };

    // Flag wins, then the canonical env var, then the legacy name (warned),
    // then the compiled default — one precedence chain in one place.
    let upstream = cli
        .upstream
        .or_else(|| std::env::var("FREEDAS_GATEWAY_UPSTREAM").ok())
        .or_else(|| {
            std::env::var("FREEDAS_UPSTREAM_URL")
                .ok()
                .inspect(|_| {
                    eprintln!(
                        "warning: FREEDAS_UPSTREAM_URL is deprecated; use FREEDAS_GATEWAY_UPSTREAM"
                    );
                })
        })
        .unwrap_or_else(|| "https://api.openai.com/v1".into());
    let mut state = freedas_gateway::AppState::new(upstream.clone(), pool.clone());
    for (provider, env) in freedas_gateway::PROVIDER_ENV_KEYS {
        if let Ok(key) = std::env::var(env)
            && !key.trim().is_empty()
        {
            state = state.with_upstream_key(*provider, key);
        }
    }
    for spec in &cli.provider_keys {
        let (provider, key) = spec
            .split_once('=')
            .filter(|(p, k)| !p.trim().is_empty() && !k.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("--provider-key expects PROVIDER=KEY, got {spec:?}"))?;
        state = state.with_upstream_key(provider.trim(), key.trim());
    }
    if cli.insecure_no_auth {
        state = state.with_insecure_no_auth();
        eprintln!("warning: --insecure-no-auth: any bearer is accepted and usage is not metered");
    }

    println!(
        "freedas-gateway metering: {}",
        if pool.is_some() {
            "database configured"
        } else {
            "off (insecure mode)"
        }
    );
    let app = freedas_gateway::app_with_state(state);
    let listener = tokio::net::TcpListener::bind((cli.hostname.as_str(), cli.port)).await?;
    println!(
        "freedas-gateway listening on http://{}:{} -> {}",
        cli.hostname, cli.port, upstream
    );
    axum::serve(listener, app).await?;
    Ok(())
}
