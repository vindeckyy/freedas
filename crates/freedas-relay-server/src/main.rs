//! `freedas-relay-server` — self-hosted relay for remote control.

use axum::{response::Html, routing::get};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "freedas-relay-server",
    version,
    about = "Freedas self-hosted relay server"
)]
struct Cli {
    /// Bind address.
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    /// Bind port.
    #[arg(long, default_value_t = 8082)]
    port: u16,
    /// Token machines must present in their `hello` frame.
    #[arg(long, env = "FREEDAS_RELAY_TOKEN", default_value = "")]
    token: String,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    if cli.token.is_empty() && !is_loopback(&cli.host) {
        eprintln!(
            "freedas-relay-server: refusing to bind {} without --token; set FREEDAS_RELAY_TOKEN",
            cli.host
        );
        std::process::exit(2);
    }
    println!(
        "freedas-relay-server listening on ws://{}:{}/ws{}",
        cli.host,
        cli.port,
        if cli.token.is_empty() {
            " (no token configured: connections refused)"
        } else {
            " (token required)"
        }
    );
    // The dashboard API requires the same bearer token as the WS `hello`.
    let router = freedas_relay_server::app(cli.token).route("/", get(index));
    let listener = tokio::net::TcpListener::bind((cli.host.as_str(), cli.port)).await?;
    axum::serve(listener, router).await
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// `GET /`: the dashboard SPA, which drives `/machines` and `/sessions`.
async fn index() -> Html<&'static str> {
    Html(freedas_web::INDEX_HTML)
}
