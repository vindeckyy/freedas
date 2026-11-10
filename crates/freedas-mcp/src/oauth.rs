//! OAuth 2.1 for remote MCP servers: protected-resource discovery, dynamic
//! client registration, PKCE, and a loopback callback.

use base64::Engine;
use sha2::Digest;
use std::time::Duration;

pub struct Discovery {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: Option<String>,
}

pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Token endpoint the refresh token was issued by; persisted as
    /// `mcp-<name>-token-url` so `refresh_stored` can rotate the access token.
    pub token_endpoint: Option<String>,
}

fn is_loopback(url: &reqwest::Url) -> bool {
    matches!(
        url.host_str(),
        Some("127.0.0.1") | Some("::1") | Some("localhost")
    )
}

fn require_https(label: &str, endpoint: &str) -> Result<(), String> {
    let url = reqwest::Url::parse(endpoint).map_err(|e| format!("{label}: {e}"))?;
    if url.scheme() == "https" || (url.scheme() == "http" && is_loopback(&url)) {
        return Ok(());
    }
    Err(format!("{label} must use https (got {endpoint})"))
}

fn origin(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(u) => format!(
            "{}://{}{}",
            u.scheme(),
            u.host_str().unwrap_or_default(),
            u.port().map(|p| format!(":{p}")).unwrap_or_default()
        ),
        Err(_) => url.trim_end_matches('/').to_string(),
    }
}

async fn get_json(client: &reqwest::Client, url: &str) -> Option<serde_json::Value> {
    let resp = client.get(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json().await.ok()
}

/// Discover the authorization server for a remote MCP endpoint.
pub async fn discover(server_url: &str) -> Result<Discovery, String> {
    require_https("mcp server url", server_url)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let base = origin(server_url);
    let protected = get_json(
        &client,
        &format!("{base}/.well-known/oauth-protected-resource"),
    )
    .await;
    let issuer = protected
        .as_ref()
        .and_then(|v| v["authorization_servers"][0].as_str())
        .map(str::to_string)
        .unwrap_or_else(|| base.clone());
    require_https("authorization server issuer", &issuer)?;
    let meta = get_json(
        &client,
        &format!("{issuer}/.well-known/oauth-authorization-server"),
    )
    .await
    .or(get_json(
        &client,
        &format!("{issuer}/.well-known/openid-configuration"),
    )
    .await)
    .ok_or("no authorization server metadata")?;
    let discovery = Discovery {
        authorization_endpoint: meta["authorization_endpoint"]
            .as_str()
            .ok_or("no authorization_endpoint")?
            .to_string(),
        token_endpoint: meta["token_endpoint"]
            .as_str()
            .ok_or("no token_endpoint")?
            .to_string(),
        registration_endpoint: meta["registration_endpoint"].as_str().map(str::to_string),
    };
    require_https("authorization endpoint", &discovery.authorization_endpoint)?;
    require_https("token endpoint", &discovery.token_endpoint)?;
    Ok(discovery)
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn random_token(len: usize) -> String {
    use rand::RngCore;
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    b64url(&bytes)
}

/// Run the interactive flow and return the tokens.
pub async fn authorize(server_url: &str) -> Result<TokenSet, String> {
    let discovery = discover(server_url).await?;
    let verifier = random_token(48);
    let challenge = b64url(&sha2::Sha256::digest(verifier.as_bytes()));
    let state = random_token(16);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("callback listener: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let redirect = format!("http://127.0.0.1:{port}/callback");

    let client = reqwest::Client::new();
    let client_id = if let Some(reg) = &discovery.registration_endpoint {
        require_https("registration endpoint", reg)?;
        let resp = client
            .post(reg)
            .json(&serde_json::json!({
                "client_name": "freedas",
                "redirect_uris": [redirect],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            }))
            .send()
            .await
            .map_err(|e| format!("client registration: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("client registration failed: {}", resp.status()));
        }
        let v: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        v["client_id"]
            .as_str()
            .ok_or("registration returned no client_id")?
            .to_string()
    } else {
        return Err("authorization server has no registration endpoint".into());
    };

    let mut url = reqwest::Url::parse(&discovery.authorization_endpoint)
        .map_err(|e| format!("authorization endpoint: {e}"))?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", &redirect)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", &state)
        .append_pair("resource", server_url);
    println!("open this URL to authorize:\n{url}");
    let _ = std::process::Command::new("open")
        .arg(url.as_str())
        .status();
    let _ = std::process::Command::new("xdg-open")
        .arg(url.as_str())
        .status();

    let accept = async {
        let (mut stream, _) = listener.accept().await.ok()?;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await.ok()?;
        let request = String::from_utf8_lossy(&buf[..n]).to_string();
        let line = request.lines().next()?;
        let path = line.split_whitespace().nth(1)?;
        // Percent-decode via URL parsing; auth codes may carry reserved chars.
        let mut code = None;
        let mut got_state = None;
        let fake = format!("http://127.0.0.1{path}");
        if let Ok(url) = reqwest::Url::parse(&fake) {
            for (k, v) in url.query_pairs() {
                match k.as_ref() {
                    "code" => code = Some(v.into_owned()),
                    "state" => got_state = Some(v.into_owned()),
                    _ => {}
                }
            }
        }
        let body = "<html><body>Authorization received. You can close this tab.</body></html>";
        let _ = stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: {}\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await;
        if got_state.as_deref() != Some(state.as_str()) {
            return None;
        }
        code
    };
    let code = tokio::time::timeout(Duration::from_secs(180), accept)
        .await
        .map_err(|_| "timed out waiting for the browser")?
        .ok_or("callback carried no code")?;

    let resp = client
        .post(&discovery.token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect.as_str()),
            ("client_id", client_id.as_str()),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await
        .map_err(|e| format!("token exchange: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("token exchange failed: {}", resp.status()));
    }
    let v: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    Ok(TokenSet {
        access_token: v["access_token"]
            .as_str()
            .ok_or("no access_token")?
            .to_string(),
        refresh_token: v["refresh_token"].as_str().map(str::to_string),
        token_endpoint: Some(discovery.token_endpoint.clone()),
    })
}

/// Exchange a stored refresh token for a new access token.
pub async fn refresh(token_endpoint: &str, refresh_token: &str) -> Result<TokenSet, String> {
    require_https("token endpoint", token_endpoint)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .post(token_endpoint)
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ])
        .send()
        .await
        .map_err(|e| format!("token refresh: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("token refresh failed: {}", resp.status()));
    }
    let v: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    Ok(TokenSet {
        access_token: v["access_token"]
            .as_str()
            .ok_or("no access_token")?
            .to_string(),
        refresh_token: v["refresh_token"].as_str().map(str::to_string),
        token_endpoint: Some(token_endpoint.to_string()),
    })
}
