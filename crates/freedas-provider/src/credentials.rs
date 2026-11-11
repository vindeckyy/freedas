//! Provider credential storage: env first, then a 0600 JSON file.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn credentials_path(data_dir: &Path) -> PathBuf {
    data_dir.join("credentials.json")
}

/// Read the credential file. Missing is empty; a corrupt file is an error so
/// callers do not silently replace it on the next write.
pub fn load(data_dir: &Path) -> std::io::Result<BTreeMap<String, String>> {
    let path = credentials_path(data_dir);
    match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{}: {e}", path.display()),
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(e),
    }
}

/// Write via a 0600 temp file, fsync, then rename, so a crash cannot leave a
/// half-written or world-readable credential file.
fn write_atomic_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "tmp".into());
    // Random suffix + create_new: no predictable tmp path, no silent truncation.
    let tmp = parent.join(format!(
        ".{name}-{}-{:016x}.tmp",
        std::process::id(),
        rand::random::<u64>()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    let write_outcome = (|| -> std::io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    })();
    drop(file);
    if write_outcome.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return write_outcome;
    }
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Same atomic 0600 write for a caller-chosen file (oauth.json and friends).
pub fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    write_atomic_0600(path, text.as_bytes())
}

fn write_all(data_dir: &Path, all: &BTreeMap<String, String>) -> std::io::Result<()> {
    let path = credentials_path(data_dir);
    let text = serde_json::to_string_pretty(all).map_err(std::io::Error::other)?;
    write_atomic_0600(&path, text.as_bytes())
}

pub fn store(data_dir: &Path, provider: &str, api_key: &str) -> std::io::Result<()> {
    let mut all = load(data_dir)?;
    all.insert(provider.to_string(), api_key.to_string());
    write_all(data_dir, &all)
}

pub fn remove(data_dir: &Path, provider: &str) -> std::io::Result<()> {
    let mut all = load(data_dir)?;
    all.remove(provider);
    write_all(data_dir, &all)
}

/// Environment names checked before the stored key. `google` also accepts
/// `GEMINI_API_KEY`, which is the name Google's own tooling exports.
fn env_names(provider: &str) -> Vec<String> {
    let derived = format!("{}_API_KEY", provider.to_uppercase().replace('-', "_"));
    match provider {
        "google" | "gemini" => vec!["GEMINI_API_KEY".to_string(), "GOOGLE_API_KEY".to_string()],
        // models.dev canonical name first, freedas convention second.
        "meta" => vec!["META_MODEL_API_KEY".to_string(), "META_API_KEY".to_string()],
        _ => vec![derived],
    }
}

pub fn api_key_for(data_dir: &Path, provider: &str) -> Option<String> {
    for name in env_names(provider) {
        if let Ok(value) = std::env::var(&name) {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    match load(data_dir) {
        Ok(all) => all
            .get(provider)
            .map(|key| key.trim().to_string())
            .filter(|key| !key.is_empty()),
        Err(e) => {
            eprintln!(
                "warning: corrupt credentials file {}: {e}",
                data_dir.display()
            );
            None
        }
    }
}

/// Refresh a stored OAuth access token when a refresh token and token endpoint
/// are stored (`<provider>-refresh`, `<provider>-token-url` in
/// `credentials.json`). OAuth grants in `oauth.json` use
/// `oauth::refresh_credential` instead; this helper is OAuth-only legacy path
/// for providers that persist a refresh token + token URL as plain keys.
/// Returns `None` when the provider has no refresh path, so the caller asks
/// for a re-login.
pub async fn refresh_stored(data_dir: &Path, provider: &str) -> Option<String> {
    let all = load(data_dir).ok()?;
    let refresh = all
        .get(&format!("{provider}-refresh"))
        .filter(|token| !token.is_empty())?;
    let url = all
        .get(&format!("{provider}-token-url"))
        .filter(|url| !url.is_empty())?;
    if !crate::endpoint_url_ok(url) {
        eprintln!(
            "warning: stored token URL for {provider} is not https/loopback; skipping refresh"
        );
        return None;
    }
    let resp = crate::http_client()
        .post(url)
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.as_str()),
        ])
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body: serde_json::Value = resp.json().await.ok()?;
    let token = body["access_token"].as_str().filter(|t| !t.is_empty())?;
    if let Some(new_refresh) = body["refresh_token"].as_str().filter(|t| !t.is_empty()) {
        let _ = store(data_dir, &format!("{provider}-refresh"), new_refresh);
    }
    store(data_dir, provider, token).ok()?;
    Some(token.to_string())
}

/// Cache the selected workspace's settings so config loads can merge them
/// without a network call.
pub fn cache_org_settings(
    paths: &freedas_core::paths::Paths,
    workspaces: &serde_json::Value,
    slug: &str,
) -> std::io::Result<()> {
    let settings = workspaces
        .as_array()
        .and_then(|rows| rows.iter().find(|w| w["slug"].as_str() == Some(slug)))
        .and_then(|w| w.get("settings"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let wrapped = serde_json::json!({
        "fetched_at": now_ms,
        "ttl_secs": 3600,
        "settings": settings,
    });
    std::fs::create_dir_all(&paths.cache_dir)?;
    write_private(
        &paths.cache_dir.join("org-settings.json"),
        &serde_json::to_string_pretty(&wrapped)?,
    )
}

/// Result of an approved device-flow login.
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceLogin {
    pub token: String,
    pub workspace_slug: Option<String>,
    pub workspace_id: Option<String>,
}

/// One `/device/token` poll outcome.
#[derive(Debug, PartialEq)]
pub enum DevicePoll {
    Pending,
    /// RFC 8628 `slow_down`: add 5 seconds before polling again.
    SlowDown,
    Approved(DeviceLogin),
    Expired,
    /// Terminal: the server will not approve this device code.
    Failed(String),
}

/// Map a `/device/token` response to a poll outcome.
pub fn parse_token_response(status: u16, body: &serde_json::Value) -> DevicePoll {
    if status == 410 {
        return DevicePoll::Expired;
    }
    if (200..300).contains(&status) {
        return match body["token"].as_str().filter(|t| !t.is_empty()) {
            Some(token) => DevicePoll::Approved(DeviceLogin {
                token: token.to_string(),
                workspace_id: body["workspaceID"].as_str().map(str::to_string),
                workspace_slug: body["workspaceSlug"].as_str().map(str::to_string),
            }),
            None => DevicePoll::Pending,
        };
    }
    let error = body["error"].as_str().unwrap_or_default();
    if error.contains("expired") {
        return DevicePoll::Expired;
    }
    match error {
        "authorization_pending" => DevicePoll::Pending,
        "slow_down" => DevicePoll::SlowDown,
        "access_denied"
        | "invalid_grant"
        | "invalid_client"
        | "invalid_device_code"
        | "unauthorized_client"
        | "unsupported_grant_type" => DevicePoll::Failed(error.to_string()),
        // Server errors and rate limits are transient; anything else is terminal.
        _ if status == 429 || status >= 500 => DevicePoll::Pending,
        _ if error.is_empty() => DevicePoll::Failed(format!("HTTP {status}")),
        _ => DevicePoll::Failed(error.to_string()),
    }
}

fn open_browser(url: &str) {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    std::process::Command::new(opener)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok();
}

/// RFC 8628 device-code login against the control plane. Prints the approval
/// URL and code, then polls until approved or expired (10 minute cap).
/// Single resolution order with [`control_base`]: `FREEDAS_CONTROL_URL`, then
/// the legacy `FREEDAS_API_URL`, then the passed-in URL (stored `control_url`),
/// so the ceremony and later token use agree on the host.
fn effective_control_base(explicit: &str, data_dir: &Path) -> String {
    for var in ["FREEDAS_CONTROL_URL", "FREEDAS_API_URL"] {
        if let Ok(url) = std::env::var(var) {
            let url = url.trim().to_string();
            if !url.is_empty() {
                if !crate::endpoint_url_ok(&url) {
                    eprintln!("warning: {var} is not https/loopback; ignoring");
                    continue;
                }
                if !explicit.trim().is_empty() && explicit.trim() != url {
                    eprintln!("warning: {var} overrides configured control URL");
                }
                return url;
            }
        }
    }
    let trimmed = explicit.trim();
    if !trimmed.is_empty() {
        if crate::endpoint_url_ok(trimmed) {
            return trimmed.to_string();
        }
        eprintln!("warning: configured control URL is not https/loopback; using default");
    }
    control_base(data_dir)
}

/// The approved device token must belong to a workspace the user is actually
/// a member of. A mismatched slug/id means the approval was for the wrong
/// workspace (or a forged token response) and must not be stored.
async fn verify_device_workspace(base: &str, login: &DeviceLogin) -> Result<(), String> {
    if login.workspace_slug.is_none() && login.workspace_id.is_none() {
        return Ok(());
    }
    let client = crate::http_client();
    let url = format!("{}/workspaces", base.trim_end_matches('/'));
    let resp = client
        .get(&url)
        .bearer_auth(&login.token)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!(
            "device login workspace verification failed: {}",
            resp.status()
        ));
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    let rows: Vec<serde_json::Value> = match &body {
        serde_json::Value::Array(rows) => rows.clone(),
        serde_json::Value::Object(map) => map
            .get("workspaces")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    let ok = rows.iter().any(|w| {
        let id_ok = match (&login.workspace_id, w.get("id").and_then(|v| v.as_str())) {
            (Some(exp), Some(act)) => exp == act,
            (None, _) => true,
            (Some(_), None) => false,
        };
        let slug_ok = match (
            &login.workspace_slug,
            w.get("slug").and_then(|v| v.as_str()),
        ) {
            (Some(exp), Some(act)) => exp == act,
            (None, _) => true,
            (Some(_), None) => false,
        };
        id_ok && slug_ok
    });
    if ok {
        Ok(())
    } else {
        Err(
            "device login workspace mismatch: token workspace is not in your membership list"
                .into(),
        )
    }
}

pub async fn device_login(control_url: &str, data_dir: &Path) -> Result<DeviceLogin, String> {
    let resolved = effective_control_base(control_url, data_dir);
    let base = resolved.trim_end_matches('/');
    let client = crate::http_client();
    let code: serde_json::Value = client
        .post(format!("{base}/device/code"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| format!("device/code: {e}"))?
        .json()
        .await
        .map_err(|e| format!("device/code: {e}"))?;

    let device_code = code["deviceCode"]
        .as_str()
        .filter(|c| !c.is_empty())
        .ok_or("device/code: missing deviceCode")?
        .to_string();
    let user_code = code["userCode"].as_str().unwrap_or_default().to_string();
    let uri = code["verificationUriComplete"]
        .as_str()
        .or_else(|| code["verificationUri"].as_str())
        .unwrap_or(base)
        .to_string();
    let mut interval = code["interval"].as_u64().filter(|v| *v > 0).unwrap_or(5);
    let expires_in = code["expiresIn"]
        .as_u64()
        .filter(|v| *v > 0)
        .unwrap_or(600)
        .min(600);

    let expires_mins = expires_in.div_ceil(60).max(1);
    println!("Open {uri}");
    println!("Code: {user_code}");
    println!(
        "Only approve this code ({user_code}) on the verification page; it expires in ~{expires_mins} min. Do not approve a different code."
    );
    open_browser(&uri);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(expires_in);
    loop {
        if std::time::Instant::now() >= deadline {
            return Err("device code expired".into());
        }
        let poll = client
            .post(format!("{base}/device/token"))
            .json(&serde_json::json!({ "deviceCode": device_code }))
            .send()
            .await;
        if let Ok(resp) = poll {
            let status = resp.status().as_u16();
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            match parse_token_response(status, &body) {
                DevicePoll::Approved(login) => {
                    verify_device_workspace(base, &login).await?;
                    store(data_dir, "control", &login.token).map_err(|e| e.to_string())?;
                    // The gateway takes the same credential.
                    store(data_dir, "freedas", &login.token).map_err(|e| e.to_string())?;
                    return Ok(login);
                }
                DevicePoll::Expired => return Err("device code expired".into()),
                DevicePoll::Failed(error) => return Err(format!("device login failed: {error}")),
                DevicePoll::SlowDown => interval = (interval + 5).min(60),
                DevicePoll::Pending => {}
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
    }
}

/// Base URL of the self-hosted control plane, one resolution order for every
/// caller: `FREEDAS_CONTROL_URL`, the legacy `FREEDAS_API_URL`, the
/// `control_url` stored at login, then the default port.
pub fn control_base(data_dir: &Path) -> String {
    for var in ["FREEDAS_CONTROL_URL", "FREEDAS_API_URL"] {
        if let Ok(url) = std::env::var(var) {
            let trimmed = url.trim();
            if !trimmed.is_empty() {
                if crate::endpoint_url_ok(trimmed) {
                    return trimmed.to_string();
                }
                eprintln!("warning: {var} is not https/loopback; ignoring");
            }
        }
    }
    match load(data_dir) {
        Ok(all) => {
            if let Some(url) = all.get("control_url")
                && !url.is_empty()
            {
                if crate::endpoint_url_ok(url) {
                    return url.clone();
                }
                eprintln!("warning: stored control_url is not https/loopback; using default");
            }
        }
        Err(e) => {
            eprintln!(
                "warning: corrupt credentials file {}: {e}",
                data_dir.display()
            );
        }
    }
    "http://127.0.0.1:8080".to_string()
}

async fn control_request(
    client: &reqwest::Client,
    url: &str,
    token: &str,
) -> Result<reqwest::Response, String> {
    client
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| e.to_string())
}

/// GET a path on the self-hosted control plane using the stored `control`
/// credential. Shared by the CLI and the TUI.
pub async fn control_get(
    paths: &freedas_core::paths::Paths,
    path: &str,
) -> Result<serde_json::Value, String> {
    let base = control_base(&paths.data_dir);
    let url = format!("{}{}", base.trim_end_matches('/'), path);
    let client = crate::http_client();
    let token = api_key_for(&paths.data_dir, "control")
        .ok_or("not signed in: store a control-plane token first")?;
    let mut resp = control_request(&client, &url, &token).await?;
    // A rejected token is either refreshed (when the credential carries a
    // refresh path) or needs a fresh login.
    if resp.status().as_u16() == 401 {
        match refresh_stored(&paths.data_dir, "control").await {
            Some(refreshed) => resp = control_request(&client, &url, &refreshed).await?,
            None => {
                return Err(
                    "control-plane token rejected: run `freedas providers login` again".into(),
                );
            }
        }
    }
    if !resp.status().is_success() {
        return Err(format!("control plane returned {}", resp.status()));
    }
    resp.json().await.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn temp_dir() -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "freedas-cred-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn parses_token_response_statuses() {
        assert_eq!(
            parse_token_response(400, &json!({"error":"authorization_pending"})),
            DevicePoll::Pending
        );
        assert_eq!(
            parse_token_response(400, &json!({"error":"slow_down"})),
            DevicePoll::SlowDown
        );
        assert_eq!(
            parse_token_response(400, &json!({"error":"access_denied"})),
            DevicePoll::Failed("access_denied".into())
        );
        assert_eq!(
            parse_token_response(503, &json!({"error":"unavailable"})),
            DevicePoll::Pending
        );
        assert_eq!(
            parse_token_response(410, &json!({"error":"expired_token"})),
            DevicePoll::Expired
        );
        let approved = parse_token_response(
            200,
            &json!({
                "token":"tok","userID":"usr_1","workspaceID":"ws_1","workspaceSlug":"acme"
            }),
        );
        assert_eq!(
            approved,
            DevicePoll::Approved(DeviceLogin {
                token: "tok".into(),
                workspace_slug: Some("acme".into()),
                workspace_id: Some("ws_1".into()),
            })
        );
    }

    #[test]
    fn loads_missing_file_as_empty() {
        let dir = temp_dir();
        assert!(load(&dir).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stores_atomically_with_private_mode() {
        let dir = temp_dir();
        store(&dir, "anthropic", "sk-ant").unwrap();
        store(&dir, "openai", "sk-openai").unwrap();
        let loaded = load(&dir).unwrap();
        assert_eq!(loaded.get("anthropic").unwrap(), "sk-ant");
        assert_eq!(loaded.get("openai").unwrap(), "sk-openai");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(credentials_path(&dir))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuses_to_overwrite_corrupt_credentials() {
        let dir = temp_dir();
        let path = credentials_path(&dir);
        std::fs::write(&path, "not json").unwrap();
        assert!(load(&dir).is_err());
        assert!(store(&dir, "anthropic", "sk-ant").is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "not json");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_keeps_other_credentials() {
        let dir = temp_dir();
        store(&dir, "anthropic", "sk-ant").unwrap();
        store(&dir, "openai", "sk-openai").unwrap();
        remove(&dir, "anthropic").unwrap();
        let loaded = load(&dir).unwrap();
        assert!(!loaded.contains_key("anthropic"));
        assert_eq!(loaded.get("openai").unwrap(), "sk-openai");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
