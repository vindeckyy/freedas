//! Skill registry client: push/pull skill directories as tarballs.

use std::path::{Component, Path, PathBuf};

/// Percent-encode a skill name for a URL path segment (unreserved set only).
pub fn encode_skill_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for b in name.as_bytes() {
        let b = *b;
        if matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn reject_crlf(value: &str, what: &str) -> Result<(), String> {
    if value.contains('\r') || value.contains('\n') {
        return Err(format!("{what} must not contain CR or LF"));
    }
    Ok(())
}
pub fn registry_base() -> String {
    if let Ok(url) = std::env::var("FREEDAS_REGISTRY")
        && !url.is_empty()
    {
        return url;
    }
    // Same control-plane resolution as `freedas_provider::credentials`, with
    // `/registry` appended; this crate does not depend on the provider crate.
    let base = ["FREEDAS_CONTROL_URL", "FREEDAS_API_URL"]
        .iter()
        .find_map(|var| std::env::var(var).ok().filter(|u| !u.is_empty()))
        .unwrap_or_else(|| "http://127.0.0.1:8080".to_string());
    format!("{}/registry", base.trim_end_matches('/'))
}

/// HTTPS everywhere except loopback HTTP for local dev registries. A cleartext
/// remote registry could serve both the tarball and its `x-skill-sha256`
/// header, making the integrity check self-referential.
fn registry_endpoint_ok(url: &str) -> bool {
    let Ok(u) = reqwest::Url::parse(url) else {
        return false;
    };
    if u.scheme() == "https" {
        return true;
    }
    u.scheme() == "http"
        && u.host_str()
            .map(|h| {
                h == "localhost"
                    || h == "[::1]"
                    || h == "::1"
                    || h == "127.0.0.1"
                    || h.starts_with("127.")
            })
            .unwrap_or(false)
}

fn check_registry_endpoint() -> Result<String, String> {
    let base = registry_base();
    if !registry_endpoint_ok(&base) {
        return Err(format!(
            "registry endpoint {base} is not https (http allowed for loopback only)"
        ));
    }
    Ok(base)
}

/// Hard caps for pulled packages: guards memory on the response body and
/// disk on unpack.
const MAX_PULL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PULL_ENTRIES: usize = 4096;
const MAX_PULL_UNPACKED: u64 = 256 * 1024 * 1024;

/// Package a skill directory into a gzipped tarball in memory.
pub async fn package_skill(dir: &Path) -> Result<Vec<u8>, String> {
    tokio::task::spawn_blocking({
        let dir = dir.to_path_buf();
        move || package_blocking(&dir)
    })
    .await
    .map_err(|e| e.to_string())?
}

fn package_blocking(dir: &Path) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    {
        let mut tar = tar::Builder::new(&mut buf);
        for entry in walk_dir(dir) {
            let rel = entry.strip_prefix(dir).unwrap_or(&entry);
            let mut file = std::fs::File::open(&entry).map_err(|e| e.to_string())?;
            tar.append_file(rel, &mut file).map_err(|e| e.to_string())?;
        }
        tar.finish().map_err(|e| e.to_string())?;
    }
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    use std::io::Write;
    gz.write_all(&buf).map_err(|e| e.to_string())?;
    gz.finish().map_err(|e| e.to_string())
}

fn walk_dir(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let Ok(ft) = e.file_type() else {
                continue;
            };
            let p = e.path();
            if ft.is_dir() {
                out.extend(walk_dir(&p));
            } else if ft.is_file() {
                out.push(p);
            }
            // Symlinks ignored: never package a link out of the skill dir.
        }
    }
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
}

fn skill_description(dir: &Path) -> String {
    let Ok(text) = std::fs::read_to_string(dir.join("SKILL.md")) else {
        return String::new();
    };
    let (front, _) =
        freedas_agent::parse_frontmatter(&text).unwrap_or((serde_json::json!({}), String::new()));
    front["description"].as_str().unwrap_or("").to_string()
}

pub async fn push_skill(name: &str, dir: &Path, token: Option<&str>) -> Result<String, String> {
    reject_crlf(name, "skill name")?;
    let bytes = package_skill(dir).await?;
    let sha = sha256_hex(&bytes);
    let description = skill_description(dir);
    reject_crlf(&description, "skill description")?;
    let base = check_registry_endpoint()?;
    let client = reqwest::Client::new();
    let url = format!("{}/skills/{}", base, encode_skill_name(name));
    let mut req = client
        .post(&url)
        .header("content-type", "application/octet-stream")
        .header("x-skill-sha256", sha)
        .header("x-skill-description", description)
        .body(bytes);
    if let Some(token) = token {
        req = req.bearer_auth(token);
    }
    let resp = req.send().await.map_err(|e| format!("push: {e}"))?;
    if resp.status().is_success() {
        Ok(format!("pushed skill {name}"))
    } else {
        Err(format!("push failed: {}", resp.status()))
    }
}

/// List the skills published to the workspace registry.
pub async fn list_skills(token: Option<&str>) -> Result<Vec<(String, String)>, String> {
    let client = reqwest::Client::new();
    let url = format!("{}/skills", registry_base());
    let mut req = client.get(&url);
    if let Some(token) = token {
        req = req.bearer_auth(token);
    }
    let resp = req.send().await.map_err(|e| format!("list: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("list failed: {}", resp.status()));
    }
    let rows: Vec<serde_json::Value> = resp.json().await.map_err(|e| e.to_string())?;
    Ok(rows
        .into_iter()
        .map(|r| {
            (
                r["name"].as_str().unwrap_or("").to_string(),
                r["description"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect())
}

pub async fn pull_skill(
    name: &str,
    dest: &Path,
    token: Option<&str>,
    force: bool,
) -> Result<String, String> {
    reject_crlf(name, "skill name")?;
    let base = check_registry_endpoint()?;
    let client = reqwest::Client::new();
    let url = format!("{}/skills/{}", base, encode_skill_name(name));
    let mut req = client.get(&url);
    if let Some(token) = token {
        req = req.bearer_auth(token);
    }
    let resp = req.send().await.map_err(|e| format!("pull: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("pull failed: {}", resp.status()));
    }
    // An out-of-band pin beats the response header: the header is a
    // corruption check only, since a compromised registry supplies both
    // sides. `FREEDAS_SKILL_SHA256_<NAME>` (uppercased, non-alnum -> `_`)
    // pins the expected digest from a trusted channel.
    let pin_var = format!(
        "FREEDAS_SKILL_SHA256_{}",
        name.chars()
            .map(|c| if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            })
            .collect::<String>()
    );
    let expected = match std::env::var(&pin_var).ok().filter(|s| !s.is_empty()) {
        Some(pin) => pin,
        None => resp
            .headers()
            .get("x-skill-sha256")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "pull failed: missing integrity header".to_string())?
            .to_string(),
    };
    if resp.content_length().map(|n| n > MAX_PULL_BYTES).unwrap_or(false) {
        return Err(format!("pull failed: package exceeds {MAX_PULL_BYTES} bytes"));
    }
    let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_PULL_BYTES {
        return Err(format!("pull failed: package exceeds {MAX_PULL_BYTES} bytes"));
    }
    if expected != sha256_hex(&bytes) {
        return Err("pull failed: integrity check failed".into());
    }
    if dest.exists() && !force {
        let non_empty = std::fs::read_dir(dest)
            .map(|mut d| d.next().is_some())
            .unwrap_or(false);
        if non_empty {
            return Err(format!(
                "{} already exists; pass --force to overwrite",
                dest.display()
            ));
        }
    }
    std::fs::create_dir_all(dest).map_err(|e| e.to_string())?;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(std::io::Cursor::new(
        bytes.to_vec(),
    )));
    let mut count = 0usize;
    let mut unpacked: u64 = 0;
    for entry in archive.entries().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        count += 1;
        if count > MAX_PULL_ENTRIES {
            return Err(format!("pull failed: more than {MAX_PULL_ENTRIES} entries"));
        }
        unpacked = unpacked.saturating_add(entry.header().size().unwrap_or(0));
        if unpacked > MAX_PULL_UNPACKED {
            return Err(format!(
                "pull failed: unpacked size exceeds {MAX_PULL_UNPACKED} bytes"
            ));
        }
        let kind = entry.header().entry_type();
        // Only regular files and directories; reject symlinks, hard links,
        // fifos, devices, and other special entries.
        if !(kind.is_file() || kind.is_dir()) {
            return Err("pull failed: refusing non-regular entry".into());
        }
        if kind.is_symlink() || kind.is_hard_link() {
            return Err("pull failed: refusing link entry".into());
        }
        let rel = entry.path().map_err(|e| e.to_string())?.into_owned();
        if rel.is_absolute() {
            return Err("pull failed: refusing absolute entry".into());
        }
        if rel.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err("pull failed: refusing parent-dir entry".into());
        }
        entry.unpack_in(dest).map_err(|e| e.to_string())?;
    }
    Ok(format!("pulled skill {name}"))
}
