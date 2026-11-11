//! Minimal LSP client: PATH discovery plus a stdio JSON-RPC session that
//! answers `diagnostics`, `hover`, and `definition` for one file and exits.

use serde_json::{Value, json};
use std::ffi::OsString;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStdin, ChildStdout, Command};

/// Server binaries we know how to talk to.
pub const SERVERS: [&str; 6] = [
    "rust-analyzer",
    "typescript-language-server",
    "pylsp",
    "gopls",
    "clangd",
    "bash-language-server",
];

/// How long the whole exchange (startup, initialize, one request) may take.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long to collect diagnostics after `didOpen`.
const COLLECT: Duration = Duration::from_secs(3);
/// Hover/definition wait: the server must load the project before answering.
const REQUEST_WAIT: Duration = Duration::from_secs(15);
/// Largest file sent to a language server; a model-chosen huge file must not OOM the host.
const MAX_FILE_BYTES: u64 = 1024 * 1024;
/// Largest framed reply accepted from a server before the connection is cut.
const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
/// Header scan cap: a server sending an endless header block is misbehaving.
const MAX_HEADER_BYTES: usize = 64 * 1024;
/// Concurrent language-server processes; servers are heavy, parallel tool
/// calls must not spawn one each.
const MAX_CONCURRENT: usize = 4;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Diagnostic {
    #[serde(default)]
    pub range: Value,
    #[serde(default = "default_severity")]
    pub severity: u8,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub source: Option<String>,
}

fn default_severity() -> u8 {
    3
}

/// Server binaries present and executable on `PATH`.
pub fn servers_available() -> Vec<String> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    SERVERS
        .iter()
        .filter(|bin| in_path(&path, bin))
        .map(|bin| bin.to_string())
        .collect()
}

fn in_path(path: &OsString, bin: &str) -> bool {
    resolve_in(path, bin).is_some()
}

fn resolve_in(path: &OsString, bin: &str) -> Option<PathBuf> {
    std::env::split_paths(path).find_map(|dir| {
        let candidate = dir.join(bin);
        if !candidate.is_file() {
            return None;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if candidate
                .metadata()
                .map(|m| m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
            {
                Some(candidate)
            } else {
                None
            }
        }
        #[cfg(not(unix))]
        {
            Some(candidate)
        }
    })
}

/// Re-resolve `server` at spawn time: the binary must still be on the
/// allowlist and resolve to the same canonical absolute path on PATH. Never
/// spawn a name the shell would resolve for us.
fn resolve_server(server: &str) -> Option<PathBuf> {
    let name = Path::new(server).file_name()?.to_str()?;
    if !SERVERS.contains(&name) {
        return None;
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    resolve_in(&path, name)
        .and_then(|p| p.canonicalize().ok())
        .filter(|abs| abs.file_name().and_then(|f| f.to_str()) == Some(name))
}

fn spawn_permit() -> &'static tokio::sync::Semaphore {
    static SEM: OnceLock<tokio::sync::Semaphore> = OnceLock::new();
    SEM.get_or_init(|| tokio::sync::Semaphore::new(MAX_CONCURRENT))
}

/// Crawl up from `file` to the nearest manifest or repository root so the
/// language server loads the whole project, not just the file's directory.
pub fn workspace_root(file: &Path) -> PathBuf {
    workspace_root_within(file, Path::new("/"))
}

/// Same crawl, but never above `ceiling`: a marker planted in an ancestor the
/// tool was not granted must not lift the server's working directory there.
pub fn workspace_root_within(file: &Path, ceiling: &Path) -> PathBuf {
    const MANIFESTS: [&str; 6] = [
        "Cargo.toml",
        "package.json",
        "pyproject.toml",
        "go.mod",
        "Makefile",
        ".git",
    ];
    let ceiling = ceiling.canonicalize().unwrap_or_else(|_| ceiling.to_path_buf());
    let mut cur = file.parent();
    let fallback = cur.unwrap_or(file).to_path_buf();
    while let Some(dir) = cur {
        if !dir.starts_with(&ceiling) {
            break;
        }
        if MANIFESTS
            .iter()
            .any(|m| dir.join(m).symlink_metadata().is_ok_and(|m| !m.file_type().is_symlink()))
        {
            return dir.to_path_buf();
        }
        cur = dir.parent();
    }
    fallback
}

pub async fn diagnostics(
    server: &str,
    file: &Path,
    allowed_root: &Path,
) -> Result<Vec<Diagnostic>, String> {
    let result = lsp_request(server, file, allowed_root, Op::Diagnostics)
        .await?
        .unwrap_or_else(|| Value::Array(Vec::new()));
    Ok(result
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|d| serde_json::from_value(d.clone()).ok())
                .collect()
        })
        .unwrap_or_default())
}

pub async fn hover(
    server: &str,
    file: &Path,
    allowed_root: &Path,
    line: u32,
    col: u32,
) -> Result<Option<Value>, String> {
    Ok(
        lsp_request(server, file, allowed_root, Op::Hover { line, col })
            .await?
            .filter(non_empty),
    )
}

pub async fn definition(
    server: &str,
    file: &Path,
    allowed_root: &Path,
    line: u32,
    col: u32,
) -> Result<Option<Value>, String> {
    Ok(
        lsp_request(server, file, allowed_root, Op::Definition { line, col })
            .await?
            .filter(non_empty),
    )
}

fn non_empty(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

#[derive(Clone, Copy)]
pub enum Op {
    Diagnostics,
    Hover { line: u32, col: u32 },
    Definition { line: u32, col: u32 },
}

/// Start `server` on `file`, run the initialize handshake, perform `op`, and
/// shut the server down. `line`/`col` are zero-based, as LSP wants. The
/// server's working directory never leaves `allowed_root`.
pub async fn lsp_request(
    server: &str,
    file: &Path,
    allowed_root: &Path,
    op: Op,
) -> Result<Option<Value>, String> {
    let abs = file
        .canonicalize()
        .map_err(|e| format!("{}: {e}", file.display()))?;
    if abs.parent().is_none() {
        return Err(format!("{} has no parent directory", abs.display()));
    }
    let granted = allowed_root
        .canonicalize()
        .map_err(|e| format!("{}: {e}", allowed_root.display()))?;
    let root = workspace_root_within(&abs, &granted);
    // Bounded read: an open + take() avoids the metadata-then-read window.
    let mut f = tokio::fs::File::open(&abs)
        .await
        .map_err(|e| format!("{}: {e}", abs.display()))?;
    let mut bytes = Vec::new();
    (&mut f)
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|e| format!("{}: {e}", abs.display()))?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(format!(
            "{} too large (>1 MiB)",
            abs.display()
        ));
    }
    let text = String::from_utf8(bytes).map_err(|_| format!("{} is not utf-8", abs.display()))?;
    let bin = resolve_server(server).ok_or_else(|| format!("{server} not found on PATH"))?;
    let _permit = spawn_permit()
        .acquire()
        .await
        .map_err(|_| "lsp spawn pool closed")?;
    let mut cmd = Command::new(&bin);
    cmd.current_dir(&root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    // The server is untrusted code; it gets a scrubbed environment (PATH to
    // find its own helpers, HOME/TMPDIR/LANG for sane defaults) — never the
    // provider keys sitting in ours.
    cmd.env_clear();
    for key in ["PATH", "HOME", "TMPDIR", "LANG", "USERPROFILE", "GOPATH", "GOCACHE"] {
        if let Ok(v) = std::env::var(key) {
            cmd.env(key, v);
        }
    }
    let mut child = cmd.spawn().map_err(|e| format!("spawn {server}: {e}"))?;
    let stdin = child.stdin.take().ok_or("server has no stdin")?;
    let stdout = child.stdout.take().ok_or("server has no stdout")?;
    let mut conn = Conn {
        stdin,
        reader: BufReader::new(stdout),
    };

    let exchange = async {
        handshake(&mut conn, &root, &abs, &text).await?;
        run_op(&mut conn, &abs, op).await
    };
    let result = tokio::time::timeout(EXCHANGE_TIMEOUT, exchange).await;
    drop(conn);
    let _ = child.kill().await;
    match result {
        Ok(r) => r,
        Err(_) => Err(format!("{server} timed out")),
    }
}

struct Conn {
    stdin: ChildStdin,
    reader: BufReader<ChildStdout>,
}

impl Conn {
    async fn send(&mut self, msg: &Value) -> Result<(), String> {
        let body = msg.to_string();
        let frame = format!("Content-Length: {}\r\n\r\n{}", body.len(), body);
        self.stdin
            .write_all(frame.as_bytes())
            .await
            .map_err(|e| format!("write: {e}"))?;
        self.stdin.flush().await.map_err(|e| format!("flush: {e}"))
    }

    /// Read one `Content-Length`-framed JSON-RPC message; `None` on EOF, a
    /// malformed frame, or an oversize one (which means the server is
    /// unusable). Sizes are enforced before any allocation.
    async fn read(&mut self) -> Option<Value> {
        let mut len = None;
        let mut header_bytes = 0usize;
        loop {
            let mut line = String::new();
            let n = self.reader.read_line(&mut line).await.ok()?;
            if n == 0 {
                return None;
            }
            header_bytes += n;
            if header_bytes > MAX_HEADER_BYTES {
                return None;
            }
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            if let Some(v) = line.strip_prefix("Content-Length:") {
                len = v.trim().parse::<usize>().ok();
            }
        }
        let len = len?;
        if len > MAX_FRAME_BYTES {
            return None;
        }
        let mut body = vec![0u8; len];
        self.reader.read_exact(&mut body).await.ok()?;
        serde_json::from_slice(&body).ok()
    }
}

async fn handshake(conn: &mut Conn, root: &Path, file: &Path, text: &str) -> Result<(), String> {
    conn.send(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "processId": null,
            "rootUri": uri(root),
            "capabilities": {
                "textDocument": {
                    "hover": { "contentFormat": ["markdown", "plaintext"] },
                    "definition": { "linkSupport": true }
                }
            }
        }
    }))
    .await?;
    // Servers may issue requests of their own (registration, configuration)
    // before answering initialize; refuse them so startup does not stall.
    loop {
        let msg = conn.read().await.ok_or("server closed during initialize")?;
        if msg.get("method").is_none() && msg.get("id").and_then(Value::as_i64) == Some(1) {
            return match msg.get("error") {
                Some(err) => Err(format!("initialize: {err}")),
                None => {
                    conn.send(&json!({"jsonrpc":"2.0","method":"initialized","params":{}}))
                        .await?;
                    conn.send(&json!({
                        "jsonrpc": "2.0",
                        "method": "textDocument/didOpen",
                        "params": {
                            "textDocument": {
                                "uri": uri(file),
                                "languageId": language_id(file),
                                "version": 1,
                                "text": text
                            }
                        }
                    }))
                    .await
                }
            };
        }
        if let (Some(id), Some(_)) = (msg.get("id"), msg.get("method")) {
            refuse_request(conn, id).await?;
        }
    }
}

async fn run_op(conn: &mut Conn, file: &Path, op: Op) -> Result<Option<Value>, String> {
    let method = match op {
        Op::Diagnostics => return collect_diagnostics(conn, file).await.map(Some),
        Op::Hover { .. } => "textDocument/hover",
        Op::Definition { .. } => "textDocument/definition",
    };
    let (line, col) = match op {
        Op::Hover { line, col } | Op::Definition { line, col } => (line, col),
        Op::Diagnostics => unreachable!(),
    };
    conn.send(&json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": method,
        "params": {
            "textDocument": { "uri": uri(file) },
            "position": { "line": line, "character": col }
        }
    }))
    .await?;
    let deadline = tokio::time::Instant::now() + REQUEST_WAIT;
    loop {
        let Some(msg) = wait(conn, deadline).await else {
            return Err(format!("{method} timed out"));
        };
        if msg.get("method").is_some() {
            if let Some(id) = msg.get("id") {
                refuse_request(conn, id).await?;
            }
            continue;
        }
        if msg.get("id").and_then(Value::as_i64) != Some(2) {
            continue;
        }
        if let Some(err) = msg.get("error") {
            return Err(format!("{method}: {err}"));
        }
        return Ok(Some(msg.get("result").cloned().unwrap_or(Value::Null)));
    }
}

async fn collect_diagnostics(conn: &mut Conn, file: &Path) -> Result<Value, String> {
    let deadline = tokio::time::Instant::now() + COLLECT;
    let ours = uri(file);
    // Return the first publish for our file: subsequent publishes only refine
    // the same result, and waiting the whole budget made every call take 3s.
    while let Some(msg) = wait(conn, deadline).await {
        match msg.get("method").and_then(Value::as_str) {
            Some("textDocument/publishDiagnostics") => {
                let params = &msg["params"];
                if params["uri"].as_str() == Some(ours.as_str()) {
                    return Ok(Value::Array(
                        params["diagnostics"]
                            .as_array()
                            .cloned()
                            .unwrap_or_default(),
                    ));
                }
            }
            Some(_) => {
                if let Some(id) = msg.get("id") {
                    refuse_request(conn, id).await?;
                }
            }
            None => {}
        }
    }
    // No publish at all is unknown, not clean.
    Err(format!(
        "no diagnostics for {} within {}s",
        file.display(),
        COLLECT.as_secs()
    ))
}

async fn wait(conn: &mut Conn, deadline: tokio::time::Instant) -> Option<Value> {
    timeout_at(deadline, conn.read()).await.flatten()
}

async fn timeout_at<T>(deadline: tokio::time::Instant, fut: impl Future<Output = T>) -> Option<T> {
    tokio::time::timeout_at(deadline, fut).await.ok()
}

/// A blind `null` result can satisfy server requests we never meant to grant
/// (client/registerCapability, workspace/configuration); refuse instead.
async fn refuse_request(conn: &mut Conn, id: &Value) -> Result<(), String> {
    conn.send(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": -32601, "message": "method not supported"}
    }))
    .await
}

fn uri(path: &Path) -> String {
    let mut out = String::from("file://");
    for b in path.to_string_lossy().bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn language_id(file: &Path) -> &'static str {
    match file.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "rs" => "rust",
        "ts" => "typescript",
        "tsx" => "typescriptreact",
        "js" => "javascript",
        "jsx" => "javascriptreact",
        "py" => "python",
        "go" => "go",
        "c" => "c",
        "cpp" | "cc" | "cxx" | "h" | "hpp" => "cpp",
        "sh" | "bash" => "shellscript",
        _ => "plaintext",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_encodes_spaces() {
        assert_eq!(uri(Path::new("/tmp/a b.rs")), "file:///tmp/a%20b.rs");
    }

    #[test]
    fn language_ids() {
        assert_eq!(language_id(Path::new("x.rs")), "rust");
        assert_eq!(language_id(Path::new("x.tsx")), "typescriptreact");
        assert_eq!(language_id(Path::new("x.unknown")), "plaintext");
    }

    #[test]
    fn avail_does_not_panic() {
        let _ = servers_available();
    }

    #[test]
    fn unknown_server_name_rejected() {
        // Absolute paths and non-allowlist names must not spawn.
        assert!(resolve_server("/bin/sh").is_none());
        assert!(resolve_server("definitely-not-an-lsp").is_none());
    }

    #[tokio::test]
    async fn missing_server_is_err() {
        let f = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        assert!(
            diagnostics("freedas-no-such-language-server", &f, Path::new("/"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected() {
        // A fake server announcing a huge Content-Length must fail, not OOM.
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("freedas-lsp-huge-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("a.rs");
        std::fs::write(&file, "fn main() {}\n").unwrap();
        let script = dir.join("fake-lsp");
        std::fs::write(
            &script,
            "#!/bin/sh\nprintf 'Content-Length: 999999999\\r\\n\\r\\n'\nsleep 1\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Not on the allowlist: lsp_request refuses before spawn.
        let err = diagnostics(script.to_str().unwrap(), &file, &dir)
            .await
            .unwrap_err();
        assert!(err.contains("not found"), "got {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn workspace_root_clamps_at_ceiling() {
        let dir = std::env::temp_dir().join(format!("freedas-lsp-clamp-{}", std::process::id()));
        // Marker above the granted root must not lift the workspace there.
        let root = dir.join("granted").join("sub");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(dir.join("granted").join("..").join("no_marker"), "").ok();
        std::fs::write(dir.join("Cargo.toml"), "[package]").unwrap();
        let file = root.join("lib.rs");
        std::fs::write(&file, "").unwrap();
        let granted = dir.join("granted").canonicalize().unwrap();
        let found = workspace_root_within(&file.canonicalize().unwrap(), &granted);
        assert!(found.starts_with(&granted), "got {}", found.display());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn workspace_root_walks_up_to_the_manifest() {
        let dir = std::env::temp_dir().join(format!("freedas-lsp-root-{}", std::process::id()));
        let root = dir.join("repo");
        let nested = root.join("src").join("deep");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(root.join("Cargo.toml"), "[package]").unwrap();
        let file = nested.join("lib.rs");
        std::fs::write(&file, "").unwrap();
        assert_eq!(
            workspace_root(&file.canonicalize().unwrap()),
            root.canonicalize().unwrap()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn missing_file_is_err() {
        assert!(
            diagnostics("rust-analyzer", Path::new("/nonexistent/freedas.rs"), Path::new("/"))
                .await
                .is_err()
        );
    }
}
