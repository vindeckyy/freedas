//! Minimal LSP client: PATH discovery plus a stdio JSON-RPC session that
//! answers `diagnostics`, `hover`, and `definition` for one file and exits.

use serde_json::{Value, json};
use std::ffi::OsString;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::process::Stdio;
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
    std::env::split_paths(path).any(|dir| {
        let candidate = dir.join(bin);
        if !candidate.is_file() {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            candidate
                .metadata()
                .map(|m| m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        }
        #[cfg(not(unix))]
        {
            true
        }
    })
}

/// Crawl up from `file` to the nearest manifest or repository root so the
/// language server loads the whole project, not just the file's directory.
pub fn workspace_root(file: &Path) -> PathBuf {
    const MANIFESTS: [&str; 6] = [
        "Cargo.toml",
        "package.json",
        "pyproject.toml",
        "go.mod",
        "Makefile",
        ".git",
    ];
    let mut cur = file.parent();
    while let Some(dir) = cur {
        if MANIFESTS.iter().any(|m| dir.join(m).exists()) {
            return dir.to_path_buf();
        }
        cur = dir.parent();
    }
    file.parent().unwrap_or(file).to_path_buf()
}

pub async fn diagnostics(server: &str, file: &Path) -> Result<Vec<Diagnostic>, String> {
    let result = lsp_request(server, file, Op::Diagnostics)
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
    line: u32,
    col: u32,
) -> Result<Option<Value>, String> {
    Ok(lsp_request(server, file, Op::Hover { line, col })
        .await?
        .filter(non_empty))
}

pub async fn definition(
    server: &str,
    file: &Path,
    line: u32,
    col: u32,
) -> Result<Option<Value>, String> {
    Ok(lsp_request(server, file, Op::Definition { line, col })
        .await?
        .filter(non_empty))
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
/// shut the server down. `line`/`col` are zero-based, as LSP wants.
pub async fn lsp_request(server: &str, file: &Path, op: Op) -> Result<Option<Value>, String> {
    let abs = file
        .canonicalize()
        .map_err(|e| format!("{}: {e}", file.display()))?;
    if abs.parent().is_none() {
        return Err(format!("{} has no parent directory", abs.display()));
    }
    let root = workspace_root(&abs);
    let len = tokio::fs::metadata(&abs)
        .await
        .map_err(|e| format!("{}: {e}", abs.display()))?
        .len();
    if len > MAX_FILE_BYTES {
        return Err(format!(
            "{} too large ({} bytes > 1 MiB)",
            abs.display(),
            len
        ));
    }
    let text = tokio::fs::read_to_string(&abs)
        .await
        .map_err(|e| format!("{}: {e}", abs.display()))?;
    let mut child = Command::new(server)
        .current_dir(&root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("spawn {server}: {e}"))?;
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

    /// Read one `Content-Length`-framed JSON-RPC message; `None` on EOF or a
    /// malformed frame (which means the server is unusable).
    async fn read(&mut self) -> Option<Value> {
        let mut len = None;
        loop {
            let mut line = String::new();
            if self.reader.read_line(&mut line).await.ok()? == 0 {
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
        let mut body = vec![0u8; len?];
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
    // before answering initialize; answer them so startup does not stall.
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
            answer_null(conn, id).await?;
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
                answer_null(conn, id).await?;
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
                    answer_null(conn, id).await?;
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

async fn answer_null(conn: &mut Conn, id: &Value) -> Result<(), String> {
    conn.send(&json!({"jsonrpc":"2.0","id":id,"result":null}))
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

    #[tokio::test]
    async fn missing_server_is_err() {
        let f = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        assert!(
            diagnostics("freedas-no-such-language-server", &f)
                .await
                .is_err()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fake_server_reports_diagnostics() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("freedas-lsp-fake-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("a.rs");
        std::fs::write(&file, "fn main() {}\n").unwrap();
        let canon = file.canonicalize().unwrap();
        let init = r#"{"jsonrpc":"2.0","id":1,"result":{"capabilities":{}}}"#;
        let diag = format!(
            r#"{{"jsonrpc":"2.0","method":"textDocument/publishDiagnostics","params":{{"uri":"{}","diagnostics":[{{"range":{{"start":{{"line":0,"character":0}},"end":{{"line":0,"character":1}}}},"severity":1,"message":"boom","source":"fake"}}]}}}}"#,
            uri(&canon)
        );
        let script = dir.join("fake-lsp");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf 'Content-Length: {}\r\n\r\n%s' '{}'\nprintf 'Content-Length: {}\r\n\r\n%s' '{}'\nsleep 1\n",
                init.len(),
                init,
                diag.len(),
                diag
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let found = diagnostics(script.to_str().unwrap(), &file).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].message, "boom");
        assert_eq!(found[0].severity, 1);
        assert_eq!(found[0].source.as_deref(), Some("fake"));
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

    #[cfg(unix)]
    #[tokio::test]
    async fn no_publish_reports_unknown_not_clean() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("freedas-lsp-silent-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("a.rs");
        std::fs::write(&file, "fn main() {}\n").unwrap();
        let init = r#"{"jsonrpc":"2.0","id":1,"result":{"capabilities":{}}}"#;
        let script = dir.join("silent-lsp");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf 'Content-Length: {}\\r\\n\\r\\n%s' '{}'\n",
                init.len(),
                init
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let err = diagnostics(script.to_str().unwrap(), &file)
            .await
            .unwrap_err();
        assert!(err.contains("no diagnostics"), "got {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn missing_file_is_err() {
        assert!(
            diagnostics("rust-analyzer", Path::new("/nonexistent/freedas.rs"))
                .await
                .is_err()
        );
    }
}
