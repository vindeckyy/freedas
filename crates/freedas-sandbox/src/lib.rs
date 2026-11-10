//! Local OS sandbox backends (macOS sandbox-exec, Linux bubblewrap).

use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    pub read: Vec<PathBuf>,
    pub write: Vec<PathBuf>,
    pub network: String,
    pub env_allowlist: Vec<String>,
    pub timeout_ms: u64,
    pub cwd: Option<PathBuf>,
    /// Escape hatch for platforms where filtered read rules break `sandbox-exec`.
    pub allow_all_reads: bool,
}

/// Readable regardless of policy: the toolchain needs them to start.
const SYSTEM_READ_PATHS: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/System",
    "/Library",
    "/opt/homebrew",
    "/usr/local",
    "/etc",
    "/private/etc",
    "/dev",
    "/private/var/folders",
    "/tmp",
    "/private/tmp",
];

pub fn available() -> bool {
    which("sandbox-exec").is_some() || which("bwrap").is_some()
}

pub fn status() -> String {
    if which("sandbox-exec").is_some() {
        "sandbox-exec".into()
    } else if which("bwrap").is_some() {
        "bubblewrap".into()
    } else {
        "unavailable".into()
    }
}

/// Only an executable regular file counts; a directory named like the tool
/// must not make the sandbox look available.
fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let cand = dir.join(name);
        if is_executable_file(&cand) {
            return Some(cand);
        }
    }
    None
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn esc(p: &Path) -> String {
    p.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

fn network_allowed(network: &str) -> bool {
    network == "allow"
}

/// Generate a macOS sandbox profile.
///
/// Note: `/tmp`, `/private/tmp`, and `/private/var/folders` are shared scratch
/// on macOS. `sandbox-exec` cannot bind-mount a private tmpfs the way bwrap
/// does on Linux, so per-run tmp isolation (a fresh dir under a policy write
/// root exported via `TMPDIR`) is caller-side and out of scope here.
pub fn macos_profile(policy: &SandboxPolicy) -> String {
    let mut s = String::from("(version 1)\n(deny default)\n");
    // Stock Rust gate commands live outside /usr: rustup shims in
    // ~/.cargo/bin, `cargo install` binaries in ~/.local/bin, and toolchains
    // under /opt. Allow exec there; everything else stays deny-by-default.
    let mut exec_rule = String::from(
        "(allow process-exec (subpath \"/bin\") (subpath \"/usr/bin\") (subpath \"/usr/sbin\") (subpath \"/usr/local/bin\") (subpath \"/opt\")",
    );
    if let Ok(home) = std::env::var("HOME")
        && !home.is_empty()
    {
        let home = PathBuf::from(home);
        for sub in [".cargo/bin", ".local/bin"] {
            exec_rule.push_str(&format!(" (subpath \"{}\")", esc(&home.join(sub))));
        }
    }
    exec_rule.push_str(")\n");
    s.push_str(&exec_rule);
    s.push_str("(allow process-fork)\n");
    if policy.allow_all_reads {
        eprintln!("freedas: sandbox: allowing all file reads because allow_all_reads is set");
        s.push_str("(allow file-read*)\n");
    } else {
        s.push_str("(allow file-read*");
        for p in SYSTEM_READ_PATHS {
            s.push_str(&format!(" (subpath \"{p}\")"));
        }
        for p in policy.read.iter().chain(policy.write.iter()) {
            s.push_str(&format!(" (subpath \"{}\")", esc(p)));
        }
        s.push_str(")\n");
        // Seatbelt denies lookup at every unlisted ancestor, so startup/getcwd
        // fails without traversal rights. Literal file-read-data on a directory
        // exposes only names for traversal, not contents outside policy roots.
        let mut literals = vec!["/".to_string(), "/private".to_string(), "/var".to_string()];
        for p in policy.read.iter().chain(policy.write.iter()) {
            let canon = std::fs::canonicalize(p).unwrap_or_else(|_| p.clone());
            for anc in canon.ancestors() {
                literals.push(esc(anc));
            }
        }
        literals.sort();
        literals.dedup();
        for dir in &literals {
            s.push_str(&format!("(allow file-read-data (literal \"{dir}\"))\n"));
        }
    }
    // Writes stay limited to temp dirs and the policy's write roots.
    s.push_str("(allow file-write* (subpath \"/tmp\") (subpath \"/private/tmp\") (subpath \"/private/var/folders\")");
    for p in &policy.write {
        s.push_str(&format!(" (subpath \"{}\")", esc(p)));
    }
    s.push_str(")\n(allow sysctl-read)\n(allow mach-lookup)\n");
    if network_allowed(&policy.network) {
        s.push_str("(allow network*)\n");
    } else {
        s.push_str("(deny network*)\n");
    }
    s
}

fn bwrap_command(policy: &SandboxPolicy, program: &str, args: &[&str]) -> Vec<String> {
    let mut out = vec![
        "bwrap".to_string(),
        "--die-with-parent".to_string(),
        "--unshare-all".to_string(),
    ];
    if network_allowed(&policy.network) {
        out.push("--share-net".to_string());
    }
    for base in ["/usr", "/bin", "/sbin"] {
        out.push("--ro-bind".to_string());
        out.push(base.to_string());
        out.push(base.to_string());
    }
    // /lib and /lib64 differ per distro; -try keeps bwrap working where absent.
    for base in ["/lib", "/lib64"] {
        out.push("--ro-bind-try".to_string());
        out.push(base.to_string());
        out.push(base.to_string());
    }
    // /etc is needed for nsswitch.conf, passwd, and TLS certs.
    out.push("--ro-bind".to_string());
    out.push("/etc".to_string());
    out.push("/etc".to_string());
    out.push("--proc".to_string());
    out.push("/proc".to_string());
    out.push("--dev".to_string());
    out.push("/dev".to_string());
    let tmp_write = policy.write.iter().any(|w| w == Path::new("/tmp"));
    if !tmp_write {
        out.push("--tmpfs".to_string());
        out.push("/tmp".to_string());
    }
    for p in &policy.read {
        let covered = policy.write.iter().any(|w| p.starts_with(w))
            || p == Path::new("/tmp")
            || p.starts_with("/usr")
            || p.starts_with("/bin")
            || p.starts_with("/sbin")
            || p.starts_with("/lib")
            || p == Path::new("/etc")
            || p == Path::new("/proc")
            || p == Path::new("/dev");
        if !covered {
            out.push("--ro-bind-try".to_string());
            out.push(p.to_string_lossy().to_string());
            out.push(p.to_string_lossy().to_string());
        }
    }
    for p in &policy.write {
        out.push("--bind".to_string());
        out.push(p.to_string_lossy().to_string());
        out.push(p.to_string_lossy().to_string());
    }
    if let Some(cwd) = &policy.cwd {
        // Canonicalize so `proj/../proj` or a symlinked cwd cannot pass a
        // lexical prefix check that the kernel would resolve differently.
        let canon = std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.clone());
        if policy
            .write
            .iter()
            .chain(policy.read.iter())
            .any(|root| canon.starts_with(root))
        {
            out.push("--chdir".to_string());
            out.push(cwd.to_string_lossy().to_string());
        }
    }
    out.push("--".to_string());
    out.push(program.to_string());
    out.extend(args.iter().map(|a| a.to_string()));
    out
}

/// Wrap a command with the platform sandbox. `None` means no backend is
/// available; the caller must warn and decide what to do.
pub fn wrap_command(policy: &SandboxPolicy, program: &str, args: &[&str]) -> Option<Vec<String>> {
    if which("sandbox-exec").is_some() {
        let profile = macos_profile(policy);
        let mut out = vec![
            "sandbox-exec".to_string(),
            "-p".to_string(),
            profile,
            "--".to_string(),
            program.to_string(),
        ];
        out.extend(args.iter().map(|a| a.to_string()));
        Some(out)
    } else if which("bwrap").is_some() {
        Some(bwrap_command(policy, program, args))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(network: &str) -> SandboxPolicy {
        SandboxPolicy {
            read: vec![PathBuf::from("/proj")],
            write: vec![PathBuf::from("/proj")],
            network: network.into(),
            env_allowlist: Vec::new(),
            timeout_ms: 1000,
            cwd: Some(PathBuf::from("/proj")),
            allow_all_reads: false,
        }
    }

    #[test]
    fn macos_profile_restricts_reads_to_policy_and_system_paths() {
        let p = macos_profile(&policy("deny"));
        assert!(p.contains("(allow file-read* (subpath \"/usr\")"));
        assert!(p.contains("(subpath \"/proj\")"));
        assert!(!p.contains("(allow file-read*)\n"));
        assert!(p.contains("(deny network*)"));

        let mut open = policy("deny");
        open.allow_all_reads = true;
        assert!(macos_profile(&open).contains("(allow file-read*)\n"));
    }

    #[test]
    fn sandbox_network_parsing_is_fail_closed() {
        assert!(macos_profile(&policy("allow")).contains("(allow network*)"));
        for value in ["deny", "ALLOW ", "yes", ""] {
            assert!(
                macos_profile(&policy(value)).contains("(deny network*)"),
                "{value}"
            );
        }
        assert!(
            !bwrap_command(&policy("yes"), "/bin/bash", &[])
                .iter()
                .any(|a| a == "--share-net")
        );
        assert!(
            bwrap_command(&policy("allow"), "/bin/bash", &[])
                .iter()
                .any(|a| a == "--share-net")
        );
    }

    #[test]
    fn bwrap_binds_system_dirs_and_chdir() {
        let out = bwrap_command(&policy("deny"), "/bin/bash", &["-lc", "true"]);
        for arg in ["/lib", "/lib64", "/etc", "/tmp"] {
            assert!(out.iter().any(|a| a == arg), "missing {arg}");
        }
        assert!(out.iter().any(|a| a == "--chdir"));
        let chdir = out
            .iter()
            .position(|a| a == "--chdir")
            .map(|i| out[i + 1].as_str());
        assert_eq!(chdir, Some("/proj"));
        assert_eq!(out.last().map(String::as_str), Some("true"));
    }
}
