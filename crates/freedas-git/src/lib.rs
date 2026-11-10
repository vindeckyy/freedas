//! Git helpers: worktrees, diffs, shadow-git snapshots.

use std::path::{Path, PathBuf};

fn is_valid_id_component(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_valid_commit(s: &str) -> bool {
    (4..=64).contains(&s.len()) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub async fn git(args: &[&str], cwd: &Path) -> Result<std::process::Output, std::io::Error> {
    tokio::process::Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .await
}

pub async fn git_text(args: &[&str], cwd: &Path) -> Result<String, String> {
    let out = git(args, cwd).await.map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Create a worktree at `dest` tracking a new branch `freedas/<name>`.
pub async fn create_worktree(
    data_dir: &Path,
    project_id: &str,
    name: &str,
    cwd: &Path,
) -> Result<PathBuf, String> {
    // CLI-supplied: reject absolute paths and escapes before joining.
    // `Path::join` with an absolute component discards the data dir entirely.
    if !is_valid_id_component(name) {
        return Err(format!("invalid worktree name: {name}"));
    }
    if !is_valid_id_component(project_id) {
        return Err(format!("invalid project id: {project_id}"));
    }
    let dest = data_dir.join("worktrees").join(project_id).join(name);
    if dest.exists() {
        return Err(format!("worktree exists: {}", dest.display()));
    }
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| e.to_string())?;
    }
    let branch = format!("freedas/{name}");
    let out = git(
        &[
            "worktree",
            "add",
            "-b",
            &branch,
            &dest.to_string_lossy(),
            "HEAD",
        ],
        cwd,
    )
    .await
    .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).to_string());
    }
    Ok(dest)
}

/// Shadow-git snapshot store: one bare repo per project.
pub struct SnapshotStore {
    pub dir: PathBuf,
    pub index: PathBuf,
    excludes: PathBuf,
}

impl SnapshotStore {
    pub async fn open(data_dir: &Path, project_id: &str) -> Result<Self, String> {
        if !is_valid_id_component(project_id) {
            return Err(format!("invalid project id: {project_id}"));
        }
        let dir = data_dir.join("snapshots").join(project_id);
        let index = dir.join("index");
        let repo = dir.join("repo.git");
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| e.to_string())?;
        if !repo.exists() {
            tokio::process::Command::new("git")
                .args(["init", "--bare", &repo.to_string_lossy()])
                .env_remove("GIT_DIR")
                .env_remove("GIT_WORK_TREE")
                .env_remove("GIT_INDEX_FILE")
                .output()
                .await
                .map_err(|e| e.to_string())?;
        }
        // Build artifacts are never worth restoring, and a checkout without a
        // .gitignore can hold gigabytes of them. The project's own .gitignore
        // files still apply on top of this list.
        let excludes = dir.join("excludes");
        tokio::fs::write(
            &excludes,
            "target/\nnode_modules/\n.venv/\nvenv/\ndist/\nbuild/\n.next/\n__pycache__/\n.pytest_cache/\n",
        )
        .await
        .map_err(|e| e.to_string())?;
        Ok(Self {
            dir,
            index,
            excludes,
        })
    }

    fn env(&self, project: &Path, cmd: &mut tokio::process::Command) {
        cmd.env("GIT_DIR", self.dir.join("repo.git"))
            .env("GIT_WORK_TREE", project)
            .env("GIT_INDEX_FILE", &self.index);
    }

    /// Run a shadow-git subcommand, returning its output or git's stderr.
    async fn run_ok(&self, project: &Path, args: &[&str]) -> Result<std::process::Output, String> {
        let mut cmd = tokio::process::Command::new("git");
        cmd.args([
            "-c",
            &format!("core.excludesFile={}", self.excludes.display()),
        ]);
        cmd.args(args);
        self.env(project, &mut cmd);
        let out = cmd.output().await.map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(format!(
                "git {}: {}",
                args.first().copied().unwrap_or(""),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(out)
    }

    /// Lock file git writes next to the custom index while adding.
    fn index_lock(&self) -> std::path::PathBuf {
        let mut path = self.index.clone().into_os_string();
        path.push(".lock");
        std::path::PathBuf::from(path)
    }

    /// Previous snapshot commit, tracked in a private ref.
    async fn previous(&self, project: &Path) -> Option<String> {
        let mut cmd = tokio::process::Command::new("git");
        cmd.args(["rev-parse", "--verify", "--quiet", "refs/freedas/last"]);
        self.env(project, &mut cmd);
        let out = cmd.output().await.ok()?;
        if !out.status.success() {
            return None;
        }
        let sha = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!sha.is_empty()).then_some(sha)
    }

    /// Snapshot the project tree and return the commit SHA.
    pub async fn snapshot(&self, project: &Path) -> Result<String, String> {
        // A run killed mid-add leaves index.lock behind and would wedge every
        // later snapshot. Older than ten minutes means the writer is gone.
        if let Ok(meta) = tokio::fs::metadata(&self.index_lock()).await
            && meta
                .modified()
                .ok()
                .and_then(|at| at.elapsed().ok())
                .is_some_and(|age| age.as_secs() > 600)
        {
            let _ = tokio::fs::remove_file(self.index_lock()).await;
        }
        self.run_ok(project, &["add", "-A"]).await?;
        let out = self.run_ok(project, &["write-tree"]).await?;
        let tree = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if tree.is_empty() {
            return Err("git write-tree returned no tree".into());
        }
        let parent = self.previous(project).await;
        let mut args = vec!["commit-tree", tree.as_str(), "-m", "freedas snapshot"];
        if let Some(parent) = &parent {
            args.extend(["-p", parent.as_str()]);
        }
        let out = self.run_ok(project, &args).await?;
        let sha = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if sha.is_empty() {
            return Err("git commit-tree returned no commit".into());
        }
        self.run_ok(project, &["update-ref", "refs/freedas/last", &sha])
            .await?;
        Ok(sha)
    }

    /// Restore the project tree from a snapshot commit.
    pub async fn restore(&self, project: &Path, commit: &str) -> Result<(), String> {
        if !is_valid_commit(commit) {
            return Err(format!("invalid commit: {commit}"));
        }
        self.run_ok(project, &["read-tree", "--", commit]).await?;
        self.run_ok(project, &["checkout-index", "-a", "-f"])
            .await?;
        // Files created after the snapshot are not in its tree. Remove them so
        // the tree matches the snapshot; ignored paths are skipped by the walker.
        // `-c core.quotePath=false` keeps non-ASCII names raw instead of quoted/escaped.
        // `%(objecttype)` distinguishes gitlinks (`commit`) from blobs so
        // submodule checkouts are never descended into or deleted.
        let out = self
            .run_ok(
                project,
                &[
                    "-c",
                    "core.quotePath=false",
                    "ls-tree",
                    "-r",
                    "-z",
                    "--format=%(objecttype) %(path)",
                    "--",
                    commit,
                ],
            )
            .await?;
        let mut tracked: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut gitlinks: Vec<String> = Vec::new();
        for raw in out.stdout.split(|b| *b == 0) {
            if raw.is_empty() {
                continue;
            }
            let entry = String::from_utf8_lossy(raw);
            let Some((kind, raw_path)) = entry.split_once(' ') else {
                continue;
            };
            // Defensive: if some git appends `\n` before the NUL, it must not
            // poison the tracked set (a missed entry would delete user data).
            let path = raw_path.trim_end_matches(['\n', '\r']);
            tracked.insert(path.to_owned());
            if kind == "commit" {
                gitlinks.push(path.to_owned());
            }
        }
        for entry in ignore::WalkBuilder::new(project)
            .hidden(false)
            .git_ignore(true)
            // Same dirs `open()` excludes from snapshots via core.excludesFile;
            // pruning here keeps /undo from deleting pre-existing build output
            // that was never snapshotted. Submodule checkouts (a dir holding a
            // `.git` file/dir) are pruned too: /undo never snapshotted their
            // contents and must not delete them.
            .filter_entry(|e| {
                if e.depth() == 0 {
                    return true;
                }
                if !e.file_type().is_some_and(|t| t.is_dir()) {
                    return true;
                }
                if e.file_name().to_str().is_some_and(|n| n == ".git") {
                    return false;
                }
                // symlink_metadata so a dangling `.git` file still prunes.
                if std::fs::symlink_metadata(e.path().join(".git")).is_ok() {
                    return false;
                }
                if let Some(name) = e.file_name().to_str()
                    && matches!(
                        name,
                        "target"
                            | "node_modules"
                            | ".venv"
                            | "venv"
                            | "dist"
                            | "build"
                            | ".next"
                            | "__pycache__"
                            | ".pytest_cache"
                    )
                {
                    return false;
                }
                true
            })
            .build()
            .flatten()
        {
            let path = entry.path();
            // symlink_metadata (not entry.file_type) so a dangling link
            // created after the snapshot is still seen and removed.
            let meta = match std::fs::symlink_metadata(path) {
                Ok(meta) => meta,
                Err(_) => continue,
            };
            if !(meta.file_type().is_file() || meta.file_type().is_symlink()) {
                continue;
            }
            let rel = match path.strip_prefix(project) {
                Ok(rel) => rel.to_string_lossy().replace('\\', "/"),
                Err(_) => continue,
            };
            let first = rel.split('/').next().unwrap_or("");
            if first == ".git" || first == ".freedas" {
                continue;
            }
            // The snapshot holds only the gitlink itself, not the submodule's
            // files; belt-and-braces alongside the `.git` prune above.
            if gitlinks
                .iter()
                .any(|g| rel == *g || rel.starts_with(&format!("{g}/")))
            {
                continue;
            }
            if !tracked.contains(&rel) {
                let _ = std::fs::remove_file(path);
            }
        }
        Ok(())
    }
}

/// Current git branch for a project, or empty when not a repository.
pub fn branch(cwd: &Path) -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(cwd)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod restore_tests {
    use super::*;

    #[tokio::test]
    async fn restore_removes_files_created_after_the_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(&project)
            .output()
            .unwrap();
        std::fs::write(project.join("a.txt"), "a").unwrap();
        let store = SnapshotStore::open(&dir.path().join("data"), "prj_test")
            .await
            .unwrap();
        let sha = store.snapshot(&project).await.unwrap();
        std::fs::write(project.join("b.txt"), "b").unwrap();
        store.restore(&project, &sha).await.unwrap();
        assert!(project.join("a.txt").exists());
        assert!(
            !project.join("b.txt").exists(),
            "created file should be removed"
        );
    }

    #[tokio::test]
    async fn restore_keeps_non_ascii_tracked_paths() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(&project)
            .output()
            .unwrap();
        std::fs::write(project.join("café.txt"), "snapshot").unwrap();
        let store = SnapshotStore::open(&dir.path().join("data"), "prj_test")
            .await
            .unwrap();
        let sha = store.snapshot(&project).await.unwrap();
        std::fs::write(project.join("café.txt"), "edited").unwrap();
        std::fs::write(project.join("ünïcode.txt"), "new").unwrap();
        store.restore(&project, &sha).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(project.join("café.txt")).unwrap(),
            "snapshot",
            "non-ASCII tracked file must be restored, not deleted"
        );
        assert!(!project.join("ünïcode.txt").exists());
    }

    #[tokio::test]
    async fn snapshot_skips_build_directories() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(project.join("target/debug")).unwrap();
        std::fs::create_dir_all(project.join("src")).unwrap();
        std::fs::write(project.join("target/debug/big.bin"), vec![0u8; 1024]).unwrap();
        std::fs::write(project.join("src/main.rs"), "fn main() {}").unwrap();
        let store = SnapshotStore::open(&dir.path().join("data"), "prj_test")
            .await
            .unwrap();
        let sha = store.snapshot(&project).await.unwrap();
        let out = std::process::Command::new("git")
            .args(["--git-dir", store.dir.join("repo.git").to_str().unwrap()])
            .args(["ls-tree", "-r", "--name-only", &sha])
            .output()
            .unwrap();
        let files = String::from_utf8_lossy(&out.stdout);
        assert!(files.contains("src/main.rs"), "{files}");
        assert!(
            !files.contains("target/"),
            "build output was snapshotted: {files}"
        );
    }

    #[tokio::test]
    async fn snapshots_chain_to_the_previous_commit() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(&project)
            .output()
            .unwrap();
        let store = SnapshotStore::open(&dir.path().join("data"), "prj_test")
            .await
            .unwrap();
        std::fs::write(project.join("a.txt"), "1").unwrap();
        let first = store.snapshot(&project).await.unwrap();
        std::fs::write(project.join("a.txt"), "2").unwrap();
        let second = store.snapshot(&project).await.unwrap();
        assert_ne!(first, second);
        let parent = std::process::Command::new("git")
            .args(["--git-dir", store.dir.join("repo.git").to_str().unwrap()])
            .args(["rev-parse", &format!("{second}^")])
            .output()
            .unwrap();
        assert!(parent.status.success(), "second snapshot has no parent");
        assert_eq!(
            String::from_utf8_lossy(&parent.stdout).trim(),
            first,
            "parent must be the previous snapshot"
        );
    }
}
