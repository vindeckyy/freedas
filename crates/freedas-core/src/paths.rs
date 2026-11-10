use std::ffi::OsString;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn env_path(get: &impl Fn(&str) -> Option<OsString>, name: &str) -> Option<PathBuf> {
    get(name).filter(|v| !v.is_empty()).map(PathBuf::from)
}

/// First set, non-empty environment variable among the names.
fn first_env(get: &impl Fn(&str) -> Option<OsString>, names: &[&str]) -> Option<PathBuf> {
    names.iter().find_map(|n| env_path(get, n))
}

fn home_dir(get: &impl Fn(&str) -> Option<OsString>) -> PathBuf {
    first_env(get, &["FREEDAS_HOME", "MIDAS_HOME", "HOME"])
        .expect("home directory unavailable: set HOME or FREEDAS_HOME")
}

fn xdg(
    get: &impl Fn(&str) -> Option<OsString>,
    home: &std::path::Path,
    base: &str,
    sub: &str,
    fallback: &str,
) -> PathBuf {
    env_path(get, base)
        .unwrap_or_else(|| home.join(fallback))
        .join(sub)
}

/// Resolved filesystem locations for config, data, state, and cache.
#[derive(Debug, Clone)]
pub struct Paths {
    pub home: PathBuf,
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub state_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub bin_dir: PathBuf,
    pub project_root: PathBuf,
}

impl Paths {
    pub fn resolve(project_root: PathBuf) -> Self {
        Self::resolve_with(project_root, |name: &str| std::env::var_os(name))
    }

    fn resolve_with(project_root: PathBuf, get: impl Fn(&str) -> Option<OsString>) -> Self {
        let home = home_dir(&get);
        let config_dir = first_env(&get, &["FREEDAS_CONFIG_DIR", "MIDAS_CONFIG_DIR"])
            .unwrap_or_else(|| home.join(".config").join("freedas"));
        let data_dir = first_env(&get, &["FREEDAS_DATA", "MIDAS_DATA"])
            .unwrap_or_else(|| xdg(&get, &home, "XDG_DATA_HOME", "freedas", ".local/share"));
        let state_dir = first_env(&get, &["FREEDAS_STATE", "MIDAS_STATE"])
            .unwrap_or_else(|| xdg(&get, &home, "XDG_STATE_HOME", "freedas", ".local/state"));
        let cache_dir = first_env(&get, &["FREEDAS_CACHE", "MIDAS_CACHE"])
            .unwrap_or_else(|| xdg(&get, &home, "XDG_CACHE_HOME", "freedas", ".cache"));
        let bin_dir = home.join(".freedas").join("bin");
        Self {
            home,
            config_dir,
            data_dir,
            state_dir,
            cache_dir,
            bin_dir,
            project_root,
        }
    }

    pub fn db_path(&self) -> PathBuf {
        first_env(&|n: &str| std::env::var_os(n), &["FREEDAS_DB", "MIDAS_DB"])
            .unwrap_or_else(|| self.data_dir.join("freedas.db"))
    }

    pub fn global_config(&self) -> PathBuf {
        self.config_dir.join("freedas.json")
    }

    pub fn project_config(&self) -> PathBuf {
        self.project_root.join(".freedas").join("freedas.json")
    }

    pub fn snapshot_dir(&self, project_id: &str) -> PathBuf {
        self.data_dir.join("snapshots").join(project_id)
    }

    pub fn worktree_dir(&self, project_id: &str) -> PathBuf {
        self.data_dir.join("worktrees").join(project_id)
    }

    pub fn plans_dir(&self) -> PathBuf {
        self.data_dir.join("plans")
    }

    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        for dir in [
            &self.config_dir,
            &self.data_dir,
            &self.state_dir,
            &self.cache_dir,
            &self.plans_dir(),
        ] {
            std::fs::create_dir_all(dir)?;
        }
        Ok(())
    }
}

/// Canonicalize the project directory. Config discovery walks ancestors from
/// here, so this is the cwd (or the explicit project arg), not the enclosing
/// git root. Git operations handle non-repository directories themselves.
pub fn find_project_root(start: &std::path::Path) -> PathBuf {
    start.canonicalize().unwrap_or_else(|_| start.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn with_vars(vars: &'static [(&'static str, &'static str)]) -> Paths {
        let map: HashMap<&str, &str> = vars.iter().copied().collect();
        Paths::resolve_with(PathBuf::from("/repo"), move |name| {
            map.get(name).map(|v| OsString::from(*v))
        })
    }

    #[test]
    fn honours_freedas_home_and_midas_aliases() {
        let p = with_vars(&[
            ("HOME", "/home/user"),
            ("FREEDAS_HOME", "/srv/freedas"),
            ("MIDAS_DATA", "/srv/data"),
            ("FREEDAS_STATE", "/srv/state"),
        ]);
        assert_eq!(p.home, PathBuf::from("/srv/freedas"));
        assert_eq!(p.data_dir, PathBuf::from("/srv/data"));
        assert_eq!(p.state_dir, PathBuf::from("/srv/state"));
        assert_eq!(p.bin_dir, PathBuf::from("/srv/freedas/.freedas/bin"));
    }

    #[test]
    fn empty_xdg_is_treated_as_unset() {
        let p = with_vars(&[
            ("HOME", "/home/user"),
            ("XDG_DATA_HOME", ""),
            ("XDG_CACHE_HOME", ""),
        ]);
        assert_eq!(p.data_dir, PathBuf::from("/home/user/.local/share/freedas"));
        assert_eq!(p.cache_dir, PathBuf::from("/home/user/.cache/freedas"));
    }
}
