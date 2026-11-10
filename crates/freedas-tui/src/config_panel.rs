//! `/config` settings browser: grouped effective-config rows, search, inline
//! editing, and an atomic merge into the global config file.

use std::path::PathBuf;
use std::time::Instant;

use freedas_core::config::Config;
use freedas_core::paths::Paths;
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Bool,
    Number,
    Text,
    List,
    ReadOnly,
}

#[derive(Clone, Debug)]
pub(crate) struct Row {
    pub category: &'static str,
    /// Key as shown inside its category, e.g. `recall.limit`.
    pub key: String,
    /// Dotted config path used when saving; empty for read-only rows.
    pub path: String,
    pub value: Value,
    pub kind: Kind,
}

pub(crate) struct Panel {
    pub rows: Vec<Row>,
    pub query: String,
    pub searching: bool,
    pub selected: usize,
    /// `(config path, edit buffer)` while the inline editor is open.
    pub editing: Option<(String, String)>,
    /// `(message, shown_at)`; the view drops it after a few seconds.
    pub notice: Option<(String, Instant)>,
}

/// Category/keys exposed by the browser, in display order.
const KEYS: [(&str, &[(&str, &str)]); 7] = [
    (
        "model",
        &[
            ("model", "model"),
            ("small_model", "small_model"),
            ("default_agent", "default_agent"),
            ("subagent_depth", "subagent_depth"),
            ("disabled_providers", "disabled_providers"),
        ],
    ),
    (
        "memory",
        &[
            ("enabled", "memory.enabled"),
            ("profile", "memory.profile"),
            ("recall.limit", "memory.recall.limit"),
            ("distill.enabled", "memory.distill.enabled"),
        ],
    ),
    (
        "router",
        &[
            ("mode", "router.mode"),
            ("quality_floor", "router.quality_floor"),
            ("max_escalations", "router.max_escalations"),
            ("learn", "router.learn"),
        ],
    ),
    (
        "standards",
        &[
            ("enabled", "standards.enabled"),
            ("commands", "standards.commands"),
            ("max_attempts", "standards.max_attempts"),
        ],
    ),
    (
        "sandbox",
        &[("mode", "sandbox.mode"), ("network", "sandbox.network")],
    ),
    (
        "ui",
        &[
            ("theme", "theme"),
            ("snapshots", "snapshots"),
            ("telemetry", "telemetry"),
        ],
    ),
    (
        "server",
        &[("hostname", "server.hostname"), ("port", "server.port")],
    ),
];

const NULL: Value = Value::Null;

pub(crate) fn flatten(cfg: &Config) -> Vec<Row> {
    let snapshot = serde_json::to_value(cfg).unwrap_or_else(|_| json!({}));
    let mut rows = Vec::new();
    for (category, keys) in KEYS {
        for (key, path) in keys {
            let value = get(&snapshot, path);
            rows.push(Row {
                category,
                key: (*key).to_string(),
                path: (*path).to_string(),
                value: value.clone(),
                kind: kind_of(value),
            });
        }
    }
    for rule in snapshot["permission"]["rules"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let field =
            |name: &str, fallback: &str| rule[name].as_str().unwrap_or(fallback).to_string();
        rows.push(Row {
            category: "permissions",
            key: format!("{} {}", field("action", "*"), field("resource", "*")),
            path: String::new(),
            value: json!(field("effect", "allow")),
            kind: Kind::ReadOnly,
        });
    }
    rows
}

fn kind_of(value: &Value) -> Kind {
    match value {
        Value::Bool(_) => Kind::Bool,
        Value::Number(_) => Kind::Number,
        Value::Array(_) => Kind::List,
        _ => Kind::Text,
    }
}

fn get<'a>(root: &'a Value, path: &str) -> &'a Value {
    let mut node = root;
    for key in path.split('.') {
        match node.get(key) {
            Some(next) => node = next,
            None => return &NULL,
        }
    }
    node
}

/// Text shown after a row's key. `read_only` permission rows render as
/// `= effect`.
pub(crate) fn value_text(row: &Row) -> String {
    if row.kind == Kind::ReadOnly {
        return format!("= {}", row.value.as_str().unwrap_or_default());
    }
    let text = edit_text(row);
    if text.is_empty() {
        "—".to_string()
    } else {
        text
    }
}

/// Prefill for the inline editor, without the display-only `—` placeholder.
pub(crate) fn edit_text(row: &Row) -> String {
    match &row.value {
        Value::Bool(on) => (if *on { "on" } else { "off" }).to_string(),
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        Value::Array(items) => items
            .iter()
            .map(|item| item.as_str().unwrap_or_default().to_string())
            .collect::<Vec<_>>()
            .join(", "),
        other => other.to_string(),
    }
}

/// Set a dotted path, creating intermediate objects. Empty paths are ignored
/// so read-only rows cannot write.
pub(crate) fn set_path(root: &mut Value, path: &str, value: Value) {
    let mut parts = path.split('.').filter(|p| !p.is_empty());
    let Some(first) = parts.next() else { return };
    if !root.is_object() {
        *root = json!({});
    }
    let mut node = root;
    let mut part = first;
    for next in parts {
        let map = node.as_object_mut().expect("object built above");
        node = map.entry(part.to_string()).or_insert_with(|| json!({}));
        if !node.is_object() {
            *node = json!({});
        }
        part = next;
    }
    if let Some(map) = node.as_object_mut() {
        map.insert(part.to_string(), value);
    }
}

pub(crate) fn filter(query: &str, rows: &[Row]) -> Vec<Row> {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return rows.to_vec();
    }
    rows.iter()
        .filter(|row| {
            row.category.to_lowercase().contains(&query)
                || row.key.to_lowercase().contains(&query)
                || value_text(row).to_lowercase().contains(&query)
        })
        .cloned()
        .collect()
}

impl Panel {
    pub(crate) fn new(cfg: &Config) -> Self {
        Self {
            rows: flatten(cfg),
            query: String::new(),
            searching: false,
            selected: 0,
            editing: None,
            notice: None,
        }
    }

    pub(crate) fn reload(&mut self, cfg: &Config) {
        self.rows = flatten(cfg);
        self.select(self.selected);
    }

    pub(crate) fn matches(&self) -> Vec<Row> {
        filter(&self.query, &self.rows)
    }

    pub(crate) fn selected_row(&self) -> Option<Row> {
        self.matches().get(self.selected).cloned()
    }

    pub(crate) fn move_by(&mut self, delta: isize) {
        let len = self.matches().len();
        if len == 0 {
            self.selected = 0;
            return;
        }
        self.selected = (self.selected as isize + delta).clamp(0, (len - 1) as isize) as usize;
    }

    pub(crate) fn select(&mut self, index: usize) {
        self.selected = index.min(self.matches().len().saturating_sub(1));
    }
}

/// Merge one dotted key into the global config file atomically. Comments are
/// lost by the pretty-JSON rewrite, matching the server's config PATCH.
///
/// `shortcut: JSONC is parsed by stripping comments and trailing commas,
/// upgrade when freedas-core exposes a comment-preserving writer.`
///
/// Returns the file written plus its previous bytes (`None` when the file did
/// not exist) so a failed reload can undo the write exactly.
pub(crate) fn save(
    paths: &Paths,
    path: &str,
    value: Value,
) -> std::io::Result<(PathBuf, Option<Vec<u8>>)> {
    let json_path = paths.global_config();
    let jsonc_path = json_path.with_extension("jsonc");
    let target = if jsonc_path.exists() {
        jsonc_path
    } else {
        json_path
    };
    let previous = std::fs::read(&target).ok();
    let mut root = match previous.as_deref() {
        None | Some([]) => json!({}),
        Some(bytes) => {
            let text = String::from_utf8_lossy(bytes);
            let parsed = serde_json::from_str::<Value>(&text)
                .ok()
                .or_else(|| serde_json::from_str::<Value>(&strip_jsonc(&text)).ok());
            match parsed {
                Some(root) if root.is_object() => root,
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("cannot parse {}", target.display()),
                    ));
                }
            }
        }
    };
    set_path(&mut root, path, value);
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = target.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&root)?)?;
    std::fs::rename(&tmp, &target)?;
    Ok((target, previous))
}

fn strip_jsonc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
            }
            '/' if chars.peek() == Some(&'/') => {
                chars.next();
                for c in chars.by_ref() {
                    if c == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut prev = '\0';
                for c in chars.by_ref() {
                    if prev == '*' && c == '/' {
                        break;
                    }
                    prev = c;
                }
            }
            _ => out.push(c),
        }
    }
    let chars = out.chars().collect::<Vec<_>>();
    let mut cleaned = String::with_capacity(out.len());
    let mut in_string = false;
    let mut escaped = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            cleaned.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if c == '"' {
            in_string = true;
        } else if c == ',' {
            let mut next = i + 1;
            while next < chars.len() && chars[next].is_whitespace() {
                next += 1;
            }
            if next < chars.len() && (chars[next] == '}' || chars[next] == ']') {
                i += 1;
                continue;
            }
        }
        cleaned.push(c);
        i += 1;
    }
    cleaned
}

#[cfg(test)]
mod tests {
    use super::*;
    use freedas_core::config::PermissionRule;

    #[test]
    fn flatten_covers_every_category() {
        let rows = flatten(&Config::default());
        let categories: Vec<&str> = rows.iter().map(|r| r.category).collect();
        for category in [
            "model",
            "memory",
            "router",
            "standards",
            "sandbox",
            "ui",
            "server",
            "permissions",
        ] {
            assert!(categories.contains(&category), "missing {category}");
        }
        let recall = rows
            .iter()
            .find(|r| r.path == "memory.recall.limit")
            .unwrap();
        assert_eq!(recall.key, "recall.limit");
        assert_eq!(recall.kind, Kind::Number);
        assert_eq!(value_text(recall), "8");
        let theme = rows.iter().find(|r| r.path == "theme").unwrap();
        assert_eq!(value_text(theme), "—");
        let snapshots = rows.iter().find(|r| r.path == "snapshots").unwrap();
        assert_eq!(snapshots.kind, Kind::Bool);
        assert_eq!(value_text(snapshots), "on");
    }

    #[test]
    fn permission_rules_are_read_only_rows() {
        let mut cfg = Config::default();
        cfg.permission.rules = vec![PermissionRule::new("bash", "git push", "ask")];
        let rows = flatten(&cfg);
        let rule = rows.iter().find(|r| r.category == "permissions").unwrap();
        assert_eq!(rule.key, "bash git push");
        assert_eq!(rule.kind, Kind::ReadOnly);
        assert!(rule.path.is_empty());
        assert_eq!(value_text(rule), "= ask");
    }

    #[test]
    fn set_path_creates_and_overwrites() {
        let mut root = json!({});
        set_path(&mut root, "memory.recall.limit", json!(12));
        assert_eq!(root["memory"]["recall"]["limit"], json!(12));
        set_path(&mut root, "memory.recall.limit", json!(4));
        assert_eq!(root["memory"]["recall"]["limit"], json!(4));
        set_path(&mut root, "snapshots", json!(false));
        assert_eq!(root["snapshots"], json!(false));
        // A scalar mid-path is replaced by the object the write needs.
        set_path(&mut root, "theme.name", json!("dark"));
        assert_eq!(root["theme"]["name"], json!("dark"));
        // Empty paths (read-only rows) never write.
        set_path(&mut root, "", json!("nope"));
        assert!(root.get("").is_none());
    }

    #[test]
    fn filter_matches_key_category_and_value() {
        let rows = flatten(&Config::default());
        let keys = |query: &str| -> Vec<String> {
            filter(query, &rows).iter().map(|r| r.key.clone()).collect()
        };
        assert!(keys("recall").contains(&"recall.limit".to_string()));
        assert!(keys("router").contains(&"quality_floor".to_string()));
        assert!(keys("standards").iter().all(|k| k != "quality_floor"));
        assert!(keys("deny").contains(&"network".to_string()));
        assert_eq!(filter("no-such-key", &rows).len(), 0);
        assert_eq!(filter("", &rows).len(), rows.len());
    }

    #[test]
    fn jsonc_config_round_trips_through_save() {
        let root = std::env::temp_dir().join(format!("freedas-config-{}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        std::fs::create_dir_all(root.join("config")).unwrap();
        let paths = Paths {
            home: root.join("home"),
            config_dir: root.join("config"),
            data_dir: root.join("data"),
            state_dir: root.join("state"),
            cache_dir: root.join("cache"),
            bin_dir: root.join("bin"),
            project_root: root.clone(),
        };
        std::fs::write(
            paths.global_config(),
            "{\n  // keep me\n  \"model\": \"freedas/auto\",\n  \"snapshots\": true,\n}\n",
        )
        .unwrap();
        save(&paths, "snapshots", json!(false)).unwrap();
        let written: Value =
            serde_json::from_str(&std::fs::read_to_string(paths.global_config()).unwrap()).unwrap();
        assert_eq!(written["snapshots"], json!(false));
        assert_eq!(written["model"], json!("freedas/auto"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn save_refuses_unparseable_config() {
        let root = std::env::temp_dir().join(format!("freedas-config-bad-{}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        std::fs::create_dir_all(root.join("config")).unwrap();
        let paths = Paths {
            home: root.join("home"),
            config_dir: root.join("config"),
            data_dir: root.join("data"),
            state_dir: root.join("state"),
            cache_dir: root.join("cache"),
            bin_dir: root.join("bin"),
            project_root: root.clone(),
        };
        let original = "{not json";
        std::fs::write(paths.global_config(), original).unwrap();
        assert!(save(&paths, "snapshots", json!(false)).is_err());
        assert_eq!(
            std::fs::read_to_string(paths.global_config()).unwrap(),
            original
        );
        std::fs::remove_dir_all(&root).ok();
    }
}
