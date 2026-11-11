//! Interactive terminal UI: transcript, composer, status, and dialogs.
//!
//! The TUI here is a local client of the session runner's data layer:
//! sessions are listed from the database, prompts run through
//! `freedas_session::Runner`, and permission prompts are resolved
//! interactively when a TTY is present.

mod cell;
mod composer;
mod config_panel;
mod markdown;
mod popup;
mod style;
mod view;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use cell::Cell;

use composer::{Composer, cursor_row_col, wrapped_height};
use crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    Event, KeyCode, KeyModifiers, MouseEventKind,
};
use crossterm::execute;
use freedas_core::config::{Config, PermissionMode};
use freedas_core::paths::Paths;
use freedas_db::Db;
use ratatui::prelude::*;
use view::FooterState;

/// Transcript cells with their timestamps; rendered according to the
/// `/timestamps` toggle.
#[derive(Default)]
struct Transcript {
    cells: Vec<(i64, Cell)>,
    timestamps: bool,
}

fn stamp(ts: i64) -> String {
    let fmt = time::macros::format_description!("[hour]:[minute]:[second]");
    time::OffsetDateTime::from_unix_timestamp(ts / 1000)
        .ok()
        .and_then(|d| d.format(&fmt).ok())
        .unwrap_or_default()
}
/// Strip C0 controls and CSI/OSC escape sequences at ingest so model or tool
/// output cannot rewrite the terminal, spoof prompts, or hide diffs.
/// Keeps `\n` and `\t`; everything else control-like is dropped.
fn sanitize_terminal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        // ESC-prefixed sequences: CSI `ESC [ … final`, OSC `ESC ] … BEL|ESC\`.
        if c == '\x1b' {
            match chars.peek() {
                Some('[') => {
                    chars.next();
                    for c2 in chars.by_ref() {
                        if ('\x40'..='\x7e').contains(&c2) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    chars.next();
                    while let Some(c2) = chars.next() {
                        if c2 == '\x07' {
                            break;
                        }
                        if c2 == '\x1b' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                Some(_) => {
                    chars.next();
                }
                None => {}
            }
            continue;
        }
        // Single-byte C1 CSI/OSC openers without ESC.
        if c == '\u{9B}' {
            for c2 in chars.by_ref() {
                if ('\x40'..='\x7e').contains(&c2) {
                    break;
                }
            }
            continue;
        }
        if c == '\u{9D}' || c == '\u{9C}' {
            while let Some(c2) = chars.next() {
                if c2 == '\x07' {
                    break;
                }
                if c2 == '\x1b' && chars.peek() == Some(&'\\') {
                    chars.next();
                    break;
                }
            }
            continue;
        }
        if c.is_control() && c != '\n' && c != '\t' {
            continue;
        }
        if c == '\x7f' {
            continue;
        }
        out.push(c);
    }
    out
}

/// Drop queued prompts tagged for another session; returns how many dropped.
fn drop_queued_for_session(
    queue: &mut VecDeque<(Option<String>, String)>,
    next: Option<&str>,
) -> usize {
    let before = queue.len();
    queue.retain(|(sid, _)| sid.as_deref() == next);
    before - queue.len()
}

impl Transcript {
    fn new() -> Self {
        Self::default()
    }

    fn push(&mut self, text: String) {
        self.cells
            .push((freedas_core::paths::now_ms(), Cell::Notice(text)));
    }
    fn push_user(&mut self, text: String) {
        self.cells
            .push((freedas_core::paths::now_ms(), Cell::User(text)));
    }
    fn push_assistant(&mut self, text: String) {
        let text = sanitize_terminal(&text);
        self.cells
            .push((freedas_core::paths::now_ms(), Cell::Assistant(text)));
    }
    fn push_error(&mut self, text: String) {
        self.cells
            .push((freedas_core::paths::now_ms(), Cell::Error(text)));
    }
    fn push_reasoning(&mut self, text: String) {
        self.cells
            .push((freedas_core::paths::now_ms(), Cell::Reasoning(text)));
    }
    fn push_tool(&mut self, tool: cell::Tool) {
        self.cells
            .push((freedas_core::paths::now_ms(), Cell::Tool(tool)));
    }

    /// Apply a `\u{2}` result event to the newest running cell for `name`.
    fn complete_tool(&mut self, name: &str, ok: bool, output: &str, diff: Option<String>) {
        let name = sanitize_terminal(name);
        let output = sanitize_terminal(output);
        let diff = diff.map(|d| sanitize_terminal(&d));
        for (_, cell) in self.cells.iter_mut().rev() {
            if let Cell::Tool(tool) = cell
                && tool.name == name
            {
                tool.ok = Some(ok);
                tool.output = output;
                tool.diff = diff;
                return;
            }
        }
        self.push_tool(cell::Tool {
            name,
            ok: Some(ok),
            output,
            diff,
        });
    }

    fn clear(&mut self) {
        self.cells.clear();
    }
    /// Drop the newest user message and everything after it; returns whether a
    /// user message was found.
    fn truncate_user_tail(&mut self) -> bool {
        match self
            .cells
            .iter()
            .rposition(|(_, c)| matches!(c, Cell::User(_)))
        {
            Some(at) => {
                self.cells.truncate(at);
                true
            }
            None => false,
        }
    }
    fn len(&self) -> usize {
        self.cells.len()
    }
    fn extend(&mut self, other: Vec<(i64, Cell)>) {
        self.cells.extend(other);
    }
    fn split_off(&mut self, at: usize) -> Vec<(i64, Cell)> {
        self.cells.split_off(at)
    }
    fn text(&self) -> String {
        self.cells
            .iter()
            .map(|(_, c)| c.plain())
            .collect::<Vec<_>>()
            .join("\n")
    }
    fn render(&self) -> String {
        if !self.timestamps {
            return self.text();
        }
        self.cells
            .iter()
            .map(|(ts, c)| format!("[{}] {}", stamp(*ts), c.plain()))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Lines as actually painted: stamped when toggled, with the in-flight
    /// stream text appended as a provisional assistant block.
    fn display_lines(&self, live: &str, width: usize) -> Vec<Line<'static>> {
        let mut out = Vec::with_capacity(self.cells.len() + 4);
        for (ts, cell) in &self.cells {
            let mut lines = cell.lines(width);
            if self.timestamps
                && let Some(first) = lines.first_mut()
            {
                first
                    .spans
                    .insert(0, Span::styled(format!("[{}] ", stamp(*ts)), style::dim()));
            }
            out.extend(lines);
        }
        if !live.is_empty() {
            out.extend(markdown::render(live, width));
        }
        out
    }
}

fn init_terminal() -> Terminal<CrosstermBackend<std::io::Stdout>> {
    let terminal = ratatui::init();
    let _ = execute!(std::io::stdout(), EnableMouseCapture, EnableBracketedPaste);
    terminal
}

fn restore_terminal() {
    let _ = execute!(
        std::io::stdout(),
        DisableBracketedPaste,
        DisableMouseCapture
    );
    ratatui::restore();
}

fn branch_of(root: &std::path::Path) -> Option<String> {
    // Read HEAD directly: a `git rev-parse` subprocess costs ~10ms, which is
    // most of the time-to-first-frame budget on launch.
    let dotgit = root.join(".git");
    let head = if dotgit.is_file() {
        // Worktree/submodule: `.git` is a file pointing at the real gitdir.
        let body = std::fs::read_to_string(&dotgit).ok()?;
        let dir = body.trim().strip_prefix("gitdir:")?.trim();
        let dir = std::path::Path::new(dir);
        let dir = if dir.is_absolute() {
            dir.to_path_buf()
        } else {
            root.join(dir)
        };
        dir.join("HEAD")
    } else {
        dotgit.join("HEAD")
    };
    let head = std::fs::read_to_string(head).ok()?;
    let head = head.trim();
    let name = head
        .strip_prefix("ref: refs/heads/")
        .map(str::to_string)
        .or_else(|| {
            head.chars()
                .all(|c| c.is_ascii_hexdigit())
                .then(|| "detached".to_string())
        })?;
    (!name.is_empty()).then_some(name)
}

fn project_name(root: &std::path::Path) -> String {
    root.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| root.display().to_string())
}

fn usage_of(db: &Db, project_id: &str) -> (i64, i64, f64) {
    let mut totals = (0i64, 0i64, 0f64);
    if let Ok(rows) = db.usage_totals(None, Some(project_id), None) {
        for t in rows {
            totals.0 += t.input;
            totals.1 += t.output;
            totals.2 += t.cost;
        }
    }
    totals
}

/// Percentage of the session model's context the last request used, when the
/// model is in the bundled catalog. Unknown models hide the indicator.
fn context_used_pct(db: &Db, session: Option<&str>) -> Option<u8> {
    let session = session?;
    let (provider, id) = {
        let row = db.session_full(session).ok().flatten()?;
        (row.model_provider?, row.model_id?)
    };
    let context = freedas_catalog::builtin_catalog()
        .into_iter()
        .find(|m| m.provider == provider && m.id == id)
        .map(|m| m.context)?;
    let input = db
        .list_messages(session)
        .ok()?
        .into_iter()
        .rev()
        .find_map(|m| {
            m.usage
                .as_deref()
                .and_then(|u| serde_json::from_str::<serde_json::Value>(u).ok())
                .and_then(|v| v["input"].as_u64())
        })?;
    if context == 0 {
        return None;
    }
    Some((input.saturating_mul(100) / context).min(100) as u8)
}

/// Most recent submitted prompts matching `query`, newest first.
fn search_matches(history: &[String], query: &str) -> Vec<String> {
    let needle = query.to_lowercase();
    history
        .iter()
        .rev()
        .filter(|h| h.to_lowercase().contains(&needle))
        .take(50)
        .cloned()
        .collect()
}

/// Next prompt-history index for Up/Down. `None` means "off the history"
/// (empty draft); indexes are clamped so a stale position cannot panic.
fn history_step(len: usize, pos: Option<usize>, up: bool) -> Option<usize> {
    if len == 0 {
        return None;
    }
    match (up, pos) {
        (true, None) => Some(len - 1),
        (true, Some(p)) => Some(p.min(len - 1).saturating_sub(1)),
        (false, Some(p)) if p + 1 < len => Some(p + 1),
        (false, _) => None,
    }
}

fn copy_to_clipboard(text: &str) -> std::io::Result<()> {
    use std::io::Write;
    let candidates: &[(&str, &[&str])] = &[
        ("pbcopy", &[]),
        ("wl-copy", &[]),
        ("xclip", &["-selection", "clipboard"]),
        ("xsel", &["--clipboard", "--input"]),
        ("clip.exe", &[]),
    ];
    for (cmd, args) in candidates {
        let Ok(mut child) = std::process::Command::new(cmd)
            .args(*args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
        else {
            continue;
        };
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(text.as_bytes());
        }
        if child.wait().map(|s| s.success()).unwrap_or(false) {
            return Ok(());
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "no clipboard command (pbcopy, wl-copy, xclip, xsel, clip.exe)",
    ))
}

#[derive(Debug, Clone)]
pub struct TuiOptions {
    pub project_root: std::path::PathBuf,
    pub agent: String,
    pub model: Option<String>,
    pub variant: Option<String>,
    pub auto: bool,
    pub manual: bool,
    pub session_id: Option<String>,
}

impl Default for TuiOptions {
    fn default() -> Self {
        Self {
            project_root: std::env::current_dir().unwrap_or_default(),
            agent: "build".into(),
            model: None,
            variant: None,
            auto: false,
            manual: false,
            session_id: None,
        }
    }
}

pub fn run() -> std::io::Result<()> {
    run_with(std::env::current_dir().unwrap_or_default())
}

pub fn run_with(project_root: std::path::PathBuf) -> std::io::Result<()> {
    run_with_opts(TuiOptions {
        project_root,
        ..Default::default()
    })
}

pub fn run_with_opts(opts: TuiOptions) -> std::io::Result<()> {
    let timing = std::env::var_os("FREEDAS_TUI_TIMING").is_some();
    let t0 = Instant::now();
    let paths = Paths::resolve(opts.project_root.clone());
    if timing {
        eprintln!("paths: {:?}", t0.elapsed());
    }
    let db = Arc::new(Db::open(&paths.db_path()).map_err(|e| {
        std::io::Error::other(format!("cannot open {}: {e}", paths.db_path().display()))
    })?);
    if timing {
        eprintln!("db: {:?}", t0.elapsed());
    }
    let cfg = freedas_core::config::load(&paths, false)
        .map_err(|e| std::io::Error::other(format!("config: {e}")))?;
    if timing {
        eprintln!("cfg: {:?}", t0.elapsed());
    }
    let project_id = db
        .ensure_project(&opts.project_root)
        .map_err(|e| std::io::Error::other(format!("cannot register project: {e}")))?;
    if timing {
        eprintln!("ensure_project: {:?}", t0.elapsed());
    }
    let mut terminal = init_terminal();
    if timing {
        eprintln!("terminal: {:?}", t0.elapsed());
    }
    let result = event_loop(&mut terminal, db, paths, cfg, project_id, opts);
    restore_terminal();
    result
}

/// One slash command, resolved from built-ins, `.freedas/commands/*.md`,
/// skills, and MCP prompts.
struct SlashCommand {
    name: String,
    description: String,
    body: Option<String>,
    agent: Option<String>,
    model: Option<String>,
    subtask: bool,
}

fn discover_commands(
    project_root: &std::path::Path,
    paths: &Paths,
    extra_skill_dirs: &[String],
) -> Vec<SlashCommand> {
    let mut out = Vec::new();
    let mut dirs = vec![project_root.join(".freedas").join("commands")];
    dirs.push(paths.config_dir.join("commands"));
    for dir in dirs {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                let p = e.path();
                if p.extension().map(|x| x == "md").unwrap_or(false) {
                    let name = p
                        .file_stem()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default();
                    if freedas_skill::is_reserved_name(&name) {
                        continue;
                    }
                    let text = std::fs::read_to_string(&p).unwrap_or_default();
                    let (front, body) = freedas_agent::parse_frontmatter(&text)
                        .unwrap_or((serde_json::json!({}), text.clone()));
                    out.push(SlashCommand {
                        name,
                        description: front["description"].as_str().unwrap_or("").to_string(),
                        body: Some(body),
                        agent: front["agent"].as_str().map(|s| s.to_string()),
                        model: front["model"].as_str().map(|s| s.to_string()),
                        subtask: front["subtask"].as_bool().unwrap_or(false),
                    });
                }
            }
        }
    }
    for s in freedas_skill::discover_with(project_root, extra_skill_dirs) {
        out.push(SlashCommand {
            name: s.id.clone(),
            description: s.description.clone(),
            body: Some(s.body.clone()),
            agent: None,
            model: None,
            subtask: false,
        });
    }
    out
}

/// One compact line: first line, collapsed whitespace, capped with `…`.
fn one_line(text: &str, max: usize) -> String {
    let flat = text
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if flat.chars().count() <= max {
        flat
    } else {
        let mut out: String = flat.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

/// `/help` text, shared with the Ctrl+P and Ctrl+H keybindings.
fn help_lines(commands: &[SlashCommand]) -> Vec<String> {
    let mut out = vec![
        "session: /new /sessions /rename /fork /compact /undo /redo /editor /move /export /copy /timestamps /thinking /status /debug /changelog /help /exit".to_string(),
        "setup: /init /sync /config /agents /variants /mcps /login /credits /usage /workspace /org /remote /update /code-standards /ui-standards".to_string(),
        "review: /review /standards-review /standards-audit /ui-review /ui-audit /quick-plan /deep-plan".to_string(),
        "keys: Enter submit · Shift+Enter/Ctrl+J newline · Esc interrupt or clear · Up/Down history · PgUp/PgDn scroll · Tab/Shift+Tab agent · ? shortcuts".to_string(),
        "keys: Ctrl+R search · Ctrl+T transcript · Ctrl+E editor · Ctrl+Y copy · ? shortcuts".to_string(),
        "completion: / commands · @ files · Up/Down move · Tab/Enter complete · Esc dismiss".to_string(),
        "permission prompt: a allow once · A allow always · d deny".to_string(),
        "commands:".to_string(),
    ];
    for c in commands {
        out.push(format!("/{} — {}", c.name, one_line(&c.description, 88)));
    }
    out
}

/// Built-in slash commands as `(name, description)`; the popup completes these
/// and custom commands/skills register after them.
fn builtin_commands() -> &'static [(&'static str, &'static str)] {
    &[
        ("new", "start a new session (alias: clear)"),
        (
            "sessions",
            "resume, fork, rename, or delete (aliases: resume, continue)",
        ),
        ("rename", "rename the current session"),
        ("fork", "fork the current session"),
        ("compact", "summarize older messages (alias: summarize)"),
        ("undo", "revert the last message and its edits"),
        ("redo", "reapply the last undone change"),
        ("editor", "compose the next message in $EDITOR"),
        ("move", "move the session to another project"),
        ("export", "export the transcript"),
        ("copy", "copy the transcript"),
        ("timestamps", "toggle message timestamps"),
        ("thinking", "show or hide reasoning"),
        ("status", "session, model, token, and cost totals"),
        ("debug", "paths, providers, MCP, and last error"),
        ("changelog", "open the changelog"),
        ("help", "commands, keys, version, and paths"),
        ("config", "open the settings browser"),
        ("exit", "exit freedas (aliases: quit, q)"),
        ("init", "create or update AGENTS.md"),
        ("sync", "import setup from other agents (alias: adopt)"),
        ("agents", "switch the active agent"),
        ("model", "choose the model and reasoning level"),
        ("permissions", "choose how tool permissions ask"),
        ("variants", "switch the model variant"),
        ("mcps", "toggle MCP servers"),
        ("login", "sign in to a provider"),
        ("credits", "show the workspace balance"),
        ("usage", "tokens and cost by model"),
        ("workspace", "choose the billing workspace (alias: billing)"),
        ("org", "switch organization (aliases: orgs, switch-org)"),
        ("remote", "share the session for remote control (alias: rc)"),
        ("update", "check for and install an update"),
        ("code-standards", "load the code standards"),
        ("ui-standards", "load the UI standards"),
        ("review", "review changes, a commit, a branch, or a PR"),
        ("standards-review", "review changes for over-engineering"),
        (
            "standards-audit",
            "audit the repository for over-engineering",
        ),
        ("ui-review", "review changes for UI and UX issues"),
        ("ui-audit", "audit the repository for UI and UX issues"),
        (
            "quick-plan",
            "draft a plan on the cheap tier (alias: plan-quick)",
        ),
        (
            "deep-plan",
            "draft a plan on the strong tier (alias: plan-deep)",
        ),
    ]
}

fn slash_rows(commands: &[SlashCommand]) -> Vec<popup::Row> {
    let mut rows: Vec<popup::Row> = builtin_commands()
        .iter()
        .map(|(name, description)| popup::row(*name, format!("/{name} — {description}"), *name))
        .collect();
    for command in commands {
        if rows.iter().any(|r| r.value == command.name) {
            continue;
        }
        rows.push(popup::row(
            command.name.clone(),
            format!("/{} — {}", command.name, one_line(&command.description, 64)),
            command.name.clone(),
        ));
    }
    rows
}

/// Up to 2000 project files for `@` completion, skipping heavy directories.
fn project_file_rows(root: &std::path::Path) -> Vec<popup::Row> {
    const SKIP: [&str; 4] = [".git", "target", "node_modules", ".freedas"];
    let mut paths = Vec::new();
    for entry in ignore::WalkBuilder::new(root)
        .hidden(false)
        .filter_entry(|e| {
            !(e.depth() > 0
                && e.file_type().is_some_and(|t| t.is_dir())
                && SKIP.contains(&e.file_name().to_string_lossy().as_ref()))
        })
        .build()
        .flatten()
    {
        if entry.file_type().is_some_and(|t| t.is_file())
            && let Ok(relative) = entry.path().strip_prefix(root)
        {
            paths.push(relative.to_string_lossy().replace('\\', "/"));
            if paths.len() >= 2000 {
                break;
            }
        }
    }
    paths.sort();
    paths
        .into_iter()
        .map(|path| popup::row(path.clone(), path.clone(), path))
        .collect()
}

/// Replace the transcript with a stored session's messages and parts; returns
/// the newest assistant message id.
fn load_session(
    db: &Db,
    transcript: &mut Transcript,
    session_id: &str,
    thinking: bool,
) -> Option<String> {
    transcript.clear();
    let mut last = None;
    for message in db.list_messages(session_id).unwrap_or_default() {
        for part in db.list_parts(&message.id).unwrap_or_default() {
            let data: serde_json::Value =
                serde_json::from_str(&part.data).unwrap_or(serde_json::Value::Null);
            match part.kind.as_str() {
                "text" => {
                    if let Some(text) = data["text"].as_str() {
                        if message.role == "user" {
                            transcript.push_user(text.to_string());
                        } else {
                            transcript.push_assistant(text.to_string());
                        }
                    }
                }
                "reasoning" if thinking => {
                    if let Some(text) = data["text"].as_str() {
                        transcript.push_reasoning(text.to_string());
                    }
                }
                "tool" => {
                    let names: Vec<&str> = data["calls"]
                        .as_array()
                        .map(|calls| calls.iter().filter_map(|c| c.as_str()).collect())
                        .unwrap_or_default();
                    if !names.is_empty() {
                        transcript.push(format!("· tools: {}", names.join(", ")));
                    }
                }
                _ => {}
            }
        }
        if message.role == "assistant" {
            last = Some(message.id.clone());
        }
    }
    last
}

fn open_picker(
    kind: popup::Kind,
    db: &Db,
    project_id: &str,
    root: &std::path::Path,
    cfg: &Config,
    disabled: &[String],
) -> popup::Picker {
    match kind {
        popup::Kind::Sessions => popup::Picker::new(
            kind,
            "Sessions",
            db.list_sessions(project_id, 200)
                .unwrap_or_default()
                .into_iter()
                .map(|s| {
                    popup::row(
                        format!("{} {}", s.id, s.title),
                        format!("{} — {}", s.title, s.id),
                        s.id,
                    )
                })
                .collect(),
        ),
        popup::Kind::Models => {
            let models: Vec<_> = freedas_catalog::builtin_catalog()
                .into_iter()
                .filter(|m| cfg.provider_enabled(&m.provider))
                .collect();
            let mut picker = popup::Picker::new(
                kind,
                "Models",
                models
                    .iter()
                    .map(|m| {
                        popup::detailed_row(
                            m.full_id(),
                            m.full_id(),
                            format!(
                                "{} · {} · {}K · ${:.2}/${:.2} per 1M",
                                m.name,
                                m.tier,
                                m.context / 1000,
                                m.cost_input,
                                m.cost_output
                            ),
                            m.full_id(),
                        )
                    })
                    .collect(),
            );
            picker.variants = models
                .iter()
                .map(|m| (m.full_id(), m.variants.clone()))
                .collect();
            picker
        }
        popup::Kind::Permissions => {
            let mut picker = popup::Picker::new(
                kind,
                "Permissions",
                [
                    ("bypass", "never ask; explicit deny rules still block"),
                    ("auto", "ask only for risky actions"),
                    ("ask", "prompt before every action"),
                ]
                .into_iter()
                .map(|(value, detail)| {
                    popup::detailed_row(
                        value,
                        freedas_core::config::PermissionMode::parse(value)
                            .map(|m| m.label())
                            .unwrap_or(value),
                        format!("— {detail}"),
                        value,
                    )
                })
                .collect(),
            );
            picker.active = Some(cfg.permission_mode.as_str().to_string());
            picker
        }
        popup::Kind::Agents => popup::Picker::new(
            kind,
            "Agents",
            freedas_agent::merged_agents(root)
                .into_iter()
                .map(|a| {
                    popup::row(
                        a.id.clone(),
                        format!("{} [{}] {}", a.id, a.mode, a.description),
                        a.id,
                    )
                })
                .collect(),
        ),
        popup::Kind::Mcp => popup::Picker::new(
            kind,
            "MCP servers",
            freedas_mcp::status_from_config(cfg)
                .into_iter()
                .map(|s| {
                    let off = s.state == "disabled" || disabled.iter().any(|d| d == &s.name);
                    popup::row(
                        s.name.clone(),
                        format!(
                            "{} · {}{}",
                            s.name,
                            s.state,
                            if off { " (off)" } else { "" }
                        ),
                        s.name,
                    )
                })
                .collect(),
        ),
    }
}

/// A private scratch file for `/editor`; `create_new` refuses to follow a
/// planted symlink.
fn editor_temp(contents: &str) -> std::io::Result<std::path::PathBuf> {
    use std::io::Write;

    let dir = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    for attempt in 0..32 {
        let path = dir.join(format!(
            "freedas-{}-{nanos}-{attempt}.md",
            std::process::id()
        ));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(contents.as_bytes())?;
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "cannot create an editor scratch file",
    ))
}

fn edit_in_editor(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    composer: &mut Composer,
) -> std::io::Result<()> {
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| "vi".to_string());
    let mut text = composer.text().to_string();
    let path = match editor_temp(&text) {
        Ok(path) => path,
        Err(e) => {
            composer.set(format!("editor unavailable: {e}"));
            return Ok(());
        }
    };
    // Hand the terminal to the editor, then build a fresh Terminal so every
    // cell is repainted.
    restore_terminal();
    let status = std::process::Command::new(&editor).arg(&path).status();
    *terminal = init_terminal();
    if status.map(|s| s.success()).unwrap_or(false) {
        text = std::fs::read_to_string(&path).unwrap_or_default();
    }
    composer.set(text);
    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Build the `/init` section from the project type.
fn init_section(root: &std::path::Path) -> String {
    let has = |f: &str| root.join(f).exists();
    let mut commands = Vec::new();
    if has("Cargo.toml") {
        commands.push("cargo build");
        commands.push("cargo test");
        commands.push("cargo fmt --all --check");
        commands.push("cargo clippy --workspace --all-targets -- -D warnings");
    }
    if has("package.json") {
        commands.push("npm install");
        commands.push("npm test");
    }
    if has("pyproject.toml") || has("setup.py") {
        commands.push("pytest");
    }
    if has("go.mod") {
        commands.push("go build ./...");
        commands.push("go test ./...");
    }
    if has("Makefile") {
        commands.push("make");
    }
    let mut layout = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }
            let suffix = if e.path().is_dir() { "/" } else { "" };
            layout.push(format!("{name}{suffix}"));
        }
    }
    layout.sort();
    let mut out = String::from("<!-- freedas:init:begin -->\n");
    out.push_str("## Project\n\n");
    out.push_str(&format!("Root: {}\n\n", root.display()));
    if !layout.is_empty() {
        out.push_str("Layout: ");
        out.push_str(&layout.join(", "));
        out.push_str("\n\n");
    }
    if !commands.is_empty() {
        out.push_str("Commands:\n");
        for c in commands {
            out.push_str(&format!("- `{c}`\n"));
        }
        out.push('\n');
    }
    out.push_str("Run the narrowest check that covers a change, and do not claim a result you did not observe.\n");
    out.push_str("<!-- freedas:init:end -->\n");
    out
}

/// Render a session as Markdown for `/export`.
fn markdown_export(db: &Db, session_id: &str) -> String {
    let mut out = format!("# Session {session_id}\n\n");
    for m in db.list_messages(session_id).unwrap_or_default() {
        out.push_str(&format!("## {}\n\n", m.role));
        for p in db.list_parts(&m.id).unwrap_or_default() {
            let data: serde_json::Value =
                serde_json::from_str(&p.data).unwrap_or(serde_json::Value::Null);
            match p.kind.as_str() {
                "text" => {
                    if let Some(t) = data["text"].as_str() {
                        out.push_str(t);
                        out.push_str("\n\n");
                    }
                }
                "reasoning" => {
                    if let Some(t) = data["text"].as_str() {
                        out.push_str("<details><summary>Reasoning</summary>\n\n");
                        out.push_str(t);
                        out.push_str("\n\n</details>\n\n");
                    }
                }
                "tool" => {
                    if let Some(calls) = data["calls"].as_array() {
                        out.push_str("```\ntool calls: ");
                        out.push_str(
                            &calls
                                .iter()
                                .filter_map(|c| c.as_str())
                                .collect::<Vec<_>>()
                                .join(", "),
                        );
                        out.push_str("\n```\n\n");
                    }
                }
                _ => {}
            }
        }
    }
    out
}

fn relay_state(paths: &Paths) -> serde_json::Value {
    std::fs::read_to_string(paths.state_dir.join("relay.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_else(|| serde_json::json!({"running": false}))
}

/// Write one dotted key to the global config and reload it; a value the config
/// layer rejects is rolled back so a typo cannot brick the next start.
fn save_setting(paths: &Paths, path: &str, value: serde_json::Value) -> Result<Config, String> {
    let (file, previous) = config_panel::save(paths, path, value).map_err(|e| e.to_string())?;
    match freedas_core::config::load(paths, false) {
        Ok(cfg) => Ok(cfg),
        Err(e) => {
            // A save that created the file is undone by removing it; an empty
            // file would fail every later load.
            match previous {
                Some(bytes) => {
                    let _ = std::fs::write(&file, bytes);
                }
                None => {
                    let _ = std::fs::remove_file(&file);
                }
            }
            Err(e.to_string())
        }
    }
}

/// Adopt a reloaded config in the UI and the runner; callers keep the old one
/// when `save_setting` fails.
fn reload_into(
    cfg: &mut Config,
    runner: &mut Arc<freedas_session::Runner>,
    paths: &Paths,
    db: &Arc<Db>,
    next: Config,
) {
    *cfg = next;
    *runner = Arc::new(freedas_session::Runner::new(
        db.clone(),
        paths.clone(),
        cfg.clone(),
        freedas_catalog::builtin_catalog(),
    ));
}

/// Persist a setting and hand the reloaded config to the UI and the runner.
/// Returns whether the value was saved.
fn apply_setting(
    cfg: &mut Config,
    runner: &mut Arc<freedas_session::Runner>,
    panel: &mut config_panel::Panel,
    paths: &Paths,
    db: &Arc<Db>,
    path: &str,
    value: serde_json::Value,
) -> bool {
    match save_setting(paths, path, value) {
        Ok(next) => {
            reload_into(cfg, runner, paths, db, next);
            panel.editing = None;
            panel.reload(cfg);
            panel.notice = Some((format!("saved {path}"), Instant::now()));
            true
        }
        Err(e) => {
            panel.notice = Some((format!("not saved: {e}"), Instant::now()));
            false
        }
    }
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    db: Arc<Db>,
    paths: Paths,
    mut cfg: Config,
    project_id: String,
    opts: TuiOptions,
) -> std::io::Result<()> {
    let mut project_root = opts.project_root.clone();
    let mut runner = Arc::new(freedas_session::Runner::new(
        db.clone(),
        paths.clone(),
        cfg.clone(),
        freedas_catalog::builtin_catalog(),
    ));
    // Permission prompts from the runner worker thread reach the input loop
    // over this pair; `ask` blocks the worker until a keypress replies. The
    // receiver is optional so exit can drop it and unblock the approver.
    let (perm_tx, perm_rx) = mpsc::channel::<(
        String,
        String,
        Option<String>,
        std::sync::mpsc::Sender<freedas_tools::PermissionReply>,
    )>();
    let mut perm_rx = Some(perm_rx);
    #[derive(Debug)]
    struct TuiApprover {
        tx: mpsc::Sender<(
            String,
            String,
            Option<String>,
            std::sync::mpsc::Sender<freedas_tools::PermissionReply>,
        )>,
        paths: freedas_core::paths::Paths,
    }
    impl TuiApprover {
        fn ask_with(
            &self,
            action: &str,
            resource: &str,
            preview: Option<&str>,
        ) -> freedas_tools::PermissionReply {
            let (rtx, rrx) = std::sync::mpsc::channel();
            if self
                .tx
                .send((
                    action.to_string(),
                    resource.to_string(),
                    preview.map(str::to_string),
                    rtx,
                ))
                .is_err()
            {
                return freedas_tools::PermissionReply::Reject;
            }
            rrx.recv().unwrap_or(freedas_tools::PermissionReply::Reject)
        }
    }
    impl freedas_tools::PermissionApprover for TuiApprover {
        fn ask(&self, action: &str, resource: &str) -> freedas_tools::PermissionReply {
            self.ask_with(action, resource, None)
        }
        fn ask_preview(
            &self,
            action: &str,
            resource: &str,
            preview: Option<&str>,
        ) -> freedas_tools::PermissionReply {
            self.ask_with(action, resource, preview)
        }
        fn remember(&self, action: &str, resource: &str) {
            let _ = append_remembered_rule(&self.paths, action, resource);
        }
    }
    let approver: std::sync::Arc<dyn freedas_tools::PermissionApprover> =
        std::sync::Arc::new(TuiApprover {
            tx: perm_tx,
            paths: paths.clone(),
        });
    let session_rules: std::sync::Arc<std::sync::Mutex<Vec<freedas_core::config::PermissionRule>>> =
        Default::default();
    let mut composer = Composer::default();
    let mut current_session: Option<String> = opts.session_id.clone();
    let mut last_message: Option<String> = None;
    let mut last_prompt: Option<String> = None;
    let mut pending_permission: Option<(
        String,
        String,
        Option<String>,
        std::sync::mpsc::Sender<freedas_tools::PermissionReply>,
    )> = None;
    let mut pending_queue: VecDeque<(
        String,
        String,
        Option<String>,
        std::sync::mpsc::Sender<freedas_tools::PermissionReply>,
    )> = VecDeque::new();
    // When the permission modal appeared; a/A/d within ~300ms are ignored so a
    // keypress meant for the running session cannot answer the fresh prompt.
    let mut permission_shown_at: Option<Instant> = None;
    let mut pending_login: Option<String> = None;
    enum LoginEvent {
        Progress {
            generation: u64,
            message: String,
        },
        Auth {
            generation: u64,
            url: String,
            launch: Option<String>,
            instructions: Option<String>,
        },
        Prompt {
            generation: u64,
            prompt: freedas_provider::oauth::OAuthPrompt,
            reply: mpsc::Sender<Result<String, String>>,
        },
        Manual {
            generation: u64,
            reply: mpsc::Sender<Result<String, String>>,
        },
        Done {
            generation: u64,
            provider: String,
            result: Result<(), String>,
        },
    }
    let mut login_rx: Option<mpsc::Receiver<LoginEvent>> = None;
    let mut login_worker: Option<std::thread::JoinHandle<()>> = None;
    let mut login_generation: u64 = 0;
    let mut login_cancel = Arc::new(AtomicBool::new(false));
    let mut pending_login_prompt: Option<(
        freedas_provider::oauth::OAuthPrompt,
        mpsc::Sender<Result<String, String>>,
    )> = None;
    let mut pending_login_manual: Option<mpsc::Sender<Result<String, String>>> = None;
    let mut pending_sync: Option<(std::path::PathBuf, Vec<freedas_sync::PlanEntry>)> = None;
    let mut show_thinking = false;
    let mut disabled_mcps: Vec<String> = Vec::new();
    let mut agent = opts.agent.clone();
    let mut model = opts.model.clone().or_else(|| cfg.model.clone());
    let mut variant = opts.variant.clone().or_else(|| cfg.variant.clone());
    // The CLI flags win at startup; after that `auto`/`manual` are the source
    // of truth (`/permissions` updates all three). Explicit `deny` rules
    // still apply in every mode.
    let permission_mode = if opts.auto {
        PermissionMode::Bypass
    } else if opts.manual {
        PermissionMode::Ask
    } else {
        cfg.permission_mode
    };
    let (mut auto, mut manual) = permission_mode.flags();
    let timing = std::env::var_os("FREEDAS_TUI_TIMING").is_some();
    let t0 = Instant::now();
    let mut commands = discover_commands(&project_root, &paths, &cfg.skills);
    if timing {
        eprintln!("discover_commands: {:?}", t0.elapsed());
    }
    let mut project_id = project_id;
    let mut transcript = Transcript::new();
    let mut branch = branch_of(&project_root).unwrap_or_else(|| "no git".to_string());
    if timing {
        eprintln!("branch: {:?}", t0.elapsed());
    }
    let mut usage = usage_of(&db, &project_id);
    let mut context_pct: Option<u8> = None;
    let mut history: Vec<String> = Vec::new();
    let mut history_pos: Option<usize> = None;
    let mut scroll: u16 = 0;
    let mut tail_mark = 0usize;
    let mut run_started: Option<Instant> = None;
    let mut activity = String::from("Working");
    let mut cancel: Option<tokio_util::sync::CancellationToken> = None;
    // Queued prompts are tagged with the session they were queued for; a
    // session switch drops entries tagged for the previous session.
    let mut queue: VecDeque<(Option<String>, String)> = VecDeque::new();
    let mut quit_armed: Option<Instant> = None;
    let mut esc_armed: Option<Instant> = None;
    let mut shortcuts_open = false;
    let mut help_open = false;
    let mut help_scroll: u16 = 0;
    let mut settings: Option<config_panel::Panel> = None;
    let mut help_text = help_lines(&commands);
    let mut search: Option<(String, usize)> = None;
    let mut transcript_open = false;
    let mut transcript_scroll: u16 = 0;
    let mut picker: Option<popup::Picker> = None;
    let mut slash_items = slash_rows(&commands);
    let mut file_items = project_file_rows(&project_root);
    let mut slash_selected = 0usize;
    let mut file_selected = 0usize;
    let mut last_completion_draft = String::new();
    let mut slash_dismissed: Option<String> = None;
    let mut file_dismissed: Option<String> = None;
    let mut relay_on = relay_state(&paths)["running"].as_bool().unwrap_or(false);
    let mut relay_checked = Instant::now();
    const ARMED: Duration = Duration::from_secs(3);
    // One-line nudge when no provider has a credential; never blocks startup.
    // Any stored provider credential counts, including providers that are not
    // in the bundled catalog (opencode-go, opencode-zen, a self-hosted gateway).
    let stored_provider = freedas_provider::credentials::load(&paths.data_dir)
        .unwrap_or_default()
        .into_iter()
        .any(|(provider, key)| provider != "control_url" && !key.is_empty());
    let signed_in = std::env::var("FREEDAS_TEST_PROVIDER").is_ok() || stored_provider;
    let at_home = project_root == paths.home;

    // `--continue`/`--session`: show the stored transcript, not an empty pane.
    if let Some(sid) = current_session.clone() {
        last_message = load_session(&db, &mut transcript, &sid, show_thinking);
        context_pct = context_used_pct(&db, Some(sid.as_str()));
        tail_mark = transcript.len();
    }

    // One background run at a time. The worker streams text deltas into
    // `live_text` and markers into `live_events`; the UI keeps drawing.
    enum Outcome {
        Done(freedas_session::RunResult),
        Permission {
            // Fields carried for diagnostics; the arm below only notes that a
            // run needed permission, since approver-wired asks answer inline.
            #[allow(dead_code)]
            action: String,
            #[allow(dead_code)]
            resource: String,
            #[allow(dead_code)]
            prompt: String,
        },
        Failed(String),
    }
    let live_text = Arc::new(Mutex::new(String::new()));
    let live_events = Arc::new(Mutex::new(Vec::<String>::new()));
    let live_reasoning = Arc::new(Mutex::new(String::new()));
    let thinking_flag = Arc::new(AtomicBool::new(false));
    let mut pending: Option<mpsc::Receiver<Outcome>> = None;
    let mut worker: Option<std::thread::JoinHandle<()>> = None;
    enum BgDone {
        RenameTitle {
            sid: String,
            result: Result<String, String>,
        },
        Compact(Result<String, String>),
        Undo(Result<String, String>),
        Redo(Result<String, String>),
        Credits(Result<serde_json::Value, String>),
        Orgs(Result<serde_json::Value, String>),
        Review(Result<freedas_review::ReviewResult, String>),
    }
    let mut bg_pending: Option<mpsc::Receiver<BgDone>> = None;
    let mut bg_worker: Option<std::thread::JoinHandle<()>> = None;

    macro_rules! run_prompt {
        ($prompt:expr, $auto:expr) => {{
            let __prompt: String = $prompt.to_string();
            // Create the session up front so a run that fails before its first
            // model call still leaves a session the next prompt continues.
            if current_session.is_none() {
                let title: String = __prompt.chars().take(80).collect();
                match db.create_session(&project_id, &agent, &title, cfg.workspace.as_deref()) {
                    Ok(id) => {
                        current_session = Some(id);
                        last_message = None;
                    }
                    Err(e) => transcript.push_error(format!("cannot start session: {e}")),
                }
            }
            if let Some(__session) = current_session.clone() {
                let opts = freedas_session::RunOpts {
                    project_root: project_root.clone(),
                    agent: agent.clone(),
                    model: model.clone(),
                    prompt: __prompt.clone(),
                    auto: $auto,
                    manual,
                    workspace: cfg.workspace.clone(),
                    session_id: Some(__session),
                    title: None,
                    variant: variant.clone(),
                    depth: 0,
                    parent_id: None,
                    review_mode: false,
                    headless: false,
                    mcp_disabled: disabled_mcps.clone(),
                    approver: Some(approver.clone()),
                    session_rules: session_rules.clone(),
                    progress: Some({
                        let text = live_text.clone();
                        let events = live_events.clone();
                        let reasoning = live_reasoning.clone();
                        let thinking = thinking_flag.clone();
                        Arc::new(move |chunk: String| {
                            if let Some(marker) = chunk.strip_prefix('\u{1}') {
                                events.lock().unwrap().push(sanitize_terminal(marker));
                            } else if let Some(json) = chunk.strip_prefix('\u{2}') {
                                // Sanitize the JSON payload text fields, not the framing.
                                events.lock().unwrap().push(format!("\u{2}{json}"));
                            } else if let Some(delta) = chunk.strip_prefix('\u{3}') {
                                if thinking.load(Ordering::Relaxed) {
                                    reasoning
                                        .lock()
                                        .unwrap()
                                        .push_str(&sanitize_terminal(delta));
                                }
                            } else {
                                text.lock().unwrap().push_str(&sanitize_terminal(&chunk));
                            }
                        })
                    }),
                };
                let runner = runner.clone();
                let (tx, rx) = mpsc::channel();
                let token = tokio_util::sync::CancellationToken::new();
                let run_token = token.clone();
                worker = Some(std::thread::spawn(move || {
                    let rt = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(rt) => rt,
                        Err(e) => {
                            let _ = tx.send(Outcome::Failed(format!("cannot start runtime: {e}")));
                            return;
                        }
                    };
                    let out = match rt.block_on(runner.run_task_opts(opts, run_token)) {
                        Ok(result) => Outcome::Done(result),
                        Err(freedas_core::FreedasError::PermissionAsked { action, resource }) => {
                            Outcome::Permission {
                                action,
                                resource,
                                prompt: __prompt,
                            }
                        }
                        Err(e) => Outcome::Failed(e.to_string()),
                    };
                    let _ = tx.send(out);
                }));
                pending = Some(rx);
                cancel = Some(token);
                run_started = Some(Instant::now());
                activity = "Working".to_string();
                history_pos = None;
            }
        }};
    }

    macro_rules! start_login {
        ($provider:expr) => {{
            let __provider: String = $provider.to_string();
            if pending_login.is_some() {
                transcript.push("login already in progress".into());
            } else {
                login_generation += 1;
                let __generation = login_generation;
                let __cancel = Arc::new(AtomicBool::new(false));
                login_cancel = __cancel.clone();
                pending_login = Some(__provider.clone());
                transcript.push(format!("signing in to {__provider}…"));
                let (__tx, __rx) = mpsc::channel::<LoginEvent>();
                login_rx = Some(__rx);
                let __data_dir = paths.data_dir.clone();
                login_worker = Some(std::thread::spawn(move || {
                    let auth_tx = Arc::new(Mutex::new(__tx.clone()));
                    let mut auth_cb =
                        move |url: &str, launch: Option<&str>, instructions: Option<&str>| {
                            let _ = auth_tx.lock().unwrap().send(LoginEvent::Auth {
                                generation: __generation,
                                url: url.to_string(),
                                launch: launch.map(str::to_string),
                                instructions: instructions.map(str::to_string),
                            });
                        };
                    let progress_tx = Arc::new(Mutex::new(__tx.clone()));
                    let mut progress_cb = move |message: &str| {
                        let _ = progress_tx.lock().unwrap().send(LoginEvent::Progress {
                            generation: __generation,
                            message: message.to_string(),
                        });
                    };
                    let prompt_tx = Arc::new(Mutex::new(__tx.clone()));
                    let mut prompt_cb = move |prompt: &freedas_provider::oauth::OAuthPrompt| {
                        let (reply_tx, reply_rx) = mpsc::channel::<Result<String, String>>();
                        let owned = freedas_provider::oauth::OAuthPrompt {
                            message: prompt.message.clone(),
                            placeholder: prompt.placeholder.clone(),
                            allow_empty: prompt.allow_empty,
                            secret: prompt.secret,
                        };
                        if prompt_tx
                            .lock()
                            .unwrap()
                            .send(LoginEvent::Prompt {
                                generation: __generation,
                                prompt: owned,
                                reply: reply_tx,
                            })
                            .is_err()
                        {
                            return Err("login cancelled".into());
                        }
                        reply_rx
                            .recv()
                            .unwrap_or_else(|_| Err("login cancelled".into()))
                    };
                    let manual_tx = Arc::new(Mutex::new(__tx.clone()));
                    let mut manual_cb = move || {
                        let (reply_tx, reply_rx) = mpsc::channel::<Result<String, String>>();
                        if manual_tx
                            .lock()
                            .unwrap()
                            .send(LoginEvent::Manual {
                                generation: __generation,
                                reply: reply_tx,
                            })
                            .is_err()
                        {
                            return Err("login cancelled".into());
                        }
                        reply_rx
                            .recv()
                            .unwrap_or_else(|_| Err("login cancelled".into()))
                    };
                    let mut host = freedas_provider::oauth::LoginHost {
                        on_auth: Some(&mut auth_cb),
                        on_progress: Some(&mut progress_cb),
                        on_prompt: Some(&mut prompt_cb),
                        on_manual_code: Some(&mut manual_cb),
                        open_browser: false,
                        data_dir: &__data_dir,
                    };
                    let rt = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(rt) => rt,
                        Err(e) => {
                            let _ = __tx.send(LoginEvent::Done {
                                generation: __generation,
                                provider: __provider.clone(),
                                result: Err(format!("cannot start runtime: {e}")),
                            });
                            return;
                        }
                    };
                    let result =
                        rt.block_on(freedas_provider::oauth::run_login(&__provider, &mut host));
                    let stored = if __cancel.load(Ordering::Relaxed) {
                        Err("login cancelled".to_string())
                    } else {
                        match result {
                            Ok(freedas_provider::oauth::LoginResult::ApiKey(key)) => {
                                let stored_id =
                                    freedas_provider::oauth::credential_provider(&__provider);
                                freedas_provider::credentials::store(&__data_dir, stored_id, &key)
                                    .map_err(|e| e.to_string())
                            }
                            Ok(freedas_provider::oauth::LoginResult::OAuth(credentials)) => {
                                let stored_id =
                                    freedas_provider::oauth::credential_provider(&__provider);
                                freedas_provider::oauth::store_oauth(
                                    &__data_dir,
                                    stored_id,
                                    &credentials,
                                )
                                .map_err(|e| e.to_string())
                            }
                            Err(e) => Err(e),
                        }
                    };
                    let _ = __tx.send(LoginEvent::Done {
                        generation: __generation,
                        provider: __provider,
                        result: stored,
                    });
                }));
            }
        }};
    }

    loop {
        if relay_checked.elapsed() > Duration::from_secs(2) {
            relay_on = relay_state(&paths)["running"].as_bool().unwrap_or(false);
            relay_checked = Instant::now();
        }
        let unseen = if scroll > 0 {
            transcript.len().saturating_sub(tail_mark)
        } else {
            0
        };
        terminal.draw(|f| {
            let area = f.area();
            let content_width = area.width.max(1) as usize;
            // Mask secret login input (API keys, tokens) so shoulder-surfing
            // the TUI never reveals it; the composer keeps the real text.
            let composer_secret = pending_login_prompt
                .as_ref()
                .is_some_and(|(prompt, _)| prompt.secret);
            let composer_display = if composer_secret {
                "•".repeat(composer.text().chars().count())
            } else {
                composer.text().to_string()
            };
            let composer_height =
                (wrapped_height(&composer_display, content_width) as u16 + 2).clamp(3, 8);
            let live_thinking = live_reasoning.lock().unwrap().clone();
            let thinking_lines = if run_started.is_some() && !live_thinking.is_empty() {
                view::reasoning_lines(&live_thinking, content_width)
            } else {
                Vec::new()
            };
            let run_height = if run_started.is_some() {
                1 + thinking_lines.len() as u16
            } else {
                0
            };
            let chunks = Layout::vertical([
                Constraint::Length(1),
                Constraint::Min(1),
                Constraint::Length(run_height),
                Constraint::Length(composer_height),
                Constraint::Length(1),
            ])
            .split(area);

            view::draw_header(
                f,
                chunks[0],
                &view::header_line(
                    &project_name(&project_root),
                    &branch,
                    &agent,
                    &view::model_label(model.as_deref(), variant.as_deref()),
                    usage,
                    area.width,
                ),
            );
            let live = live_text.lock().unwrap().clone();
            let lines = transcript.display_lines(&live, content_width);
            // The pane scrolls over rendered lines, so a stale count after
            // compaction/undo must not leave a blank view.
            let max_scroll = lines
                .len()
                .saturating_sub(chunks[1].height as usize)
                .min(u16::MAX as usize) as u16;
            scroll = scroll.min(max_scroll);
            let welcome = transcript.len() == 0
                && live.is_empty()
                && run_started.is_none()
                && pending_permission.is_none();
            if welcome {
                view::draw_welcome(
                    f,
                    chunks[1],
                    &project_name(&project_root),
                    &branch,
                    at_home,
                    signed_in,
                );
            } else {
                view::draw_pane(f, chunks[1], &lines, scroll);
            }
            if let Some(started) = run_started {
                view::draw_running(
                    f,
                    Rect::new(chunks[2].x, chunks[2].y, chunks[2].width, 1),
                    &view::running_line(&activity, started.elapsed(), queue.len()),
                );
                if !thinking_lines.is_empty() {
                    view::draw_thinking(
                        f,
                        Rect::new(
                            chunks[2].x,
                            chunks[2].y + 1,
                            chunks[2].width,
                            thinking_lines.len() as u16,
                        ),
                        thinking_lines,
                    );
                }
            }
            let composer_rows = chunks[3].height.saturating_sub(1);
            let (cursor_row, cursor_col) =
                cursor_row_col(&composer_display, composer.cursor(), content_width);
            let composer_scroll =
                (cursor_row as u16).saturating_sub(composer_rows.saturating_sub(1));
            let inner = view::draw_composer(
                f,
                chunks[3],
                &composer_display,
                "Ask anything, / for commands",
                composer_scroll,
            );

            // Composer completion lists, filtered from what is typed so far.
            let draft = composer.text();
            if draft != last_completion_draft.as_str() {
                last_completion_draft = draft.to_string();
                slash_selected = 0;
                file_selected = 0;
            }
            let completions = pending_login.is_none() && pending_sync.is_none();
            let slash_picks = popup::slash_query(draft)
                .filter(|_| completions && slash_dismissed.as_deref() != Some(draft))
                .map(|query| popup::rank(query, &slash_items, popup::MENU_ROWS))
                .filter(|picks| !picks.is_empty());
            let file_picks = popup::at_token(draft, composer.cursor())
                .filter(|_| completions && file_dismissed.as_deref() != Some(draft))
                .map(|(_, _, query)| popup::rank(&query, &file_items, popup::MENU_ROWS))
                .filter(|picks| !picks.is_empty());
            if let Some(picks) = &slash_picks {
                popup::draw_completion(f, chunks[3], &slash_items, picks, slash_selected);
            } else if let Some(picks) = &file_picks {
                popup::draw_completion(f, chunks[3], &file_items, picks, file_selected);
            }
            if let Some(active) = &picker {
                popup::draw_picker(f, area, active);
            }

            let state = FooterState {
                permission: pending_permission.is_some(),
                shortcuts: shortcuts_open,
                help: help_open,
                search: search.is_some(),
                transcript: transcript_open,
                login: pending_login.is_some(),
                sync: pending_sync.is_some(),
                running: run_started.is_some(),
                picker: picker.is_some(),
                slash: slash_picks.is_some(),
                file: file_picks.is_some(),
                quit_armed: quit_armed.map(|t| t.elapsed() < ARMED).unwrap_or(false),
                esc_armed: esc_armed.map(|t| t.elapsed() < ARMED).unwrap_or(false),
                draft: !composer.is_empty(),
                unseen,
            };
            view::draw_footer(
                f,
                chunks[4],
                &view::footer_hint(&state),
                &view::status_right(
                    current_session.as_deref(),
                    auto,
                    manual,
                    cfg.sandbox.mode == "on",
                    relay_on,
                    context_pct,
                    area.width,
                ),
            );

            let overlay = pending_permission.is_some()
                || shortcuts_open
                || help_open
                || search.is_some()
                || transcript_open
                || picker.is_some()
                || settings.is_some();
            if !overlay {
                f.set_cursor_position((
                    inner.x + (cursor_col as u16).min(inner.width.saturating_sub(1)),
                    inner.y
                        + (cursor_row as u16)
                            .saturating_sub(composer_scroll)
                            .min(inner.height.saturating_sub(1)),
                ));
            }
            if let Some((action, resource, preview, _)) = &pending_permission {
                view::draw_permission(f, area, action, resource, preview.as_deref());
            }
            if shortcuts_open {
                view::draw_shortcuts(f, area);
            }
            if help_open {
                view::draw_help(f, area, &help_text, help_scroll);
            }
            if let Some((query, selected)) = &search {
                let found = search_matches(&history, query);
                view::draw_search(
                    f,
                    area,
                    query,
                    &found,
                    (*selected).min(found.len().saturating_sub(1)),
                );
            }
            if transcript_open {
                let overlay =
                    transcript.display_lines(&live, (area.width.saturating_sub(2)).max(1) as usize);
                view::draw_transcript_overlay(f, area, &overlay, transcript_scroll);
            }
            if let Some(panel) = &settings {
                view::draw_config(f, area, panel);
            }
        })?;

        // A permission request from the worker thread shows the modal.
        // Parallel-safe tools can ask twice before the next poll; queue
        // instead of collapsing to the last request.
        if let Some(rx) = &perm_rx {
            while let Ok((a, r, p, reply)) = rx.try_recv() {
                if pending_permission.is_none() {
                    pending_permission = Some((a, r, p, reply));
                    permission_shown_at = Some(Instant::now());
                } else {
                    pending_queue.push_back((a, r, p, reply));
                }
            }
        }
        // Login worker events update the transcript or park a synchronous
        // prompt reply on the composer.
        {
            let mut events = Vec::new();
            if let Some(rx) = &login_rx {
                while let Ok(event) = rx.try_recv() {
                    events.push(event);
                }
            }
            for event in events {
                match event {
                    LoginEvent::Progress {
                        generation,
                        message,
                    } if generation == login_generation => transcript.push(message),
                    LoginEvent::Auth {
                        generation,
                        url,
                        launch,
                        instructions,
                    } if generation == login_generation => {
                        if let Some(instructions) = instructions {
                            transcript.push(instructions);
                        }
                        transcript.push(format!("open: {url}"));
                        if let Some(launch) = launch {
                            transcript
                                .push(format!("if the browser does not open, visit: {launch}"));
                        }
                    }
                    LoginEvent::Prompt {
                        generation,
                        prompt,
                        reply,
                    } => {
                        if generation == login_generation {
                            let mut message = prompt.message.clone();
                            if let Some(placeholder) = &prompt.placeholder {
                                message.push_str(&format!(" [{placeholder}]"));
                            }
                            transcript.push(format!("{message} (Enter answers, Esc cancels)"));
                            // Only one login slot may be pending: a new prompt displaces
                            // any pending prompt or manual reply.
                            if let Some((_, old)) = pending_login_prompt.take() {
                                let _ = old.send(Err("login cancelled".into()));
                            }
                            if let Some(old) = pending_login_manual.take() {
                                let _ = old.send(Err("login cancelled".into()));
                            }
                            pending_login_prompt = Some((prompt, reply));
                        } else {
                            let _ = reply.send(Err("login cancelled".into()));
                        }
                    }
                    LoginEvent::Manual { generation, reply } => {
                        if generation == login_generation {
                            transcript.push(
                                "paste the redirect URL or authorization code and press Enter (Esc cancels)"
                                    .into(),
                            );
                            if let Some(old) = pending_login_manual.take() {
                                let _ = old.send(Err("login cancelled".into()));
                            }
                            if let Some((_, old)) = pending_login_prompt.take() {
                                let _ = old.send(Err("login cancelled".into()));
                            }
                            pending_login_manual = Some(reply);
                        } else {
                            let _ = reply.send(Err("login cancelled".into()));
                        }
                    }
                    LoginEvent::Done {
                        generation,
                        provider,
                        result,
                    } if generation == login_generation => {
                        pending_login = None;
                        pending_login_prompt = None;
                        pending_login_manual = None;
                        login_rx = None;
                        if let Some(handle) = login_worker.take() {
                            let _ = handle.join();
                        }
                        match result {
                            Ok(()) => transcript.push(format!("stored credential for {provider}")),
                            Err(e) => transcript.push_error(format!("login failed: {e}")),
                        }
                    }
                    LoginEvent::Done { generation, .. }
                        if generation != login_generation && pending_login.is_none() =>
                    {
                        login_rx = None;
                        if let Some(handle) = login_worker.take() {
                            let _ = handle.join();
                        }
                    }
                    _ => {}
                }
            }
            if pending_login.is_some()
                && login_worker
                    .as_ref()
                    .is_some_and(|handle| handle.is_finished())
                && login_rx.is_some()
            {
                pending_login = None;
                pending_login_prompt = None;
                pending_login_manual = None;
                login_rx = None;
                if let Some(handle) = login_worker.take() {
                    let _ = handle.join();
                }
                transcript.push_error("login failed: worker stopped".into());
            }
        }
        // Drain streamed markers: `\u{1}name` starts a tool card, `\u{2}<json>`
        // completes it with status, output, and diff.
        {
            let mut events = live_events.lock().unwrap();
            for marker in events.drain(..) {
                if let Some(json) = marker.strip_prefix('\u{2}') {
                    let event: serde_json::Value =
                        serde_json::from_str(json).unwrap_or(serde_json::Value::Null);
                    transcript.complete_tool(
                        event["tool"].as_str().unwrap_or("tool"),
                        event["ok"].as_bool().unwrap_or(true),
                        event["output"].as_str().unwrap_or(""),
                        event["diff"].as_str().map(str::to_string),
                    );
                } else {
                    activity = marker.clone();
                    transcript.push_tool(cell::Tool::running(marker));
                }
            }
        }
        let finished = match pending.as_ref().map(|rx| rx.try_recv()) {
            None => None,
            Some(Ok(out)) => Some(Some(out)),
            Some(Err(mpsc::TryRecvError::Empty)) => None,
            Some(Err(mpsc::TryRecvError::Disconnected)) => Some(None),
        };
        if let Some(outcome) = finished {
            pending = None;
            if let Some(handle) = worker.take() {
                let _ = handle.join();
            }
            let interrupted = cancel.as_ref().map(|t| t.is_cancelled()).unwrap_or(false);
            cancel = None;
            run_started = None;
            activity = String::from("Working");
            live_text.lock().unwrap().clear();
            live_reasoning.lock().unwrap().clear();
            let mut completed = false;
            match outcome {
                Some(Outcome::Done(result)) => {
                    completed = !interrupted;
                    let text = if result.text.is_empty() {
                        "(no text output)".to_string()
                    } else {
                        result.text
                    };
                    transcript.push_assistant(text);
                    current_session = Some(result.session_id);
                    if show_thinking {
                        for p in db.list_parts(&result.message_id).unwrap_or_default() {
                            if p.kind == "reasoning" {
                                let text = serde_json::from_str::<serde_json::Value>(&p.data)
                                    .ok()
                                    .and_then(|v| v["text"].as_str().map(str::to_string))
                                    .unwrap_or_default();
                                if !text.is_empty() {
                                    transcript.push_reasoning(text);
                                }
                            }
                        }
                    }
                    last_message = Some(result.message_id);
                    let marker = project_root.join(".freedas").join(".sync-offered");
                    if !marker.exists() {
                        let entries = freedas_sync::detect(&project_root);
                        if !entries.is_empty() {
                            let _ =
                                std::fs::create_dir_all(marker.parent().unwrap_or(&project_root));
                            let _ = std::fs::write(&marker, "1");
                            transcript.push(format!(
                                "import setup from other agents? {} sources — Enter imports, Esc cancels",
                                entries.len()
                            ));
                            pending_sync = Some((project_root.clone(), entries));
                        }
                    }
                }
                Some(Outcome::Permission { .. }) => {
                    // With an approver wired, runner-level asks are answered
                    // inline; this arm only fires for the repeated-fail loop.
                    transcript.push("run needs permission (re-run with --auto or --manual)".into());
                }
                Some(Outcome::Failed(e)) if e == "cancelled" => {}
                Some(Outcome::Failed(e)) => transcript.push_error(format!("error: {e}")),
                None => transcript.push("run ended without a result".to_string()),
            }
            if interrupted {
                transcript.push("· interrupted".to_string());
            }
            usage = usage_of(&db, &project_id);
            context_pct = context_used_pct(&db, current_session.as_deref());
            // A failed or interrupted run must not consume the queue: keep the
            // order and let the next successful run drain it.
            if !completed && !queue.is_empty() {
                transcript.push(format!("· {} queued prompt(s) kept", queue.len()));
            } else if let Some((_, next)) = queue.pop_front() {
                if history.last() != Some(&next) {
                    history.push(next.clone());
                }
                last_prompt = Some(next.clone());
                transcript.push_user(next.clone());
                run_prompt!(next, auto);
            }
        }
        // Background tasks keep rename/compact/undo/redo/credits/orgs/review
        // off the event loop so the TUI stays responsive. Workers do the
        // blocking work on their own runtime; the UI applies the result.
        if let Some(rx) = bg_pending.as_ref() {
            match rx.try_recv() {
                Ok(done) => {
                    bg_pending = None;
                    if let Some(handle) = bg_worker.take() {
                        let _ = handle.join();
                    }
                    match done {
                        BgDone::RenameTitle { sid, result } => match result {
                            Ok(title) => transcript.push(format!("renamed {sid} → {title}")),
                            Err(e) => transcript.push(format!("rename failed: {e}")),
                        },
                        BgDone::Compact(result) => match result {
                            Ok(summary) => {
                                let kept =
                                    transcript.split_off(transcript.len().saturating_sub(20));
                                let mut fresh = Transcript::new();
                                fresh.push(
                                    "[context compacted — older turns summarized]".to_string(),
                                );
                                fresh.extend(kept);
                                transcript = fresh;
                                transcript.push(summary);
                            }
                            Err(e) => transcript.push(format!("compact failed: {e}")),
                        },
                        BgDone::Undo(result) => match result {
                            Ok(sha) => {
                                transcript.truncate_user_tail();
                                last_message = None;
                                context_pct = context_used_pct(&db, current_session.as_deref());
                                tail_mark = transcript.len();
                                transcript.push(format!("undone: restored {sha}"));
                            }
                            Err(e) => transcript.push(format!("undo failed: {e}")),
                        },
                        BgDone::Redo(result) => match result {
                            Ok(sha) => transcript.push(format!("redo: restored {sha}")),
                            Err(e) => transcript.push(format!("redo failed: {e}")),
                        },
                        BgDone::Credits(result) => match result {
                            Ok(v) => transcript.push(format!(
                                "balance ${:.2} ({})",
                                v["balanceUsd"].as_f64().unwrap_or(0.0),
                                v["workspaceId"].as_str().unwrap_or("")
                            )),
                            Err(e) => transcript.push(format!("credits: {e}")),
                        },
                        BgDone::Orgs(result) => match result {
                            Ok(v) => {
                                let selected =
                                    cfg.workspace.clone().unwrap_or_else(|| "personal".into());
                                let _ = freedas_provider::credentials::cache_org_settings(
                                    &paths, &v, &selected,
                                );
                                let orgs = v
                                    .as_array()
                                    .cloned()
                                    .unwrap_or_default()
                                    .into_iter()
                                    .filter(|w| w["kind"].as_str() == Some("organization"))
                                    .collect::<Vec<_>>();
                                if orgs.is_empty() {
                                    transcript.push("no organizations".into());
                                }
                                for w in orgs {
                                    transcript.push(format!(
                                        "· {} {}",
                                        w["slug"].as_str().unwrap_or(""),
                                        w["name"].as_str().unwrap_or("")
                                    ));
                                }
                            }
                            Err(e) => transcript.push(format!("org: {e}")),
                        },
                        BgDone::Review(result) => match result {
                            Ok(review) => {
                                transcript
                                    .push(format!("review: {} findings", review.findings.len()));
                                for f in review.findings {
                                    transcript.push(format!(
                                        "  {}:{} {} {} — {}",
                                        f.file, f.line, f.severity, f.title, f.body
                                    ));
                                }
                            }
                            Err(e) => transcript.push(format!("review failed: {e}")),
                        },
                    }
                    usage = usage_of(&db, &project_id);
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    bg_pending = None;
                    if let Some(handle) = bg_worker.take() {
                        let _ = handle.join();
                    }
                    transcript.push_error("background task ended without a result".into());
                }
            }
        }
        if event::poll(Duration::from_millis(50))? {
            match event::read()? {
                Event::Paste(text) => {
                    if pending_permission.is_none()
                        && !shortcuts_open
                        && !help_open
                        && search.is_none()
                        && !transcript_open
                        && picker.is_none()
                        && settings.is_none()
                    {
                        composer.insert_str(&text);
                    }
                }
                Event::Mouse(mouse) => match mouse.kind {
                    MouseEventKind::ScrollUp
                        if pending_permission.is_none()
                            && !shortcuts_open
                            && !help_open
                            && search.is_none()
                            && picker.is_none()
                            && settings.is_none() =>
                    {
                        if transcript_open {
                            transcript_scroll = transcript_scroll.saturating_add(3);
                        } else {
                            scroll = scroll.saturating_add(3);
                        }
                    }
                    MouseEventKind::ScrollDown
                        if pending_permission.is_none()
                            && !shortcuts_open
                            && !help_open
                            && search.is_none()
                            && picker.is_none()
                            && settings.is_none() =>
                    {
                        if transcript_open {
                            transcript_scroll = transcript_scroll.saturating_sub(3);
                        } else {
                            scroll = scroll.saturating_sub(3);
                        }
                    }
                    _ => {}
                },
                Event::Key(key) => {
                    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
                    let running = run_started.is_some();
                    // One modal owns the keyboard; precedence, top first:
                    // permission, config panel, help, shortcuts, search,
                    // transcript, picker. Each branch consumes its key, so a
                    // second overlay can only open from the composer.
                    // Unrelated activity disarms the Ctrl+C quit and Esc recall
                    // timers; only a repeat of the same key counts.
                    if key.code != KeyCode::Esc && !(ctrl && key.code == KeyCode::Char('c')) {
                        quit_armed = None;
                        esc_armed = None;
                    }

                    if ctrl && key.code == KeyCode::Char('d') {
                        break;
                    }

                    if let Some((action, resource, preview, reply)) = pending_permission.take() {
                        // Ctrl+C cancels the run and fails the ask closed, so a
                        // later allow cannot execute after the cancel.
                        if ctrl && key.code == KeyCode::Char('c') {
                            let _ = reply.send(freedas_tools::PermissionReply::Reject);
                            for (_, _, _, queued) in pending_queue.drain(..) {
                                let _ = queued.send(freedas_tools::PermissionReply::Reject);
                            }
                            permission_shown_at = None;
                            if let Some(token) = &cancel {
                                token.cancel();
                            }
                            activity = "interrupting".to_string();
                            transcript.push(format!("cancelled: {action} {resource}"));
                            continue;
                        }
                        // Ignore a/A/d (and 1/2/3 aliases) within ~300ms of the
                        // modal appearing; the keypress likely predates it.
                        let fresh = permission_shown_at
                            .is_some_and(|t| t.elapsed() < Duration::from_millis(300));
                        let is_decision = matches!(
                            key.code,
                            KeyCode::Char('a')
                                | KeyCode::Char('A')
                                | KeyCode::Char('d')
                                | KeyCode::Char('1')
                                | KeyCode::Char('2')
                                | KeyCode::Char('3')
                        );
                        if fresh && is_decision && !ctrl {
                            pending_permission = Some((action, resource, preview, reply));
                            continue;
                        }
                        let answer = match key.code {
                            KeyCode::Char('a') | KeyCode::Char('1') => {
                                Some(freedas_tools::PermissionReply::Once)
                            }
                            KeyCode::Char('A') | KeyCode::Char('2') => {
                                Some(freedas_tools::PermissionReply::Always)
                            }
                            KeyCode::Char('d') | KeyCode::Char('3') => {
                                Some(freedas_tools::PermissionReply::Reject)
                            }
                            KeyCode::Esc => Some(freedas_tools::PermissionReply::Reject),
                            _ => None,
                        };
                        match answer {
                            Some(freedas_tools::PermissionReply::Reject) => {
                                let _ = reply.send(freedas_tools::PermissionReply::Reject);
                                for (_, _, _, queued) in pending_queue.drain(..) {
                                    let _ = queued.send(freedas_tools::PermissionReply::Reject);
                                }
                                permission_shown_at = None;
                                transcript.push(format!("denied: {action} {resource}"));
                            }
                            Some(answer) => {
                                let _ = reply.send(answer);
                                if let Some(next) = pending_queue.pop_front() {
                                    pending_permission = Some(next);
                                    permission_shown_at = Some(Instant::now());
                                } else {
                                    permission_shown_at = None;
                                }
                            }
                            None => pending_permission = Some((action, resource, preview, reply)),
                        }
                        continue;
                    }

                    if ctrl && key.code == KeyCode::Char('c') {
                        let armed = quit_armed.map(|t| t.elapsed() < ARMED).unwrap_or(false);
                        if running {
                            if let Some(token) = &cancel {
                                token.cancel();
                            }
                            activity = "interrupting".to_string();
                            quit_armed = None;
                        } else if !composer.is_empty() {
                            composer.clear();
                            quit_armed = None;
                        } else if armed {
                            break;
                        } else {
                            quit_armed = Some(Instant::now());
                        }
                        continue;
                    }

                    if settings.is_some() {
                        // Esc leaves search/edit first; from the list it closes.
                        let back = settings
                            .as_ref()
                            .is_some_and(|panel| panel.editing.is_some() || panel.searching);
                        if key.code == KeyCode::Esc && !back {
                            settings = None;
                            continue;
                        }
                        let panel = settings.as_mut().expect("checked above");
                        if let Some((path, mut buffer)) = panel.editing.clone() {
                            match key.code {
                                KeyCode::Esc => panel.editing = None,
                                KeyCode::Enter => {
                                    let row = panel.rows.iter().find(|r| r.path == path).cloned();
                                    let Some(row) = row else {
                                        panel.editing = None;
                                        continue;
                                    };
                                    let text = buffer.trim().to_string();
                                    let value = match row.kind {
                                        config_panel::Kind::Number
                                            if row.value.is_i64() || row.value.is_u64() =>
                                        {
                                            match text.parse::<i64>() {
                                                Ok(n) => serde_json::json!(n),
                                                Err(_) => {
                                                    panel.notice = Some((
                                                        format!("not a number: {text}"),
                                                        Instant::now(),
                                                    ));
                                                    continue;
                                                }
                                            }
                                        }
                                        config_panel::Kind::Number => match text.parse::<f64>() {
                                            Ok(n) => serde_json::json!(n),
                                            Err(_) => {
                                                panel.notice = Some((
                                                    format!("not a number: {text}"),
                                                    Instant::now(),
                                                ));
                                                continue;
                                            }
                                        },
                                        config_panel::Kind::List => serde_json::json!(
                                            text.split(',')
                                                .map(str::trim)
                                                .filter(|item| !item.is_empty())
                                                .collect::<Vec<_>>()
                                        ),
                                        _ => serde_json::json!(text),
                                    };
                                    if apply_setting(
                                        &mut cfg,
                                        &mut runner,
                                        panel,
                                        &paths,
                                        &db,
                                        &path,
                                        value,
                                    ) {
                                        commands =
                                            discover_commands(&project_root, &paths, &cfg.skills);
                                        slash_items = slash_rows(&commands);
                                        help_text = help_lines(&commands);
                                        file_items = project_file_rows(&project_root);
                                    }
                                }
                                KeyCode::Backspace => {
                                    buffer.pop();
                                    panel.editing = Some((path, buffer));
                                }
                                KeyCode::Char(c) if !ctrl => {
                                    buffer.push(c);
                                    panel.editing = Some((path, buffer));
                                }
                                _ => {}
                            }
                            continue;
                        }
                        if panel.searching {
                            match key.code {
                                KeyCode::Esc => {
                                    panel.searching = false;
                                    panel.query.clear();
                                    panel.selected = 0;
                                }
                                KeyCode::Enter => panel.searching = false,
                                KeyCode::Up => panel.move_by(-1),
                                KeyCode::Down => panel.move_by(1),
                                KeyCode::Backspace => {
                                    panel.query.pop();
                                    panel.selected = 0;
                                }
                                KeyCode::Char(c) if !ctrl => {
                                    panel.query.push(c);
                                    panel.selected = 0;
                                }
                                _ => {}
                            }
                            continue;
                        }
                        match key.code {
                            KeyCode::Char('/') => panel.searching = true,
                            KeyCode::Up => panel.move_by(-1),
                            KeyCode::Down => panel.move_by(1),
                            KeyCode::PageUp => panel.move_by(-8),
                            KeyCode::PageDown => panel.move_by(8),
                            KeyCode::Home => panel.select(0),
                            KeyCode::End => panel.select(usize::MAX),
                            KeyCode::Enter => {
                                let Some(row) = panel.selected_row() else {
                                    continue;
                                };
                                match row.kind {
                                    config_panel::Kind::ReadOnly => {
                                        panel.notice = Some((
                                            "edit rules in freedas.json".to_string(),
                                            Instant::now(),
                                        ));
                                    }
                                    config_panel::Kind::Bool => {
                                        let value = serde_json::Value::Bool(
                                            !row.value.as_bool().unwrap_or(false),
                                        );
                                        if apply_setting(
                                            &mut cfg,
                                            &mut runner,
                                            panel,
                                            &paths,
                                            &db,
                                            &row.path,
                                            value,
                                        ) {
                                            commands = discover_commands(
                                                &project_root,
                                                &paths,
                                                &cfg.skills,
                                            );
                                            slash_items = slash_rows(&commands);
                                            help_text = help_lines(&commands);
                                            file_items = project_file_rows(&project_root);
                                        }
                                    }
                                    _ => {
                                        panel.editing =
                                            Some((row.path.clone(), config_panel::edit_text(&row)));
                                    }
                                }
                            }
                            _ => {}
                        }
                        continue;
                    }

                    if help_open {
                        match key.code {
                            KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q') => {
                                help_open = false;
                            }
                            KeyCode::PageUp | KeyCode::Up => {
                                help_scroll = help_scroll.saturating_sub(5)
                            }
                            KeyCode::PageDown | KeyCode::Down => {
                                help_scroll = help_scroll.saturating_add(5)
                            }
                            KeyCode::Home => help_scroll = 0,
                            KeyCode::End => help_scroll = u16::MAX,
                            _ => {}
                        }
                        continue;
                    }

                    if shortcuts_open {
                        if key.code == KeyCode::Esc || key.code == KeyCode::Char('?') {
                            shortcuts_open = false;
                        }
                        continue;
                    }

                    if let Some((query, selected)) = search.clone() {
                        let mut query = query;
                        let mut selected = selected;
                        let mut keep = true;
                        match key.code {
                            KeyCode::Esc => keep = false,
                            KeyCode::Enter => {
                                if let Some(m) = search_matches(&history, &query).get(selected) {
                                    composer.set(m.clone());
                                }
                                keep = false;
                            }
                            KeyCode::Up => selected = selected.saturating_sub(1),
                            KeyCode::Down => {
                                selected = (selected + 1)
                                    .min(search_matches(&history, &query).len().saturating_sub(1));
                            }
                            KeyCode::Backspace => {
                                query.pop();
                                selected = 0;
                            }
                            KeyCode::Char(c) if !ctrl => {
                                query.push(c);
                                selected = 0;
                            }
                            _ => {}
                        }
                        if keep {
                            search = Some((query, selected));
                        }
                        continue;
                    }

                    if transcript_open {
                        if key.code == KeyCode::Esc || (ctrl && key.code == KeyCode::Char('t')) {
                            transcript_open = false;
                            transcript_scroll = 0;
                            continue;
                        }
                        match key.code {
                            KeyCode::PageUp => {
                                transcript_scroll = transcript_scroll.saturating_add(5)
                            }
                            KeyCode::PageDown => {
                                transcript_scroll = transcript_scroll.saturating_sub(5)
                            }
                            KeyCode::Home => transcript_scroll = u16::MAX,
                            KeyCode::End => transcript_scroll = 0,
                            _ => {}
                        }
                        continue;
                    }

                    // Ctrl+K/L/O/M pickers: type to filter, Enter selects.
                    if let Some(active) = picker.as_mut() {
                        let mut close = false;
                        match key.code {
                            KeyCode::Esc => close = true,
                            KeyCode::Tab | KeyCode::BackTab => {
                                // Only the Models picker uses Tab: it cycles
                                // the selected model's reasoning level.
                                if active.kind == popup::Kind::Models {
                                    active.cycle_variant(key.code == KeyCode::BackTab);
                                }
                            }
                            KeyCode::Enter => {
                                let chosen = active.chosen().map(|row| {
                                    (
                                        active.kind,
                                        row.value.clone(),
                                        active.variant_label().map(|s| s.to_string()),
                                    )
                                });
                                match chosen {
                                    Some((popup::Kind::Sessions, id, _)) => {
                                        current_session = Some(id.clone());
                                        last_message =
                                            load_session(&db, &mut transcript, &id, show_thinking);
                                        context_pct = context_used_pct(&db, Some(id.as_str()));
                                        scroll = 0;
                                        tail_mark = transcript.len();
                                        history_pos = None;
                                        let dropped =
                                            drop_queued_for_session(&mut queue, Some(id.as_str()));
                                        if dropped > 0 {
                                            transcript.push(format!(
                                                "· dropped {dropped} queued prompt(s) for previous session"
                                            ));
                                        }
                                        transcript.push(format!("session → {id}"));
                                    }
                                    Some((popup::Kind::Models, id, picked_variant)) => {
                                        let mut failed = false;
                                        match save_setting(&paths, "model", serde_json::json!(id)) {
                                            Ok(next) => {
                                                reload_into(
                                                    &mut cfg,
                                                    &mut runner,
                                                    &paths,
                                                    &db,
                                                    next,
                                                );
                                                model = Some(id.clone());
                                            }
                                            Err(e) => {
                                                transcript.push(format!("model not saved: {e}"));
                                                failed = true;
                                            }
                                        }
                                        if !failed {
                                            if let Some(v) = picked_variant.clone() {
                                                match save_setting(
                                                    &paths,
                                                    "variant",
                                                    serde_json::json!(v),
                                                ) {
                                                    Ok(next) => {
                                                        reload_into(
                                                            &mut cfg,
                                                            &mut runner,
                                                            &paths,
                                                            &db,
                                                            next,
                                                        );
                                                        variant = Some(v);
                                                    }
                                                    Err(e) => {
                                                        transcript.push(format!(
                                                            "variant not saved: {e}"
                                                        ));
                                                        failed = true;
                                                    }
                                                }
                                            } else {
                                                variant = None;
                                            }
                                        }
                                        if !failed {
                                            let suffix = picked_variant
                                                .map(|v| format!(" ({v})"))
                                                .unwrap_or_default();
                                            transcript.push(format!("model → {id}{suffix}"));
                                        }
                                    }
                                    Some((popup::Kind::Agents, id, _)) => {
                                        agent = id.clone();
                                        transcript.push(format!("agent → {id}"));
                                    }
                                    Some((popup::Kind::Mcp, name, _)) => {
                                        toggle_mcp(&mut disabled_mcps, &name);
                                        transcript.push(format!(
                                            "mcp {name}: {}",
                                            if disabled_mcps.iter().any(|d| d == &name) {
                                                "off"
                                            } else {
                                                "on"
                                            }
                                        ));
                                    }
                                    Some((popup::Kind::Permissions, mode, _)) => {
                                        if let Some(next_mode) = PermissionMode::parse(&mode) {
                                            match save_setting(
                                                &paths,
                                                "permission_mode",
                                                serde_json::json!(next_mode.as_str()),
                                            ) {
                                                Ok(next) => {
                                                    reload_into(
                                                        &mut cfg,
                                                        &mut runner,
                                                        &paths,
                                                        &db,
                                                        next,
                                                    );
                                                    let (a, m) = next_mode.flags();
                                                    auto = a;
                                                    manual = m;
                                                    transcript.push(format!(
                                                        "permissions → {}",
                                                        next_mode.as_str()
                                                    ));
                                                }
                                                Err(e) => transcript
                                                    .push(format!("permissions not saved: {e}")),
                                            }
                                        }
                                    }
                                    None => {}
                                }
                                close = true;
                            }
                            KeyCode::Up => {
                                active.selected = active.selected.saturating_sub(1);
                                active.follow(variant.as_deref());
                            }
                            KeyCode::Down => {
                                active.selected = (active.selected + 1)
                                    .min(active.picks().len().saturating_sub(1));
                                active.follow(variant.as_deref());
                            }
                            KeyCode::Backspace => {
                                active.filter.pop();
                                active.selected = 0;
                                active.follow(variant.as_deref());
                            }
                            KeyCode::Char(c) if !ctrl => {
                                active.filter.push(c);
                                active.selected = 0;
                                active.follow(variant.as_deref());
                            }
                            _ => {}
                        }
                        if close {
                            picker = None;
                        }
                        continue;
                    }

                    if ctrl && key.code == KeyCode::Char('t') {
                        transcript_open = true;
                        transcript_scroll = 0;
                        continue;
                    }
                    if ctrl && key.code == KeyCode::Char('r') {
                        search = Some((String::new(), 0));
                        continue;
                    }
                    if key.code == KeyCode::Char('?') && composer.is_empty() && !ctrl {
                        shortcuts_open = true;
                        continue;
                    }

                    // Composer completions: Enter/Tab accept, Esc dismisses and
                    // keeps the text, Up/Down move. Enter here never submits.
                    if pending_login.is_none() && pending_sync.is_none() {
                        let draft = composer.text().to_string();
                        if draft != last_completion_draft {
                            last_completion_draft = draft.clone();
                            slash_selected = 0;
                            file_selected = 0;
                        }
                        let slash = popup::slash_query(&draft)
                            .filter(|_| slash_dismissed.as_deref() != Some(draft.as_str()))
                            .map(|query| popup::rank(query, &slash_items, popup::MENU_ROWS))
                            .filter(|picks| !picks.is_empty());
                        let file = popup::at_token(&draft, composer.cursor())
                            .filter(|_| file_dismissed.as_deref() != Some(draft.as_str()))
                            .map(|(_, _, query)| popup::rank(&query, &file_items, popup::MENU_ROWS))
                            .filter(|picks| !picks.is_empty());
                        if slash.is_some() || file.is_some() {
                            match key.code {
                                KeyCode::Esc => {
                                    slash_dismissed = Some(draft);
                                    file_dismissed = Some(composer.text().to_string());
                                    continue;
                                }
                                KeyCode::Up => {
                                    if slash.is_some() {
                                        slash_selected = slash_selected.saturating_sub(1);
                                    } else {
                                        file_selected = file_selected.saturating_sub(1);
                                    }
                                    continue;
                                }
                                KeyCode::Down => {
                                    if let Some(picks) = &slash {
                                        slash_selected =
                                            (slash_selected + 1).min(picks.len().saturating_sub(1));
                                    } else if let Some(picks) = &file {
                                        file_selected =
                                            (file_selected + 1).min(picks.len().saturating_sub(1));
                                    }
                                    continue;
                                }
                                KeyCode::Tab | KeyCode::Enter => {
                                    if let Some(picks) = slash {
                                        let pick = picks[popup::clamp(&picks, slash_selected)];
                                        composer.set(format!("/{} ", slash_items[pick].value));
                                    } else if let Some(picks) = file {
                                        let pick = picks[popup::clamp(&picks, file_selected)];
                                        if let Some((start, end, _)) =
                                            popup::at_token(&draft, composer.cursor())
                                        {
                                            composer.replace_range(
                                                start,
                                                end,
                                                &format!("@{} ", file_items[pick].value),
                                            );
                                        }
                                    }
                                    continue;
                                }
                                _ => {}
                            }
                        }
                    }

                    match key.code {
                        KeyCode::Enter => {
                            if key.modifiers.contains(KeyModifiers::SHIFT) {
                                composer.newline();
                                continue;
                            }
                            if let Some((root, entries)) = pending_sync.take() {
                                match freedas_sync::apply_plan(&root, &entries) {
                                    Ok((applied, skipped)) => transcript.push(format!(
                                        "sync: {applied} imported, {skipped} unchanged"
                                    )),
                                    Err(e) => transcript.push(format!("sync failed: {e}")),
                                }
                                continue;
                            }
                            if let Some((prompt, reply)) = pending_login_prompt.take() {
                                let answer = composer.take_trimmed();
                                let result = if answer.is_empty() && !prompt.allow_empty {
                                    Err("login cancelled".to_string())
                                } else {
                                    Ok(answer)
                                };
                                let _ = reply.send(result);
                                continue;
                            }
                            if let Some(reply) = pending_login_manual.take() {
                                let answer = composer.take_trimmed();
                                let result = if answer.is_empty() {
                                    Err("login cancelled".to_string())
                                } else {
                                    Ok(answer)
                                };
                                let _ = reply.send(result);
                                continue;
                            }
                            if let Some(provider) = pending_login.clone() {
                                if login_rx.is_none() {
                                    // Legacy paste path for the gateway and
                                    // providers outside the login table.
                                    let key = composer.take_trimmed();
                                    if !key.is_empty() {
                                        match freedas_provider::credentials::store(
                                            &paths.data_dir,
                                            &provider,
                                            &key,
                                        ) {
                                            Ok(()) => transcript
                                                .push(format!("stored credential for {provider}")),
                                            Err(e) => transcript.push(format!("login failed: {e}")),
                                        }
                                    }
                                    pending_login = None;
                                } else {
                                    transcript.push("login in progress…".into());
                                }
                                continue;
                            }
                            if running {
                                let draft = composer.text().trim().to_string();
                                if draft.is_empty() {
                                    continue;
                                }
                                // Slash commands are parsed by this arm, not by
                                // the runner, so queuing one would send it to the
                                // model as text.
                                if draft.starts_with('/') {
                                    transcript.push(format!(
                                        "· {draft} waits for the current run — press Enter then"
                                    ));
                                    continue;
                                }
                                let queued = composer.take_trimmed();
                                transcript.push(format!("· queued ({}) {queued}", queue.len() + 1));
                                queue.push_back((current_session.clone(), queued));
                                continue;
                            }
                            let prompt = composer.take_trimmed();
                            if prompt.is_empty() {
                                continue;
                            }
                            quit_armed = None;
                            esc_armed = None;
                            if history.last() != Some(&prompt) {
                                history.push(prompt.clone());
                            }
                            history_pos = None;
                            scroll = 0;
                            tail_mark = transcript.len();
                            last_prompt = Some(prompt.clone());
                            if let Some(cmd) = prompt.strip_prefix('/') {
                                let (name, args) = cmd
                                    .split_once(' ')
                                    .map(|(n, a)| (n, a.trim()))
                                    .unwrap_or((cmd, ""));
                                match name {
                                    "help" => {
                                        help_open = true;
                                        help_scroll = 0;
                                    }
                                    "config" => {
                                        settings = Some(config_panel::Panel::new(&cfg));
                                    }
                                    "new" | "clear" => {
                                        current_session = None;
                                        last_message = None;
                                        context_pct = None;
                                        transcript.clear();
                                        scroll = 0;
                                        tail_mark = 0;
                                        history_pos = None;
                                        let dropped = drop_queued_for_session(&mut queue, None);
                                        if dropped > 0 {
                                            transcript.push(format!(
                                                "· dropped {dropped} queued prompt(s) for previous session"
                                            ));
                                        }
                                        transcript.push("new session".into());
                                    }
                                    "sessions" | "resume" | "continue" => {
                                        let sessions =
                                            db.list_sessions(&project_id, 20).unwrap_or_default();
                                        let mut it = args.split_whitespace();
                                        let verb = it.next().unwrap_or("");
                                        let target = it.next().unwrap_or("");
                                        if args.is_empty() {
                                            for s in sessions {
                                                transcript.push(format!(
                                                    "· {} [{}] {}",
                                                    s.id, s.agent, s.title
                                                ));
                                            }
                                            transcript.push(
                                        "tip: /sessions <id> resumes · /sessions fork|delete|export <id>"
                                            .into(),
                                    );
                                        } else if sessions.iter().any(|s| s.id == args) {
                                            current_session = Some(args.to_string());
                                            last_message = load_session(
                                                &db,
                                                &mut transcript,
                                                args,
                                                show_thinking,
                                            );
                                            context_pct = context_used_pct(&db, Some(args));
                                            scroll = 0;
                                            tail_mark = transcript.len();
                                            history_pos = None;
                                            let dropped =
                                                drop_queued_for_session(&mut queue, Some(args));
                                            if dropped > 0 {
                                                transcript.push(format!(
                                                    "· dropped {dropped} queued prompt(s) for previous session"
                                                ));
                                            }
                                            transcript.push(format!("session → {args}"));
                                        } else if sessions.iter().any(|s| s.id == target) {
                                            match verb {
                                                "fork" => {
                                                    match db.fork_session(&project_id, target, None)
                                                    {
                                                        Ok(new) => {
                                                            last_message = load_session(
                                                                &db,
                                                                &mut transcript,
                                                                &new,
                                                                show_thinking,
                                                            );
                                                            context_pct = context_used_pct(
                                                                &db,
                                                                Some(new.as_str()),
                                                            );
                                                            scroll = 0;
                                                            tail_mark = transcript.len();
                                                            history_pos = None;
                                                            current_session = Some(new.clone());
                                                            let dropped = drop_queued_for_session(
                                                                &mut queue,
                                                                Some(new.as_str()),
                                                            );
                                                            if dropped > 0 {
                                                                transcript.push(format!(
                                                                    "· dropped {dropped} queued prompt(s) for previous session"
                                                                ));
                                                            }
                                                            transcript
                                                                .push(format!("forked → {new}"));
                                                        }
                                                        Err(e) => transcript
                                                            .push(format!("fork failed: {e}")),
                                                    }
                                                }
                                                "delete" => match db.delete_session(target) {
                                                    Ok(_) => {
                                                        if current_session.as_deref()
                                                            == Some(target)
                                                        {
                                                            current_session = None;
                                                            let dropped = drop_queued_for_session(
                                                                &mut queue, None,
                                                            );
                                                            if dropped > 0 {
                                                                transcript.push(format!(
                                                                    "· dropped {dropped} queued prompt(s) for previous session"
                                                                ));
                                                            }
                                                        }
                                                        transcript
                                                            .push(format!("deleted {target}"));
                                                    }
                                                    Err(e) => transcript
                                                        .push(format!("delete failed: {e}")),
                                                },
                                                "export" => {
                                                    match freedas_db::export_session(
                                                        &db,
                                                        &paths,
                                                        &project_root,
                                                        Some(target),
                                                        false,
                                                        "json",
                                                    ) {
                                                        Ok(json) => {
                                                            let path = project_root
                                                                .join(format!("{target}.json"));
                                                            match std::fs::write(&path, json) {
                                                                Ok(()) => transcript.push(format!(
                                                                    "exported {}",
                                                                    path.display()
                                                                )),
                                                                Err(e) => transcript.push(format!(
                                                                    "export failed: {e}"
                                                                )),
                                                            }
                                                        }
                                                        Err(e) => transcript
                                                            .push(format!("export failed: {e}")),
                                                    }
                                                }
                                                _ => transcript.push(format!(
                                                    "unknown action: {verb} (fork|delete|export)"
                                                )),
                                            }
                                        } else {
                                            transcript.push(format!("unknown session: {args}"));
                                        }
                                    }
                                    "rename" => {
                                        if let Some(sid) = &current_session {
                                            if args.trim().is_empty() {
                                                if bg_pending.is_some() {
                                                    transcript.push(
                                                        "busy — background task running".into(),
                                                    );
                                                } else {
                                                    let sid2 = sid.clone();
                                                    let runner2 = runner.clone();
                                                    let (tx, rx) = mpsc::channel();
                                                    bg_pending = Some(rx);
                                                    bg_worker = Some(std::thread::spawn(
                                                        move || {
                                                            let rt2 = match tokio::runtime::Builder::new_current_thread()
                                                            .enable_all()
                                                            .build()
                                                        {
                                                            Ok(rt2) => rt2,
                                                            Err(e) => {
                                                                let _ = tx.send(BgDone::RenameTitle {
                                                                    sid: sid2,
                                                                    result: Err(format!(
                                                                        "cannot start runtime: {e}"
                                                                    )),
                                                                });
                                                                return;
                                                            }
                                                        };
                                                            let result = rt2
                                                                .block_on(
                                                                    runner2.generate_title(&sid2),
                                                                )
                                                                .map_err(|e| e.to_string());
                                                            let _ = tx.send(BgDone::RenameTitle {
                                                                sid: sid2,
                                                                result,
                                                            });
                                                        },
                                                    ));
                                                    transcript.push("renaming…".into());
                                                }
                                            } else {
                                                match db.rename_session(sid, args) {
                                                    Ok(()) => transcript
                                                        .push(format!("renamed {sid} → {args}")),
                                                    Err(e) => transcript
                                                        .push(format!("rename failed: {e}")),
                                                }
                                            }
                                        } else {
                                            transcript.push("no session".into());
                                        }
                                    }
                                    "fork" => {
                                        if let Some(sid) = &current_session {
                                            match db.fork_session(&project_id, sid, None) {
                                                Ok(id) => {
                                                    last_message = load_session(
                                                        &db,
                                                        &mut transcript,
                                                        &id,
                                                        show_thinking,
                                                    );
                                                    context_pct =
                                                        context_used_pct(&db, Some(id.as_str()));
                                                    scroll = 0;
                                                    tail_mark = transcript.len();
                                                    history_pos = None;
                                                    transcript.push(format!("forked {sid} → {id}"));
                                                    current_session = Some(id.clone());
                                                    let dropped = drop_queued_for_session(
                                                        &mut queue,
                                                        Some(id.as_str()),
                                                    );
                                                    if dropped > 0 {
                                                        transcript.push(format!(
                                                            "· dropped {dropped} queued prompt(s) for previous session"
                                                        ));
                                                    }
                                                }
                                                Err(e) => {
                                                    transcript.push(format!("fork failed: {e}"))
                                                }
                                            }
                                        } else {
                                            transcript.push("no session".into());
                                        }
                                    }
                                    "compact" | "summarize" => {
                                        if let Some(sid) = &current_session {
                                            if bg_pending.is_some() {
                                                transcript
                                                    .push("busy — background task running".into());
                                            } else {
                                                let sid2 = sid.clone();
                                                let runner2 = runner.clone();
                                                let (tx, rx) = mpsc::channel();
                                                bg_pending = Some(rx);
                                                bg_worker = Some(std::thread::spawn(move || {
                                                    let rt2 = match tokio::runtime::Builder::new_current_thread()
                                                        .enable_all()
                                                        .build()
                                                    {
                                                        Ok(rt2) => rt2,
                                                        Err(e) => {
                                                            let _ = tx.send(BgDone::Compact(Err(format!(
                                                                "cannot start runtime: {e}"
                                                            ))));
                                                            return;
                                                        }
                                                    };
                                                    let result = rt2
                                                        .block_on(runner2.compact(&sid2))
                                                        .map_err(|e| e.to_string());
                                                    let _ = tx.send(BgDone::Compact(result));
                                                }));
                                                transcript.push("compacting…".into());
                                            }
                                        } else {
                                            transcript.push("no session".into());
                                        }
                                    }
                                    "undo" => {
                                        if let (Some(sid), Some(mid)) =
                                            (&current_session, &last_message)
                                        {
                                            if bg_pending.is_some() {
                                                transcript
                                                    .push("busy — background task running".into());
                                            } else {
                                                let sid2 = sid.clone();
                                                let mid2 = mid.clone();
                                                let root2 = project_root.clone();
                                                let runner2 = runner.clone();
                                                let (tx, rx) = mpsc::channel();
                                                bg_pending = Some(rx);
                                                bg_worker = Some(std::thread::spawn(move || {
                                                    let rt2 = match tokio::runtime::Builder::new_current_thread()
                                                        .enable_all()
                                                        .build()
                                                    {
                                                        Ok(rt2) => rt2,
                                                        Err(e) => {
                                                            let _ = tx.send(BgDone::Undo(Err(format!(
                                                                "cannot start runtime: {e}"
                                                            ))));
                                                            return;
                                                        }
                                                    };
                                                    let result = rt2
                                                        .block_on(
                                                            runner2.undo(&root2, &sid2, &mid2),
                                                        )
                                                        .map_err(|e| e.to_string());
                                                    let _ = tx.send(BgDone::Undo(result));
                                                }));
                                                transcript.push("undoing…".into());
                                            }
                                        } else {
                                            transcript.push("nothing to undo".to_string());
                                        }
                                    }
                                    "redo" => {
                                        if let Some(sid) = &current_session {
                                            if bg_pending.is_some() {
                                                transcript
                                                    .push("busy — background task running".into());
                                            } else {
                                                let sid2 = sid.clone();
                                                let root2 = project_root.clone();
                                                let runner2 = runner.clone();
                                                let (tx, rx) = mpsc::channel();
                                                bg_pending = Some(rx);
                                                bg_worker = Some(std::thread::spawn(move || {
                                                    let rt2 = match tokio::runtime::Builder::new_current_thread()
                                                        .enable_all()
                                                        .build()
                                                    {
                                                        Ok(rt2) => rt2,
                                                        Err(e) => {
                                                            let _ = tx.send(BgDone::Redo(Err(format!(
                                                                "cannot start runtime: {e}"
                                                            ))));
                                                            return;
                                                        }
                                                    };
                                                    let result = rt2
                                                        .block_on(runner2.redo(&root2, &sid2))
                                                        .map_err(|e| e.to_string());
                                                    let _ = tx.send(BgDone::Redo(result));
                                                }));
                                                transcript.push("redoing…".into());
                                            }
                                        } else {
                                            transcript.push("nothing to redo".to_string());
                                        }
                                    }
                                    "export" => {
                                        if let Some(sid) = &current_session {
                                            let mut parts = args.split_whitespace();
                                            let fmt = parts.next().unwrap_or("markdown");
                                            let sanitize = parts.any(|f| f == "--sanitize");
                                            if fmt == "json" {
                                                match freedas_db::export_session(
                                                    &db,
                                                    &paths,
                                                    &project_root,
                                                    Some(sid),
                                                    sanitize,
                                                    "json",
                                                ) {
                                                    Ok(json) => {
                                                        let path = project_root
                                                            .join(format!("{sid}.json"));
                                                        match std::fs::write(&path, json) {
                                                            Ok(()) => transcript.push(format!(
                                                                "exported {}",
                                                                path.display()
                                                            )),
                                                            Err(e) => transcript.push(format!(
                                                                "export failed: {e}"
                                                            )),
                                                        }
                                                    }
                                                    Err(e) => transcript
                                                        .push(format!("export failed: {e}")),
                                                }
                                            } else {
                                                let mut out = markdown_export(&db, sid);
                                                if sanitize {
                                                    out = freedas_core::redact::redact(&out);
                                                }
                                                let path = project_root.join("transcript.md");
                                                match std::fs::write(&path, out) {
                                                    Ok(()) => transcript.push(format!(
                                                        "exported {}",
                                                        path.display()
                                                    )),
                                                    Err(e) => transcript
                                                        .push(format!("export failed: {e}")),
                                                }
                                            }
                                        } else {
                                            transcript.push("no session".into());
                                        }
                                    }
                                    "copy" => match copy_to_clipboard(&transcript.render()) {
                                        Ok(()) => {
                                            transcript.push("transcript copied to clipboard".into())
                                        }
                                        Err(e) => transcript.push(format!("copy failed: {e}")),
                                    },
                                    "status" => {
                                        let (mut input, mut output, mut cost) = (0i64, 0i64, 0f64);
                                        if let Ok(rows) =
                                            db.usage_totals(None, Some(&project_id), None)
                                        {
                                            for t in rows {
                                                input += t.input;
                                                output += t.output;
                                                cost += t.cost;
                                            }
                                        }
                                        transcript.push(format!(
                                    "agent={agent} model={} session={} auto={auto} manual={manual}",
                                    model.clone().unwrap_or_else(|| "auto".into()),
                                    current_session.clone().unwrap_or_else(|| "new".into())
                                ));
                                        transcript.push(format!(
                                            "tokens in={input} out={output} cost=${cost:.4}"
                                        ));
                                        let relay = relay_state(&paths);
                                        transcript.push(format!(
                                            "relay={} snapshots={}",
                                            if relay["running"].as_bool().unwrap_or(false) {
                                                "on"
                                            } else {
                                                "off"
                                            },
                                            if cfg.snapshots { "on" } else { "off" }
                                        ));
                                    }
                                    "init" => {
                                        let agents_md = project_root.join("AGENTS.md");
                                        let section = init_section(&project_root);
                                        let existing =
                                            std::fs::read_to_string(&agents_md).unwrap_or_default();
                                        let merged = match (
                                            existing.find("<!-- freedas:init:begin -->"),
                                            existing.find("<!-- freedas:init:end -->"),
                                        ) {
                                            (Some(a), Some(b)) if a < b => {
                                                let end = b + "<!-- freedas:init:end -->".len();
                                                format!("{}{}", &existing[..a], section)
                                                    + &existing[end..]
                                            }
                                            _ if existing.is_empty() => section.clone(),
                                            _ => format!("{existing}\n\n{section}"),
                                        };
                                        match std::fs::write(&agents_md, &merged) {
                                            Ok(()) => {
                                                transcript.push(format!(
                                                    "AGENTS.md updated ({} lines)",
                                                    merged.lines().count()
                                                ));
                                                transcript.push(section);
                                            }
                                            Err(e) => transcript
                                                .push(format!("AGENTS.md write failed: {e}")),
                                        }
                                    }
                                    "sync" | "adopt" => {
                                        let root = if args.is_empty() || args == "apply" {
                                            project_root.clone()
                                        } else {
                                            std::path::PathBuf::from(args)
                                        };
                                        if args == "apply" {
                                            match freedas_sync::apply(&root) {
                                                Ok((applied, skipped)) => transcript.push(format!(
                                                    "sync: {applied} imported, {skipped} unchanged"
                                                )),
                                                Err(e) => {
                                                    transcript.push(format!("sync failed: {e}"))
                                                }
                                            }
                                        } else {
                                            let entries = freedas_sync::detect(&root);
                                            if entries.is_empty() {
                                                transcript.push("sync: nothing detected".into());
                                            } else {
                                                for e in &entries {
                                                    transcript.push(format!(
                                                        "  {} → {} ({})",
                                                        e.source, e.target, e.kind
                                                    ));
                                                }
                                                transcript.push(format!(
                                                    "sync: {} sources — Enter imports, Esc cancels",
                                                    entries.len()
                                                ));
                                                pending_sync = Some((root.clone(), entries));
                                            }
                                        }
                                    }
                                    "agents" => {
                                        let agents = freedas_agent::merged_agents(&project_root);
                                        if args.is_empty() {
                                            for a in &agents {
                                                transcript.push(format!(
                                                    "· {} [{}] {}",
                                                    a.id, a.mode, a.description
                                                ));
                                            }
                                        } else if agents.iter().any(|a| a.id == args) {
                                            agent = args.to_string();
                                            transcript.push(format!("agent → {agent}"));
                                        } else {
                                            transcript.push(format!("unknown agent: {args}"));
                                        }
                                    }
                                    "model" => {
                                        let mut next = open_picker(
                                            popup::Kind::Models,
                                            &db,
                                            &project_id,
                                            &project_root,
                                            &cfg,
                                            &disabled_mcps,
                                        );
                                        next.follow(variant.as_deref());
                                        picker = Some(next);
                                    }
                                    "permissions" => {
                                        picker = Some(open_picker(
                                            popup::Kind::Permissions,
                                            &db,
                                            &project_id,
                                            &project_root,
                                            &cfg,
                                            &disabled_mcps,
                                        ));
                                    }
                                    "variants" => {
                                        if args.is_empty() {
                                            transcript.push(format!(
                                                "variant: {}",
                                                variant.clone().unwrap_or_else(|| "auto".into())
                                            ));
                                        } else {
                                            variant = Some(args.to_string());
                                            transcript.push(format!("variant → {args}"));
                                        }
                                    }
                                    "mcps" => {
                                        if args.is_empty() {
                                            for s in freedas_mcp::status_from_config(&cfg) {
                                                let off =
                                                    disabled_mcps.iter().any(|d| d == &s.name);
                                                transcript.push(format!(
                                                    "· {} {} tools={} prompts={}{}",
                                                    s.name,
                                                    s.state,
                                                    s.tools_label(),
                                                    s.prompts_label(),
                                                    if off { " (off)" } else { "" }
                                                ));
                                            }
                                        } else if cfg.mcp.contains_key(args) {
                                            if let Some(pos) =
                                                disabled_mcps.iter().position(|d| d == args)
                                            {
                                                disabled_mcps.remove(pos);
                                                transcript.push(format!("mcp {args}: on"));
                                            } else {
                                                disabled_mcps.push(args.to_string());
                                                transcript.push(format!("mcp {args}: off"));
                                            }
                                        } else {
                                            transcript.push(format!("unknown mcp server: {args}"));
                                        }
                                    }
                                    "workspace" | "billing" => {
                                        if args.is_empty() {
                                            transcript.push(format!(
                                                "workspace: {}",
                                                cfg.workspace
                                                    .clone()
                                                    .unwrap_or_else(|| "personal".into())
                                            ));
                                        } else {
                                            match save_setting(
                                                &paths,
                                                "workspace",
                                                serde_json::json!(args),
                                            ) {
                                                Ok(next) => {
                                                    reload_into(
                                                        &mut cfg,
                                                        &mut runner,
                                                        &paths,
                                                        &db,
                                                        next,
                                                    );
                                                    transcript.push(format!("workspace → {args}"));
                                                }
                                                Err(e) => transcript
                                                    .push(format!("workspace failed: {e}")),
                                            }
                                        }
                                    }
                                    "remote" | "rc" => {
                                        let Some(sid) = current_session.clone() else {
                                            transcript.push("no session to share".into());
                                            continue;
                                        };
                                        let exe = std::env::current_exe().unwrap_or_default();
                                        let relay = relay_state(&paths);
                                        if !relay["running"].as_bool().unwrap_or(false) {
                                            let _ = std::process::Command::new(&exe)
                                                .args(["relay", "start"])
                                                .stdout(std::process::Stdio::null())
                                                .stderr(std::process::Stdio::null())
                                                .spawn();
                                        }
                                        let out = std::process::Command::new(&exe)
                                            .args(["relay", "share", &sid])
                                            .output();
                                        match out {
                                            Ok(o) if o.status.success() => {
                                                let relay = relay_state(&paths);
                                                let url = format!(
                                                    "{}/sessions/{sid}",
                                                    relay["url"].as_str().unwrap_or("")
                                                );
                                                match copy_to_clipboard(&url) {
                                                    Ok(()) => transcript.push(format!(
                                                        "remote control on — link copied ({url})"
                                                    )),
                                                    Err(_) => transcript.push(format!(
                                                        "remote control on — {sid} shared at {url}"
                                                    )),
                                                }
                                            }
                                            Ok(o) => transcript.push(format!(
                                                "relay share failed: {}",
                                                String::from_utf8_lossy(&o.stderr).trim()
                                            )),
                                            Err(e) => {
                                                transcript.push(format!("relay share failed: {e}"))
                                            }
                                        }
                                    }
                                    "update" => {
                                        let exe = std::env::current_exe().unwrap_or_default();
                                        match std::process::Command::new(&exe)
                                            .arg("upgrade")
                                            .output()
                                        {
                                            Ok(o) => {
                                                let text = String::from_utf8_lossy(&o.stdout);
                                                for line in text.lines() {
                                                    transcript.push(line.to_string());
                                                }
                                                if !o.status.success() {
                                                    transcript.push(format!(
                                                        "upgrade failed: {}",
                                                        String::from_utf8_lossy(&o.stderr).trim()
                                                    ));
                                                }
                                            }
                                            Err(e) => {
                                                transcript.push(format!("upgrade failed: {e}"))
                                            }
                                        }
                                    }
                                    "review" => {
                                        if bg_pending.is_some() {
                                            transcript
                                                .push("busy — background task running".into());
                                        } else {
                                            let label = if args.is_empty() {
                                                "uncommitted changes".to_string()
                                            } else {
                                                args.to_string()
                                            };
                                            transcript.push(format!("reviewing {label}"));
                                            // `run_local_review` takes a sync model_fn; run the
                                            // agent on its own runtime in a worker thread so the
                                            // event loop stays responsive and never nests `block_on`.
                                            let db2 = db.clone();
                                            let paths2 = paths.clone();
                                            let cfg2 = cfg.clone();
                                            let root2 = project_root.clone();
                                            let agent2 = agent.clone();
                                            let model2 = model.clone();
                                            let variant2 = variant.clone();
                                            let model_fn = move |prompt: &str| -> String {
                                                let db2 = db2.clone();
                                                let paths2 = paths2.clone();
                                                let cfg2 = cfg2.clone();
                                                let root2 = root2.clone();
                                                let agent2 = agent2.clone();
                                                let model2 = model2.clone();
                                                let variant2 = variant2.clone();
                                                let prompt = prompt.to_string();
                                                std::thread::spawn(move || {
                                                    let rt = match tokio::runtime::Builder::new_current_thread()
                                                        .enable_all()
                                                        .build()
                                                    {
                                                        Ok(rt) => rt,
                                                        Err(_) => return String::new(),
                                                    };
                                                    let runner = freedas_session::Runner::new(
                                                        db2,
                                                        paths2,
                                                        cfg2.clone(),
                                                        freedas_catalog::builtin_catalog(),
                                                    );
                                                    rt.block_on(runner.run_task_opts(
                                                        freedas_session::RunOpts {
                                                            project_root: root2,
                                                            agent: agent2,
                                                            model: model2,
                                                            prompt,
                                                            auto: true,
                                                            manual: false,
                                                            workspace: cfg2.workspace.clone(),
                                                            session_id: None,
                                                            title: Some("review".into()),
                                                            variant: variant2,
                                                            depth: 0,
                                                            parent_id: None,
                                                            // The review flow classifies as `Review`.
                                                            review_mode: true,
                                                            progress: None,
                                                            headless: false,
                                                            mcp_disabled: Vec::new(),
                                                            approver: None,
                                                            session_rules: Default::default(),
                                                        },
                                                        tokio_util::sync::CancellationToken::new(),
                                                    ))
                                                    .map(|x| x.text)
                                                    .unwrap_or_default()
                                                })
                                                .join()
                                                .unwrap_or_default()
                                            };
                                            let target_owned = if args.trim().is_empty() {
                                                None
                                            } else {
                                                Some(args.trim().to_string())
                                            };
                                            let root3 = project_root.clone();
                                            let (tx, rx) = mpsc::channel();
                                            bg_pending = Some(rx);
                                            bg_worker = Some(std::thread::spawn(move || {
                                                let rt2 = match tokio::runtime::Builder::new_current_thread()
                                                    .enable_all()
                                                    .build()
                                                {
                                                    Ok(rt2) => rt2,
                                                    Err(e) => {
                                                        let _ = tx.send(BgDone::Review(Err(format!(
                                                            "cannot start runtime: {e}"
                                                        ))));
                                                        return;
                                                    }
                                                };
                                                let result = rt2.block_on(
                                                    freedas_review::run_local_review_target(
                                                        &root3,
                                                        target_owned.as_deref(),
                                                        model_fn,
                                                    ),
                                                );
                                                let _ = tx.send(BgDone::Review(Ok(result)));
                                            }));
                                        }
                                    }
                                    "standards-review" | "standards-audit" | "ui-review"
                                    | "ui-audit" => {
                                        let audit = name.ends_with("-audit");
                                        let scope = if audit {
                                            "the whole repository"
                                        } else {
                                            "the current changes"
                                        };
                                        transcript.push(format!(
                                            "/{name}: run the standards pass on {scope}"
                                        ));
                                        run_prompt!(
                                            format!(
                                                "Run the {name} pass: review {scope} for over-engineering, UI, or UX issues and return a delete list."
                                            ),
                                            false
                                        );
                                    }
                                    "quick-plan" | "plan-quick" => {
                                        let task = if args.trim().is_empty() {
                                            last_prompt.clone()
                                        } else {
                                            Some(args.to_string())
                                        };
                                        let Some(task) = task else {
                                            transcript.push(format!("usage: /{name} <task>"));
                                            continue;
                                        };
                                        let prev = agent.clone();
                                        agent = "plan-quick".into();
                                        run_prompt!(task, auto);
                                        agent = prev;
                                    }
                                    "deep-plan" | "plan-deep" => {
                                        let task = if args.trim().is_empty() {
                                            last_prompt.clone()
                                        } else {
                                            Some(args.to_string())
                                        };
                                        let Some(task) = task else {
                                            transcript.push(format!("usage: /{name} <task>"));
                                            continue;
                                        };
                                        let prev = agent.clone();
                                        agent = "plan".into();
                                        run_prompt!(task, auto);
                                        agent = prev;
                                    }
                                    "code-standards" => {
                                        run_prompt!(
                                    "Review the current changes against the code standards in .freedas/standards and the standards config; return violations as a list."
                                        .to_string(),
                                    false
                                );
                                    }
                                    "ui-standards" => {
                                        run_prompt!(
                                    "Review the current changes for UI and UX violations against the ui-review standards; return violations as a list."
                                        .to_string(),
                                    false
                                );
                                    }
                                    "login" => {
                                        let provider = if args.is_empty() {
                                            "freedas".to_string()
                                        } else {
                                            args.to_string()
                                        };
                                        let definition = freedas_provider::oauth::providers()
                                            .iter()
                                            .find(|candidate| candidate.id == provider);
                                        if provider != "freedas"
                                            && let Some(definition) = definition
                                        {
                                            let mut handled = false;
                                            if matches!(
                                                definition.login,
                                                freedas_provider::oauth::LoginKind::ApiKey(_)
                                            ) {
                                                for env in definition.env {
                                                    if let Ok(key) = std::env::var(env)
                                                        && !key.trim().is_empty()
                                                    {
                                                        let stored =
                                                            freedas_provider::oauth::credential_provider(
                                                                &provider,
                                                            );
                                                        match freedas_provider::credentials::store(
                                                            &paths.data_dir,
                                                            stored,
                                                            key.trim(),
                                                        ) {
                                                            Ok(()) => transcript.push(format!(
                                                                "stored credential for {provider} from {env}"
                                                            )),
                                                            Err(e) => transcript
                                                                .push(format!("login failed: {e}")),
                                                        }
                                                        handled = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            if !handled {
                                                start_login!(provider);
                                            }
                                        } else {
                                            let env_key =
                                                format!("{}_API_KEY", provider.to_uppercase());
                                            match std::env::var(&env_key) {
                                                Ok(key) => match freedas_provider::credentials::store(
                                                    &paths.data_dir,
                                                    &provider,
                                                    &key,
                                                ) {
                                                    Ok(()) => transcript.push(format!(
                                                        "stored credential for {provider} from {env_key}"
                                                    )),
                                                    Err(e) => transcript
                                                        .push(format!("login failed: {e}")),
                                                },
                                                Err(_) => {
                                                    pending_login = Some(provider.clone());
                                                    transcript.push(format!(
                                                        "paste the {provider} credential and press Enter (Esc cancels)"
                                                    ));
                                                }
                                            }
                                        }
                                    }
                                    "credits" => {
                                        if bg_pending.is_some() {
                                            transcript
                                                .push("busy — background task running".into());
                                        } else {
                                            let paths2 = paths.clone();
                                            let (tx, rx) = mpsc::channel();
                                            bg_pending = Some(rx);
                                            bg_worker = Some(std::thread::spawn(move || {
                                                let rt2 = match tokio::runtime::Builder::new_current_thread()
                                                    .enable_all()
                                                    .build()
                                                {
                                                    Ok(rt2) => rt2,
                                                    Err(e) => {
                                                        let _ = tx.send(BgDone::Credits(Err(format!(
                                                            "cannot start runtime: {e}"
                                                        ))));
                                                        return;
                                                    }
                                                };
                                                let result = rt2
                                                    .block_on(
                                                        freedas_provider::credentials::control_get(
                                                            &paths2, "/wallet",
                                                        ),
                                                    )
                                                    .map_err(|e| e.to_string());
                                                let _ = tx.send(BgDone::Credits(result));
                                            }));
                                            transcript.push("checking balance…".into());
                                        }
                                    }
                                    "usage" => {
                                        match db.usage_totals(None, Some(&project_id), None) {
                                            Ok(rows) if rows.is_empty() => transcript
                                                .push("usage: no recorded requests".into()),
                                            Ok(rows) => {
                                                for t in rows {
                                                    transcript.push(format!(
                                                        "{} {} in={} out={} ${:.4}",
                                                        t.provider,
                                                        t.model,
                                                        t.input,
                                                        t.output,
                                                        t.cost
                                                    ));
                                                }
                                            }
                                            Err(e) => transcript.push(format!("usage failed: {e}")),
                                        }
                                    }
                                    "org" | "orgs" | "switch-org" => {
                                        if !args.is_empty() {
                                            match save_setting(
                                                &paths,
                                                "workspace",
                                                serde_json::json!(args),
                                            ) {
                                                Ok(next) => {
                                                    reload_into(
                                                        &mut cfg,
                                                        &mut runner,
                                                        &paths,
                                                        &db,
                                                        next,
                                                    );
                                                    transcript
                                                        .push(format!("organization → {args}"));
                                                }
                                                Err(e) => {
                                                    transcript.push(format!("org failed: {e}"))
                                                }
                                            }
                                        } else if bg_pending.is_some() {
                                            transcript
                                                .push("busy — background task running".into());
                                        } else {
                                            let paths2 = paths.clone();
                                            let (tx, rx) = mpsc::channel();
                                            bg_pending = Some(rx);
                                            bg_worker = Some(std::thread::spawn(move || {
                                                let rt2 = match tokio::runtime::Builder::new_current_thread()
                                                    .enable_all()
                                                    .build()
                                                {
                                                    Ok(rt2) => rt2,
                                                    Err(e) => {
                                                        let _ = tx.send(BgDone::Orgs(Err(format!(
                                                            "cannot start runtime: {e}"
                                                        ))));
                                                        return;
                                                    }
                                                };
                                                let result = rt2
                                                    .block_on(
                                                        freedas_provider::credentials::control_get(
                                                            &paths2,
                                                            "/workspaces",
                                                        ),
                                                    )
                                                    .map_err(|e| e.to_string());
                                                let _ = tx.send(BgDone::Orgs(result));
                                            }));
                                            transcript.push("listing organizations…".into());
                                        }
                                    }
                                    "debug" => {
                                        transcript
                                            .push(format!("version {}", env!("CARGO_PKG_VERSION")));
                                        transcript
                                            .push(format!("project {}", project_root.display()));
                                        transcript
                                            .push(format!("db {}", paths.db_path().display()));
                                        transcript.push(format!(
                                            "config {}",
                                            paths.global_config().display()
                                        ));
                                        transcript.push(format!(
                                            "agent={agent} model={} session={}",
                                            model.clone().unwrap_or_else(|| "auto".into()),
                                            current_session.clone().unwrap_or_else(|| "new".into())
                                        ));
                                        for s in freedas_mcp::status_from_config(&cfg) {
                                            transcript.push(format!(
                                                "mcp {} {} tools={} prompts={}",
                                                s.name,
                                                s.state,
                                                s.tools_label(),
                                                s.prompts_label()
                                            ));
                                        }
                                    }
                                    "changelog" => transcript
                                        .push(include_str!("../../../CHANGELOG.md").into()),
                                    "editor" => {
                                        edit_in_editor(terminal, &mut composer)?;
                                    }
                                    "move" => {
                                        if args.is_empty() {
                                            transcript.push("usage: /move <project path>".into());
                                        } else if let Some(sid) = &current_session {
                                            let target = freedas_core::paths::find_project_root(
                                                &std::path::PathBuf::from(args),
                                            );
                                            if !target.is_dir() {
                                                transcript.push(format!(
                                                    "not a directory: {}",
                                                    target.display()
                                                ));
                                            } else {
                                                match db.ensure_project(&target).and_then(|pid| {
                                                    db.move_session(sid, &pid).map(|_| pid)
                                                }) {
                                                    Ok(pid) => {
                                                        project_root = target.clone();
                                                        project_id = pid;
                                                        branch = branch_of(&project_root)
                                                            .unwrap_or_else(|| {
                                                                "no git".to_string()
                                                            });
                                                        usage = usage_of(&db, &project_id);
                                                        file_items =
                                                            project_file_rows(&project_root);
                                                        transcript.push(format!(
                                                            "moved {sid} → {}",
                                                            target.display()
                                                        ));
                                                    }
                                                    Err(e) => {
                                                        transcript.push(format!("move failed: {e}"))
                                                    }
                                                }
                                            }
                                        } else {
                                            transcript.push("no session".into());
                                        }
                                    }
                                    "timestamps" => {
                                        transcript.timestamps = !transcript.timestamps;
                                        transcript.push(format!(
                                            "timestamps: {}",
                                            if transcript.timestamps { "on" } else { "off" }
                                        ));
                                    }
                                    "thinking" => {
                                        show_thinking = !show_thinking;
                                        thinking_flag.store(show_thinking, Ordering::Relaxed);
                                        transcript.push(format!(
                                            "thinking: {}",
                                            if show_thinking { "shown" } else { "hidden" }
                                        ));
                                        if show_thinking && let Some(mid) = &last_message {
                                            for p in db.list_parts(mid).unwrap_or_default() {
                                                if p.kind == "reasoning" {
                                                    let text =
                                                        serde_json::from_str::<serde_json::Value>(
                                                            &p.data,
                                                        )
                                                        .ok()
                                                        .and_then(|v| {
                                                            v["text"].as_str().map(str::to_string)
                                                        })
                                                        .unwrap_or_default();
                                                    if !text.is_empty() {
                                                        transcript.push_reasoning(text);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    "exit" | "quit" | "q" => break,
                                    other => {
                                        if let Some(c) = commands.iter().find(|c| c.name == other) {
                                            let body = freedas_skill::expand_args(
                                                &c.body.clone().unwrap_or_default(),
                                                args,
                                            );
                                            let prev = agent.clone();
                                            let prev_model = model.clone();
                                            if let Some(a) = &c.agent {
                                                agent = a.clone();
                                            }
                                            if let Some(m) = &c.model {
                                                model = Some(m.clone());
                                            }
                                            // subtask runs the expanded body under the
                                            // general subagent instead of in-session.
                                            let body = if c.subtask {
                                                format!(
                                                    "Use the task tool to run this under the general agent: {body}"
                                                )
                                            } else {
                                                body
                                            };
                                            transcript.push_user(format!("/{other}"));
                                            run_prompt!(body, auto);
                                            agent = prev;
                                            model = prev_model;
                                        } else {
                                            transcript.push(format!(
                                                "unknown command: /{other} (try /help)"
                                            ));
                                        }
                                    }
                                }
                                commands = discover_commands(&project_root, &paths, &cfg.skills);
                                slash_items = slash_rows(&commands);
                                continue;
                            }
                            transcript.push_user(prompt.clone());
                            run_prompt!(prompt, auto);
                        }
                        KeyCode::Backspace => composer.backspace(),
                        KeyCode::Delete => composer.delete(),
                        KeyCode::Left => composer.left(),
                        KeyCode::Right => composer.right(),
                        KeyCode::Home => {
                            if ctrl || (composer.is_empty() && scroll > 0) {
                                // `scroll` counts rendered lines back from the
                                // tail; the draw clamps it to the pane.
                                scroll = u16::MAX;
                            } else {
                                composer.home();
                            }
                        }
                        KeyCode::End => {
                            if ctrl || (composer.is_empty() && scroll > 0) {
                                scroll = 0;
                            } else {
                                composer.end();
                            }
                        }
                        KeyCode::Esc => {
                            // Pending offers win, then the live run, then the draft,
                            // then the two-press recall of the last prompt.
                            let armed = esc_armed.take().is_some_and(|t| t.elapsed() < ARMED);
                            if pending_sync.take().is_some() {
                                transcript.push("import cancelled".into());
                            } else if pending_login.is_some() {
                                login_cancel.store(true, Ordering::Relaxed);
                                login_generation += 1;
                                if let Some((_, reply)) = pending_login_prompt.take() {
                                    let _ = reply.send(Err("login cancelled".into()));
                                }
                                if let Some(reply) = pending_login_manual.take() {
                                    let _ = reply.send(Err("login cancelled".into()));
                                }
                                pending_login = None;
                                transcript.push("login cancelled".into());
                            } else if running {
                                if let Some(token) = &cancel {
                                    token.cancel();
                                }
                                activity = "interrupting".to_string();
                            } else if !composer.is_empty() {
                                composer.clear();
                            } else if armed {
                                if let Some(prompt) = last_prompt.clone() {
                                    history_pos = None;
                                    composer.set(prompt);
                                }
                            } else if last_prompt.is_some() {
                                esc_armed = Some(Instant::now());
                            }
                        }
                        KeyCode::Up => {
                            if let Some(pos) = history_step(history.len(), history_pos, true) {
                                history_pos = Some(pos);
                                composer.set(history[pos].clone());
                            }
                        }
                        KeyCode::Down => {
                            if history_pos.is_some() {
                                history_pos = history_step(history.len(), history_pos, false);
                                match history_pos {
                                    Some(pos) => composer.set(history[pos].clone()),
                                    None => composer.clear(),
                                }
                            }
                        }
                        KeyCode::PageUp => scroll = scroll.saturating_add(5),
                        KeyCode::PageDown => scroll = scroll.saturating_sub(5),
                        KeyCode::Tab | KeyCode::BackTab => {
                            let back = key.code == KeyCode::BackTab;
                            if running && !back {
                                let draft = composer.text().trim().to_string();
                                if !draft.is_empty() && !draft.starts_with('/') {
                                    let queued = composer.take_trimmed();
                                    transcript
                                        .push(format!("· queued ({}) {queued}", queue.len() + 1));
                                    queue.push_back((current_session.clone(), queued));
                                }
                                continue;
                            }
                            let agents: Vec<String> = freedas_agent::merged_agents(&project_root)
                                .into_iter()
                                .filter(|a| a.mode == "primary" || a.mode == "all")
                                .map(|a| a.id)
                                .collect();
                            if !agents.is_empty() {
                                let next = match (agents.iter().position(|a| a == &agent), back) {
                                    (Some(i), false) => (i + 1) % agents.len(),
                                    (Some(i), true) => (i + agents.len() - 1) % agents.len(),
                                    (None, false) => 0,
                                    (None, true) => agents.len() - 1,
                                };
                                agent = agents[next].clone();
                                transcript.push(format!("agent → {agent}"));
                            }
                        }
                        KeyCode::F(1) => {
                            shortcuts_open = true;
                        }
                        KeyCode::Char('p') if ctrl => {
                            help_open = true;
                            help_scroll = 0;
                        }
                        KeyCode::Char('h') if ctrl => {
                            help_open = true;
                            help_scroll = 0;
                        }
                        KeyCode::Char('k') if ctrl => {
                            if composer.is_empty() {
                                picker = Some(open_picker(
                                    popup::Kind::Sessions,
                                    &db,
                                    &project_id,
                                    &project_root,
                                    &cfg,
                                    &disabled_mcps,
                                ));
                            } else {
                                composer.kill_to_end();
                            }
                        }
                        KeyCode::Char('l') if ctrl => {
                            let mut next = open_picker(
                                popup::Kind::Models,
                                &db,
                                &project_id,
                                &project_root,
                                &cfg,
                                &disabled_mcps,
                            );
                            next.follow(variant.as_deref());
                            picker = Some(next);
                        }
                        KeyCode::Char('o') if ctrl => {
                            picker = Some(open_picker(
                                popup::Kind::Agents,
                                &db,
                                &project_id,
                                &project_root,
                                &cfg,
                                &disabled_mcps,
                            ));
                        }
                        KeyCode::Char('m') if key.modifiers.contains(KeyModifiers::ALT) => {
                            picker = Some(open_picker(
                                popup::Kind::Mcp,
                                &db,
                                &project_id,
                                &project_root,
                                &cfg,
                                &disabled_mcps,
                            ));
                        }
                        KeyCode::Char('e') if ctrl => {
                            edit_in_editor(terminal, &mut composer)?;
                        }
                        KeyCode::Char('y') if ctrl => match copy_to_clipboard(&transcript.render())
                        {
                            Ok(()) => transcript.push("transcript copied to clipboard".into()),
                            Err(e) => transcript.push(format!("copy failed: {e}")),
                        },
                        KeyCode::Char('w') if ctrl => composer.delete_word(),
                        KeyCode::Char('u') if ctrl => composer.clear_line(),
                        KeyCode::Char('j') if ctrl => composer.newline(),
                        KeyCode::Char(c) if !ctrl => composer.insert_char(c),
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        // Remember where the tail was so a scrolled-up view can count arrivals.
        if scroll == 0 {
            tail_mark = transcript.len();
        }
    }
    // Stop the worker before the terminal is restored. Dropping a pending
    // permission's reply sender fails the approver closed (reject), then the
    // token ends the run so no tool process group outlives the TUI.
    drop(pending_permission.take());
    for (_, _, _, queued) in pending_queue.drain(..) {
        let _ = queued.send(freedas_tools::PermissionReply::Reject);
    }
    // Closing the channel makes any further ask fail closed immediately.
    drop(perm_rx.take());
    if let Some(token) = &cancel {
        token.cancel();
    }
    if let Some(rx) = pending.take() {
        let stopped = !matches!(
            rx.recv_timeout(Duration::from_secs(5)),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
        if stopped && let Some(handle) = worker.take() {
            let _ = handle.join();
        }
    }
    login_cancel.store(true, Ordering::Relaxed);
    drop(login_rx.take());
    if let Some(handle) = login_worker.take()
        && handle.is_finished()
    {
        let _ = handle.join();
    }
    drop(bg_pending.take());
    if let Some(handle) = bg_worker.take()
        && handle.is_finished()
    {
        let _ = handle.join();
    }
    Ok(())
}

fn append_remembered_rule(paths: &Paths, action: &str, resource: &str) -> std::io::Result<()> {
    freedas_core::config::remember_rule(paths, action, resource)
}

/// Toggle one server in the session's disabled list.
fn toggle_mcp(disabled: &mut Vec<String>, name: &str) {
    if let Some(pos) = disabled.iter().position(|d| d == name) {
        disabled.remove(pos);
    } else {
        disabled.push(name.to_string());
    }
}

pub fn not_interactive_message() -> String {
    "Interactive UI requires a TTY. Use `freedas run \"task\"` for headless runs.".into()
}

#[cfg(test)]
mod keymap_tests {
    use super::*;

    #[test]
    fn file_rows_include_project_files() {
        let dir = std::env::temp_dir().join(format!("freedas-files-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/main.rs"), "fn main() {}").unwrap();
        std::fs::write(dir.join("README.md"), "hi").unwrap();
        let rows = project_file_rows(&dir);
        let keys: Vec<&str> = rows.iter().map(|r| r.key.as_str()).collect();
        assert!(keys.contains(&"src/main.rs"), "{keys:?}");
        assert!(keys.contains(&"README.md"), "{keys:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn history_step_clamps_and_walks() {
        assert_eq!(history_step(0, None, true), None);
        assert_eq!(history_step(0, Some(3), false), None);
        assert_eq!(history_step(3, None, true), Some(2));
        assert_eq!(history_step(3, Some(2), true), Some(1));
        assert_eq!(history_step(3, Some(0), true), Some(0));
        // A stale position from a shorter history cannot index out of range.
        assert_eq!(history_step(2, Some(9), false), None);
        assert_eq!(history_step(3, Some(2), false), None);
        assert_eq!(history_step(3, Some(1), false), Some(2));
        assert_eq!(history_step(3, None, false), None);
    }

    #[test]
    fn undo_tail_drops_the_last_user_turn() {
        let mut transcript = Transcript::new();
        transcript.push_user("first".into());
        transcript.push_assistant("one".into());
        transcript.push_user("second".into());
        transcript.push_assistant("two".into());
        transcript.push_error("boom".into());
        assert!(transcript.truncate_user_tail());
        let text = transcript.text();
        assert!(text.contains("one"), "{text}");
        assert!(!text.contains("second"), "{text}");
        assert!(!text.contains("boom"), "{text}");

        let mut empty = Transcript::new();
        empty.push_assistant("only".into());
        assert!(!empty.truncate_user_tail());
        assert_eq!(empty.len(), 1);
    }

    fn temp_paths(tag: &str) -> Paths {
        let root = std::env::temp_dir().join(format!("freedas-tui-{tag}-{}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        std::fs::create_dir_all(root.join("config")).unwrap();
        Paths {
            home: root.join("home"),
            config_dir: root.join("config"),
            data_dir: root.join("data"),
            state_dir: root.join("state"),
            cache_dir: root.join("cache"),
            bin_dir: root.join("bin"),
            project_root: root.clone(),
        }
    }

    #[test]
    fn save_setting_keeps_jsonc_and_reloads() {
        let paths = temp_paths("jsonc");
        std::fs::write(
            paths.global_config(),
            "{\n  // comment\n  \"model\": \"freedas/auto\",\n}\n",
        )
        .unwrap();
        let cfg = save_setting(&paths, "workspace", serde_json::json!("team")).unwrap();
        assert_eq!(cfg.workspace.as_deref(), Some("team"));
        let saved: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(paths.global_config()).unwrap()).unwrap();
        assert_eq!(saved["model"], serde_json::json!("freedas/auto"));
        assert_eq!(saved["workspace"], serde_json::json!("team"));
        std::fs::remove_dir_all(&paths.project_root).ok();
    }

    #[test]
    fn save_setting_removes_the_file_it_created_on_a_bad_value() {
        let paths = temp_paths("rollback");
        let err = save_setting(&paths, "model", serde_json::json!("not-a-model"));
        assert!(err.is_err());
        assert!(
            !paths.global_config().exists(),
            "rollback left {} behind",
            paths.global_config().display()
        );
        std::fs::remove_dir_all(&paths.project_root).ok();
    }

    #[test]
    fn permission_mode_maps_to_run_flags() {
        assert_eq!(PermissionMode::Bypass.flags(), (true, false));
        assert_eq!(PermissionMode::Auto.flags(), (false, false));
        assert_eq!(PermissionMode::Ask.flags(), (false, true));
        assert_eq!(PermissionMode::parse("manual"), Some(PermissionMode::Ask));
        assert_eq!(
            PermissionMode::parse("bypass").map(|m| m.as_str()),
            Some("bypass")
        );
    }

    #[test]
    fn slash_commands_register_model_and_permissions() {
        let names: Vec<&str> = builtin_commands().iter().map(|(name, _)| *name).collect();
        assert!(names.contains(&"model"), "{names:?}");
        assert!(names.contains(&"permissions"), "{names:?}");
        // `/model` and `/permissions` complete like every other command.
        let rows = slash_rows(&[]);
        assert!(rows.iter().any(|r| r.value == "model"));
        assert!(rows.iter().any(|r| r.value == "permissions"));
    }

    #[test]
    fn model_label_joins_variant() {
        assert_eq!(view::model_label(Some("a/b"), Some("max")), "a/b · max");
        assert_eq!(view::model_label(Some("a/b"), None), "a/b");
        assert_eq!(view::model_label(None, None), "auto");
    }
}
