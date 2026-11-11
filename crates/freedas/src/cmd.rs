use std::path::PathBuf;
use std::sync::Arc;

use crate::{Cli, Commands};
use freedas_core::config::{self, PermissionMode};
use freedas_core::paths::Paths;
use freedas_db::Db;

fn paths(project_root: PathBuf) -> Result<Paths, Box<dyn std::error::Error>> {
    let p = Paths::resolve(project_root);
    p.ensure_dirs()?;
    Ok(p)
}

fn db(p: &Paths) -> Result<Db, Box<dyn std::error::Error>> {
    Ok(Db::open(&p.db_path())?)
}

/// Collapse the user's home directory to `~` so CLI errors do not disclose
/// the account name or directory layout in shared logs.
fn scrub_home(s: &str) -> String {
    if let Ok(home) = std::env::var("HOME") {
        let home = home.trim_end_matches(['/', '\\']);
        if !home.is_empty() {
            return s
                .replace(&format!("{home}/"), "~/")
                .replace(&format!("{home}\\"), "~\\");
        }
    }
    s.to_string()
}

/// Render a URL with userinfo, query, and fragment stripped, so credentials
/// embedded in `--attach`/server URLs cannot leak into logs or transcripts.
fn display_url(url: &str) -> String {
    match reqwest::Url::parse(url.trim()) {
        Ok(mut u) => {
            let _ = u.set_username("");
            let _ = u.set_password(None);
            u.set_query(None);
            u.set_fragment(None);
            u.to_string()
        }
        Err(_) => "[invalid-url]".into(),
    }
}

/// Replace occurrences of `base` inside an error message with its
/// credential-free display form.
fn scrub_url(msg: &str, base: &str) -> String {
    let safe = display_url(base);
    let mut out = msg.replace(base.trim_end_matches('/'), safe.trim_end_matches('/'));
    if let Ok(u) = reqwest::Url::parse(base) {
        out = out.replace(u.as_str().trim_end_matches('/'), safe.trim_end_matches('/'));
    }
    out
}

/// CLI `--auto`/`--manual` override the configured mode; both become the
/// session's `(auto, manual)` tool-context flags.
fn permission_flags(cli_auto: bool, cli_manual: bool, configured: PermissionMode) -> (bool, bool) {
    if cli_auto {
        PermissionMode::Bypass
    } else if cli_manual {
        PermissionMode::Ask
    } else {
        configured
    }
    .flags()
}

/// Key in `credentials.json` holding a configured control-plane URL.
const CONTROL_URL_KEY: &str = "control_url";

/// Control-plane base URL for the device login flow: explicit env, else the
/// stored `control_url`. `None` keeps the API-key path.
fn control_url(p: &Paths) -> Option<String> {
    if let Ok(url) = std::env::var("FREEDAS_CONTROL_URL") {
        let url = url.trim();
        if !url.is_empty() {
            return Some(url.to_string());
        }
    }
    freedas_provider::credentials::load(&p.data_dir)
        .unwrap_or_default()
        .get(CONTROL_URL_KEY)
        .map(|url| url.trim().to_string())
        .filter(|url| !url.is_empty())
}

fn runner(
    p: &Paths,
    _project_root: PathBuf,
    d: Arc<Db>,
) -> Result<freedas_session::Runner, Box<dyn std::error::Error>> {
    let cfg = config::load(p, false)?;
    Ok(freedas_session::Runner::new(
        d,
        p.clone(),
        cfg,
        freedas_catalog::builtin_catalog(),
    ))
}

/// POST to the local server. `path` starts with `/`.
/// Mirror the local server's SSE stream onto the relay as `Event` frames and
/// surface `permission.asked` as a `Permission` frame. Reconnects when the
/// local server restarts.
pub async fn run(cli: Cli, project_root: PathBuf) -> Result<i32, Box<dyn std::error::Error>> {
    let disable_project = std::env::var("FREEDAS_DISABLE_PROJECT_CONFIG")
        .map(|v| v == "1")
        .unwrap_or(false);
    let p = paths(project_root.clone())?;
    let d = Arc::new(db(&p)?);
    // A broken config must stop `run`/TUI, not silently become allow-all
    // defaults. Diagnostic commands still work so the operator can inspect it.
    let cfg = match config::load(&p, disable_project) {
        Ok(cfg) => cfg,
        Err(e) => {
            if matches!(&cli.command, None | Some(Commands::Run { .. })) {
                return Err(format!("config: {}", scrub_home(&e.to_string())).into());
            }
            eprintln!("config: {}", scrub_home(&e.to_string()));
            Default::default()
        }
    };
    let cli_worktree = cli.worktree.clone();

    match cli.command {
        None => {
            // Interactive TUI.
            if cli.fork && cli.session.is_none() && !cli.continue_ {
                eprintln!("freedas: --fork requires --continue or --session");
                return Ok(2);
            }
            if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                let project_root = match &cli_worktree {
                    Some(name) => {
                        let pid = d.ensure_project(&project_root)?;
                        let name = name.clone().unwrap_or_else(default_worktree_name);
                        freedas_git::create_worktree(&p.data_dir, &pid, &name, &project_root)
                            .await
                            .map_err(|e| format!("worktree: {}", scrub_home(&e.to_string())))?
                    }
                    None => project_root,
                };
                let pid = d.ensure_project(&project_root)?;
                let mut session_id: Option<String> = None;
                if cli.continue_ {
                    session_id = d.list_sessions(&pid, 1)?.first().map(|s| s.id.clone());
                }
                if let Some(sid) = &cli.session {
                    // Same project-scope guard as `run --session`.
                    match d.session_full(sid)? {
                        Some(s) if s.project_id == pid => session_id = Some(sid.clone()),
                        Some(_) => {
                            eprintln!("freedas: session {sid} belongs to a different project");
                            return Ok(2);
                        }
                        None => {
                            eprintln!("freedas: session {sid} not found");
                            return Ok(2);
                        }
                    }
                }
                if cli.fork
                    && let Some(sid) = &session_id
                {
                    session_id = Some(d.fork_session(&pid, sid, None)?);
                }
                let (auto, manual) = permission_flags(cli.auto, cli.manual, cfg.permission_mode);
                let opts = freedas_tui::TuiOptions {
                    project_root,
                    agent: cli
                        .agent
                        .clone()
                        .unwrap_or_else(|| cfg.default_agent.clone()),
                    model: cli.model.clone(),
                    variant: cli.variant.clone(),
                    auto,
                    manual,
                    session_id,
                };
                // The TUI owns a blocking loop; main runs a current_thread
                // runtime so this is a plain call, not a `block_in_place`.
                freedas_tui::run_with_opts(opts)?;
            } else {
                eprintln!("{}", freedas_tui::not_interactive_message());
                return Ok(2);
            }
            Ok(0)
        }
        Some(Commands::Run {
            task,
            format,
            file,
            attach,
            title,
            worktree: run_worktree,
            continue_,
            session,
            fork,
            agent,
            model,
            variant,
            auto,
            manual,
        }) => {
            // The nested flags win over the global pair when either is set;
            // otherwise the global --auto/--manual applies (same precedence
            // as --worktree below).
            let (auto, manual) = if auto || manual {
                (auto, manual)
            } else {
                (cli.auto, cli.manual)
            };
            let (auto, manual) = permission_flags(auto, manual, cfg.permission_mode);
            if format != "json" && format != "text" {
                eprintln!("freedas: --format must be json or text");
                return Ok(2);
            }
            // A configured default applies when the flag is absent.
            let variant = variant.or_else(|| cfg.variant.clone());
            // Attach files and piped stdin to the message. Each source is
            // capped — a multi-MB log piped in should not go verbatim into the
            // prompt (and the provider bill).
            const PROMPT_SOURCE_CAP: usize = 200_000;
            let cap_source = |text: &str| -> String {
                if text.len() <= PROMPT_SOURCE_CAP {
                    return text.to_string();
                }
                let mut end = PROMPT_SOURCE_CAP;
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                format!("{}\n[truncated {} bytes]", &text[..end], text.len() - end)
            };
            let mut prompt = task.clone();
            for f in &file {
                match std::fs::read_to_string(f) {
                    Ok(c) => prompt.push_str(&format!("\n\n--- {f} ---\n{}", cap_source(&c))),
                    Err(e) => {
                        return Err(format!("cannot read {}: {e}", scrub_home(f)).into());
                    }
                }
            }
            if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                use std::io::Read;
                let mut buf = String::new();
                if std::io::stdin().read_to_string(&mut buf).is_ok() && !buf.trim().is_empty() {
                    prompt.push_str(&format!("\n\n--- stdin ---\n{}", cap_source(&buf)));
                }
            }

            // Attach mode: run against a remote server, streaming its events.
            if let Some(url) = attach {
                if fork && session.is_none() && !continue_ {
                    eprintln!("freedas: --fork requires --continue or --session");
                    return Ok(2);
                }
                // A worktree is a local checkout; the server owns its own cwd.
                if run_worktree.is_some() || cli_worktree.is_some() {
                    eprintln!("freedas: --worktree cannot be used with --attach");
                    return Ok(2);
                }
                let code = attach_run(AttachRun {
                    base: url,
                    task: prompt,
                    session,
                    resume_latest: continue_,
                    fork,
                    auto,
                    manual,
                    format,
                    title,
                    agent,
                    model: model
                        .clone()
                        .filter(|m| m != "freedas/auto" && m != "freedas/auto-cheap"),
                    variant,
                })
                .await?;
                return Ok(code);
            }
            // The nested flag wins over the global one, including bare `--worktree`.
            let worktree = run_worktree.or(cli_worktree);
            let project_root = if let Some(name) = worktree {
                let pid = d.ensure_project(&project_root)?;
                let name = name.unwrap_or_else(default_worktree_name);
                freedas_git::create_worktree(&p.data_dir, &pid, &name, &project_root)
                    .await
                    .map_err(|e| format!("worktree: {}", scrub_home(&e.to_string())))?
            } else {
                project_root
            };

            // Continue/fork: resolve the session to reuse.
            if fork && session.is_none() && !continue_ {
                eprintln!("freedas: --fork requires --continue or --session");
                return Ok(2);
            }
            let pid = d.ensure_project(&project_root)?;
            let mut session_id: Option<String> = None;
            if continue_ {
                session_id = d.list_sessions(&pid, 1)?.first().map(|s| s.id.clone());
            }
            if let Some(sid) = session {
                // Sessions are project-scoped: an id from another project would
                // resume with this project's root and corrupt both histories.
                match d.session_full(&sid)? {
                    Some(s) if s.project_id == pid => session_id = Some(sid),
                    Some(_) => {
                        eprintln!("freedas: session {sid} belongs to a different project");
                        return Ok(2);
                    }
                    None => {
                        eprintln!("freedas: session {sid} not found");
                        return Ok(2);
                    }
                }
            }
            if fork && let Some(sid) = &session_id {
                session_id = Some(d.fork_session(&pid, sid, None)?);
            }
            let fresh_session = session_id.is_none();
            let want_title = title.is_none();

            let agent_name = agent.unwrap_or(cfg.default_agent.clone());
            let model_opt = model
                .clone()
                .filter(|m| m != "freedas/auto" && m != "freedas/auto-cheap");
            if cfg.sandbox.mode == "on" && !freedas_sandbox::available() {
                eprintln!("sandbox required but unavailable");
                return Ok(5);
            }
            // JSON mode emits one event per line; create the session first so
            // `session.started` carries its id. Resumed runs emit it too —
            // consumers need the id before any other event arrives.
            if format == "json" {
                if session_id.is_none() {
                    let fallback = prompt.chars().take(80).collect::<String>();
                    let created = d.create_session(
                        &pid,
                        &agent_name,
                        title.as_deref().unwrap_or(&fallback),
                        cfg.workspace.as_deref(),
                    )?;
                    session_id = Some(created);
                }
                println!(
                    "{}",
                    serde_json::json!({
                        "type": "session.started",
                        "sessionID": session_id.as_deref().unwrap_or_default(),
                        "timestamp": freedas_core::paths::now_ms(),
                    })
                );
            }
            let project_display = project_root.display().to_string();
            let prompt_excerpt: String = prompt.chars().take(200).collect();
            let started_at = freedas_core::paths::now_ms();
            let runner_inst = runner(&p, project_root.clone(), d.clone())?;
            let run = runner_inst
                .run_task_opts(
                    freedas_session::RunOpts {
                        project_root,
                        agent: agent_name,
                        model: model_opt.clone(),
                        prompt,
                        auto,
                        manual,
                        workspace: cfg.workspace.clone(),
                        session_id: session_id.clone(),
                        title,
                        variant,
                        depth: 0,
                        parent_id: None,
                        review_mode: false,
                        progress: if format == "json" {
                            let sid = session_id.clone().unwrap_or_default();
                            Some(std::sync::Arc::new(move |msg: String| {
                                // \u{1} markers name the running tool or gate;
                                // \u{2} payloads are tool results. Forward both
                                // so headless consumers see activity and
                                // failures as they happen, not only the summary.
                                if let Some(marker) = msg.strip_prefix('\u{1}') {
                                    println!(
                                        "{}",
                                        serde_json::json!({
                                            "type": "session.marker",
                                            "sessionID": sid,
                                            "marker": marker,
                                        })
                                    );
                                } else if let Some(json) = msg.strip_prefix('\u{2}') {
                                    if let Ok(mut v) =
                                        serde_json::from_str::<serde_json::Value>(json)
                                    {
                                        v["type"] = "tool.result".into();
                                        v["sessionID"] = sid.clone().into();
                                        println!("{v}");
                                    }
                                } else if let Some(t) = msg.strip_prefix('\u{3}') {
                                    println!(
                                        "{}",
                                        serde_json::json!({
                                            "type": "message.part.delta",
                                            "sessionID": sid,
                                            "part": {"type": "reasoning", "text": t},
                                        })
                                    );
                                } else {
                                    println!(
                                        "{}",
                                        serde_json::json!({
                                            "type": "message.part.delta",
                                            "sessionID": sid,
                                            "text": msg,
                                        })
                                    );
                                }
                            })
                                as freedas_session::ProgressSink)
                        } else {
                            // Text mode: surface tool names as they run and
                            // failures on stderr; the final text still goes to
                            // stdout alone for clean piping.
                            Some(std::sync::Arc::new(|msg: String| {
                                if let Some(marker) = msg.strip_prefix('\u{1}') {
                                    eprintln!("{marker}");
                                } else if let Some(json) = msg.strip_prefix('\u{2}')
                                    && let Ok(v) = serde_json::from_str::<serde_json::Value>(json)
                                    && v["ok"].as_bool() == Some(false)
                                {
                                    eprintln!(
                                        "{} failed: {}",
                                        v["tool"].as_str().unwrap_or("tool"),
                                        v["output"].as_str().unwrap_or("")
                                    );
                                }
                            })
                                as freedas_session::ProgressSink)
                        },
                        headless: true,
                        mcp_disabled: Vec::new(),
                        approver: if auto || !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                            // Piped stdin is prompt input, not an answer
                            // channel; asks become blocked.
                            None
                        } else {
                            Some(std::sync::Arc::new(StdinApprover {
                                json_events: (format == "json")
                                    .then(|| session_id.clone().unwrap_or_default()),
                            })
                                as std::sync::Arc<dyn freedas_tools::PermissionApprover>)
                        },
                        session_rules: Default::default(),
                    },
                    {
                        // First Ctrl-C cancels the run gracefully (partial text
                        // is persisted, in-flight tools abort); a second hits
                        // the default disposition once this task exits.
                        let cancel = tokio_util::sync::CancellationToken::new();
                        let c2 = cancel.clone();
                        tokio::spawn(async move {
                            let _ = tokio::signal::ctrl_c().await;
                            c2.cancel();
                        });
                        cancel
                    },
                )
                .await;
            let r = match run {
                Ok(r) => r,
                // Every error exit ends the JSONL stream with session.error so
                // consumers can tell a terminal failure from a truncated pipe.
                Err(e) => {
                    if format == "json" {
                        println!(
                            "{}",
                            serde_json::json!({
                                "type": "session.error",
                                "sessionID": session_id.as_deref().unwrap_or_default(),
                                "error": e.to_string(),
                            })
                        );
                    }
                    match e {
                        freedas_core::FreedasError::BudgetExceeded => return Ok(4),
                        freedas_core::FreedasError::SandboxUnavailable(m) => {
                            eprintln!("sandbox unavailable: {m}");
                            return Ok(5);
                        }
                        _ => return Err(e.into()),
                    }
                }
            };
            // Name a fresh session from its first exchange.
            if fresh_session && want_title {
                let _ = runner_inst.generate_title(&r.session_id).await;
            }
            if format == "json" {
                let ts = freedas_core::paths::now_ms();
                println!(
                    "{}",
                    serde_json::json!({
                        "type": "message.part.updated",
                        "sessionID": r.session_id,
                        "messageID": r.message_id,
                        "part": {"type": "text", "text": r.text},
                    })
                );
                let (provider, model) = last_assistant_model(&d, &r.session_id);
                if let Ok((input, output, cost)) = d.session_usage(&r.session_id) {
                    println!(
                        "{}",
                        serde_json::json!({
                            "type": "usage",
                            "sessionID": r.session_id,
                            "provider": provider,
                            "model": model,
                            "inputTokens": input,
                            "outputTokens": output,
                            "costUsd": cost,
                        })
                    );
                }
                // Headless runs auto-reject blocked permissions; replay the
                // ask/reply pair so JSON consumers see why.
                for (i, b) in r.blocked.iter().enumerate() {
                    let (action, resource) = b
                        .split_once(": ")
                        .map(|(a, r)| (a.to_string(), r.to_string()))
                        .unwrap_or_else(|| ("permission".into(), b.clone()));
                    let permission_id = format!("perm_{i}");
                    println!(
                        "{}",
                        serde_json::json!({
                            "type": "permission.asked",
                            "sessionID": r.session_id,
                            "permissionID": permission_id,
                            "action": action,
                            "resource": resource,
                        })
                    );
                    println!(
                        "{}",
                        serde_json::json!({
                            "type": "permission.replied",
                            "sessionID": r.session_id,
                            "permissionID": permission_id,
                            "response": "reject",
                        })
                    );
                }
                println!(
                    "{}",
                    serde_json::json!({
                        "type": "session.completed",
                        "sessionID": r.session_id,
                        "completed": r.completed,
                        "timestamp": ts,
                    })
                );
                println!(
                    "{}",
                    serde_json::json!({
                        "type": "result", "sessionID": r.session_id, "text": r.text,
                        "completed": r.completed, "blocked": r.blocked
                    })
                );
            } else {
                if r.text.is_empty() {
                    println!("(done)");
                } else {
                    println!("{}", r.text);
                }
                eprintln!("session {}", r.session_id);
            }
            if !r.blocked.is_empty() {
                for b in &r.blocked {
                    eprintln!("auto-rejecting {b}");
                }
            }
            report_session_metadata(&p, &d, &r, &project_display, &prompt_excerpt, started_at)
                .await;
            // Exit 3 whenever a blocked action was auto-rejected.
            Ok(blocked_exit_code(&r.blocked))
        }
        Some(Commands::Session { command }) => match command {
            crate::SessionCommands::List => {
                let pid = d.ensure_project(&project_root)?;
                for s in d.list_sessions(&pid, 50)? {
                    println!("{}\t{}\t{}\t{}", s.id, s.status, s.agent, s.title);
                }
                Ok(0)
            }
            crate::SessionCommands::Delete { id } => {
                safe_id(&id)?;
                println!("deleted={}", d.delete_session(&id)?);
                // Snapshot trees live under the project id; older layouts also
                // kept a per-session directory.
                let pid = d.ensure_project(&project_root)?;
                for dir in [p.snapshot_dir(&pid).join(&id), p.snapshot_dir(&id)] {
                    if dir.exists() {
                        let _ = std::fs::remove_dir_all(&dir);
                    }
                }
                Ok(0)
            }
            crate::SessionCommands::Fork { id, at } => {
                let pid = d.ensure_project(&project_root)?;
                let new_id = d.fork_session(&pid, &id, at.as_deref())?;
                println!("{}", new_id);
                Ok(0)
            }
            crate::SessionCommands::Rename { id, title } => {
                d.rename_session(&id, &title)?;
                println!("renamed {id}");
                Ok(0)
            }
        },
        Some(Commands::Export {
            id,
            unsanitized,
            output,
        }) => {
            let text = freedas_db::export_session(
                &d,
                &p,
                &project_root,
                id.as_deref(),
                !unsanitized,
                "json",
            )?;
            if let Some(path) = output {
                std::fs::write(path, text)?;
            } else {
                println!("{text}");
            }
            Ok(0)
        }
        Some(Commands::Import { file }) => {
            let text = std::fs::read_to_string(&file)?;
            let v: serde_json::Value = serde_json::from_str(&text)?;
            let pid = d.ensure_project(&project_root)?;
            let report = d.import_session(&pid, &v)?;
            println!(
                "imported session {} from {file} ({} messages, {} parts, {} usage, {} ids remapped)",
                report.session_id, report.messages, report.parts, report.usage, report.remapped
            );
            Ok(0)
        }
        Some(Commands::Stats {
            days,
            tools,
            models,
            project,
        }) => {
            let project_id = match project.as_deref() {
                Some(p) if !p.is_empty() => {
                    let root = if std::path::Path::new(p).is_absolute() {
                        PathBuf::from(p)
                    } else {
                        project_root.join(p)
                    };
                    Some(d.ensure_project(&root)?)
                }
                Some(_) => Some(d.ensure_project(&project_root)?),
                None => None,
            };
            if tools {
                for t in d.tool_usage_totals(days, project_id.as_deref())? {
                    println!(
                        "{}\tcalls={}\tduration_ms={}",
                        t.tool, t.calls, t.duration_ms
                    );
                }
                return Ok(0);
            }
            // Group by recorded provider/model; `--models` keeps
            // `freedas/auto` as its own row because that is what was recorded.
            let totals = d.usage_totals(days, project_id.as_deref(), None)?;
            if models {
                for t in totals {
                    println!(
                        "{}\t{}\tin={}\tout={}\tcost=${:.6}",
                        t.provider, t.model, t.input, t.output, t.cost
                    );
                }
            } else {
                for t in totals {
                    println!(
                        "{}\t{}\tin={}\tout={}\tcost=${:.4}",
                        t.provider, t.model, t.input, t.output, t.cost
                    );
                }
            }
            Ok(0)
        }
        Some(Commands::Sync {
            action,
            json,
            dir,
            memory,
            global,
        }) => {
            let root = dir.map(PathBuf::from).unwrap_or(project_root.clone());
            if let Some(mem) = memory {
                let text = if mem == "-" {
                    use std::io::Read;
                    let mut s = String::new();
                    std::io::stdin().read_to_string(&mut s)?;
                    s
                } else {
                    std::fs::read_to_string(&mem)?
                };
                let records = freedas_memory::parse_memory_import(&text);
                // Project scope by default so an import only affects this project;
                // `--global` opts into user scope. Every record goes through
                // `remember`'s gates (length window, secret refusal) and the
                // parser already capped per-record size and total count.
                let project_id = if global {
                    None
                } else {
                    Some(d.ensure_project(&root)?)
                };
                let mem = freedas_memory::Memory::new(d.clone(), project_id);
                let mut imported = 0usize;
                let mut skipped = 0usize;
                for (kind, text, created_at) in
                    records.iter().take(freedas_memory::MAX_IMPORT_RECORDS)
                {
                    match mem.remember(kind, text, 0.7) {
                        Some(id) => {
                            if let Some(at) = created_at {
                                let _ = d.set_memory_created_at(&id, *at);
                            }
                            imported += 1;
                        }
                        None => skipped += 1,
                    }
                }
                println!("imported {imported} memory records (skipped {skipped})");
                if records.len() >= freedas_memory::MAX_IMPORT_RECORDS {
                    eprintln!(
                        "warn: import truncated at {} records",
                        freedas_memory::MAX_IMPORT_RECORDS
                    );
                }
                if skipped > 0 {
                    eprintln!(
                        "warn: skipped {skipped} records outside the length window or containing secrets"
                    );
                }
                return Ok(0);
            }
            let apply = match sync_apply(&action) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("freedas: {e}");
                    return Ok(2);
                }
            };
            let entries = freedas_sync::detect(&root);
            if apply {
                let (applied, skipped) = freedas_sync::apply(&root)?;
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"applied": applied, "skipped": skipped})
                    );
                } else {
                    println!("synced {applied} entries (skipped {skipped} unchanged)");
                }
            } else if json {
                println!("{}", serde_json::to_string_pretty(&entries.iter().map(|e| serde_json::json!({"source": e.source, "target": e.target, "kind": e.kind})).collect::<Vec<_>>())?);
            } else {
                for e in &entries {
                    println!("{} -> {} ({})", e.source, e.target, e.kind);
                }
            }
            Ok(0)
        }
        Some(Commands::Agent { command }) => match command {
            crate::AgentCommands::List => {
                for a in freedas_agent::merged_agents(&project_root, cfg.trust_project_code) {
                    println!("{}\t{}\t{}", a.id, a.mode, a.description);
                }
                Ok(0)
            }
            crate::AgentCommands::Create {
                global,
                id,
                description,
                mode,
                model,
                permission,
            } => {
                let dir = if global {
                    p.config_dir.join("agents")
                } else {
                    project_root.join(".freedas").join("agents")
                };
                if id.is_none() && !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                    println!(
                        "template: {}\npass --id <name> (optionally --description/--mode/--model/--permission) to write it non-interactively",
                        dir.join("<id>.md").display()
                    );
                    return Ok(0);
                }
                let tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
                let id = id.unwrap_or_else(|| prompt_line("id", "reviewer"));
                if id.is_empty() || id.contains("..") || id.starts_with('/') {
                    return Err("agent id must be a relative path".into());
                }
                let description = description.unwrap_or_else(|| {
                    if tty {
                        prompt_line("description", "Review migrations for data loss")
                    } else {
                        "Review migrations for data loss".into()
                    }
                });
                let mode = mode.unwrap_or_else(|| {
                    if tty {
                        prompt_line("mode (primary|subagent|all)", "primary")
                    } else {
                        "primary".into()
                    }
                });
                let model = model.unwrap_or_else(|| {
                    if tty {
                        prompt_line("model (blank = inherit)", "")
                    } else {
                        String::new()
                    }
                });
                let mut permission = permission;
                if permission.is_empty() && tty {
                    let raw = prompt_line(
                        "permissions (action:resource=effect, comma separated; blank = inherit)",
                        "",
                    );
                    permission = raw
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect();
                }
                // Frontmatter is `key: value` lines; a newline in any field
                // would inject extra keys into the generated file.
                for (name, v) in [
                    ("id", id.as_str()),
                    ("description", description.as_str()),
                    ("mode", mode.as_str()),
                    ("model", model.as_str()),
                ]
                .into_iter()
                .chain(permission.iter().map(|p| ("permission", p.as_str())))
                {
                    if v.chars().any(|c| c == '\n' || c == '\r') {
                        return Err(format!("{name} must not contain newlines").into());
                    }
                }
                std::fs::create_dir_all(&dir)?;
                let file = dir.join(format!("{id}.md"));
                if file.exists() {
                    println!("agent already exists: {}", file.display());
                    return Ok(0);
                }
                let mut fm = format!("---\ndescription: {description}\nmode: {mode}\n");
                if !model.trim().is_empty() {
                    fm.push_str(&format!("model: {}\n", model.trim()));
                }
                let mut rules = Vec::new();
                for spec in &permission {
                    let Some((action, rest)) = spec.split_once(':') else {
                        continue;
                    };
                    let Some((resource, effect)) = rest.split_once('=') else {
                        continue;
                    };
                    rules.push((action.trim(), resource.trim(), effect.trim()));
                }
                if !rules.is_empty() {
                    fm.push_str("permission:\n");
                    for (action, resource, effect) in &rules {
                        if *resource == "*" {
                            fm.push_str(&format!("  {action}: {effect}\n"));
                        } else {
                            fm.push_str(&format!("  {action}:\n    \"{resource}\": {effect}\n"));
                        }
                    }
                }
                fm.push_str(&format!("---\nYou are the {id} agent. {description}\n"));
                if let Some(parent) = file.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&file, fm)?;
                println!("created {}", file.display());
                Ok(0)
            }
        },
        Some(Commands::Skill { command }) => match command {
            crate::SkillCommands::List { local, auto } => {
                if auto {
                    for s in freedas_skill::discover(&project_root)
                        .into_iter()
                        .filter(|s| s.autogenerated)
                    {
                        println!("{}\t{}", s.id, s.description);
                    }
                } else if local {
                    for s in freedas_skill::discover(&project_root) {
                        println!("{}\t{}", s.id, s.description);
                    }
                } else {
                    let token = freedas_provider::credentials::api_key_for(&p.data_dir, "control");
                    match freedas_skill::registry::list_skills(token.as_deref()).await {
                        Ok(rows) => {
                            if rows.is_empty() {
                                println!("(no skills published in this workspace)");
                            }
                            for (name, description) in rows {
                                println!("{name}\t{description}");
                            }
                        }
                        Err(e) => eprintln!("(no team registry: {e})"),
                    }
                }
                Ok(0)
            }
            crate::SkillCommands::Push { name, dir } => {
                safe_id(&name)?;
                let dir = dir
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|| project_root.join(".freedas").join("skills").join(&name));
                let token = freedas_provider::credentials::api_key_for(&p.data_dir, "control");
                println!(
                    "{}",
                    freedas_skill::registry::push_skill(&name, &dir, token.as_deref()).await?
                );
                Ok(0)
            }
            crate::SkillCommands::Pull {
                name,
                global,
                force,
            } => {
                safe_id(&name)?;
                let dest = if global {
                    p.config_dir.join("skills").join(&name)
                } else {
                    project_root.join(".freedas").join("skills").join(&name)
                };
                let token = freedas_provider::credentials::api_key_for(&p.data_dir, "control");
                println!(
                    "{}",
                    freedas_skill::registry::pull_skill(&name, &dest, token.as_deref(), force,)
                        .await?
                );
                Ok(0)
            }
            crate::SkillCommands::Forget { id } => {
                safe_id(&id)?;
                let removed = freedas_skill::forget_skill(&project_root, &cfg.skills, &id);
                for dir in &removed {
                    println!("removed {}", dir.display());
                }
                if removed.is_empty() {
                    println!("skill {id} not found");
                }
                // A losing same-id copy can re-surface once the winner is
                // gone; report what still resolves so the operator knows.
                if freedas_skill::discover_with(&project_root, &cfg.skills)
                    .iter()
                    .any(|sk| sk.id == id)
                {
                    eprintln!(
                        "warning: skill {id} still resolves from a copy outside the removed roots"
                    );
                }
                Ok(0)
            }
        },
        Some(Commands::Mcp { command }) => {
            match command {
                crate::McpCommands::List => {
                    for s in freedas_mcp::status_from_config(&cfg) {
                        println!(
                            "{}\t{}\ttools={} prompts={}",
                            s.name,
                            s.state,
                            s.tools_label(),
                            s.prompts_label()
                        );
                    }
                }
                crate::McpCommands::Add { name, url, command } => {
                    let entry = if let Some(url) = url {
                        serde_json::json!({"type": "remote", "url": url})
                    } else if !command.is_empty() {
                        serde_json::json!({"type": "local", "command": command})
                    } else {
                        eprintln!("freedas: mcp add needs --url <url> or a command after --");
                        return Ok(2);
                    };
                    write_config_entry(&project_root, "mcp", &name, entry)?;
                    println!("added mcp {name}");
                }
                crate::McpCommands::Auth { name } => {
                    // Remote servers use OAuth when the server advertises it.
                    if let Some(sc) = cfg.mcp.get(&name)
                        && let Some(url) = &sc.url
                    {
                        println!("starting OAuth for {name}…");
                        match freedas_mcp::oauth::authorize(url).await {
                            Ok(tokens) => {
                                freedas_provider::credentials::store(
                                    &p.data_dir,
                                    &format!("mcp-{name}"),
                                    &tokens.access_token,
                                )?;
                                if let Some(refresh) = tokens.refresh_token {
                                    freedas_provider::credentials::store(
                                        &p.data_dir,
                                        &format!("mcp-{name}-refresh"),
                                        &refresh,
                                    )?;
                                }
                                if let Some(url) = tokens.token_endpoint {
                                    freedas_provider::credentials::store(
                                        &p.data_dir,
                                        &format!("mcp-{name}-token-url"),
                                        &url,
                                    )?;
                                }
                                println!("stored credential for mcp {name}");
                                return Ok(0);
                            }
                            Err(e) => eprintln!("oauth: {e}; falling back to a token"),
                        }
                    }
                    let env_key = format!("MCP_{}_TOKEN", name.to_uppercase());
                    let mut token = std::env::var(&env_key).unwrap_or_default();
                    if token.is_empty() && std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                        token = rpassword::prompt_password(format!("OAuth token for {name}: "))
                            .unwrap_or_default()
                            .trim()
                            .to_string();
                    }
                    if token.is_empty() {
                        println!("no token provided; set {env_key} or enter one interactively");
                    } else {
                        freedas_provider::credentials::store(
                            &p.data_dir,
                            &format!("mcp-{name}"),
                            &token,
                        )?;
                        println!("stored credential for mcp {name}");
                    }
                }
                crate::McpCommands::Logout { name } => {
                    freedas_provider::credentials::remove(&p.data_dir, &format!("mcp-{name}"))?;
                    freedas_provider::credentials::remove(
                        &p.data_dir,
                        &format!("mcp-{name}-refresh"),
                    )?;
                    freedas_provider::credentials::remove(
                        &p.data_dir,
                        &format!("mcp-{name}-token-url"),
                    )?;
                    println!("removed credential for mcp {name}");
                }
                crate::McpCommands::Debug { name } => {
                    let Some(sc) = cfg.mcp.get(&name) else {
                        return Err(format!("mcp server {name} is not configured").into());
                    };
                    let auth = freedas_provider::credentials::api_key_for(
                        &p.data_dir,
                        &format!("mcp-{name}"),
                    );
                    // Route through the same per-hash trust gate session
                    // connects use; debugging an unapproved project server
                    // must not silently become code execution.
                    let server = freedas_mcp::connect_configured_with_approval(
                        &name,
                        sc,
                        auth.as_deref(),
                        cfg.trust_project_code,
                    )
                    .await;
                    match server {
                        Ok(s) => {
                            println!("connected to {name}");
                            if let Ok(tools) = freedas_mcp::list_tools(&s).await {
                                for t in tools.tools {
                                    println!("tool\t{}", t.name);
                                }
                            }
                            if let Ok(prompts) = freedas_mcp::list_prompts(&s).await {
                                for pr in prompts {
                                    println!("prompt\t{pr}");
                                }
                            }
                        }
                        Err(e) => eprintln!("connect failed: {e}"),
                    }
                }
            }
            Ok(0)
        }
        Some(Commands::Plugin {
            module,
            global,
            command,
        }) => {
            let (list, remove, update) = match &command {
                Some(crate::PluginCommands::List) => (true, None, None),
                Some(crate::PluginCommands::Remove { name }) => (false, Some(name.clone()), None),
                Some(crate::PluginCommands::Update { name }) => (false, None, Some(name.clone())),
                None => (false, None, None),
            };
            if list {
                for spec in &cfg.plugin {
                    match spec {
                        freedas_core::config::PluginSpec::Simple(s) => println!("{s}"),
                        freedas_core::config::PluginSpec::WithOptions { package, .. } => {
                            println!("{package}")
                        }
                    }
                }
            } else if let Some(m) = module {
                let value = freedas_plugin::install(&m, &p.data_dir).await?;
                let path = if global {
                    p.global_config().to_path_buf()
                } else {
                    project_root.join(".freedas").join("freedas.json")
                };
                append_config_array_at(&path, "plugin", value)?;
                println!("installed plugin {m}");
            } else if let Some(r) = &remove {
                // Specs are stored as installed paths like
                // `<data>/plugins/<name>@<ver>` or `[<path>, {opts}]`; match the
                // name either way so `plugin remove <name>` works.
                let matches = |v: &serde_json::Value| {
                    let spec = v
                        .as_str()
                        .or_else(|| v.get("package").and_then(|p| p.as_str()));
                    let Some(spec) = spec else { return false };
                    spec == r
                        || spec == format!("{r}.ts")
                        || spec
                            .rsplit('/')
                            .next()
                            .is_some_and(|base| base == *r || base.starts_with(&format!("{r}@")))
                };
                let mut found = false;
                for path in [
                    project_root.join(".freedas").join("freedas.json"),
                    p.global_config().to_path_buf(),
                ] {
                    if !path.exists() {
                        continue;
                    }
                    let mut root = read_config(&path)?;
                    let before = root["plugin"].as_array().map(Vec::len).unwrap_or(0);
                    if let Some(arr) = root["plugin"].as_array_mut() {
                        arr.retain(|v| !matches(v));
                    }
                    let after = root["plugin"].as_array().map(Vec::len).unwrap_or(0);
                    if after != before {
                        found = true;
                        std::fs::write(&path, serde_json::to_string_pretty(&root)?)?;
                    }
                }
                // Delete the installed package dir if it lives under the
                // managed plugins dir.
                let dir = p.data_dir.join("plugins");
                if let Ok(rd) = std::fs::read_dir(&dir) {
                    for e in rd.flatten() {
                        let base = e.file_name().to_string_lossy().to_string();
                        if base == *r || base.starts_with(&format!("{r}@")) {
                            let path = e.path();
                            let _ = std::fs::remove_dir_all(&path);
                            freedas_plugin::prune_trust(&path);
                            found = true;
                        }
                    }
                }
                if found {
                    println!("removed plugin {r}");
                } else {
                    println!("plugin {r} not installed");
                }
            } else if let Some(update_name) = update {
                if let Some(only) = &update_name {
                    // Update just this npm package when it has a manifest.
                    let installed = std::fs::read_dir(p.data_dir.join("plugins"))
                        .ok()
                        .into_iter()
                        .flatten()
                        .flatten()
                        .any(|e| {
                            e.file_name().to_string_lossy().starts_with(only.as_str())
                                && e.path().join("freedas-install.json").exists()
                        });
                    if installed {
                        freedas_plugin::install(only, &p.data_dir).await?;
                        println!("updated {only}");
                    } else {
                        println!("plugin {only} is not an installed npm plugin");
                    }
                } else {
                    let updated = freedas_plugin::update(&p.data_dir).await?;
                    if updated.is_empty() {
                        println!("no npm plugins installed");
                    }
                    for name in updated {
                        println!("updated {name}");
                    }
                }
            } else if global {
                println!("(plugin flag requires a module)");
            }
            Ok(0)
        }
        Some(Commands::Models { json }) => {
            // Only show models you can actually call: enabled provider plus a
            // stored credential (or its env key).
            let cat: Vec<_> = freedas_catalog::builtin_catalog()
                .into_iter()
                .filter(|m| cfg.provider_enabled(&m.provider))
                .filter(|m| {
                    freedas_provider::credentials::api_key_for(&p.data_dir, &m.provider)
                        .is_some_and(|k| !k.trim().is_empty())
                })
                .collect();
            if json {
                println!("{}", serde_json::to_string_pretty(&cat)?);
            } else {
                for m in cat {
                    println!(
                        "{}\t{}\t{}\t{}\t{}",
                        m.tier,
                        m.full_id(),
                        m.context,
                        m.max_output,
                        m.quality
                    );
                }
            }
            Ok(0)
        }
        Some(Commands::Providers { command }) => {
            match command {
                crate::ProvidersCommands::Login { provider } => {
                    let provider = match provider {
                        Some(provider) => provider,
                        None if std::io::IsTerminal::is_terminal(&std::io::stdin()) => {
                            match choose_provider() {
                                Some(provider) => provider,
                                None => {
                                    eprintln!("invalid provider selection");
                                    return Ok(2);
                                }
                            }
                        }
                        None => "freedas".to_string(),
                    };
                    // The `freedas` gateway uses the control plane's device flow.
                    // Every other table provider runs through the shared OAuth /
                    // device-code / API-key engine.
                    if provider != "freedas"
                        && let Some(definition) = freedas_provider::oauth::providers()
                            .iter()
                            .find(|candidate| candidate.id == provider)
                    {
                        // API-key providers can be configured non-interactively
                        // from the provider's documented environment variable.
                        if matches!(
                            definition.login,
                            freedas_provider::oauth::LoginKind::ApiKey(_)
                        ) {
                            for env in definition.env {
                                if let Ok(key) = std::env::var(env)
                                    && !key.trim().is_empty()
                                {
                                    let stored =
                                        freedas_provider::oauth::credential_provider(&provider);
                                    freedas_provider::credentials::store(
                                        &p.data_dir,
                                        stored,
                                        key.trim(),
                                    )?;
                                    println!("stored credential for {provider}");
                                    return Ok(0);
                                }
                            }
                        }
                        let mut auth_cb =
                            |url: &str, launch: Option<&str>, instructions: Option<&str>| {
                                if let Some(instructions) = instructions {
                                    eprintln!("{instructions}");
                                }
                                eprintln!("Open: {url}");
                                if let Some(launch) = launch {
                                    eprintln!("If the browser does not open, visit: {launch}");
                                }
                            };
                        let mut progress_cb = |message: &str| eprintln!("{message}");
                        let mut prompt_cb = |prompt: &freedas_provider::oauth::OAuthPrompt| {
                            use std::io::{BufRead, Write};
                            eprint!("{}", prompt.message);
                            if let Some(placeholder) = &prompt.placeholder {
                                eprint!(" [{placeholder}]");
                            }
                            eprint!(" ");
                            let _ = std::io::stderr().flush();
                            let mut line = String::new();
                            let _ = std::io::stdin().lock().read_line(&mut line);
                            let answer = line.trim().to_string();
                            if answer.is_empty() && !prompt.allow_empty {
                                return Err("login cancelled".into());
                            }
                            Ok(answer)
                        };
                        let mut manual_cb = || {
                            use std::io::{BufRead, Write};
                            eprint!("Paste the redirect URL or authorization code: ");
                            let _ = std::io::stderr().flush();
                            let mut line = String::new();
                            let _ = std::io::stdin().lock().read_line(&mut line);
                            let answer = line.trim().to_string();
                            if answer.is_empty() {
                                Err("login cancelled".into())
                            } else {
                                Ok(answer)
                            }
                        };
                        let mut host = freedas_provider::oauth::LoginHost {
                            on_auth: Some(&mut auth_cb),
                            on_progress: Some(&mut progress_cb),
                            on_prompt: Some(&mut prompt_cb),
                            on_manual_code: Some(&mut manual_cb),
                            open_browser: std::io::IsTerminal::is_terminal(&std::io::stdin()),
                            data_dir: &p.data_dir,
                        };
                        match freedas_provider::oauth::run_login(&provider, &mut host).await {
                            Ok(freedas_provider::oauth::LoginResult::ApiKey(key)) => {
                                let stored =
                                    freedas_provider::oauth::credential_provider(&provider);
                                freedas_provider::credentials::store(&p.data_dir, stored, &key)?;
                                println!("stored credential for {provider}");
                                return Ok(0);
                            }
                            Ok(freedas_provider::oauth::LoginResult::OAuth(credentials)) => {
                                let stored =
                                    freedas_provider::oauth::credential_provider(&provider);
                                freedas_provider::oauth::store_oauth(
                                    &p.data_dir,
                                    stored,
                                    &credentials,
                                )?;
                                println!("stored credential for {provider}");
                                return Ok(0);
                            }
                            Err(error) => {
                                eprintln!("login failed: {error}");
                                return Ok(1);
                            }
                        }
                    }
                    // Interactive API-key prompt; falls back to env var. OpenCode
                    // Go and Zen share one key.
                    let env_key = format!("{}_API_KEY", provider.to_uppercase().replace('-', "_"));
                    let shared_opencode = std::env::var("OPENCODE_API_KEY").ok();
                    let mut key = std::env::var(&env_key)
                        .ok()
                        .or_else(|| {
                            provider
                                .starts_with("opencode")
                                .then(|| shared_opencode.clone())
                                .flatten()
                        })
                        .unwrap_or_default();
                    if key.is_empty()
                        && provider == "freedas"
                        && let Some(url) = control_url(&p)
                    {
                        match freedas_provider::credentials::device_login(&url, &p.data_dir).await {
                            Ok(login) => {
                                let workspace = login
                                    .workspace_slug
                                    .or(login.workspace_id)
                                    .unwrap_or_else(|| "personal".into());
                                println!("signed in to {workspace}");
                                return Ok(0);
                            }
                            Err(e) => eprintln!("device login failed: {e}"),
                        }
                    }
                    if key.is_empty() && std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                        eprint!("API key for {provider}: ");
                        use std::io::{BufRead, Write};
                        std::io::stderr().flush().ok();
                        let mut line = String::new();
                        std::io::stdin().lock().read_line(&mut line).ok();
                        key = line.trim().to_string();
                    }
                    if key.is_empty() {
                        eprintln!("no key provided; set {env_key} or provide one interactively");
                        return Ok(1);
                    } else {
                        freedas_provider::credentials::store(&p.data_dir, &provider, &key)?;
                        println!("stored credential for {provider}");
                    }
                }
                crate::ProvidersCommands::List => {
                    let mut names = std::collections::BTreeSet::new();
                    for name in freedas_provider::credentials::load(&p.data_dir)
                        .unwrap_or_default()
                        .keys()
                    {
                        if name != CONTROL_URL_KEY {
                            names.insert(name.clone());
                        }
                    }
                    for name in freedas_provider::oauth::load_oauth(&p.data_dir)
                        .unwrap_or_default()
                        .keys()
                    {
                        names.insert(name.clone());
                    }
                    if names.is_empty() {
                        println!("(no providers authenticated)");
                    }
                    for name in names {
                        println!("{name}\tstored");
                    }
                }
                crate::ProvidersCommands::Logout { provider } => {
                    let name = provider.unwrap_or_default();
                    let remove_stored =
                        |data_dir: &std::path::Path,
                         name: &str|
                         -> Result<bool, Box<dyn std::error::Error>> {
                            let mut removed = false;
                            let alias = freedas_provider::oauth::credential_provider(name);
                            for key in [name, alias] {
                                let stored = freedas_provider::credentials::load(data_dir)
                                    .unwrap_or_default()
                                    .contains_key(key);
                                let oauth = freedas_provider::oauth::load_oauth(data_dir)?
                                    .contains_key(key);
                                if stored {
                                    freedas_provider::credentials::remove(data_dir, key)?;
                                    removed = true;
                                }
                                if oauth {
                                    freedas_provider::oauth::remove_oauth(data_dir, key)?;
                                    removed = true;
                                }
                            }
                            Ok(removed)
                        };
                    if name.is_empty() {
                        // Docs: `providers logout [name]` — no name logs out of
                        // every provider that has a stored credential. MCP,
                        // relay, and control-plane entries are not providers.
                        let mut candidates = std::collections::BTreeSet::new();
                        for candidate in known_providers() {
                            candidates.insert(candidate);
                        }
                        for candidate in freedas_provider::credentials::load(&p.data_dir)
                            .unwrap_or_default()
                            .keys()
                        {
                            if candidate != CONTROL_URL_KEY {
                                candidates.insert(candidate.clone());
                            }
                        }
                        for candidate in freedas_provider::oauth::load_oauth(&p.data_dir)?.keys() {
                            candidates.insert(candidate.clone());
                        }
                        let mut removed_any = false;
                        for candidate in candidates {
                            if remove_stored(&p.data_dir, &candidate)? {
                                println!("removed credential for {candidate}");
                                removed_any = true;
                            }
                        }
                        if !removed_any {
                            println!("no stored provider credentials");
                        }
                    } else {
                        remove_stored(&p.data_dir, &name)?;
                        println!("removed credential for {name}");
                    }
                }
            }
            Ok(0)
        }
        Some(Commands::Workspace { command }) => {
            match command {
                crate::WorkspaceCommands::List => match control_get(&p, "/workspaces").await {
                    Ok(v) => {
                        if let Some(slug) = &cfg.workspace {
                            let _ = freedas_provider::credentials::cache_org_settings(&p, &v, slug);
                        }
                        for w in v.as_array().cloned().unwrap_or_default() {
                            println!(
                                "{}\t{}\t{}",
                                w["slug"].as_str().unwrap_or(""),
                                w["name"].as_str().unwrap_or(""),
                                w["role"].as_str().unwrap_or("")
                            );
                        }
                    }
                    Err(e) => eprintln!("(no workspaces: {e})"),
                },
                crate::WorkspaceCommands::Use { slug } => {
                    if let Ok(v) = control_get(&p, "/workspaces").await {
                        let _ = freedas_provider::credentials::cache_org_settings(&p, &v, &slug);
                    }
                    let mut cfgv = read_config(&p.global_config())?;
                    cfgv["workspace"] = serde_json::json!(slug);
                    if let Some(parent) = p.global_config().parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(p.global_config(), serde_json::to_string_pretty(&cfgv)?)?;
                    println!("workspace {slug}");
                }
            }
            Ok(0)
        }
        Some(Commands::Attach { url }) => {
            if cli.worktree.is_some() {
                eprintln!("freedas: --worktree cannot be used with attach");
                return Ok(2);
            }
            // Read-only live transcript view of a running server.
            let sessions = freedas_server::client::list_sessions(&url)
                .await
                .map_err(|e| scrub_url(&e, &url))?;
            let mut target = cli.session.clone();
            if target.is_none() && cli.continue_ {
                target = sessions
                    .first()
                    .and_then(|s| s.get("id"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
            }
            println!("attached to {}", display_url(&url));
            for s in &sessions {
                let id = s.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let title = s.get("title").and_then(|v| v.as_str()).unwrap_or("");
                let mark = if target.as_deref() == Some(id) {
                    "*"
                } else {
                    " "
                };
                println!("{mark} {id}\t{title}");
            }
            freedas_server::client::stream_events(&url, |event: serde_json::Value| async move {
                let kind = event.get("type").and_then(|v| v.as_str()).unwrap_or("");
                match kind {
                    "message.part.delta" => {
                        if let Some(t) = event.get("text").and_then(|v| v.as_str()) {
                            use std::io::Write;
                            print!("{t}");
                            let _ = std::io::stdout().flush();
                        }
                    }
                    "message.part.updated" => {
                        if let Some(t) = event.get("text").and_then(|v| v.as_str())
                            && !t.is_empty()
                        {
                            println!("\n{t}");
                        }
                    }
                    "permission.asked" => println!(
                        "[permission] {} {}",
                        event.get("action").and_then(|v| v.as_str()).unwrap_or(""),
                        event.get("resource").and_then(|v| v.as_str()).unwrap_or("")
                    ),
                    "session.marker" => {
                        if let Some(m) = event.get("marker").and_then(|v| v.as_str()) {
                            println!("[{m}]");
                        }
                    }
                    "tool.result" => {
                        if event.get("ok").and_then(|v| v.as_bool()) == Some(false) {
                            println!(
                                "[tool failed] {}: {}",
                                event.get("tool").and_then(|v| v.as_str()).unwrap_or("tool"),
                                event.get("output").and_then(|v| v.as_str()).unwrap_or("")
                            );
                        }
                    }
                    "session.completed" | "session.error" | "session.idle" | "session.stopped" => {
                        println!("[{kind}]")
                    }
                    _ => {}
                }
            })
            .await
            .map_err(|e| scrub_url(&e, &url))?;
            Ok(0)
        }
        Some(Commands::Pr { number }) => {
            if number < 1 {
                return Err("PR number must be positive".into());
            }
            // Prefer `gh pr checkout`; fall back to a git fetch of the PR ref.
            let gh = tokio::process::Command::new("gh")
                .args(["pr", "checkout", &number.to_string()])
                .current_dir(&project_root)
                .output()
                .await;
            let ok = gh.as_ref().map(|o| o.status.success()).unwrap_or(false);
            if ok {
                println!("checked out PR #{number}");
            } else {
                let branch = format!("pr-{number}");
                let fetch = tokio::process::Command::new("git")
                    .args(["fetch", "origin", &format!("pull/{number}/head:{branch}")])
                    .current_dir(&project_root)
                    .output()
                    .await?;
                if !fetch.status.success() {
                    return Err("failed to fetch PR ref (is `gh` installed? or set a token)".into());
                }
                let out = tokio::process::Command::new("git")
                    .args(["checkout", "-B", &branch])
                    .current_dir(&project_root)
                    .output()
                    .await?;
                if !out.status.success() {
                    return Err(format!(
                        "git checkout failed: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    )
                    .into());
                }
                println!("checked out PR #{number} on branch {branch}");
            }
            // Start the TUI in that checkout.
            if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                std::env::set_current_dir(&project_root).ok();
                freedas_tui::run()?;
            }
            Ok(0)
        }
        Some(Commands::Web { port }) => {
            let port = port.unwrap_or(4096);
            let url = format!("http://127.0.0.1:{port}/");
            println!("Freedas web UI: {url}");
            // Open the browser when a TTY is present.
            if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                let opener = if cfg!(target_os = "macos") {
                    "open"
                } else {
                    "xdg-open"
                };
                let _ = tokio::process::Command::new(opener)
                    .arg(&url)
                    .status()
                    .await;
            }
            freedas_server::serve("127.0.0.1", port).await?;
            Ok(0)
        }
        Some(Commands::Serve {
            port,
            hostname,
            cors,
            allow_remote,
        }) => {
            let hostname = hostname.unwrap_or("127.0.0.1".into());
            // A non-loopback bind exposes every session to the network. Fail
            // closed unless the operator both opts in and configures the token
            // the server enforces.
            let exposed = !matches!(
                hostname.as_str(),
                "127.0.0.1" | "localhost" | "::1" | "[::1]"
            );
            if exposed {
                if !allow_remote {
                    return Err(format!(
                        "refusing to bind {hostname}; pass --allow-remote and set FREEDAS_SERVER_TOKEN"
                    )
                    .into());
                }
                let token = std::env::var("FREEDAS_SERVER_TOKEN").unwrap_or_default();
                let password = std::env::var("FREEDAS_SERVER_PASSWORD").unwrap_or_default();
                if token.trim().is_empty() && password.trim().is_empty() {
                    return Err(format!(
                        "refusing to bind {hostname} without auth; set FREEDAS_SERVER_TOKEN or FREEDAS_SERVER_PASSWORD"
                    )
                    .into());
                }
            }
            freedas_server::serve_with_cors(&hostname, port.unwrap_or(4096), cors).await?;
            Ok(0)
        }
        Some(Commands::Acp) => {
            freedas_acp::run()?;
            Ok(0)
        }
        Some(Commands::Relay { command }) => {
            let state = p.state_dir.join("relay.json");
            match command {
                crate::RelayCommands::Start { foreground } => {
                    let url = std::env::var("FREEDAS_RELAY_URL")
                        .unwrap_or_else(|_| "ws://127.0.0.1:4098/ws".to_string());
                    let token = std::env::var("FREEDAS_RELAY_TOKEN")
                        .ok()
                        .filter(|t| !t.is_empty())
                        .or_else(|| {
                            freedas_provider::credentials::api_key_for(&p.data_dir, "relay")
                                .filter(|t| !t.is_empty())
                        })
                        .unwrap_or_default();
                    if !foreground {
                        // Daemonize by re-executing with --foreground.
                        let exe = std::env::current_exe()?;
                        let log = std::fs::File::create(p.state_dir.join("relay.log"))?;
                        let err = log.try_clone()?;
                        std::process::Command::new(exe)
                            .args(["relay", "start", "--foreground"])
                            .stdout(log)
                            .stderr(err)
                            .stdin(std::process::Stdio::null())
                            .spawn()?;
                        println!("relay started");
                        return Ok(0);
                    }
                    freedas_relay::daemon::start(freedas_relay::daemon::DaemonOptions {
                        url,
                        token,
                        paths: p.clone(),
                    })
                    .await
                    .map_err(|e| format!("relay: {e}"))?;
                    Ok(0)
                }
                crate::RelayCommands::Stop => {
                    freedas_relay::daemon::stop(&p).map_err(|e| format!("relay: {e}"))?;
                    println!("relay stopped");
                    Ok(0)
                }
                crate::RelayCommands::Share { id } => {
                    let mut v: serde_json::Value = std::fs::read_to_string(&state)
                        .ok()
                        .and_then(|t| serde_json::from_str(&t).ok())
                        .unwrap_or_else(|| serde_json::json!({"running": false}));
                    if !v["shared"].is_array() {
                        v["shared"] = serde_json::json!([]);
                    }
                    if let Some(arr) = v["shared"].as_array_mut()
                        && !arr.iter().any(|s| s == &serde_json::json!(id))
                    {
                        arr.push(serde_json::json!(id));
                    }
                    std::fs::write(&state, serde_json::to_string_pretty(&v)?)?;
                    println!("shared {id} (daemon applies it on its next 2s poll)");
                    Ok(0)
                }
                crate::RelayCommands::Unshare { id } => {
                    if let Ok(t) = std::fs::read_to_string(&state) {
                        let mut v: serde_json::Value = serde_json::from_str(&t)?;
                        if let Some(arr) = v["shared"].as_array_mut() {
                            arr.retain(|s| s != &serde_json::json!(id));
                        }
                        std::fs::write(&state, serde_json::to_string_pretty(&v)?)?;
                    }
                    println!("unshared {id} (daemon applies it on its next 2s poll)");
                    Ok(0)
                }
                crate::RelayCommands::Status => {
                    let v: serde_json::Value = std::fs::read_to_string(&state)
                        .ok()
                        .and_then(|t| serde_json::from_str(&t).ok())
                        .unwrap_or_else(|| serde_json::json!({"running": false}));
                    let running = v["running"].as_bool().unwrap_or(false);
                    println!("relay: {}", if running { "running" } else { "stopped" });
                    if let Some(arr) = v["shared"].as_array() {
                        for s in arr {
                            println!("shared\t{}", s.as_str().unwrap_or(""));
                        }
                    }
                    Ok(0)
                }
            }
        }
        Some(Commands::Router { command }) => {
            match command {
                crate::RouterCommands::Explain { last } => {
                    let pid = d.ensure_project(&project_root)?;
                    let decision = d.last_router_decision(&pid)?;
                    match (last, decision) {
                        (_, Some(meta)) => {
                            let v: serde_json::Value = serde_json::from_str(&meta)?;
                            println!("{}", serde_json::to_string_pretty(&v["router"])?);
                        }
                        (_, None) => println!("(no router decisions yet)"),
                    }
                }
                crate::RouterCommands::Stats => {
                    for r in d.router_stats()? {
                        println!(
                            "{}\t{}\tattempts={} succ={} fail={} cost=${:.4}",
                            r.task_class,
                            r.model,
                            r.attempts,
                            r.successes,
                            r.failures,
                            r.total_cost
                        );
                    }
                }
            }
            Ok(0)
        }
        Some(Commands::Memory { command }) => {
            // Scoped to the current project unless --global widens it.
            let mem_scope = |d: &freedas_db::Db,
                             global: bool|
             -> Result<Option<String>, Box<dyn std::error::Error>> {
                if global {
                    Ok(None)
                } else {
                    Ok(Some(d.ensure_project(&project_root)?))
                }
            };
            match command {
                crate::MemoryCommands::List { global } => {
                    let scope = mem_scope(&d, global)?;
                    let mem = freedas_memory::Memory::new(d, scope);
                    for t in mem.recall(50) {
                        println!("- {}", freedas_core::redact::redact(&t));
                    }
                    Ok(0)
                }
                crate::MemoryCommands::Show { id, global } => {
                    match d.get_memory(&id)? {
                        Some((scope, kind, text, confidence, project_id)) => {
                            let cur = mem_scope(&d, global)?;
                            if cur.is_some() && scope == "project" && project_id != cur {
                                return Err(format!(
                                    "memory {id} belongs to another project; pass --global"
                                )
                                .into());
                            }
                            println!("{id}\tscope={scope}\tkind={kind}\tconfidence={confidence}");
                            println!("{}", freedas_core::redact::redact(&text));
                        }
                        None => println!("memory {id} not found"),
                    }
                    Ok(0)
                }
                crate::MemoryCommands::Forget { id, global } => {
                    // Ownership check before delete so one project's CLI
                    // cannot erase another project's rows.
                    if let Some((scope, _, _, _, project_id)) = d.get_memory(&id)? {
                        let cur = mem_scope(&d, global)?;
                        if cur.is_some() && scope == "project" && project_id != cur {
                            return Err(format!(
                                "memory {id} belongs to another project; pass --global"
                            )
                            .into());
                        }
                    }
                    println!("forgot={}", d.delete_memory(&id)?);
                    Ok(0)
                }
                crate::MemoryCommands::Export => {
                    print!("{}", d.export_memory()?);
                    Ok(0)
                }
            }
        }
        Some(Commands::Rules) => {
            // Print exactly the documented block; it already ends in a newline.
            print!("{RULES}");
            Ok(0)
        }
        Some(Commands::Bench { command }) => match command {
            crate::BenchCommands::Run {
                suite,
                repeat,
                router,
                model,
                json,
            } => {
                let router_mode = match router.as_deref() {
                    None => None,
                    Some("static") | Some("learned") | Some("off") => router.clone(),
                    Some(other) => {
                        eprintln!(
                            "freedas: --router must be one of static|learned|off, got {other:?}"
                        );
                        return Ok(2);
                    }
                };
                let mut bench_cfg = config::load(&p, false)?;
                if let Some(m) = &model
                    && freedas_catalog::get_model(&freedas_catalog::builtin_catalog(), m).is_none()
                {
                    eprintln!(
                        "freedas: --model {m:?} is not in the catalog;                          an unknown pin runs unpriced and unfiltered"
                    );
                    return Ok(2);
                }
                if let Some(m) = &router_mode {
                    bench_cfg.router.mode = m.clone();
                    bench_cfg.router.learn = m == "learned";
                }
                eprintln!(
                    "freedas: bench runs the agent with bypassed permissions;                      only run suites whose tasks you trust"
                );
                let suite_path = std::path::PathBuf::from(&suite);
                let repeat = repeat.unwrap_or(1);
                let mut results = Vec::new();
                for task_dir in freedas_bench::list_tasks(&suite_path) {
                    let task = freedas_bench::load_task(&task_dir)?;
                    for _ in 0..repeat {
                        // Check out the repo: local path if it exists, else shallow clone.
                        let repo_path = if std::path::Path::new(&task.repo).exists() {
                            std::path::PathBuf::from(&task.repo)
                        } else {
                            // task.yaml controls repo/branch: only HTTPS remotes
                            // and a `--` separator keep them from becoming git
                            // options or fetch-proxy URLs.
                            if !task.repo.starts_with("https://") {
                                eprintln!(
                                    "bench {} skipped: remote repo must be https://",
                                    flat(&task.id)
                                );
                                continue;
                            }
                            if task.base_branch.starts_with('-')
                                || !task.base_branch.bytes().all(|b| {
                                    b.is_ascii_alphanumeric()
                                        || matches!(b, b'-' | b'_' | b'.' | b'/')
                                })
                            {
                                eprintln!("bench {} skipped: invalid base_branch", flat(&task.id));
                                continue;
                            }
                            let dest = p.cache_dir.join("bench").join(&task.id);
                            if !dest.exists() {
                                tokio::process::Command::new("git")
                                    .args([
                                        "clone",
                                        "--depth",
                                        "1",
                                        "--branch",
                                        &task.base_branch,
                                        "--",
                                        &task.repo,
                                        &dest.to_string_lossy(),
                                    ])
                                    .output()
                                    .await?;
                            }
                            dest
                        };
                        // Run the agent on the task.
                        let bench_runner = freedas_session::Runner::new(
                            d.clone(),
                            p.clone(),
                            bench_cfg.clone(),
                            freedas_catalog::builtin_catalog(),
                        );
                        let agent_run = bench_runner
                            .run_task(
                                repo_path.clone(),
                                "build",
                                model.clone(),
                                &task.prompt,
                                true,
                                false,
                                None,
                                None,
                            )
                            .await;
                        let (completed, sid) = match &agent_run {
                            Ok(r) => (r.completed, Some(r.session_id.clone())),
                            Err(_) => (false, None),
                        };
                        let (cost_usd, tokens) = sid
                            .as_deref()
                            .map(|sid| {
                                d.session_usage(sid)
                                    .map(|(input, output, cost)| (cost, (input + output) as u64))
                                    .unwrap_or_default()
                            })
                            .unwrap_or_default();
                        let outcome = if completed {
                            freedas_bench::run_task_tests_verified(&repo_path, &task_dir).await
                        } else {
                            freedas_bench::TaskOutcome {
                                passed: false,
                                verified: false,
                            }
                        };
                        if let Err(e) = &agent_run {
                            eprintln!("bench {} failed: {e}", flat(&task.id));
                        }
                        results.push(serde_json::json!({"task": task.id, "passed": outcome.passed, "verified": outcome.verified, "completed": completed, "cost_usd": cost_usd, "tokens": tokens}));
                    }
                }
                let summary = freedas_bench::summarize(
                    &results
                        .iter()
                        .map(|r| freedas_bench::BenchResult {
                            task_id: r["task"].as_str().unwrap_or_default().to_string(),
                            verified: r["verified"].as_bool().unwrap_or(false),
                            passed: r["passed"].as_bool().unwrap_or(false),
                            cost_usd: r["cost_usd"].as_f64().unwrap_or_default(),
                            tokens: r["tokens"].as_u64().unwrap_or_default(),
                        })
                        .collect::<Vec<_>>(),
                );
                let unverified = results
                    .iter()
                    .filter(|r| !r["verified"].as_bool().unwrap_or(false))
                    .count();
                let summary = if unverified > 0 {
                    format!("{summary} · {unverified} unverified")
                } else {
                    summary
                };
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"results": results, "summary": summary})
                    );
                } else {
                    println!("{summary}");
                    for r in results {
                        let status = if r["passed"].as_bool().unwrap_or(false) {
                            "PASS"
                        } else {
                            "FAIL"
                        };
                        let suffix = if r["verified"].as_bool().unwrap_or(false) {
                            ""
                        } else {
                            " (unverified)"
                        };
                        println!(
                            "{} {}{}",
                            flat(r["task"].as_str().unwrap_or_default()),
                            status,
                            suffix
                        );
                    }
                }
                Ok(0)
            }
        },
        Some(Commands::Debug { what }) => {
            println!("config: {}", p.global_config().display());
            println!("data: {}", p.data_dir.display());
            println!("state: {}", p.state_dir.display());
            println!("cache: {}", p.cache_dir.display());
            println!("bin: {}", p.bin_dir.display());
            println!("project: {}", project_root.display());
            println!("db: {}", p.db_path().display());
            println!("sandbox: {}", freedas_sandbox::status());
            let pid = d.ensure_project(&project_root)?;
            println!("logs: {}", p.state_dir.join("logs").display());
            println!("snapshots: {}", p.snapshot_dir(&pid).display());
            println!("worktrees: {}", p.worktree_dir(&pid).display());
            println!("plans: {}", p.plans_dir().display());
            if !what.is_empty() {
                match what.as_str() {
                    "db" => println!("{}", p.db_path().display()),
                    "config" => println!("{}", p.global_config().display()),
                    _ => {}
                }
            }
            Ok(0)
        }
        Some(Commands::Upgrade { version }) => {
            let target = version.unwrap_or_else(|| "latest".to_string());
            let base = std::env::var("FREEDAS_RELEASE_BASE")
                .unwrap_or_else(|_| "https://github.com/vindeckyy/freedas/releases".to_string());
            let manifest_url = format!("{base}/{target}/download/latest.json");
            println!("checking {manifest_url} …");
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()?;
            let manifest: serde_json::Value =
                client.get(&manifest_url).send().await?.json().await?;
            let current = env!("CARGO_PKG_VERSION");
            let latest = manifest
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("latest");
            if latest == current {
                println!("already on {latest}");
                return Ok(0);
            }
            println!("upgrading {current} → {latest}");
            // Download artifact matching this platform. OS alone is not
            // enough: darwin-arm64 and darwin-x64 are different binaries.
            let (os, arch) = (release_os(), release_arch());
            let asset = manifest
                .get("assets")
                .and_then(|a| a.as_array())
                .and_then(|arr| {
                    arr.iter().find(|a| {
                        a.get("name")
                            .and_then(|n| n.as_str())
                            .is_some_and(|n| n.contains(os) && n.contains(arch))
                    })
                })
                .ok_or_else(|| format!("no release asset for {os}-{arch}"))?;
            let download_url = asset
                .get("url")
                .and_then(|u| u.as_str())
                .unwrap_or_default();
            let bytes = client.get(download_url).send().await?.bytes().await?;
            // Require the published checksum before anything touches the
            // installed binary.
            let expected = asset
                .get("sha256")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .ok_or("release asset has no sha256; refusing to install")?;
            use sha2::Digest;
            let actual = hex::encode(sha2::Sha256::digest(&bytes));
            if !actual.eq_ignore_ascii_case(expected) {
                return Err(format!("checksum mismatch: expected {expected}, got {actual}").into());
            }
            let tmpdir =
                std::env::temp_dir().join(format!("freedas-upgrade-{}", ulid::Ulid::new()));
            std::fs::create_dir_all(&tmpdir)?;
            let archive = tmpdir.join("freedas.tar.gz");
            std::fs::write(&archive, &bytes)?;
            tokio::process::Command::new("tar")
                .args([
                    "-xzf",
                    &archive.to_string_lossy(),
                    "-C",
                    &tmpdir.to_string_lossy(),
                ])
                .output()
                .await?;
            let staged = tmpdir.join("freedas");
            if !staged.is_file() {
                return Err("release archive does not contain `freedas`".into());
            }
            let current_exe = std::env::current_exe()?;
            let parent = current_exe
                .parent()
                .ok_or("cannot locate the installed binary")?;
            // Stage beside the target so the final rename stays on one
            // filesystem (atomic), then keep the old binary as `.previous`.
            let staged_path = parent.join(format!(".freedas-new-{}", ulid::Ulid::new()));
            std::fs::copy(&staged, &staged_path)?;
            if let Ok(meta) = std::fs::metadata(&current_exe) {
                let _ = std::fs::set_permissions(&staged_path, meta.permissions());
            }
            let prev = current_exe.with_extension("previous");
            std::fs::copy(&current_exe, &prev)?;
            if let Err(e) = std::fs::rename(&staged_path, &current_exe) {
                let _ = std::fs::remove_file(&staged_path);
                if !current_exe.exists() {
                    let _ = std::fs::copy(&prev, &current_exe);
                }
                return Err(format!("replace binary: {e}").into());
            }
            println!("upgraded to {latest}");
            Ok(0)
        }
        Some(Commands::Uninstall {
            keep_config,
            keep_data,
            yes,
        }) => {
            // Deleting data removes the database and stored credentials, so
            // show the paths and require an explicit confirmation.
            eprintln!("freedas uninstall will remove:");
            if !keep_data {
                eprintln!("  data   {}", p.data_dir.display());
                eprintln!("  state  {}", p.state_dir.display());
                eprintln!("  cache  {}", p.cache_dir.display());
                eprintln!("         (the session database and credentials live under data)");
            }
            if !keep_config {
                eprintln!("  config {}", p.config_dir.display());
            }
            if !yes {
                if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                    return Err(
                        "refusing to uninstall without --yes (no terminal to confirm)".into(),
                    );
                }
                if !confirm("Delete these paths?") {
                    println!("uninstall cancelled");
                    return Ok(0);
                }
            }
            let mut removed = Vec::new();
            // Stop anything a previous `relay start`/server left running.
            stop_pid_files(&p.state_dir);
            let relay = p.state_dir.join("relay.json");
            if std::fs::remove_file(&relay).is_ok() {
                removed.push(relay.display().to_string());
            }
            for bin in [
                p.bin_dir.join("freedas"),
                p.bin_dir.join("freedas.previous"),
            ] {
                if std::fs::remove_file(&bin).is_ok() {
                    removed.push(bin.display().to_string());
                }
            }
            remove_path_lines(&p.home, &p.bin_dir);
            if !keep_data {
                if std::fs::remove_dir_all(&p.data_dir).is_ok() {
                    removed.push(p.data_dir.display().to_string());
                }
                if std::fs::remove_dir_all(&p.state_dir).is_ok() {
                    removed.push(p.state_dir.display().to_string());
                }
                if std::fs::remove_dir_all(&p.cache_dir).is_ok() {
                    removed.push(p.cache_dir.display().to_string());
                }
            }
            if !keep_config && std::fs::remove_dir_all(&p.config_dir).is_ok() {
                removed.push(p.config_dir.display().to_string());
            }
            for r in &removed {
                println!("removed {r}");
            }
            println!(
                "freedas uninstall complete; remove {}",
                std::env::current_exe()
                    .map(|e| e.display().to_string())
                    .unwrap_or_else(|_| "the binary".into())
            );
            Ok(0)
        }
    }
}

/// Terminate processes recorded in `<state_dir>/*.pid`.
fn stop_pid_files(state_dir: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(state_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().map(|e| e != "pid").unwrap_or(true) {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path)
            && let Ok(pid) = text.trim().parse::<u32>()
            && pid_is_freedas(pid)
        {
            let _ = std::process::Command::new("kill")
                .arg(pid.to_string())
                .status();
        }
        let _ = std::fs::remove_file(&path);
    }
}

/// Only signal pids that still look like freedas; stale pid files from a
/// reused pid must not kill an unrelated process.
fn pid_is_freedas(pid: u32) -> bool {
    let proc_cmd = std::fs::read_to_string(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    if !proc_cmd.is_empty() {
        return proc_cmd.contains("freedas");
    }
    let out = std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "command="])
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).contains("freedas"),
        _ => false,
    }
}

/// Remove the PATH line the installer added from shell profiles.
fn remove_path_lines(home: &std::path::Path, bin: &std::path::Path) {
    let bin = bin.to_string_lossy();
    for profile in [
        home.join(".zshrc"),
        home.join(".bashrc"),
        home.join(".bash_profile"),
        home.join(".profile"),
        home.join(".config").join("fish").join("config.fish"),
    ] {
        let Ok(text) = std::fs::read_to_string(&profile) else {
            continue;
        };
        let kept = text
            .lines()
            .filter(|line| !(line.contains("export PATH") && line.contains(bin.as_ref())))
            .collect::<Vec<_>>()
            .join("\n");
        if kept != text {
            let _ = std::fs::write(&profile, format!("{kept}\n"));
        }
    }
}

/// Minimal stdin approver for interactive/headless `run` (not `--auto`).
#[derive(Debug)]
struct StdinApprover {
    /// Session ID when the run uses `--format json`: asked/replied are then
    /// emitted as JSONL events so scripted consumers see the same schema the
    /// SSE stream produces.
    json_events: Option<String>,
}

impl freedas_tools::PermissionApprover for StdinApprover {
    fn ask(&self, action: &str, resource: &str) -> freedas_tools::PermissionReply {
        use std::io::{BufRead, Write};
        let perm_id = format!("perm_{}", ulid::Ulid::new());
        if let Some(sid) = &self.json_events {
            println!(
                "{}",
                serde_json::json!({
                    "type": "permission.asked",
                    "sessionID": sid,
                    "permissionID": perm_id,
                    "action": action,
                    "resource": resource,
                })
            );
        }
        // Model-written commands can carry newlines and control chars that
        // would spoof extra prompt lines; flatten and cap before printing.
        let clean = |s: &str| -> String {
            s.chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .take(500)
                .collect()
        };
        eprint!("Allow {} {}? [y/a/n] ", clean(action), clean(resource));
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        let _ = std::io::stdin().lock().read_line(&mut line);
        let reply = match line.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => freedas_tools::PermissionReply::Once,
            "a" | "always" => freedas_tools::PermissionReply::Always,
            _ => freedas_tools::PermissionReply::Reject,
        };
        if let Some(sid) = &self.json_events {
            println!(
                "{}",
                serde_json::json!({
                    "type": "permission.replied",
                    "sessionID": sid,
                    "permissionID": perm_id,
                    "response": format!("{reply:?}").to_lowercase(),
                })
            );
        }
        reply
    }
}

/// Read one line from stdin with a default (used by `agent create`).
fn prompt_line(label: &str, default: &str) -> String {
    use std::io::{BufRead, Write};
    eprint!("{label} [{default}]: ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    let value = line.trim();
    if value.is_empty() {
        default.to_string()
    } else {
        value.to_string()
    }
}

/// Provider + model recorded on the latest assistant message.
fn last_assistant_model(d: &Db, session_id: &str) -> (String, String) {
    d.list_messages(session_id)
        .unwrap_or_default()
        .into_iter()
        .rev()
        .find(|m| m.role == "assistant")
        .and_then(|m| m.model)
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .map(|v| {
            (
                v["provider"].as_str().unwrap_or("").to_string(),
                v["id"].as_str().unwrap_or("").to_string(),
            )
        })
        .unwrap_or_default()
}

/// Best-effort session metadata for the control-plane dashboard. The
/// transcript stays local; only counts, model, and read paths leave the
/// machine. Any failure is a one-line warning, never a failed or delayed run.
async fn report_session_metadata(
    p: &Paths,
    d: &Db,
    r: &freedas_session::RunResult,
    project: &str,
    prompt_excerpt: &str,
    started_at: i64,
) {
    let Some(token) = freedas_provider::credentials::api_key_for(&p.data_dir, "control") else {
        return;
    };
    let (provider, model) = last_assistant_model(d, &r.session_id);
    let model = if provider.is_empty() || model.is_empty() {
        "freedas/auto".to_string()
    } else {
        format!("{provider}/{model}")
    };
    let (input, output, cost) = d.session_usage(&r.session_id).unwrap_or((0, 0, 0.0));
    let body = serde_json::json!({
        "sessionID": r.session_id,
        "project": project,
        "model": model,
        "inputTokens": input,
        "outputTokens": output,
        "costUsd": cost,
        "filesRead": r
            .files_read
            .iter()
            .map(|f| freedas_core::redact::redact(f))
            .collect::<Vec<_>>(),
        "promptExcerpt": freedas_core::redact::redact(prompt_excerpt),
        "startedAt": started_at,
        "endedAt": freedas_core::paths::now_ms(),
    });
    let base = freedas_provider::credentials::control_base(&p.data_dir);
    let url = format!("{}/sessions", base.trim_end_matches('/'));
    let sent = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
    {
        Ok(c) => c.post(&url).bearer_auth(&token).json(&body).send().await,
        Err(e) => Err(e),
    };
    if let Err(e) = sent {
        eprintln!("freedas: session metadata not reported: {e}");
    }
}

/// Options for `run --attach`.
struct AttachRun {
    base: String,
    task: String,
    session: Option<String>,
    resume_latest: bool,
    fork: bool,
    auto: bool,
    manual: bool,
    format: String,
    title: Option<String>,
    agent: Option<String>,
    model: Option<String>,
    variant: Option<String>,
}

/// Authorization header for the local server when one is configured.
fn server_auth() -> Option<String> {
    if let Ok(token) = std::env::var("FREEDAS_SERVER_TOKEN") {
        let token = token.trim();
        if !token.is_empty() {
            return Some(format!("Bearer {token}"));
        }
    }
    if let Ok(password) = std::env::var("FREEDAS_SERVER_PASSWORD") {
        let password = password.trim().to_string();
        if !password.is_empty() {
            let user =
                std::env::var("FREEDAS_SERVER_USERNAME").unwrap_or_else(|_| "freedas".to_string());
            use base64::Engine as _;
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
            return Some(format!("Basic {encoded}"));
        }
    }
    None
}

/// Client for the local server, carrying the configured credentials.
/// A configured-but-unencodable credential is a hard error: silently
/// dropping the header would send the request unauthenticated.
fn server_client() -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder();
    if let Some(auth) = server_auth() {
        let value = reqwest::header::HeaderValue::from_str(&auth)
            .map_err(|_| "server credential contains invalid characters".to_string())?;
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::AUTHORIZATION, value);
        builder = builder.default_headers(headers);
    }
    builder.build().map_err(|e| e.to_string())
}

/// Run one prompt against a server and stream its events until idle.
async fn attach_run(opts: AttachRun) -> Result<i32, Box<dyn std::error::Error>> {
    if opts.format != "json" && opts.format != "text" {
        eprintln!("freedas: --format must be json or text");
        return Ok(2);
    }
    let json_mode = opts.format == "json";
    let base = opts.base.trim_end_matches('/').to_string();
    let client = server_client().map_err(|e| format!("attach: {e}"))?;
    let mut session_id = opts.session;
    if session_id.is_none() && opts.resume_latest {
        let rows = freedas_server::client::request(
            &client,
            &format!("{base}/session?limit=50"),
            "GET",
            None,
        )
        .await
        .map_err(|e| format!("attach: {}", scrub_url(&e, &base)))?;
        session_id = rows
            .as_array()
            .and_then(|rows| rows.first())
            .and_then(|s| s.get("id"))
            .and_then(|v| v.as_str())
            .map(str::to_string);
    }
    if opts.fork
        && let Some(id) = &session_id
    {
        let forked = freedas_server::client::request(
            &client,
            &format!("{base}/session/{id}/fork"),
            "POST",
            Some(&serde_json::json!({})),
        )
        .await
        .map_err(|e| format!("attach: fork: {}", scrub_url(&e, &base)))?;
        session_id = Some(
            forked
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or("attach: server returned no forked session id")?
                .to_string(),
        );
    }
    let session_id = match session_id {
        Some(id) => id,
        None => {
            let created = freedas_server::client::request(
                &client,
                &format!("{base}/session"),
                "POST",
                Some(&serde_json::json!({"title": opts.title, "agent": opts.agent})),
            )
            .await
            .map_err(|e| format!("attach: {}", scrub_url(&e, &base)))?;
            created
                .get("id")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .ok_or("attach: server returned no session id")?
        }
    };
    // Mirror the local run's stream contract: session.started opens the JSONL
    // output even though the server's session.created fired before subscribe.
    if json_mode {
        println!(
            "{}",
            serde_json::json!({
                "type": "session.started",
                "sessionID": session_id,
                "timestamp": freedas_core::paths::now_ms(),
            })
        );
    }
    // Subscribe before prompting so no event is missed.
    let mut resp = client
        .get(format!("{base}/event"))
        .send()
        .await
        .map_err(|e| format!("attach: {}", scrub_url(&e.to_string(), &base)))?
        .error_for_status()
        .map_err(|e| format!("attach: {}", scrub_url(&e.to_string(), &base)))?;
    let mut body = serde_json::json!({
        "text": opts.task,
        "auto": opts.auto,
        "manual": opts.manual,
    });
    if let Some(model) = &opts.model {
        body["model"] = serde_json::json!(model);
    }
    if let Some(variant) = &opts.variant {
        body["variant"] = serde_json::json!(variant);
    }
    let prompt_url = format!("{base}/session/{session_id}/message");
    let prompt_client = client.clone();
    let prompt_task = tokio::spawn(async move {
        freedas_server::client::request(&prompt_client, &prompt_url, "POST", Some(&body)).await
    });
    let mut buffer = String::new();
    let mut streamed = String::new();
    let mut completed = false;
    let mut blocked: Vec<String> = Vec::new();
    let mut final_text = String::new();
    'outer: loop {
        // The server sends SSE keep-alives; a silent connection is dead.
        let chunk =
            match tokio::time::timeout(std::time::Duration::from_secs(300), resp.chunk()).await {
                Ok(Ok(Some(chunk))) => chunk,
                Ok(Ok(None)) => break,
                Ok(Err(e)) => {
                    return Err(format!("attach: {}", scrub_url(&e.to_string(), &base)).into());
                }
                Err(_) => return Err("attach: timed out waiting for server events".into()),
            };
        buffer.push_str(&String::from_utf8_lossy(&chunk));
        while let Some(idx) = buffer.find("\n\n") {
            let frame = buffer[..idx].to_string();
            buffer.drain(..=idx + 1);
            for line in frame.lines() {
                let Some(data) = line.strip_prefix("data:") else {
                    continue;
                };
                let Ok(event) = serde_json::from_str::<serde_json::Value>(data.trim()) else {
                    continue;
                };
                if event.get("sessionID").and_then(|v| v.as_str()) != Some(session_id.as_str()) {
                    continue;
                }
                let kind = event.get("type").and_then(|v| v.as_str()).unwrap_or("");
                if json_mode {
                    println!("{event}");
                }
                match kind {
                    "message.part.delta" => {
                        if let Some(t) = event.get("text").and_then(|v| v.as_str()) {
                            streamed.push_str(t);
                            if !json_mode {
                                use std::io::Write;
                                print!("{t}");
                                let _ = std::io::stdout().flush();
                            }
                        }
                    }
                    "message.part.updated" => {
                        if let Some(t) = event.get("text").and_then(|v| v.as_str()) {
                            final_text = t.to_string();
                        }
                        if let Some(c) = event.get("completed").and_then(|v| v.as_bool()) {
                            completed = c;
                        }
                        if let Some(arr) = event.get("blocked").and_then(|v| v.as_array()) {
                            blocked = arr
                                .iter()
                                .filter_map(|b| b.as_str().map(str::to_string))
                                .collect();
                        }
                    }
                    "session.error" => {
                        prompt_task.abort();
                        return Err(format!(
                            "attach: {}",
                            event
                                .get("error")
                                .and_then(|v| v.as_str())
                                .unwrap_or("server error")
                        )
                        .into());
                    }
                    "session.idle" => break 'outer,
                    "session.stopped" if !json_mode => {
                        eprintln!("session stopped");
                    }
                    "session.marker" if !json_mode => {
                        if let Some(m) = event.get("marker").and_then(|v| v.as_str()) {
                            eprintln!("{m}");
                        }
                    }
                    "tool.result" if !json_mode && event["ok"].as_bool() == Some(false) => {
                        eprintln!(
                            "{} failed: {}",
                            event["tool"].as_str().unwrap_or("tool"),
                            event["output"].as_str().unwrap_or("")
                        );
                    }
                    _ => {}
                }
            }
        }
    }
    // The prompt POST returns as soon as the run is accepted; a failure here
    // means the server never started it. JSON mode still ends the stream with
    // session.error so consumers don't mistake a dead prompt for a truncated pipe.
    let prompt_error =
        match tokio::time::timeout(std::time::Duration::from_secs(30), prompt_task).await {
            Ok(Ok(Ok(_))) => None,
            Ok(Ok(Err(e))) => Some(format!("attach: prompt failed: {}", scrub_url(&e, &base))),
            Ok(Err(e)) => Some(format!("attach: prompt task failed: {e}")),
            Err(_) => Some("attach: prompt request did not complete".to_string()),
        };
    if let Some(message) = prompt_error {
        if json_mode {
            println!(
                "{}",
                serde_json::json!({
                    "type": "session.error",
                    "sessionID": session_id,
                    "error": message,
                })
            );
        }
        return Err(message.into());
    }
    if !json_mode {
        if streamed.is_empty() && !final_text.is_empty() {
            println!("{final_text}");
        } else if !streamed.is_empty() {
            println!();
        }
    }
    for (i, b) in blocked.iter().enumerate() {
        let (action, resource) = b.split_once(": ").unwrap_or(("permission", b.as_str()));
        if json_mode {
            println!(
                "{}",
                serde_json::json!({
                    "type": "permission.asked", "sessionID": session_id,
                    "permissionID": format!("perm_{i}"), "action": action, "resource": resource,
                })
            );
            println!(
                "{}",
                serde_json::json!({
                    "type": "permission.replied", "sessionID": session_id,
                    "permissionID": format!("perm_{i}"), "response": "reject",
                })
            );
        } else {
            eprintln!("auto-rejecting {b}");
        }
    }
    if json_mode {
        // Server streams no usage event; pull the totals so attach consumers
        // see the same fields a local run emits.
        if let Ok(mut v) = freedas_server::client::request(
            &client,
            &format!("{base}/session/{session_id}/usage"),
            "GET",
            None,
        )
        .await
        {
            v["type"] = "usage".into();
            println!("{v}");
        }
        println!(
            "{}",
            serde_json::json!({
                "type": "session.completed", "sessionID": session_id,
                "completed": completed, "timestamp": freedas_core::paths::now_ms(),
            })
        );
        println!(
            "{}",
            serde_json::json!({
                "type": "result", "sessionID": session_id, "text": final_text,
                "completed": completed, "blocked": blocked,
            })
        );
    } else {
        eprintln!("session {session_id}");
    }
    // Exit 3 whenever a blocked action was auto-rejected (docs: headless.md).
    Ok(blocked_exit_code(&blocked))
}

/// `3` whenever a blocked action was auto-rejected.
fn blocked_exit_code(blocked: &[String]) -> i32 {
    if blocked.is_empty() { 0 } else { 3 }
}

/// Read a config file as JSONC. A missing file is an empty object; a file that
/// does not parse is an error, never silently replaced with `{}`.
fn read_config(path: &std::path::Path) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(serde_json::json!({})),
        Err(e) => return Err(format!("{}: {e}", path.display()).into()),
    };
    let parsed: Option<serde_json::Value> =
        jsonc_parser::parse_to_serde_value(&text, &jsonc_parser::ParseOptions::default())
            .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(match parsed {
        Some(v @ serde_json::Value::Object(_)) => v,
        _ => serde_json::json!({}),
    })
}

/// Reject IDs that would escape the directory they are joined to.
fn safe_id(id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let unsafe_id = id.is_empty()
        || id.contains('/')
        || id.contains('\\')
        || id.contains("..")
        || std::path::Path::new(id).is_absolute();
    if unsafe_id {
        return Err(format!("invalid id: {id:?}").into());
    }
    Ok(())
}

/// `apply` is a verb, not a format choice: `sync apply --json` still applies.
fn sync_apply(action: &str) -> Result<bool, Box<dyn std::error::Error>> {
    match action {
        "" | "plan" => Ok(false),
        "apply" => Ok(true),
        other => Err(format!("unknown sync action {other:?}; expected `apply`").into()),
    }
}

fn default_worktree_name() -> String {
    format!("s{}", ulid::Ulid::new())
}

/// Provider IDs `providers logout` may delete (never mcp/relay/control keys).
fn known_providers() -> Vec<String> {
    let mut ids: Vec<String> = freedas_catalog::builtin_catalog()
        .into_iter()
        .map(|m| m.provider)
        .collect();
    ids.push("freedas".to_string());
    ids.sort();
    ids.dedup();
    ids
}

/// Numbered provider picker for `providers login`. The gateway is selection
/// 1; every table provider follows in roster order.
fn choose_provider() -> Option<String> {
    use std::io::{BufRead, Write};
    let providers = freedas_provider::oauth::providers();
    eprintln!("Choose a provider:");
    eprintln!("1. freedas\tFreedas control plane");
    for (index, provider) in providers.iter().enumerate() {
        eprintln!("{}. {}\t{}", index + 2, provider.id, provider.name);
    }
    eprint!("Provider [freedas]: ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    let answer = line.trim();
    if answer.is_empty() || answer == "freedas" || answer == "1" {
        return Some("freedas".to_string());
    }
    if let Ok(selection) = answer.parse::<usize>()
        && selection >= 2
    {
        return providers
            .get(selection - 2)
            .map(|provider| provider.id.to_string());
    }
    providers
        .iter()
        .find(|provider| provider.id == answer)
        .map(|provider| provider.id.to_string())
}

fn release_os() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    }
}

fn release_arch() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x64",
        other => other,
    }
}

/// Ask a yes/no question on the terminal.
fn confirm(question: &str) -> bool {
    use std::io::{BufRead, Write};
    eprint!("{question} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Write `{"<section>": {"<key>": value}}` into the project config
/// (`.freedas/freedas.json`), creating it when absent.
fn write_config_entry(
    project_root: &std::path::Path,
    section: &str,
    key: &str,
    value: serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = project_root.join(".freedas").join("freedas.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut root = read_config(&path)?;
    root[section][key] = value;
    std::fs::write(&path, serde_json::to_string_pretty(&root)?)?;
    Ok(())
}

/// Append a value to an array section of a config file.
fn append_config_array_at(
    path: &std::path::Path,
    section: &str,
    value: serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut root = read_config(path)?;
    if !root[section].is_array() {
        root[section] = serde_json::json!([]);
    }
    if let Some(arr) = root[section].as_array_mut()
        && !arr.contains(&value)
    {
        arr.push(value);
    }
    std::fs::write(path, serde_json::to_string_pretty(&root)?)?;
    Ok(())
}

/// GET a control-plane path with the stored CLI token.
async fn control_get(
    paths: &Paths,
    path: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(freedas_provider::credentials::control_get(paths, path).await?)
}

/// The another-harness rule set, verbatim from the docs with `freedas`
/// substituted for the product name.
pub const RULES: &str = "## Freedas run rules

This section applies only to an agent that runs the `freedas` CLI, and only when
the person asks it to use Freedas. If you are Freedas, ignore this section.

Freedas picks the model for each task on its own. Do not choose for it. Your own
model or vendor is not a reason to prefer a model.

- Run the task with `freedas run \"<task>\"`. Do not do the task yourself instead.
- Do not pass `--model`, `-m`, or `--variant` unless the person asks for that
  model or variant in that request. If they do, use it for that run only. A
  continued session keeps a pinned model, so start a new session after.
- Do not add or change `model` or `small_model` in a Freedas config file, or
  `model` in an agent or command frontmatter, unless the person asks for that
  change.
- If a Freedas config already pins a model, leave it and tell the person.
- Do not choose a model from `freedas models`.
- Use `--agent plan` or `--agent plan-quick` when the task is planning. Do not
  pick an agent because of its model.
- If a run fails, retry it or narrow the task. Do not add a model flag.
";

/// Strip control characters so an untrusted string cannot forge output lines.
fn flat(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("freedas-cmd-{tag}-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn safe_id_rejects_path_traversal() {
        for bad in ["", "..", "../x", "a/b", "a\\b", "/etc/passwd", "foo/../bar"] {
            assert!(safe_id(bad).is_err(), "{bad:?} was accepted");
        }
        assert!(safe_id("ses_01ABC").is_ok());
        assert!(safe_id("skill-name").is_ok());
    }

    #[test]
    fn sync_apply_decides_before_format() {
        assert!(!sync_apply("").unwrap());
        assert!(!sync_apply("plan").unwrap());
        assert!(sync_apply("apply").unwrap());
        assert!(sync_apply("bogus").is_err());
    }

    #[test]
    fn blocked_runs_exit_3() {
        let blocked = vec!["bash: rm -rf /".to_string()];
        assert_eq!(blocked_exit_code(&blocked), 3);
        assert_eq!(blocked_exit_code(&[]), 0);
    }

    #[test]
    fn config_writers_keep_jsonc_and_refuse_broken_files() {
        let dir = temp_dir("config");
        let path = dir.join("freedas.json");
        std::fs::write(
            &path,
            "{\n  // keep me\n  \"model\": \"freedas/auto\",\n}\n",
        )
        .unwrap();
        append_config_array_at(&path, "plugin", serde_json::json!("pkg")).unwrap();
        let saved = std::fs::read_to_string(&path).unwrap();
        assert!(saved.contains("\"plugin\""));
        assert!(saved.contains("freedas/auto"));

        let broken = "{\"model\": ";
        std::fs::write(&path, broken).unwrap();
        assert!(read_config(&path).is_err());
        assert!(append_config_array_at(&path, "plugin", serde_json::json!("x")).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), broken);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cli_flags_override_configured_permission_mode() {
        // No flag: the configured mode decides.
        assert_eq!(
            permission_flags(false, false, PermissionMode::Ask),
            (false, true)
        );
        // `--auto` wins over an ask config; `--manual` wins over bypass.
        assert_eq!(
            permission_flags(true, false, PermissionMode::Ask),
            (true, false)
        );
        assert_eq!(
            permission_flags(false, true, PermissionMode::Bypass),
            (false, true)
        );
        assert_eq!(
            permission_flags(false, false, PermissionMode::Auto),
            (false, false)
        );
    }

    #[test]
    fn missing_config_reads_as_empty_object() {
        let dir = temp_dir("missing");
        assert_eq!(
            read_config(&dir.join("nope.json")).unwrap(),
            serde_json::json!({})
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
