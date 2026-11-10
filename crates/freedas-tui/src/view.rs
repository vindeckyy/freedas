use std::time::{Duration, Instant};

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use unicode_width::UnicodeWidthChar;
use unicode_width::UnicodeWidthStr;

use crate::composer::wrap;
use crate::config_panel;
use crate::style;

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const PERMISSION_KEYS: &str = "a/1 allow · A/2 always · d/3 deny";

pub(crate) fn header_line(
    project: &str,
    branch: &str,
    agent: &str,
    model: &str,
    usage: (i64, i64, f64),
    width: u16,
) -> String {
    let (tokens_in, tokens_out, cost) = usage;
    let line = format!(
        "freedas · {project} ({branch}) · {agent} · {model} · {} in / {} out · ${cost:.2}",
        short_tokens(tokens_in),
        short_tokens(tokens_out),
    );
    truncate(&line, width as usize)
}

fn truncate(s: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if UnicodeWidthStr::width(s) <= width {
        return s.to_string();
    }
    let mut out = String::new();
    let mut used = 0usize;
    for ch in s.chars() {
        let w = ch.width().unwrap_or(1).max(1);
        if used + w > width.saturating_sub(1) {
            break;
        }
        out.push(ch);
        used += w;
    }
    out.push('…');
    out
}

/// `<model> · <variant>` for the header; the bare model when no variant is set.
pub(crate) fn model_label(model: Option<&str>, variant: Option<&str>) -> String {
    match variant {
        Some(variant) if !variant.is_empty() => {
            format!("{} · {variant}", model.unwrap_or("auto"))
        }
        _ => model.unwrap_or("auto").to_string(),
    }
}

pub(crate) fn short_tokens(n: i64) -> String {
    let magnitude = n.unsigned_abs();
    if magnitude < 1_000 {
        n.to_string()
    } else if magnitude < 1_000_000 {
        format!("{:.1}k", n as f64 / 1_000.0)
    } else {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    }
}

pub(crate) fn spinner(elapsed: Duration) -> &'static str {
    SPINNER[(elapsed.as_millis() / 100) as usize % SPINNER.len()]
}

pub(crate) fn running_line(activity: &str, elapsed: Duration, queued: usize) -> String {
    let mut line = format!(
        "{} {activity} ({}s · Esc to interrupt)",
        spinner(elapsed),
        elapsed.as_secs()
    );
    if queued > 0 {
        line.push_str(&format!(" · {queued} queued"));
    }
    line
}

#[derive(Default)]
pub(crate) struct FooterState {
    pub permission: bool,
    pub shortcuts: bool,
    pub help: bool,
    pub search: bool,
    pub transcript: bool,
    pub login: bool,
    pub sync: bool,
    pub running: bool,
    pub picker: bool,
    pub slash: bool,
    pub file: bool,
    pub quit_armed: bool,
    pub esc_armed: bool,
    pub draft: bool,
    pub unseen: usize,
}

pub(crate) fn footer_hint(s: &FooterState) -> String {
    let mut hint = if s.permission {
        PERMISSION_KEYS
    } else if s.help {
        "Esc close · PgUp/PgDn scroll · Home/End jump"
    } else if s.shortcuts {
        "Esc close"
    } else if s.picker {
        "Up/Down move · type to filter · Enter select · Esc close"
    } else if s.slash || s.file {
        "Up/Down move · Tab/Enter complete · Esc dismiss"
    } else if s.search {
        "Type to filter · Enter insert · Esc cancel"
    } else if s.transcript {
        "Esc close · PgUp/PgDn scroll · Home/End jump"
    } else if s.login {
        "Paste credential · Enter save · Esc cancel"
    } else if s.sync {
        "Enter import · Esc cancel"
    } else if s.running {
        "Esc interrupt · Tab queue · Ctrl+C cancel"
    } else if s.quit_armed {
        "Press Ctrl+C again to quit"
    } else if s.esc_armed {
        "Esc again to edit the previous message"
    } else if s.draft {
        "Enter send · Ctrl+J newline · Esc clear"
    } else {
        "Enter send · ? shortcuts · Ctrl+C quit"
    }
    .to_string();
    if s.unseen > 0 {
        hint.push_str(&format!(" · ↓ {} new", s.unseen));
    }
    hint
}

fn short_id(id: &str) -> String {
    let tail: String = id
        .chars()
        .rev()
        .take(6)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("…{tail}")
}

fn on_off(on: bool) -> &'static str {
    if on { "on" } else { "off" }
}

/// Right-aligned footer status: session, permission mode, sandbox, relay.
pub(crate) fn status_right(
    session: Option<&str>,
    auto: bool,
    manual: bool,
    sandbox: bool,
    relay: bool,
    context_pct: Option<u8>,
    width: u16,
) -> String {
    let id = session.map(short_id).unwrap_or_else(|| "new".to_string());
    let mode = if auto {
        "auto"
    } else if manual {
        "manual"
    } else {
        "ask"
    };
    let ctx = context_pct
        .map(|pct| format!(" · ctx {pct}%"))
        .unwrap_or_default();
    truncate(
        &format!(
            "{id} · {mode} · sandbox {} · relay {}{ctx}",
            on_off(sandbox),
            on_off(relay)
        ),
        width as usize,
    )
}

pub(crate) fn draw_header(f: &mut Frame, area: Rect, line: &str) {
    f.render_widget(Paragraph::new(line).style(style::accent()), area);
}

pub(crate) fn draw_running(f: &mut Frame, area: Rect, line: &str) {
    let mut chars = line.chars();
    let Some(first) = chars.next() else {
        return;
    };
    let rest: String = chars.collect();
    let spans = vec![
        Span::styled(first.to_string(), style::accent()),
        Span::styled(rest, style::dim()),
    ];
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

pub(crate) fn draw_footer(f: &mut Frame, area: Rect, hint: &str, right: &str) {
    let right_width = right.chars().count() as u16;
    let hint_width = hint.chars().count() as u16;
    if right_width > 0 && hint_width + right_width + 2 <= area.width {
        let [left, right_area] =
            Layout::horizontal([Constraint::Min(0), Constraint::Length(right_width)]).areas(area);
        f.render_widget(Paragraph::new(hint).style(style::dim()), left);
        f.render_widget(
            Paragraph::new(right)
                .style(style::dim())
                .alignment(Alignment::Right),
            right_area,
        );
    } else {
        f.render_widget(Paragraph::new(hint).style(style::dim()), area);
    }
}

/// Live reasoning under the spinner: dim italic, tail of up to three rows.
pub(crate) fn reasoning_lines(text: &str, width: usize) -> Vec<Line<'static>> {
    let style = style::dim().add_modifier(Modifier::ITALIC);
    let rows = wrap(text, width.saturating_sub("  thinking: ".len()).max(1));
    let start = rows.len().saturating_sub(3);
    rows[start..]
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let prefix = if i == 0 {
                if start == 0 { "  thinking: " } else { "  … " }
            } else {
                "  "
            };
            Line::from(vec![
                Span::styled(prefix.to_string(), style),
                Span::styled(row.clone(), style),
            ])
        })
        .collect()
}

pub(crate) fn draw_thinking(f: &mut Frame, area: Rect, lines: Vec<Line<'static>>) {
    f.render_widget(Paragraph::new(lines), area);
}

pub(crate) fn draw_composer(
    f: &mut Frame,
    area: Rect,
    text: &str,
    placeholder: &str,
    scroll: u16,
) -> Rect {
    let block = Block::new()
        .borders(Borders::TOP)
        .border_style(style::dim());
    let inner = block.inner(area);
    let body = if text.is_empty() {
        Paragraph::new(placeholder).style(style::muted())
    } else {
        // Pre-wrap with the same function `cursor_row_col` uses: letting the
        // Paragraph wrap on its own would put the cursor on a different row.
        let rows: Vec<Line<'static>> = wrap(text, inner.width.max(1) as usize)
            .into_iter()
            .map(Line::raw)
            .collect();
        Paragraph::new(rows).scroll((scroll, 0))
    };
    f.render_widget(body.block(block), area);
    inner
}

/// First-run screen: wordmark, where you are, and four tips.
pub(crate) fn draw_welcome(
    f: &mut Frame,
    area: Rect,
    project: &str,
    branch: &str,
    at_home: bool,
    signed_in: bool,
) {
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(Line::default());
    lines.push(Line::from(vec![
        Span::styled("freedas", style::accent().add_modifier(Modifier::BOLD)),
        Span::styled(format!("  v{}", env!("CARGO_PKG_VERSION")), style::dim()),
    ]));
    lines.push(Line::default());
    if at_home {
        lines.push(Line::styled(
            "Works best inside a project directory, not your home directory.",
            style::warning(),
        ));
    } else {
        lines.push(Line::from(vec![
            Span::styled(project.to_string(), style::muted()),
            Span::styled(format!("  ({branch})"), style::dim()),
        ]));
    }
    if !signed_in {
        lines.push(Line::styled(
            "Not signed in — run /login or `freedas providers login`",
            style::dim(),
        ));
    }
    lines.push(Line::default());

    let tips = vec![
        ("1", "/help", "commands and skills"),
        ("2", "@", "mentions a project file"),
        ("3", "?", "keyboard shortcuts"),
        ("4", "Esc", "interrupts a run"),
    ];
    let width = tips
        .iter()
        .map(|(n, k, t)| n.len() + k.len() + t.len() + 8)
        .max()
        .unwrap_or(40)
        .max(34)
        .min(area.width.saturating_sub(4) as usize);
    let block = Block::new()
        .borders(Borders::ALL)
        .border_style(style::dim())
        .title(Span::styled(" Tips ", style::dim()));
    lines.push(Line::default());
    let tip_start = lines.len();
    for (n, key, text) in &tips {
        lines.push(Line::from(vec![
            Span::styled(format!(" {n}  "), style::dim()),
            Span::styled(format!("{key:<6}"), style::accent()),
            Span::styled(text.to_string(), style::muted()),
        ]));
    }
    lines.push(Line::default());

    f.render_widget(Paragraph::new(lines.clone()), area);
    // A short terminal can put the tips box below the buffer; clamp it so the
    // frame, not the tip list, decides what is visible.
    let tip_rect = Rect::new(
        area.x,
        area.y + tip_start as u16 - 1,
        (width as u16 + 2).min(area.width),
        tips.len() as u16 + 2,
    )
    .intersection(area);
    if tip_rect.height < 3 || tip_rect.width < 3 {
        return;
    }
    let inner = block.inner(tip_rect);
    f.render_widget(Clear, tip_rect);
    f.render_widget(block, tip_rect);
    f.render_widget(
        Paragraph::new(lines[tip_start..tip_start + tips.len()].to_vec()).style(style::muted()),
        inner,
    );
}

pub(crate) fn draw_pane(f: &mut Frame, area: Rect, lines: &[Line<'static>], scroll: u16) {
    let height = area.height as usize;
    let offset = lines
        .len()
        .saturating_sub(height)
        .saturating_sub(scroll as usize);
    f.render_widget(Paragraph::new(lines[offset..].to_vec()), area);
}

fn overlay_block(title: &str) -> Block<'_> {
    Block::new()
        .borders(Borders::ALL)
        .title(title)
        .border_style(style::dim())
}

pub(crate) fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    )
}

/// Selectable list body, kept centered on `selected`.
fn draw_rows(f: &mut Frame, area: Rect, lines: &[String], selected: usize) {
    let height = area.height as usize;
    if height == 0 || lines.is_empty() {
        return;
    }
    let selected = selected.min(lines.len() - 1);
    let offset = if lines.len() <= height {
        0
    } else {
        selected
            .saturating_sub(height / 2)
            .min(lines.len() - height)
    };
    let rows: Vec<Line> = lines[offset..]
        .iter()
        .enumerate()
        .map(|(i, l)| {
            if offset + i == selected {
                Line::styled(l.as_str(), style::selected())
            } else {
                Line::from(l.as_str())
            }
        })
        .collect();
    f.render_widget(Paragraph::new(rows), area);
}

/// Ctrl+R history search: the query line sits above the matching prompts.
pub(crate) fn draw_search(
    f: &mut Frame,
    area: Rect,
    query: &str,
    lines: &[String],
    selected: usize,
) {
    let block = overlay_block("History search");
    let inner = block.inner(area);
    f.render_widget(Clear, area);
    f.render_widget(block, area);
    if inner.height == 0 {
        return;
    }
    let [input_area, list_area] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(inner);
    let keep = input_area.width.saturating_sub(4).max(1) as usize;
    let shown: String = query
        .chars()
        .rev()
        .take(keep)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let input = Line::from(vec![
        Span::styled("> ", style::accent()),
        Span::raw(shown),
        Span::styled("▏", style::dim()),
    ]);
    f.render_widget(Paragraph::new(input), input_area);
    draw_rows(f, list_area, lines, selected);
}

pub(crate) fn draw_transcript_overlay(
    f: &mut Frame,
    area: Rect,
    lines: &[Line<'static>],
    scroll: u16,
) {
    let block = overlay_block("Transcript");
    let inner = block.inner(area);
    f.render_widget(Clear, area);
    f.render_widget(block, area);
    draw_pane(f, inner, lines, scroll);
}

pub(crate) fn draw_permission(
    f: &mut Frame,
    area: Rect,
    action: &str,
    resource: &str,
    preview: Option<&str>,
) {
    let width = if preview.is_some() { 80 } else { 60 }.min(area.width);
    let content_width = width.saturating_sub(2).max(1) as usize;

    let mut lines = wrap(&format!("{action} — {resource}"), content_width)
        .into_iter()
        .map(Line::from)
        .collect::<Vec<_>>();
    match preview {
        Some(preview) => {
            let rows: Vec<&str> = preview.lines().collect();
            lines.push(Line::raw(""));
            lines.push(Line::styled("Preview", style::accent()));
            for row in rows.iter().take(12) {
                let s = if row.starts_with("@@") {
                    style::dim()
                } else if row.starts_with('+') {
                    style::success()
                } else if row.starts_with('-') {
                    style::error()
                } else {
                    Style::default()
                };
                lines.push(Line::styled((*row).to_string(), s));
            }
            if rows.len() > 12 {
                lines.push(Line::styled(
                    format!("… +{}", rows.len() - 12),
                    style::dim(),
                ));
            }
        }
        None if action == "bash" => {
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "⚠ bash commands run on your machine — review the command first",
                style::warning(),
            ));
        }
        None => {}
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        Span::styled("[a] Allow once", style::success()),
        Span::raw("   "),
        Span::styled("[A] Always", style::success()),
        Span::raw("   "),
        Span::styled("[d] Deny", style::error()),
    ]));
    lines.push(Line::styled(
        "1 = allow once · 2 = always · 3 = deny · Esc = deny",
        style::dim(),
    ));

    let height = (lines.len() as u16).saturating_add(2).min(area.height);
    let rect = centered(area, width, height);
    let block = overlay_block("Permission");
    let inner = block.inner(rect);
    f.render_widget(Clear, rect);
    f.render_widget(block, rect);
    f.render_widget(Paragraph::new(lines), inner);
}

/// Scrollable `/help` panel: grouped commands and every custom command/skill.
pub(crate) fn draw_help(f: &mut Frame, area: Rect, lines: &[String], scroll: u16) {
    let block = overlay_block("Help");
    let inner = block.inner(area);
    f.render_widget(Clear, area);
    f.render_widget(block, area);
    // Pre-wrap so the scroll limit counts the rows actually painted.
    let text: Vec<Line> = lines
        .iter()
        .flat_map(|line| wrap(line, inner.width.max(1) as usize))
        .map(Line::raw)
        .collect();
    let max = (text.len().min(u16::MAX as usize) as u16).saturating_sub(inner.height);
    f.render_widget(Paragraph::new(text).scroll((scroll.min(max), 0)), inner);
}

pub(crate) fn draw_shortcuts(f: &mut Frame, area: Rect) {
    let groups = [
        (
            "Composer",
            "Enter send · Shift+Enter or Ctrl+J newline · Ctrl+W delete word · Ctrl+U clear line · Ctrl+K kill to end · Left/Right/Home/End cursor · Delete forward · Bracketed paste keeps text",
        ),
        (
            "Session",
            "Ctrl+R history search · Ctrl+E editor · Ctrl+Y copy · Esc interrupt run / clear draft / recall last message · Ctrl+C cancel, twice to quit · Ctrl+D quit",
        ),
        (
            "Panels",
            "? shortcuts · Ctrl+T transcript · PgUp/PgDn scroll · Mouse wheel scroll · Home/End jump to top/tail (Ctrl, or empty composer while scrolled) · Tab agent (queues while running) · Shift+Tab previous agent · Ctrl+K sessions (empty composer) · Ctrl+L models · Ctrl+O agents · Alt+M MCP · Ctrl+P or Ctrl+H help",
        ),
        (
            "Completion",
            "/ lists commands, @ lists files · Up/Down move · Tab/Enter complete · Esc dismiss · pickers filter as you type and Enter selects",
        ),
        (
            "Permissions",
            "a/1 allow once · A/2 always · d/3 deny · Esc deny",
        ),
    ];

    let mut lines = Vec::with_capacity(groups.len() * 2);
    for (label, text) in groups {
        lines.push(Line::from(vec![
            Span::styled(format!("{label}: "), style::accent()),
            Span::raw(text),
        ]));
        lines.push(Line::raw(""));
    }

    let block = overlay_block("Shortcuts");
    let inner = block.inner(area);
    f.render_widget(Clear, area);
    f.render_widget(block, area);
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

/// Full-screen `/config` browser: search line, grouped rows, footer hints.
pub(crate) fn draw_config(f: &mut Frame, area: Rect, panel: &config_panel::Panel) {
    let block = overlay_block("Config");
    let inner = block.inner(area);
    f.render_widget(Clear, area);
    f.render_widget(block, area);
    if inner.height < 3 || inner.width == 0 {
        return;
    }

    let rows = panel.matches();
    let total = rows.len();
    let selected = panel.selected.min(total.saturating_sub(1));
    let [top, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(inner);

    let counter = format!("{}/{}", if total == 0 { 0 } else { selected + 1 }, total);
    let counter_width = (counter.len() as u16).min(inner.width / 4);
    let [search_area, counter_area] =
        Layout::horizontal([Constraint::Min(0), Constraint::Length(counter_width)]).areas(top);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("/ ", style::accent()),
            Span::raw(panel.query.as_str()),
            Span::styled(if panel.searching { "▏" } else { "" }, style::accent()),
        ])),
        search_area,
    );
    f.render_widget(
        Paragraph::new(counter)
            .alignment(Alignment::Right)
            .style(style::dim()),
        counter_area,
    );
    if panel.searching {
        let cursor = search_area
            .x
            .saturating_add(2 + UnicodeWidthStr::width(panel.query.as_str()) as u16)
            .min(search_area.x + search_area.width.saturating_sub(1));
        f.set_cursor_position((cursor, search_area.y));
    }

    let key_width = rows
        .iter()
        .map(|row| UnicodeWidthStr::width(row.key.as_str()))
        .max()
        .unwrap_or(0)
        .min((body.width as usize).saturating_sub(12));

    let mut lines: Vec<Line> = Vec::new();
    let mut category = "";
    let mut selected_line = 0;
    let mut edit_cursor: Option<u16> = None;
    for (index, row) in rows.iter().enumerate() {
        if row.category != category {
            category = row.category;
            lines.push(Line::styled(
                row.category.to_uppercase(),
                style::accent().add_modifier(Modifier::BOLD),
            ));
        }
        let is_selected = index == selected;
        if is_selected {
            selected_line = lines.len();
        }
        let editing = panel.editing.as_ref().filter(|(path, _)| path == &row.path);
        let value = match editing {
            Some((_, buffer)) => buffer.clone(),
            None => config_panel::value_text(row),
        };
        let marker = if is_selected { "▸ " } else { "  " };
        let label = format!(
            "{marker}{:<key_width$}  {value}",
            row.key,
            key_width = key_width
        );
        if let (true, Some(_)) = (is_selected, editing) {
            edit_cursor = Some(
                body.x
                    .saturating_add(2 + key_width as u16 + 2)
                    .saturating_add(UnicodeWidthStr::width(value.as_str()) as u16)
                    .min(body.x + body.width.saturating_sub(1)),
            );
        }
        lines.push(Line::styled(
            label,
            if is_selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            },
        ));
    }

    let height = body.height as usize;
    let offset = selected_line
        .saturating_sub(height.saturating_sub(1))
        .min(lines.len().saturating_sub(height));
    if lines.is_empty() {
        f.render_widget(
            Paragraph::new("no matching settings").style(style::dim()),
            body,
        );
    } else {
        f.render_widget(
            Paragraph::new(
                lines
                    .into_iter()
                    .skip(offset)
                    .take(height)
                    .collect::<Vec<_>>(),
            ),
            body,
        );
    }
    if let Some(x) = edit_cursor {
        let y = body.y + (selected_line - offset) as u16;
        f.set_cursor_position((x, y.min(body.y + body.height.saturating_sub(1))));
    }

    let notice = panel
        .notice
        .as_ref()
        .filter(|(_, at)| Instant::now().duration_since(*at) < Duration::from_secs(3))
        .map(|(message, _)| message.as_str());
    let hint = if let Some(message) = notice {
        message.to_string()
    } else if panel.editing.is_some() {
        "Enter save · Esc cancel".to_string()
    } else if panel.searching {
        "Type to filter · Esc back".to_string()
    } else if rows
        .get(selected)
        .is_some_and(|row| row.kind == config_panel::Kind::ReadOnly)
    {
        "edit rules in freedas.json · / search · Esc close".to_string()
    } else {
        "Enter edit/toggle · / search · Esc close".to_string()
    };
    f.render_widget(Paragraph::new(hint).style(style::dim()), footer);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_panel_renders_rows_and_footer_hints() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut terminal = Terminal::new(TestBackend::new(90, 24)).unwrap();
        let panel = config_panel::Panel::new(&freedas_core::config::Config::default());
        terminal.draw(|f| draw_config(f, f.area(), &panel)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let text: String = buffer.content.iter().map(|cell| cell.symbol()).collect();
        assert!(text.contains("recall.limit"), "{text}");
        assert!(text.contains("Enter edit/toggle"), "{text}");
        assert!(text.contains("1/36"), "{text}");
        // Tiny terminals degrade instead of panicking.
        terminal
            .draw(|f| draw_config(f, Rect::new(0, 0, 4, 2), &panel))
            .unwrap();
    }

    #[test]
    fn tokens_are_shortened() {
        assert_eq!(short_tokens(0), "0");
        assert_eq!(short_tokens(950), "950");
        assert_eq!(short_tokens(1234), "1.2k");
        assert_eq!(short_tokens(1_200_000), "1.2M");
    }

    #[test]
    fn spinner_advances_at_ten_fps() {
        assert_eq!(spinner(Duration::from_millis(250)), "⠹");
        assert_eq!(spinner(Duration::from_millis(0)), "⠋");
    }

    #[test]
    fn unseen_appends_to_any_hint() {
        let s = FooterState {
            draft: true,
            unseen: 3,
            ..Default::default()
        };
        assert_eq!(
            footer_hint(&s),
            "Enter send · Ctrl+J newline · Esc clear · ↓ 3 new"
        );
    }

    #[test]
    fn popup_hints_come_before_the_composer_hints() {
        let s = FooterState {
            slash: true,
            draft: true,
            ..Default::default()
        };
        assert_eq!(
            footer_hint(&s),
            "Up/Down move · Tab/Enter complete · Esc dismiss"
        );
    }

    #[test]
    fn status_right_shows_mode_and_toggles() {
        assert_eq!(
            status_right(Some("ses_0123456789"), true, false, true, false, None, 80),
            "…456789 · auto · sandbox on · relay off"
        );
        assert_eq!(
            status_right(None, false, true, false, true, None, 80),
            "new · manual · sandbox off · relay on"
        );
    }

    #[test]
    fn thinking_keeps_the_tail_of_three_rows() {
        let lines = reasoning_lines("a\nb\nc\nd\ne", 20);
        assert_eq!(lines.len(), 3);
        let texts: Vec<String> = lines
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect();
        assert_eq!(texts[0], "  … c");
        assert_eq!(texts[2], "  e");
    }

    #[test]
    fn short_thinking_starts_with_the_label() {
        let lines = reasoning_lines("planning", 20);
        assert_eq!(lines[0].spans[0].content, "  thinking: ");
    }
}
