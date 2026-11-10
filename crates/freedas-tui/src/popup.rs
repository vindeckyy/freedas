//! Composer popups (slash commands, `@` files) and the Ctrl+K/L/O/M pickers.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use crate::style;

pub(crate) const MENU_ROWS: usize = 8;

pub(crate) struct Row {
    /// Text the typed filter matches against.
    pub key: String,
    pub display: String,
    /// Dim detail shown after `display` on the same line.
    pub detail: String,
    /// Payload applied when the row is accepted.
    pub value: String,
}

pub(crate) fn row(
    key: impl Into<String>,
    display: impl Into<String>,
    value: impl Into<String>,
) -> Row {
    Row {
        key: key.into(),
        display: display.into(),
        detail: String::new(),
        value: value.into(),
    }
}

pub(crate) fn detailed_row(
    key: impl Into<String>,
    display: impl Into<String>,
    detail: impl Into<String>,
    value: impl Into<String>,
) -> Row {
    Row {
        key: key.into(),
        display: display.into(),
        detail: detail.into(),
        value: value.into(),
    }
}

/// Prefix matches first, then substring matches, capped at `limit`.
pub(crate) fn rank(query: &str, rows: &[Row], limit: usize) -> Vec<usize> {
    let query = query.to_lowercase();
    let (mut prefix, mut contains) = (Vec::new(), Vec::new());
    for (i, row) in rows.iter().enumerate() {
        let key = row.key.to_lowercase();
        if query.is_empty() || key.starts_with(&query) {
            prefix.push(i);
        } else if key.contains(&query) {
            contains.push(i);
        }
    }
    prefix.extend(contains);
    prefix.truncate(limit);
    prefix
}

pub(crate) fn clamp(picks: &[usize], selected: usize) -> usize {
    selected.min(picks.len().saturating_sub(1))
}

/// The `/command` being typed: the draft is a single token starting with `/`.
pub(crate) fn slash_query(draft: &str) -> Option<&str> {
    let token = draft.trim_start();
    if !token.starts_with('/') || token.chars().any(char::is_whitespace) {
        return None;
    }
    Some(&token[1..])
}

/// The `@path` token around the cursor: `(start, end, query)` in chars.
pub(crate) fn at_token(text: &str, cursor: usize) -> Option<(usize, usize, String)> {
    let chars: Vec<char> = text.chars().collect();
    let cursor = cursor.min(chars.len());
    let start = (0..cursor)
        .rev()
        .find(|&i| chars[i].is_whitespace())
        .map_or(0, |i| i + 1);
    let end = (cursor..chars.len())
        .find(|&i| chars[i].is_whitespace())
        .unwrap_or(chars.len());
    let token: String = chars[start..end].iter().collect();
    let query = token.strip_prefix('@')?;
    Some((start, end, query.to_string()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Sessions,
    Models,
    Agents,
    Mcp,
    Permissions,
}

pub(crate) struct Picker {
    pub kind: Kind,
    pub title: &'static str,
    pub rows: Vec<Row>,
    pub filter: String,
    pub selected: usize,
    /// Reasoning variants per row value (Models only).
    pub variants: std::collections::BTreeMap<String, Vec<String>>,
    /// Active variant index into the chosen row's list; `None` = no variants.
    pub variant: Option<usize>,
    /// Value the variant state belongs to, so moving rows resets it once.
    pub last_value: Option<String>,
    /// Row value that is the currently applied setting (Permissions).
    pub active: Option<String>,
}

impl Picker {
    pub(crate) fn new(kind: Kind, title: &'static str, rows: Vec<Row>) -> Self {
        Self {
            kind,
            title,
            rows,
            filter: String::new(),
            selected: 0,
            variants: std::collections::BTreeMap::new(),
            variant: None,
            last_value: None,
            active: None,
        }
    }

    pub(crate) fn picks(&self) -> Vec<usize> {
        rank(&self.filter, &self.rows, self.rows.len())
    }

    pub(crate) fn chosen(&self) -> Option<&Row> {
        let picks = self.picks();
        picks
            .get(clamp(&picks, self.selected))
            .map(|&i| &self.rows[i])
    }

    fn chosen_variants(&self) -> &[String] {
        self.chosen()
            .and_then(|row| self.variants.get(&row.value))
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// The variant label the chosen row would apply.
    pub(crate) fn variant_label(&self) -> Option<&str> {
        self.variant
            .and_then(|i| self.chosen_variants().get(i))
            .map(String::as_str)
    }

    /// Point the variant state at the chosen row. Only a row change resets it:
    /// prefer `preferred` (the applied variant) when that model has it, else
    /// the model's last variant (typically `max`).
    pub(crate) fn follow(&mut self, preferred: Option<&str>) {
        let value = self.chosen().map(|row| row.value.clone());
        if value == self.last_value {
            return;
        }
        self.last_value = value.clone();
        let list = value
            .as_ref()
            .and_then(|v| self.variants.get(v))
            .map(Vec::as_slice)
            .unwrap_or_default();
        self.variant = if list.is_empty() {
            None
        } else {
            Some(
                preferred
                    .and_then(|p| list.iter().position(|v| v == p))
                    .unwrap_or(list.len() - 1),
            )
        };
    }

    /// Tab/Shift+Tab over the chosen model's variants; clamps at both ends.
    pub(crate) fn cycle_variant(&mut self, back: bool) {
        let len = self.chosen_variants().len();
        if len == 0 {
            self.variant = None;
            return;
        }
        let index = self.variant.unwrap_or(len - 1);
        self.variant = Some(if back {
            index.saturating_sub(1)
        } else {
            (index + 1).min(len - 1)
        });
    }
}

fn block(title: &str) -> Block<'_> {
    Block::new()
        .borders(Borders::ALL)
        .title(format!(" {title} "))
        .border_style(style::dim())
}

/// Rows for a bordered list, kept centered on `selected`.
fn draw_rows(f: &mut Frame, area: Rect, lines: &[Line<'static>], selected: usize) {
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
        .map(|(i, line)| {
            if offset + i == selected {
                line.clone().style(style::selected())
            } else {
                line.clone()
            }
        })
        .collect();
    f.render_widget(Paragraph::new(rows), area);
}

/// Slash and `@` completion list, drawn just above the composer.
pub(crate) fn draw_completion(
    f: &mut Frame,
    anchor: Rect,
    rows: &[Row],
    picks: &[usize],
    selected: usize,
) {
    if picks.is_empty() {
        return;
    }
    let shown = picks.len().min(MENU_ROWS);
    // Leave the header row alone and stay inside the frame on short terminals.
    let height = (shown as u16 + 2)
        .min(anchor.y.saturating_sub(1))
        .min(f.area().height);
    if height < 3 {
        return;
    }
    let rect =
        Rect::new(anchor.x, anchor.y - height, anchor.width.min(80), height).intersection(f.area());
    let lines: Vec<Line> = picks
        .iter()
        .take(shown)
        .map(|&i| Line::from(rows[i].display.clone()))
        .collect();
    f.render_widget(Clear, rect);
    let block = block("Complete");
    let inner = block.inner(rect);
    f.render_widget(block, rect);
    draw_rows(f, inner, &lines, clamp(picks, selected));
}

fn footer_height(kind: Kind) -> u16 {
    match kind {
        Kind::Models => 2,
        Kind::Permissions => 1,
        _ => 0,
    }
}

/// `Reasoning: low · medium · high · max`, active level bold, others dim.
fn reasoning_line(picker: &Picker) -> Line<'static> {
    let list = picker.chosen_variants();
    let mut spans = vec![Span::styled("Reasoning: ", style::dim())];
    if list.is_empty() {
        spans.push(Span::styled("—", style::dim()));
        return Line::from(spans);
    }
    for (i, variant) in list.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" · ", style::dim()));
        }
        let hl = if picker.variant == Some(i) {
            style::accent().add_modifier(Modifier::BOLD)
        } else {
            style::dim()
        };
        spans.push(Span::styled(variant.clone(), hl));
    }
    Line::from(spans)
}

/// Centered picker overlay with a filter input line and a per-kind footer.
pub(crate) fn draw_picker(f: &mut Frame, area: Rect, picker: &Picker) {
    let picks = picker.picks();
    let footer = footer_height(picker.kind);
    let height = picks.len().min(10) as u16 + 3 + footer;
    let rect = crate::view::centered(area, 80, height);
    f.render_widget(Clear, rect);
    let block = block(picker.title);
    let inner = block.inner(rect);
    f.render_widget(block, rect);
    if inner.height == 0 {
        return;
    }
    let [input_area, list_area, footer_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(footer),
    ])
    .areas(inner);
    let keep = input_area.width.saturating_sub(4).max(1) as usize;
    let shown: String = picker
        .filter
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
    let lines: Vec<Line> = picks
        .iter()
        .map(|&i| {
            let row = &picker.rows[i];
            let mut spans = Vec::new();
            if picker.kind == Kind::Permissions {
                let on = picker.active.as_deref() == Some(row.value.as_str());
                spans.push(Span::styled(
                    if on { "● " } else { "  " },
                    if on { style::accent() } else { style::dim() },
                ));
            }
            spans.push(Span::raw(row.display.clone()));
            if !row.detail.is_empty() {
                spans.push(Span::styled(format!("  {}", row.detail), style::dim()));
            }
            Line::from(spans)
        })
        .collect();
    draw_rows(f, list_area, &lines, clamp(&picks, picker.selected));
    match picker.kind {
        Kind::Models => {
            let [reasoning_area, hint_area] =
                Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(footer_area);
            f.render_widget(Paragraph::new(reasoning_line(picker)), reasoning_area);
            f.render_widget(
                Paragraph::new("Up/Down move · Tab reasoning · Enter apply · Esc cancel")
                    .style(style::dim()),
                hint_area,
            );
        }
        Kind::Permissions => {
            f.render_widget(
                Paragraph::new("Up/Down move · Enter apply · Esc cancel").style(style::dim()),
                footer_area,
            );
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows() -> Vec<Row> {
        vec![
            row("new", "/new — start a session", "new"),
            row("sessions", "/sessions — resume", "sessions"),
            row("news", "/news — fake", "news"),
            row("review", "/review — review the diff", "review"),
        ]
    }

    #[test]
    fn slash_query_needs_a_lone_slash_token() {
        assert_eq!(slash_query("/"), Some(""));
        assert_eq!(slash_query("/new"), Some("new"));
        assert_eq!(slash_query("  /re"), Some("re"));
        assert_eq!(slash_query("/new "), None);
        assert_eq!(slash_query("hello /new"), None);
        assert_eq!(slash_query(""), None);
    }

    #[test]
    fn rank_puts_prefix_matches_before_substrings() {
        let picks = rank("new", &rows(), MENU_ROWS);
        assert_eq!(picks, vec![0, 2]);
        let picks = rank("view", &rows(), MENU_ROWS);
        assert_eq!(picks, vec![3]);
        assert_eq!(rank("", &rows(), 2), vec![0, 1]);
        assert_eq!(rank("zzz", &rows(), 8), Vec::<usize>::new());
    }

    #[test]
    fn at_token_finds_the_path_being_typed() {
        assert_eq!(
            at_token("look at @src/ma", 15),
            Some((8, 15, "src/ma".to_string()))
        );
        assert_eq!(at_token("@a", 2), Some((0, 2, "a".to_string())));
        assert_eq!(at_token("email@x", 7), None);
        assert_eq!(at_token("plain", 5), None);
        // Cursor inside the token still matches the whole token.
        assert_eq!(at_token("x @abc y", 5), Some((2, 6, "abc".to_string())));
    }

    #[test]
    fn choice_is_clamped_to_the_filtered_rows() {
        let mut picker = Picker::new(Kind::Agents, "Agents", rows());
        picker.filter = "review".into();
        picker.selected = 9;
        assert_eq!(picker.chosen().map(|r| r.value.as_str()), Some("review"));
        picker.filter = "zzz".into();
        assert_eq!(picker.chosen().map(|r| r.value.as_str()), None);
    }

    fn models_picker() -> Picker {
        let mut picker = Picker::new(
            Kind::Models,
            "Models",
            vec![
                detailed_row("a/x", "a/x", "X · mid · 200K · $1/$2 per 1M", "a/x"),
                detailed_row("b/y", "b/y", "Y · frontier · 128K · $3/$9 per 1M", "b/y"),
                detailed_row("c/z", "c/z", "Z · cheap · 32K · $0/$0 per 1M", "c/z"),
            ],
        );
        picker.variants.insert(
            "a/x".into(),
            vec!["low".into(), "medium".into(), "high".into(), "max".into()],
        );
        picker.variants.insert("c/z".into(), vec![]);
        picker
    }

    #[test]
    fn variant_cycling_clamps_and_resets_on_row_change() {
        let mut picker = models_picker();
        picker.follow(Some("max"));
        assert_eq!(picker.variant_label(), Some("max"));
        // Forward clamps at the last variant; backward walks down.
        picker.cycle_variant(false);
        assert_eq!(picker.variant_label(), Some("max"));
        picker.cycle_variant(true);
        assert_eq!(picker.variant_label(), Some("high"));
        picker.cycle_variant(true);
        picker.cycle_variant(true);
        assert_eq!(picker.variant_label(), Some("low"));
        picker.cycle_variant(true);
        assert_eq!(picker.variant_label(), Some("low"));
        // Moving to another model resets: the preferred variant wins when the
        // new model lists it; a model with no variants selects none.
        picker.selected = 2;
        picker.follow(Some("high"));
        assert_eq!(picker.variant_label(), None);
        picker.selected = 0;
        picker.follow(Some("high"));
        assert_eq!(picker.variant_label(), Some("high"));
        // Without a preferred match the last variant wins.
        picker.selected = 1;
        picker.follow(Some("turbo"));
        assert_eq!(picker.variant_label(), None);
        picker.selected = 0;
        picker.follow(Some("turbo"));
        assert_eq!(picker.variant_label(), Some("max"));
    }

    fn render(picker: &Picker) -> String {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut terminal = Terminal::new(TestBackend::new(90, 24)).unwrap();
        terminal.draw(|f| draw_picker(f, f.area(), picker)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        buffer.content.iter().map(|cell| cell.symbol()).collect()
    }

    #[test]
    fn models_overlay_shows_reasoning_footer() {
        let mut picker = models_picker();
        picker.follow(Some("max"));
        let text = render(&picker);
        assert!(text.contains("Models"), "{text}");
        assert!(
            text.contains("Reasoning: low · medium · high · max"),
            "{text}"
        );
        assert!(
            text.contains("Tab reasoning · Enter apply · Esc cancel"),
            "{text}"
        );
        // A model without variants still shows the footer as an em dash.
        picker.selected = 2;
        picker.follow(Some("max"));
        let text = render(&picker);
        assert!(text.contains("Reasoning: —"), "{text}");
    }

    #[test]
    fn permissions_overlay_marks_the_active_mode() {
        let mut picker = Picker::new(
            Kind::Permissions,
            "Permissions",
            vec![
                detailed_row("bypass", "bypass", "Bypass", "bypass"),
                detailed_row("auto", "auto", "Auto", "auto"),
                detailed_row("ask", "ask", "Ask", "ask"),
            ],
        );
        picker.active = Some("auto".into());
        let text = render(&picker);
        assert!(text.contains("Permissions"), "{text}");
        assert!(text.contains("●"), "{text}");
        assert!(text.contains("Enter apply · Esc cancel"), "{text}");
    }
}
