//! Typed transcript cells and their terminal rendering.

use ratatui::text::{Line, Span};

use crate::composer::wrap;
use crate::markdown;
use crate::style;

pub(crate) enum Cell {
    User(String),
    Assistant(String),
    Tool(Tool),
    Error(String),
    Notice(String),
    Reasoning(String),
}

pub(crate) struct Tool {
    pub name: String,
    /// `None` while the tool runs, `Some(ok)` once the result event arrives.
    pub ok: Option<bool>,
    pub output: String,
    pub diff: Option<String>,
}

impl Tool {
    pub(crate) fn running(name: String) -> Self {
        Self {
            name,
            ok: None,
            output: String::new(),
            diff: None,
        }
    }
}

impl Cell {
    pub(crate) fn lines(&self, width: usize) -> Vec<Line<'static>> {
        match self {
            Cell::User(text) => user_lines(text, width),
            Cell::Assistant(text) => markdown::render(text, width),
            Cell::Tool(tool) => tool_lines(tool, width),
            Cell::Error(text) => styled_wrap(text, width, style::error()),
            Cell::Notice(text) => styled_wrap(text, width, style::dim()),
            Cell::Reasoning(text) => styled_wrap(
                text,
                width,
                style::dim().add_modifier(ratatui::style::Modifier::ITALIC),
            ),
        }
    }

    /// Plain text for `/copy` and `/export`.
    pub(crate) fn plain(&self) -> String {
        match self {
            Cell::User(text) => format!("> {text}"),
            Cell::Assistant(text) => text.clone(),
            Cell::Tool(tool) => {
                let mut out = format!("{} {}", tool_icon(tool.ok), tool.name);
                if !tool.output.is_empty() {
                    out.push('\n');
                    out.push_str(&tool.output);
                }
                if let Some(diff) = &tool.diff {
                    out.push('\n');
                    out.push_str(diff);
                }
                out
            }
            Cell::Error(text) | Cell::Notice(text) | Cell::Reasoning(text) => text.clone(),
        }
    }
}

fn tool_icon(ok: Option<bool>) -> &'static str {
    match ok {
        None => "⏺",
        Some(true) => "✔",
        Some(false) => "✖",
    }
}

fn user_lines(text: &str, width: usize) -> Vec<Line<'static>> {
    let body = width.saturating_sub(2).max(1);
    let mut out = Vec::new();
    for (i, row) in wrap(text, body).into_iter().enumerate() {
        let marker = if i == 0 { "› " } else { "  " };
        out.push(Line::from(vec![
            Span::styled(
                marker.to_string(),
                style::accent().add_modifier(ratatui::style::Modifier::BOLD),
            ),
            Span::styled(row, style::bold()),
        ]));
    }
    out.push(Line::raw(""));
    out
}

fn styled_wrap(text: &str, width: usize, style: ratatui::style::Style) -> Vec<Line<'static>> {
    wrap(text, width)
        .into_iter()
        .map(|row| Line::styled(row, style))
        .collect()
}

const TOOL_OUTPUT_LINES: usize = 6;
const DIFF_LINES: usize = 20;

fn tool_lines(tool: &Tool, width: usize) -> Vec<Line<'static>> {
    let width = width.max(1);
    let style = match tool.ok {
        None => style::accent(),
        Some(true) => style::success(),
        Some(false) => style::error(),
    };
    let mut out = vec![Line::from(vec![
        Span::styled(format!("{} ", tool_icon(tool.ok)), style),
        Span::styled(tool.name.clone(), style::bold()),
    ])];
    let body: Vec<&str> = tool.output.lines().collect();
    for line in body.iter().take(TOOL_OUTPUT_LINES) {
        out.extend(styled_wrap(line, width, ratatui::style::Style::default()));
    }
    if body.len() > TOOL_OUTPUT_LINES {
        out.push(Line::styled(
            format!("… +{} lines", body.len() - TOOL_OUTPUT_LINES),
            style::dim(),
        ));
    }
    if let Some(diff) = &tool.diff {
        out.push(Line::styled("╭─ diff", style::dim()));
        let lines: Vec<&str> = diff.lines().collect();
        let body_width = width.saturating_sub(2).max(1);
        for line in lines.iter().take(DIFF_LINES) {
            let row_style = if line.starts_with("@@") {
                style::dim()
            } else if line.starts_with('+') {
                style::success()
            } else if line.starts_with('-') {
                style::error()
            } else {
                ratatui::style::Style::default()
            };
            for row in wrap(line, body_width) {
                out.push(Line::styled(format!("│ {row}"), row_style));
            }
        }
        if lines.len() > DIFF_LINES {
            out.push(Line::styled(
                format!("│ … +{} lines", lines.len() - DIFF_LINES),
                style::dim(),
            ));
        }
        out.push(Line::styled("╰─", style::dim()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flat(line: &Line<'_>) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn tool_states_use_their_glyph() {
        let cell = |ok| {
            Cell::Tool(Tool {
                name: "edit".into(),
                ok,
                output: String::new(),
                diff: None,
            })
        };
        assert_eq!(flat(&cell(None).lines(40)[0]), "⏺ edit");
        assert_eq!(flat(&cell(Some(true)).lines(40)[0]), "✔ edit");
        assert_eq!(flat(&cell(Some(false)).lines(40)[0]), "✖ edit");
    }

    #[test]
    fn tool_output_wraps_instead_of_clipping() {
        let cell = Cell::Tool(Tool {
            name: "read".into(),
            ok: Some(true),
            output: "abcdefgh".into(),
            diff: Some("+0123456789".into()),
        });
        let rows: Vec<String> = cell.lines(4).iter().map(flat).collect();
        assert_eq!(rows[0], "✔ read");
        assert!(rows.contains(&"abcd".to_string()), "{rows:?}");
        assert!(rows.contains(&"efgh".to_string()), "{rows:?}");
        // The diff body is prefixed with `│ ` and wrapped to the remaining 2.
        assert!(rows.iter().any(|r| r == "│ +0"), "{rows:?}");
        assert!(rows.iter().any(|r| r == "│ 12"), "{rows:?}");
        assert!(rows.iter().all(|r| r != "│ +0123456789"));
    }

    #[test]
    fn tool_output_is_capped_at_six_lines() {
        let tool = Tool {
            name: "bash".into(),
            ok: Some(true),
            output: (1..=9)
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join("\n"),
            diff: None,
        };
        let text: Vec<String> = Cell::Tool(tool).lines(40).iter().map(flat).collect();
        assert_eq!(text.len(), 1 + 6 + 1);
        assert_eq!(text[7], "… +3 lines");
    }

    #[test]
    fn diff_is_previewed_with_a_border_and_cap() {
        let diff: String = (1..=25)
            .map(|i| {
                if i % 3 == 0 {
                    format!("+line {i}")
                } else {
                    format!("-line {i}")
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        let cell = Cell::Tool(Tool {
            name: "edit".into(),
            ok: Some(true),
            output: "edited path".into(),
            diff: Some(diff),
        });
        let text: Vec<String> = cell.lines(60).iter().map(flat).collect();
        assert_eq!(text[0], "✔ edit");
        assert_eq!(text[1], "edited path");
        assert_eq!(text[2], "╭─ diff");
        assert_eq!(text[3], "│ -line 1");
        assert_eq!(text[23], "│ … +5 lines");
        assert_eq!(text[24], "╰─");
    }

    #[test]
    fn user_cell_has_a_marker_and_a_trailing_blank() {
        let lines = Cell::User("hi there".into()).lines(40);
        let text: Vec<String> = lines.iter().map(flat).collect();
        assert_eq!(text, vec!["› hi there", ""]);
        assert!(
            lines[0].spans[1]
                .style
                .add_modifier
                .contains(ratatui::style::Modifier::BOLD)
        );
    }

    #[test]
    fn user_cell_wraps_under_the_marker() {
        let text: Vec<String> = Cell::User("abcdef".into())
            .lines(5)
            .iter()
            .map(flat)
            .collect();
        assert_eq!(text, vec!["› abc", "  def", ""]);
    }

    #[test]
    fn plain_text_keeps_what_copy_expects() {
        assert_eq!(Cell::User("hi".into()).plain(), "> hi");
        assert_eq!(Cell::Notice("note".into()).plain(), "note");
        assert_eq!(Cell::Reasoning("think".into()).plain(), "think");
    }
}
