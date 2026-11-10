//! Markdown-lite rendering for assistant text.
//!
//! Covers what models actually emit in a terminal: fenced code, inline code,
//! bold, `#` headings, `- ` bullets, and `> ` quotes. Everything else is text.

use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use unicode_width::UnicodeWidthChar;

use crate::style;

pub(crate) fn render(text: &str, width: usize) -> Vec<Line<'static>> {
    let width = width.max(1);
    let mut out = Vec::new();
    let mut code = false;
    for raw in text.split('\n') {
        let line = raw.trim_end();
        if line.trim_start().starts_with("```") {
            code = !code;
            continue;
        }
        if code {
            out.push(Line::styled(format!("│ {line}"), style::dim()));
            continue;
        }
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            let last_blank = out
                .last()
                .map(|l| l.spans.iter().all(|s| s.content.is_empty()))
                .unwrap_or(true);
            if !last_blank {
                out.push(Line::raw(""));
            }
            continue;
        }
        if let Some(rest) = heading(trimmed) {
            out.extend(wrap_spans(
                vec![Span::styled(rest.to_string(), style::bold())],
                width,
            ));
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("> ") {
            let mut spans = vec![Span::styled("│ ", style::dim())];
            spans.extend(inline(rest).into_iter().map(|s| {
                Span::styled(s.content.into_owned(), s.style.add_modifier(Modifier::DIM))
            }));
            out.extend(wrap_spans(spans, width));
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("- ") {
            let mut spans = vec![Span::styled("• ", style::dim())];
            spans.extend(inline(rest));
            out.extend(wrap_spans(spans, width));
            continue;
        }
        out.extend(wrap_spans(inline(trimmed), width));
    }
    out
}

fn heading(line: &str) -> Option<&str> {
    let hashes = line.chars().take_while(|&c| c == '#').count();
    if (1..=6).contains(&hashes) && line.chars().nth(hashes) == Some(' ') {
        Some(line[hashes..].trim_start())
    } else {
        None
    }
}

/// Split a line into spans for `` `code` `` and `**bold**`; unmatched markers
/// stay literal text.
fn inline(text: &str) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        let code_at = rest.find('`').filter(|&i| rest[i + 1..].contains('`'));
        let bold_at = rest.find("**").filter(|&i| rest[i + 2..].contains("**"));
        // Earliest valid marker wins; ties go to inline code.
        let bold_first = match (code_at, bold_at) {
            (Some(c), Some(b)) => b < c,
            (None, Some(_)) => true,
            _ => false,
        };
        let (open, marker) = if bold_first {
            (bold_at, ("**", style::bold()))
        } else {
            (code_at, ("`", style::accent()))
        };
        match open {
            Some(at) => {
                let (open_len, style) = (marker.0.len(), marker.1);
                let close = at + open_len + rest[at + open_len..].find(marker.0).unwrap_or(0);
                push_text(&mut spans, &rest[..at]);
                spans.push(Span::styled(rest[at + open_len..close].to_string(), style));
                rest = &rest[close + open_len..];
            }
            None => {
                push_text(&mut spans, rest);
                rest = "";
            }
        }
    }
    if spans.is_empty() {
        spans.push(Span::raw(String::new()));
    }
    spans
}

fn push_text(spans: &mut Vec<Span<'static>>, text: &str) {
    if !text.is_empty() {
        spans.push(Span::raw(text.to_string()));
    }
}

/// Character-exact wrapping that keeps each span's style, matching
/// `composer::wrap` so transcript math stays consistent.
fn wrap_spans(spans: Vec<Span<'static>>, width: usize) -> Vec<Line<'static>> {
    let width = width.max(1);
    let mut rows: Vec<Vec<Span<'static>>> = vec![Vec::new()];
    let mut used = 0usize;
    for span in spans {
        let style = span.style;
        let mut buf = String::new();
        for ch in span.content.chars() {
            let w = ch.width().unwrap_or(1).max(1);
            if used + w > width {
                if !buf.is_empty() {
                    rows.last_mut()
                        .expect("row")
                        .push(Span::styled(std::mem::take(&mut buf), style));
                }
                rows.push(Vec::new());
                used = 0;
            }
            buf.push(ch);
            used += w;
        }
        if !buf.is_empty() {
            rows.last_mut().expect("row").push(Span::styled(buf, style));
        }
    }
    rows.into_iter().map(Line::from).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flat(line: &Line<'_>) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn fenced_block_keeps_its_lines_with_a_gutter() {
        let lines = render("before\n```\nlet x = 1;\n```\nafter", 40);
        let text: Vec<String> = lines.iter().map(flat).collect();
        assert_eq!(text, vec!["before", "│ let x = 1;", "after"]);
        // `Line::styled` puts the style on the line, not on its spans.
        assert!(lines[1].style.add_modifier.contains(Modifier::DIM));
    }

    #[test]
    fn code_block_is_not_wrapped() {
        let long = "x".repeat(80);
        let lines = render(&format!("```\n{long}\n```"), 20);
        assert_eq!(lines.len(), 1);
        assert_eq!(flat(&lines[0]).chars().count(), 80 + 2);
    }

    #[test]
    fn inline_code_and_bold_become_separate_spans() {
        let lines = render("run `cargo test` and **fix** it", 60);
        let spans = &lines[0].spans;
        let texts: Vec<&str> = spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(texts, vec!["run ", "cargo test", " and ", "fix", " it"]);
        assert!(spans[3].style.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn headings_bullets_and_quotes() {
        let lines = render("# Title\n## Sub\n- one\n> quoted", 40);
        let text: Vec<String> = lines.iter().map(flat).collect();
        assert_eq!(text, vec!["Title", "Sub", "• one", "│ quoted"]);
        assert!(
            lines[0].spans[0]
                .style
                .add_modifier
                .contains(Modifier::BOLD)
        );
        assert!(lines[3].spans[1].style.add_modifier.contains(Modifier::DIM));
    }

    #[test]
    fn paragraphs_are_separated_by_one_blank_line() {
        let text: Vec<String> = render("one\n\n\n\ntwo", 20).iter().map(flat).collect();
        assert_eq!(text, vec!["one", "", "two"]);
    }

    #[test]
    fn long_lines_wrap_to_width_and_keep_styles() {
        let lines = render("**abcdef** ghijkl", 6);
        let text: Vec<String> = lines.iter().map(flat).collect();
        assert_eq!(text, vec!["abcdef", " ghijk", "l"]);
        assert!(
            lines[0].spans[0]
                .style
                .add_modifier
                .contains(Modifier::BOLD)
        );
    }

    #[test]
    fn unmatched_markers_stay_literal() {
        let lines = render("2 * 3 and `open", 40);
        assert_eq!(flat(&lines[0]), "2 * 3 and `open");
    }

    #[test]
    fn zero_width_never_panics() {
        assert!(!render("", 0).iter().any(|l| !l.spans.is_empty()));
        assert_eq!(render("ab", 0).len(), 2);
    }
}
