//! Local memory: store, recall, distill, import.

use freedas_db::Db;
use std::sync::Arc;

pub struct Memory {
    pub db: Arc<Db>,
    pub project_id: Option<String>,
}

impl Memory {
    pub fn new(db: Arc<Db>, project_id: Option<String>) -> Self {
        Self { db, project_id }
    }
    pub fn recall(&self, limit: usize) -> Vec<String> {
        self.db
            .recall_memory(self.project_id.as_deref(), limit)
            .unwrap_or_default()
    }
    pub fn remember(&self, kind: &str, text: &str, confidence: f32) -> Option<String> {
        let text = text.trim();
        let len = text.chars().count();
        if !(12..=500).contains(&len) {
            return None;
        }
        // Never persist secrets: reject when redaction fires.
        let redacted = freedas_core::redact::redact(text);
        if redacted != text {
            return None;
        }
        // A row with project scope but NULL project_id is never recalled
        // (recall filters `project_id = ? OR scope = 'user'`), so global
        // memories must use user scope.
        let scope = if self.project_id.is_some() {
            "project"
        } else {
            "user"
        };
        self.db
            .add_memory(
                scope,
                self.project_id.as_deref(),
                kind,
                &redacted,
                confidence,
            )
            .ok()
    }
}

/// Midnight-UTC milliseconds for a `YYYY-MM-DD` date.
fn date_to_ms(date: &str) -> Option<i64> {
    let mut parts = date.split('-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: i64 = parts.next()?.parse().ok()?;
    let d: i64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let (y, m) = if m <= 2 { (y - 1, m + 12) } else { (y, m) };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m - 3) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86_400_000)
}

/// Longest single imported record (chars). Mirrors `remember`'s upper bound;
/// longer bodies are dropped so a hostile file cannot smuggle oversized rows
/// past the import path.
pub const MAX_IMPORT_RECORD_CHARS: usize = 500;
/// Most records kept from one import file. Bounds DB writes per invocation.
pub const MAX_IMPORT_RECORDS: usize = 500;

/// Parse a memory export: `##` headings map sections to kinds and
/// `[YYYY-MM-DD] - text` lines become dated records. The date is returned
/// as `created_at` milliseconds (midnight UTC) instead of being stripped;
/// the body keeps its brackets verbatim. Unknown sections are fact memory.
/// Records over `MAX_IMPORT_RECORD_CHARS` are dropped and parsing stops at
/// `MAX_IMPORT_RECORDS`; the import path re-checks every record through
/// `Memory::remember` (length window, secret refusal).
pub fn parse_memory_import(text: &str) -> Vec<(String, String, Option<i64>)> {
    let mut out = Vec::new();
    let mut section = "fact";
    for line in text.lines() {
        if out.len() >= MAX_IMPORT_RECORDS {
            break;
        }
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("## ") {
            section = match rest.trim().to_lowercase().as_str() {
                "instructions" | "preferences" => "preference",
                "identity" | "career" | "projects" | "general" => "fact",
                "decisions" | "decision" => "decision",
                "lessons" | "lesson" => "lesson",
                _ => "fact",
            };
            continue;
        }
        if line.is_empty() {
            continue;
        }
        // `[YYYY-MM-DD] - text` or `YYYY-MM-DD - text`: keep the date.
        let bare = line.trim_start_matches('[');
        if let Some(idx) = bare.find(" - ") {
            let date = bare[..idx].trim_end_matches(']').trim_end();
            let is_date = date.len() == 10
                && date.chars().nth(4) == Some('-')
                && date.chars().nth(7) == Some('-')
                && date.chars().all(|c| c.is_ascii_digit() || c == '-');
            if is_date {
                let body = bare[idx + 3..].trim().to_string();
                if !body.is_empty() && body.chars().count() <= MAX_IMPORT_RECORD_CHARS {
                    out.push((section.to_string(), body, date_to_ms(date)));
                    continue;
                }
            }
        }
        let body = line.trim_start_matches("- ").trim().to_string();
        if !body.is_empty() && body.chars().count() <= MAX_IMPORT_RECORD_CHARS {
            out.push((section.to_string(), body, None));
        }
    }
    out
}
