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
        // A forgotten text stays forgotten: tombstoned rows cannot be
        // re-imported or re-distilled.
        if self.db.memory_tombstoned(&redacted) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn memory() -> Memory {
        Memory::new(Arc::new(Db::memory().unwrap()), None)
    }

    #[test]
    fn parses_sections_and_dated_records() {
        let text = "\
## Preferences
- prefer rust over go for services
[2026-01-02] - the api uses graphql
## Decisions
[2026-03-04] - ship the new api behind a flag
## Something else
- unknown sections are facts
";
        let records = parse_memory_import(text);
        assert_eq!(records.len(), 4);
        assert_eq!(records[0].0, "preference");
        assert_eq!(records[0].1, "prefer rust over go for services");
        assert_eq!(records[0].2, None);
        assert_eq!(records[1].0, "preference");
        assert_eq!(records[1].1, "the api uses graphql");
        assert_eq!(records[1].2, Some(1767312000000));
        assert_eq!(records[2].0, "decision");
        assert_eq!(records[2].1, "ship the new api behind a flag");
        assert_eq!(records[2].2, Some(1772582400000));
        assert_eq!(records[3].0, "fact");
        assert_eq!(records[3].1, "unknown sections are facts");
    }

    #[test]
    fn a_dated_record_keeps_its_own_brackets() {
        let records = parse_memory_import("[note] - the body keeps the brackets\n");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].1, "[note] - the body keeps the brackets");
        assert_eq!(records[0].2, None);
    }

    #[test]
    fn a_line_that_is_not_a_date_stays_a_record() {
        let records = parse_memory_import("[2026-1-2] - malformed dates are plain text\n");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].1, "[2026-1-2] - malformed dates are plain text");
        assert_eq!(records[0].2, None);
    }

    #[test]
    fn import_caps_the_record_size_and_the_count() {
        let long = "x".repeat(MAX_IMPORT_RECORD_CHARS + 1);
        let records = parse_memory_import(&format!("- {long}\n"));
        assert!(records.is_empty(), "an oversized record must be dropped");

        let many = (0..MAX_IMPORT_RECORDS + 10)
            .map(|i| format!("- record number {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let records = parse_memory_import(&many);
        assert_eq!(records.len(), MAX_IMPORT_RECORDS);
    }

    #[test]
    fn remember_stores_and_recalls_a_record() {
        let memory = memory();
        let id = memory
            .remember("preference", "prefer rust over go for services", 0.9)
            .expect("stored");
        assert!(id.starts_with("mem_"), "got {id}");
        assert_eq!(
            memory.recall(10),
            vec!["prefer rust over go for services".to_string()]
        );
    }

    #[test]
    fn remember_refuses_text_outside_the_length_window() {
        let memory = memory();
        assert!(memory.remember("fact", "too short", 0.9).is_none());
        let long = "x".repeat(501);
        assert!(memory.remember("fact", &long, 0.9).is_none());
        let edge = "x".repeat(12);
        assert!(memory.remember("fact", &edge, 0.9).is_some());
    }

    #[test]
    fn remember_refuses_a_secret() {
        let memory = memory();
        assert!(
            memory
                .remember("fact", "api_key=sk_live_0123456789abcdefghij", 0.9)
                .is_none(),
            "a secret must never be stored"
        );
        assert!(memory.recall(10).is_empty());
    }

    #[test]
    fn a_forgotten_record_stays_forgotten() {
        let memory = memory();
        let id = memory
            .remember("fact", "the api uses graphql for every query", 0.9)
            .expect("stored");
        assert!(memory.db.delete_memory(&id).expect("deleted"));
        assert!(memory.recall(10).is_empty());
        assert!(
            memory
                .remember("fact", "the api uses graphql for every query", 0.9)
                .is_none(),
            "a tombstoned text must not come back"
        );
    }

    #[test]
    fn project_memories_stay_in_their_project() {
        let db = Arc::new(Db::memory().unwrap());
        let root = std::env::temp_dir().join(format!("freedas-mem-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let project = db.ensure_project(&root).expect("project");
        let memory = Memory::new(db.clone(), Some(project.clone()));
        memory
            .remember("fact", "the api uses graphql for every query", 0.9)
            .expect("stored");
        assert_eq!(memory.recall(10).len(), 1);

        let other = db
            .ensure_project(&root.join("other"))
            .expect("other project");
        let elsewhere = Memory::new(db, Some(other));
        assert!(
            elsewhere.recall(10).is_empty(),
            "another project must not see the record"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
