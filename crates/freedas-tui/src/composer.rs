#[derive(Default)]
pub(crate) struct Composer {
    text: String,
    cursor: usize,
}

impl Composer {
    pub(crate) fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }

    pub(crate) fn set(&mut self, text: impl Into<String>) {
        self.text = text.into();
        self.cursor = self.text.chars().count();
    }

    pub(crate) fn clear(&mut self) {
        self.text.clear();
        self.cursor = 0;
    }

    /// Replace the char range `start..end`; the cursor lands after the insert.
    pub(crate) fn replace_range(&mut self, start: usize, end: usize, text: &str) {
        let total = self.char_count();
        let start = start.min(total);
        let end = end.clamp(start, total);
        let (from, to) = (self.byte_idx(start), self.byte_idx(end));
        self.text.replace_range(from..to, text);
        self.cursor = start + text.chars().count();
    }

    pub(crate) fn take_trimmed(&mut self) -> String {
        let out = self.text.trim().to_string();
        self.clear();
        out
    }

    pub(crate) fn insert_char(&mut self, c: char) {
        let at = self.byte_idx(self.cursor);
        self.text.insert(at, c);
        self.cursor += 1;
    }

    pub(crate) fn insert_str(&mut self, s: &str) {
        let at = self.byte_idx(self.cursor);
        self.text.insert_str(at, s);
        self.cursor += s.chars().count();
    }

    pub(crate) fn newline(&mut self) {
        self.insert_char('\n');
    }

    pub(crate) fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let (from, to) = (self.byte_idx(self.cursor - 1), self.byte_idx(self.cursor));
        self.text.replace_range(from..to, "");
        self.cursor -= 1;
    }

    pub(crate) fn delete(&mut self) {
        if self.cursor >= self.char_count() {
            return;
        }
        let (from, to) = (self.byte_idx(self.cursor), self.byte_idx(self.cursor + 1));
        self.text.replace_range(from..to, "");
    }

    pub(crate) fn left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub(crate) fn right(&mut self) {
        if self.cursor < self.char_count() {
            self.cursor += 1;
        }
    }

    pub(crate) fn home(&mut self) {
        self.cursor = self.line_start();
    }

    pub(crate) fn end(&mut self) {
        self.cursor = self.line_end();
    }

    pub(crate) fn delete_word(&mut self) {
        let chars: Vec<char> = self.text.chars().collect();
        let mut start = self.cursor.min(chars.len());
        while start > 0 && chars[start - 1].is_whitespace() {
            start -= 1;
        }
        while start > 0 && !chars[start - 1].is_whitespace() {
            start -= 1;
        }
        if start == self.cursor {
            return;
        }
        let (from, to) = (self.byte_idx(start), self.byte_idx(self.cursor));
        self.text.replace_range(from..to, "");
        self.cursor = start;
    }

    pub(crate) fn clear_line(&mut self) {
        let start = self.line_start();
        if start < self.cursor {
            let (from, to) = (self.byte_idx(start), self.byte_idx(self.cursor));
            self.text.replace_range(from..to, "");
            self.cursor = start;
        } else if self.cursor > 0 {
            let (from, to) = (self.byte_idx(self.cursor - 1), self.byte_idx(self.cursor));
            self.text.replace_range(from..to, "");
            self.cursor -= 1;
        }
    }

    pub(crate) fn kill_to_end(&mut self) {
        let end = self.line_end();
        if end > self.cursor {
            let (from, to) = (self.byte_idx(self.cursor), self.byte_idx(end));
            self.text.replace_range(from..to, "");
        } else if self.cursor < self.char_count() {
            let (from, to) = (self.byte_idx(self.cursor), self.byte_idx(self.cursor + 1));
            self.text.replace_range(from..to, "");
        }
    }

    fn char_count(&self) -> usize {
        self.text.chars().count()
    }

    fn byte_idx(&self, char_idx: usize) -> usize {
        self.text
            .char_indices()
            .nth(char_idx)
            .map_or(self.text.len(), |(i, _)| i)
    }

    fn line_start(&self) -> usize {
        let at = self.byte_idx(self.cursor);
        match self.text[..at].rfind('\n') {
            Some(i) => self.text[..=i].chars().count(),
            None => 0,
        }
    }

    fn line_end(&self) -> usize {
        let at = self.byte_idx(self.cursor);
        match self.text[at..].find('\n') {
            Some(i) => self.text[..at + i].chars().count(),
            None => self.char_count(),
        }
    }
}

use unicode_width::UnicodeWidthChar;
use unicode_width::UnicodeWidthStr;

pub(crate) fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut rows = Vec::new();
    for line in text.split('\n') {
        if line.is_empty() {
            rows.push(String::new());
            continue;
        }
        let mut row = String::new();
        let mut used = 0usize;
        for ch in line.chars() {
            let w = ch.width().unwrap_or(1).max(1);
            // Keep a single wide glyph on an empty row instead of emitting a
            // leading blank row when the pane is one column wide.
            if used + w > width && !row.is_empty() {
                rows.push(std::mem::take(&mut row));
                used = 0;
            }
            row.push(ch);
            used += w;
        }
        rows.push(row);
    }
    rows
}

pub(crate) fn wrapped_height(text: &str, width: usize) -> usize {
    wrap(text, width).len()
}

pub(crate) fn cursor_row_col(text: &str, cursor: usize, width: usize) -> (usize, usize) {
    let width = width.max(1);
    let mut row = 0;
    let mut remaining = cursor;
    for line in text.split('\n') {
        let count = line.chars().count();
        if remaining <= count {
            // Same wrapper as the renderer, so the cursor cannot land on a
            // different row than the text it marks.
            let prefix: String = line.chars().take(remaining).collect();
            let rows = wrap(&prefix, width);
            let last = rows.len() - 1;
            let last_width = UnicodeWidthStr::width(rows[last].as_str());
            if remaining == count || last_width < width {
                return (row + last, last_width);
            }
            // The cursor sits exactly at a wrap boundary: it starts the next
            // painted row.
            return (row + rows.len(), 0);
        }
        remaining -= count + 1;
        row += wrap(line, width).len();
    }
    let rows = wrap(text, width);
    let last = rows.len() - 1;
    (last, UnicodeWidthStr::width(rows[last].as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backspace_at_zero_is_noop() {
        let mut c = Composer::default();
        c.backspace();
        assert_eq!(c.text(), "");
        assert_eq!(c.cursor(), 0);
    }

    #[test]
    fn edits_around_multibyte_chars() {
        let mut c = Composer::default();
        c.set("héllo");
        assert_eq!(c.cursor(), 5);
        for _ in 0..4 {
            c.left();
        }
        assert_eq!(c.cursor(), 1);
        c.insert_char('X');
        assert_eq!(c.text(), "hXéllo");
        assert_eq!(c.cursor(), 2);
        c.delete();
        assert_eq!(c.text(), "hXllo");
        assert_eq!(c.cursor(), 2);
        c.backspace();
        assert_eq!(c.text(), "hllo");
        assert_eq!(c.cursor(), 1);
    }

    #[test]
    fn delete_word_drops_trailing_space_then_word() {
        let mut c = Composer::default();
        c.set("foo bar  ");
        c.delete_word();
        assert_eq!(c.text(), "foo ");
        assert_eq!(c.cursor(), 4);
        c.delete_word();
        assert_eq!(c.text(), "");
        assert_eq!(c.cursor(), 0);
    }

    #[test]
    fn height_and_cursor_follow_the_same_wrapper() {
        let text = "ab界cd\nef";
        let width = 3;
        let rows = wrap(text, width);
        assert_eq!(rows.len(), wrapped_height(text, width));
        for cursor in 0..=text.chars().count() {
            let (row, _) = cursor_row_col(text, cursor, width);
            assert!(
                row < rows.len(),
                "cursor {cursor} landed on row {row} of {}",
                rows.len()
            );
        }
    }

    #[test]
    fn narrow_pane_keeps_a_wide_glyph_on_one_row() {
        assert_eq!(wrap("界", 1), vec!["界".to_string()]);
        assert_eq!(cursor_row_col("界", 1, 1), (0, 2));
    }

    #[test]
    fn home_end_stay_on_the_logical_line() {
        let mut c = Composer::default();
        c.set("one\ntwo");
        c.left();
        c.left();
        assert_eq!(c.cursor(), 5);
        c.home();
        assert_eq!(c.cursor(), 4);
        c.end();
        assert_eq!(c.cursor(), 7);
        c.home();
        c.home();
        assert_eq!(c.cursor(), 4);
        c.left();
        c.end();
        assert_eq!(c.cursor(), 3);
    }

    #[test]
    fn clear_line_at_line_start_joins_lines() {
        let mut c = Composer::default();
        c.set("one\ntwo");
        c.home();
        c.clear_line();
        assert_eq!(c.text(), "onetwo");
        assert_eq!(c.cursor(), 3);
    }

    #[test]
    fn clear_line_mid_line_keeps_line_prefix() {
        let mut c = Composer::default();
        c.set("one\ntwo");
        c.left();
        c.clear_line();
        assert_eq!(c.text(), "one\no");
        assert_eq!(c.cursor(), 4);
    }

    #[test]
    fn replace_range_swaps_the_at_token() {
        let mut c = Composer::default();
        c.set("see @sr now");
        c.replace_range(4, 7, "@src/lib.rs ");
        assert_eq!(c.text(), "see @src/lib.rs  now");
        assert_eq!(c.cursor(), 4 + "@src/lib.rs ".chars().count());
    }

    #[test]
    fn wrap_and_cursor_row_col_agree() {
        assert_eq!(wrap("a\n\nb", 3), vec!["a", "", "b"]);
        assert_eq!(wrap("abcd", 2), vec!["ab", "cd"]);
        assert_eq!(wrapped_height("a\n\nb", 3), 3);
        assert_eq!(wrapped_height("abcd", 2), 2);
        assert_eq!(cursor_row_col("abcd", 0, 2), (0, 0));
        assert_eq!(cursor_row_col("abcd", 1, 2), (0, 1));
        assert_eq!(cursor_row_col("abcd", 2, 2), (1, 0));
        assert_eq!(cursor_row_col("abcd", 3, 2), (1, 1));
        assert_eq!(cursor_row_col("abcd", 4, 2), (1, 2));
    }

    #[test]
    fn zero_width_never_panics() {
        assert_eq!(wrap("ab", 0), vec!["a", "b"]);
        assert_eq!(wrapped_height("", 0), 1);
        let mut c = Composer::default();
        c.set("");
        c.delete();
        c.kill_to_end();
        c.clear_line();
        assert_eq!(c.text(), "");
        assert_eq!(cursor_row_col("ab\n\ncd", 0, 0), (0, 0));
        assert_eq!(cursor_row_col("ab\n\ncd", 99, 0), (4, 1));
    }
}
