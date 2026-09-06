//! Bounded shell command history: a fixed-capacity ring of the most recent
//! command lines, used for up and down arrow recall. Capping both the number of
//! entries and each entry's length keeps the memory held by history constant no
//! matter how many commands are entered, so a flood of distinct lines can never
//! grow the history `Vec` until the kernel heap is exhausted.
//!
//! This is pure logic with no hardware access, so the host `logic` crate includes
//! it verbatim to unit-test the cap on the same source the kernel runs.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Number of most-recent command lines kept for recall.
pub const HISTORY_CAP: usize = 128;

/// Longest command line stored in history. The line reader already caps a line
/// at its own MAX_LINE, but history keeps far less so the total it holds is a
/// small constant (`HISTORY_CAP * HISTORY_MAX_LINE`).
pub const HISTORY_MAX_LINE: usize = 256;

/// A bounded ring of recent command lines, oldest first.
pub struct History {
    entries: Vec<String>,
}

impl History {
    pub const fn new() -> Self {
        History { entries: Vec::new() }
    }

    /// The retained lines, oldest first. Drives up and down arrow navigation.
    pub fn entries(&self) -> &[String] {
        &self.entries
    }

    /// Record a command line. Blank lines and an immediate repeat of the last
    /// line are ignored. The line is truncated to `HISTORY_MAX_LINE`, and once
    /// the ring is full the oldest entry is dropped, so the buffer never grows
    /// past `HISTORY_CAP` entries regardless of how many lines are entered.
    pub fn remember(&mut self, line: &str) {
        let line = line.trim();
        if line.is_empty() {
            return;
        }
        let stored = truncate(line, HISTORY_MAX_LINE);
        if self.entries.last().map(|l| l.as_str()) == Some(stored) {
            return;
        }
        if self.entries.len() >= HISTORY_CAP {
            self.entries.remove(0);
        }
        self.entries.push(stored.to_string());
    }
}

impl Default for History {
    fn default() -> Self {
        History::new()
    }
}

/// Borrow the leading `max` bytes of `s`, backing off to the previous UTF-8
/// character boundary so the slice is always valid.
fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_recent_lines_in_order() {
        let mut h = History::new();
        h.remember("one");
        h.remember("two");
        h.remember("three");
        assert_eq!(h.entries(), &["one", "two", "three"]);
    }

    #[test]
    fn ignores_blank_and_consecutive_duplicates() {
        let mut h = History::new();
        h.remember("ls");
        h.remember("   ");
        h.remember("ls");
        h.remember("ls");
        h.remember("ps");
        assert_eq!(h.entries(), &["ls", "ps"]);
    }

    #[test]
    fn trims_before_storing() {
        let mut h = History::new();
        h.remember("  echo hi  ");
        assert_eq!(h.entries(), &["echo hi"]);
    }

    #[test]
    fn caps_entry_count_and_drops_oldest() {
        let mut h = History::new();
        for i in 0..(HISTORY_CAP + 50) {
            let mut line = String::from("cmd");
            line.push_str(&i.to_string());
            h.remember(&line);
        }
        assert_eq!(h.entries().len(), HISTORY_CAP);
        // Oldest surviving entry is the (50)th command, newest is the last.
        assert_eq!(h.entries().first().unwrap(), "cmd50");
        assert_eq!(
            h.entries().last().unwrap(),
            &alloc::format!("cmd{}", HISTORY_CAP + 49)
        );
    }

    #[test]
    fn flood_of_distinct_lines_stays_bounded() {
        let mut h = History::new();
        let big = "x".repeat(200);
        for i in 0..30_000 {
            let mut line = big.clone();
            line.push_str(&i.to_string());
            h.remember(&line);
        }
        assert_eq!(h.entries().len(), HISTORY_CAP);
        let held: usize = h.entries().iter().map(|s| s.len()).sum();
        assert!(held <= HISTORY_CAP * HISTORY_MAX_LINE);
    }

    #[test]
    fn caps_each_stored_line_length() {
        let mut h = History::new();
        let long = "y".repeat(HISTORY_MAX_LINE * 4);
        h.remember(&long);
        assert_eq!(h.entries()[0].len(), HISTORY_MAX_LINE);
    }

    #[test]
    fn truncation_backs_off_to_a_char_boundary() {
        // A multi-byte char straddling the cap must not be split: the stored
        // slice stays valid UTF-8 and never exceeds the cap.
        let mut h = History::new();
        let long = "e\u{0301}".repeat(HISTORY_MAX_LINE); // 'e' + combining acute, 3 bytes
        h.remember(&long);
        let stored = &h.entries()[0];
        assert!(stored.len() <= HISTORY_MAX_LINE);
        assert!(long.starts_with(stored.as_str()));
    }
}
