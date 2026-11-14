// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
// Cursor and follow line tracking for WireGuard ringlogger.

use crate::types::{
    format_timestamp, format_timestamp_sec, write_formatted_timestamp, LogMem, CURSOR_ALL,
    MAX_LINES,
};
use std::sync::atomic::Ordering;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FollowLine {
    pub line: String,
    pub timestamp_ns: i64,
}

impl FollowLine {
    /// Formats the timestamp as `YYYY-MM-DD HH:MM:SS.ffffff`.
    pub fn formatted_timestamp(&self) -> String {
        format_timestamp(self.timestamp_ns)
    }

    /// Formats the timestamp as `YYYY-MM-DD HH:MM:SS` (second precision).
    pub fn formatted_timestamp_sec(&self) -> String {
        format_timestamp_sec(self.timestamp_ns)
    }

    /// Formats as `{timestamp}: {line}` in a single allocation.
    pub fn formatted(&self) -> String {
        let mut out = String::with_capacity(28 + self.line.len());
        let _ = write_formatted_timestamp(self.timestamp_ns, &mut out);
        out.push_str(": ");
        out.push_str(&self.line);
        out
    }
}

/// Core function to follow logs from a given cursor position matching WireGuard Go's
/// `FollowFromCursor(cursor uint32) (followLines []FollowLine, nextCursor uint32)`.
pub fn follow_from_cursor_mem(log: &LogMem, cursor: u32) -> (Vec<FollowLine>, u32) {
    let next_index = log.next_index.load(Ordering::Acquire);
    let max_u32 = MAX_LINES as u32;

    // Fast path: when polling from an existing cursor and no new lines have been written,
    // return immediately with zero heap allocations.
    if cursor != CURSOR_ALL && (cursor % max_u32) == (next_index % max_u32) {
        return (Vec::new(), cursor);
    }

    let initial_cap = if cursor == CURSOR_ALL {
        (next_index as usize).min(MAX_LINES)
    } else {
        ((next_index.wrapping_sub(cursor) % max_u32) as usize).min(MAX_LINES)
    };

    let mut follow_lines = Vec::with_capacity(initial_cap);
    let mut next_cursor = cursor;
    let mut i = if cursor == CURSOR_ALL {
        next_index
    } else {
        cursor
    };

    for _ in 0..MAX_LINES {
        let slot = (i as usize) % MAX_LINES;
        let line = &log.lines[slot];

        // If not CURSOR_ALL and we have caught up to next_index, stop.
        if cursor != CURSOR_ALL && (i % max_u32) == (next_index % max_u32) {
            break;
        }

        let time_ns = line.time_ns.load(Ordering::Acquire);
        if time_ns == 0 {
            if cursor == CURSOR_ALL {
                i = i.wrapping_add(1);
                continue;
            } else {
                break;
            }
        }

        if let Some(text) = line.get_text() {
            follow_lines.push(FollowLine {
                line: text,
                timestamp_ns: time_ns,
            });
        }

        i = i.wrapping_add(1);
        next_cursor = i % max_u32;
    }

    (follow_lines, next_cursor)
}

/// A stateful cursor for streaming new log lines from a ringlogger.
pub struct Cursor<'a> {
    log: &'a LogMem,
    position: u32,
}

impl<'a> Cursor<'a> {
    pub fn new(log: &'a LogMem) -> Self {
        Self {
            log,
            position: CURSOR_ALL,
        }
    }

    pub fn from_position(log: &'a LogMem, position: u32) -> Self {
        Self { log, position }
    }

    pub fn position(&self) -> u32 {
        self.position
    }

    pub fn set_position(&mut self, pos: u32) {
        self.position = pos;
    }

    pub fn reset(&mut self) {
        self.position = CURSOR_ALL;
    }

    /// Fetches the next batch of log lines and advances the cursor.
    pub fn next_batch(&mut self) -> Vec<FollowLine> {
        let (lines, next_pos) = follow_from_cursor_mem(self.log, self.position);
        self.position = next_pos;
        lines
    }
}
