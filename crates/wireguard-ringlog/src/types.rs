// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
// Rust port of wireguard-windows ringlogger binary structure.

use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU8, Ordering};

pub const MAX_LOG_LINE_LENGTH: usize = 512;
pub const MAX_TAG_LENGTH: usize = 5;
pub const MAX_LINES: usize = 2048;
pub const MAGIC: u32 = 0x0bad_babe;
pub const CURSOR_ALL: u32 = u32::MAX;

#[repr(C)]
pub struct LogLine {
    pub time_ns: AtomicI64,
    pub line: [AtomicU8; MAX_LOG_LINE_LENGTH],
}

#[repr(C)]
pub struct LogMem {
    pub magic: u32,
    pub next_index: AtomicU32,
    pub lines: [LogLine; MAX_LINES],
}

// Compile-time layout guarantees matching WireGuard Go binary structure:
const _: () = assert!(std::mem::size_of::<LogLine>() == 520);
const _: () = assert!(std::mem::align_of::<LogLine>() == 8);
const _: () = assert!(std::mem::size_of::<LogMem>() == 1_064_968);
const _: () = assert!(std::mem::align_of::<LogMem>() == 8);

pub const LOG_MEM_SIZE: usize = std::mem::size_of::<LogMem>();

impl LogMem {
    /// Allocate a fresh LogMem directly on the heap, bypassing the stack.
    /// This prevents stack overflow since LogMem is ~1.04 MB.
    pub fn new_boxed() -> Box<Self> {
        unsafe {
            let layout = std::alloc::Layout::new::<Self>();
            let ptr = std::alloc::alloc_zeroed(layout) as *mut Self;
            if ptr.is_null() {
                std::alloc::handle_alloc_error(layout);
            }
            (*ptr).magic = MAGIC;
            Box::from_raw(ptr)
        }
    }

    /// Reset all slots and reinitialize the magic number and index.
    pub fn reset(&mut self) {
        self.magic = MAGIC;
        self.next_index.store(0, Ordering::Release);
        for line in &self.lines {
            line.time_ns.store(0, Ordering::Release);
            for b in &line.line {
                b.store(0, Ordering::Relaxed);
            }
        }
    }

    /// Initializes uninitialized memory if the magic number is not yet set.
    pub fn initialize_if_needed(&mut self) {
        if self.magic != MAGIC {
            self.reset();
        }
    }
}

impl LogLine {
    /// Returns true if this line contains valid log data.
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.time_ns.load(Ordering::Acquire) != 0
    }

    /// Returns the 64-bit nanosecond timestamp since Unix epoch.
    #[inline]
    pub fn timestamp_ns(&self) -> i64 {
        self.time_ns.load(Ordering::Acquire)
    }

    /// Reads the raw line bytes into `buf` without heap allocation, returning `(time_ns, byte_len)`.
    /// Uses an optimistic double-check on `time_ns` to skip torn reads during concurrent wraps.
    pub fn read_raw_into(&self, buf: &mut [u8; MAX_LOG_LINE_LENGTH]) -> Option<(i64, usize)> {
        for _ in 0..2 {
            let time_ns = self.time_ns.load(Ordering::Acquire);
            if time_ns == 0 {
                return None;
            }

            let mut len = 0;
            for (i, slot) in self.line.iter().enumerate() {
                let b = slot.load(Ordering::Relaxed);
                if b == 0 {
                    len = i;
                    break;
                }
                buf[i] = b;
            }

            core::sync::atomic::fence(Ordering::Acquire);
            if self.time_ns.load(Ordering::Acquire) == time_ns {
                return if len == 0 { None } else { Some((time_ns, len)) };
            }
        }
        None
    }

    /// Retrieves the text content of this log line, if complete and valid.
    pub fn get_text(&self) -> Option<String> {
        let mut buf = [0u8; MAX_LOG_LINE_LENGTH];
        let (_, len) = self.read_raw_into(&mut buf)?;

        match std::str::from_utf8(&buf[..len]) {
            Ok(s) => Some(s.to_owned()),
            Err(_) => Some(String::from_utf8_lossy(&buf[..len]).into_owned()),
        }
    }

    /// Writes a line to this slot with atomic timestamp and formatting:
    /// `[TAG] <payload>\0`
    pub fn write_text(&self, tag: &str, payload: &[u8], timestamp_ns: i64) {
        // 1. Invalidate line so concurrent readers skip it during update
        self.time_ns.store(0, Ordering::Release);

        let tag_bytes = tag.as_bytes();
        let tag_len = tag_bytes.len();

        let mut p = payload;
        // Total text length: '[' + tag + ']' + ' ' + p
        let mut text_len = 3 + p.len() + tag_len;
        if text_len > MAX_LOG_LINE_LENGTH - 1 {
            let max_p = MAX_LOG_LINE_LENGTH - 1 - 3 - tag_len;
            p = &p[..max_p];
            text_len = MAX_LOG_LINE_LENGTH - 1;
        }

        // Null out the beginning and end first; no need to zero all 512 bytes
        self.line[0].store(0, Ordering::Relaxed);
        self.line[text_len].store(0, Ordering::Relaxed);

        for (i, &b) in tag_bytes.iter().enumerate() {
            self.line[1 + i].store(b, Ordering::Relaxed);
        }
        self.line[1 + tag_len].store(b']', Ordering::Relaxed);
        self.line[2 + tag_len].store(b' ', Ordering::Relaxed);

        let prefix_len = 3 + tag_len;
        for (i, &b) in p.iter().enumerate() {
            self.line[prefix_len + i].store(b, Ordering::Relaxed);
        }

        // Make line visible with '[' at index 0
        self.line[0].store(b'[', Ordering::Release);

        // Release-store the timestamp so all previous writes are visible
        self.time_ns.store(timestamp_ns, Ordering::Release);
    }
}

/// Trims leading and trailing ASCII whitespace (spaces, tabs, newlines, CR, VT, FF).
pub fn trim_space(p: &[u8]) -> &[u8] {
    let is_space = |&b: &u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c);
    let start = p.iter().position(|b| !is_space(b)).unwrap_or(p.len());
    let end = p.iter().rposition(|b| !is_space(b)).map_or(0, |idx| idx + 1);
    if start >= end {
        &[]
    } else {
        &p[start..end]
    }
}

/// Computes current Unix timestamp in nanoseconds.
pub fn current_unix_nanos() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(dur) => dur.as_nanos() as i64,
        Err(err) => -(err.duration().as_nanos() as i64),
    }
}

/// Converts Unix nanoseconds to UTC (year, month, day, hour, minute, second, microsecond).
pub fn unix_nanos_to_utc(nanos: i64) -> (i32, u32, u32, u32, u32, u32, u32) {
    let secs = nanos.div_euclid(1_000_000_000);
    let rem_nanos = nanos.rem_euclid(1_000_000_000);
    let usecs = (rem_nanos / 1_000) as u32;

    let days = secs.div_euclid(86400);
    let rem_secs = secs.rem_euclid(86400) as u32;

    let hour = rem_secs / 3600;
    let minute = (rem_secs % 3600) / 60;
    let second = rem_secs % 60;

    // Howard Hinnant algorithm for civil date calculation
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    (y as i32, m, d, hour, minute, second, usecs)
}

/// Appends raw log bytes into `out`, avoiding allocation when valid UTF-8.
#[inline]
pub(crate) fn append_lossy_utf8(bytes: &[u8], out: &mut String) {
    match std::str::from_utf8(bytes) {
        Ok(s) => out.push_str(s),
        Err(_) => out.push_str(&String::from_utf8_lossy(bytes)),
    }
}

/// Appends `nanos` formatted as `YYYY-MM-DD HH:MM:SS.ffffff` directly into `out`.
pub fn write_formatted_timestamp<W: std::fmt::Write>(nanos: i64, out: &mut W) -> std::fmt::Result {
    let (y, m, d, hh, mm, ss, us) = unix_nanos_to_utc(nanos);
    write!(out, "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:06}", y, m, d, hh, mm, ss, us)
}

/// Formats nanoseconds as `YYYY-MM-DD HH:MM:SS.ffffff` matching WireGuard Go's format.
pub fn format_timestamp(nanos: i64) -> String {
    let mut s = String::with_capacity(26);
    let _ = write_formatted_timestamp(nanos, &mut s);
    s
}

/// Appends `nanos` formatted as `YYYY-MM-DD HH:MM:SS` directly into `out`.
pub fn write_formatted_timestamp_sec<W: std::fmt::Write>(nanos: i64, out: &mut W) -> std::fmt::Result {
    let (y, m, d, hh, mm, ss, _) = unix_nanos_to_utc(nanos);
    write!(out, "{:04}-{:02}-{:02} {:02}:{:02}:{:02}", y, m, d, hh, mm, ss)
}

/// Formats nanoseconds as `YYYY-MM-DD HH:MM:SS` (19 bytes, second precision) for UI log display.
pub fn format_timestamp_sec(nanos: i64) -> String {
    let mut s = String::with_capacity(19);
    let _ = write_formatted_timestamp_sec(nanos, &mut s);
    s
}

#[derive(Debug, thiserror::Error)]
pub enum RinglogError {
    #[error("tag length {0} exceeds maximum allowed tag length {1}")]
    TagTooLong(usize, usize),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Windows API error: code {0:#x}")]
    Windows(u32),

    #[error("invalid magic: expected {expected:#x}, got {actual:#x}")]
    InvalidMagic { expected: u32, actual: u32 },

    #[error("buffer is read-only")]
    ReadOnly,

    #[error("ringlogger closed or unmapped")]
    Closed,

    #[error("invalid handle: {0}")]
    InvalidHandle(String),

    #[error("invalid UTF-8 in log line: {0}")]
    Utf8(#[from] std::str::Utf8Error),
}
