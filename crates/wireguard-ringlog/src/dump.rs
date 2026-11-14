// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
// Dump and stream helpers for WireGuard ringlogger.

use crate::types::{
    append_lossy_utf8, write_formatted_timestamp, LogMem, RinglogError, CURSOR_ALL, MAX_LINES,
    MAX_LOG_LINE_LENGTH,
};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Dumps all existing lines from the ring buffer in chronological order to the provided writer,
/// matching WireGuard Go's `(*Ringlogger) WriteTo(out io.Writer)`.
pub fn write_mem_to<W: Write>(log: &LogMem, out: &mut W) -> std::io::Result<u64> {
    let mut written: u64 = 0;
    let next_index = log.next_index.load(Ordering::Acquire);
    let mut raw_buf = [0u8; MAX_LOG_LINE_LENGTH];
    let mut line_buf = String::with_capacity(160);

    for l in 0..(MAX_LINES as u32) {
        let slot = ((next_index.wrapping_add(l)) as usize) % MAX_LINES;
        let line = &log.lines[slot];
        if let Some((time_ns, len)) = line.read_raw_into(&mut raw_buf) {
            line_buf.clear();
            let _ = write_formatted_timestamp(time_ns, &mut line_buf);
            line_buf.push_str(": ");
            append_lossy_utf8(&raw_buf[..len], &mut line_buf);
            line_buf.push('\n');
            out.write_all(line_buf.as_bytes())?;
            written += line_buf.len() as u64;
        }
    }

    out.flush()?;
    Ok(written)
}

fn stream_mem_to_inner<W: Write, F>(
    log: &LogMem,
    out: &mut W,
    mut wait_or_stop: F,
) -> Result<(), RinglogError>
where
    F: FnMut(bool) -> bool,
{
    let max_u32 = MAX_LINES as u32;
    let mut cursor = CURSOR_ALL;
    let mut last_observed_index: Option<u32> = None;
    let mut allow_fast_skip = false;
    let mut raw_buf = [0u8; MAX_LOG_LINE_LENGTH];
    let mut line_buf = String::with_capacity(160);

    loop {
        if !wait_or_stop(false) {
            break;
        }

        let next_index = log.next_index.load(Ordering::Acquire);

        // Fast atomic check: skip buffer scan when nothing has been written since last idle check.
        if allow_fast_skip && last_observed_index == Some(next_index) {
            if !wait_or_stop(true) {
                break;
            }
            continue;
        }

        // If at least a full ring (>= MAX_LINES) was written since our last read,
        // reset to CURSOR_ALL so we dump the live buffer instead of skipping wrapped entries.
        if cursor != CURSOR_ALL {
            if let Some(prev) = last_observed_index {
                if next_index.wrapping_sub(prev) >= max_u32 {
                    cursor = CURSOR_ALL;
                }
            }
        }

        let mut wrote_any = false;
        let mut incomplete_slot = false;
        let mut i = if cursor == CURSOR_ALL {
            next_index
        } else {
            cursor
        };

        for _ in 0..MAX_LINES {
            if cursor != CURSOR_ALL && (i % max_u32) == (next_index % max_u32) {
                break;
            }

            let slot = (i as usize) % MAX_LINES;
            let line = &log.lines[slot];

            if let Some((time_ns, len)) = line.read_raw_into(&mut raw_buf) {
                line_buf.clear();
                let _ = write_formatted_timestamp(time_ns, &mut line_buf);
                line_buf.push_str(": ");
                append_lossy_utf8(&raw_buf[..len], &mut line_buf);
                line_buf.push('\n');
                if let Err(e) = out.write_all(line_buf.as_bytes()) {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof
                        || e.kind() == std::io::ErrorKind::BrokenPipe
                    {
                        return Ok(());
                    }
                    return Err(RinglogError::Io(e));
                }
                wrote_any = true;
                i = i.wrapping_add(1);
                cursor = i % max_u32;
            } else if cursor == CURSOR_ALL {
                i = i.wrapping_add(1);
            } else {
                // Concurrent writer reserved `next_index` but hasn't finished writing this slot yet.
                incomplete_slot = true;
                break;
            }
        }

        if wrote_any {
            if let Err(e) = out.flush() {
                if e.kind() == std::io::ErrorKind::UnexpectedEof
                    || e.kind() == std::io::ErrorKind::BrokenPipe
                {
                    return Ok(());
                }
                return Err(RinglogError::Io(e));
            }
        }

        let after_index = log.next_index.load(Ordering::Acquire);
        last_observed_index = Some(next_index);
        if incomplete_slot {
            allow_fast_skip = false;
            if !wait_or_stop(true) {
                break;
            }
        } else if after_index != next_index {
            // Zero-sleep fast path: more lines arrived while flushing.
            allow_fast_skip = false;
        } else {
            allow_fast_skip = cursor != CURSOR_ALL || wrote_any || next_index == 0;
            if !wait_or_stop(true) {
                break;
            }
        }
    }

    Ok(())
}

/// Continuously dumps new entries from the ring buffer to the writer until stopped.
pub fn stream_mem_to<W: Write>(
    log: &LogMem,
    out: &mut W,
    poll_interval: Duration,
    stop_signal: Option<&AtomicBool>,
) -> Result<(), RinglogError> {
    stream_mem_to_inner(log, out, |should_wait| {
        if let Some(stop) = stop_signal {
            if stop.load(Ordering::Relaxed) {
                return false;
            }
        }
        if should_wait && !poll_interval.is_zero() {
            std::thread::sleep(poll_interval);
            if let Some(stop) = stop_signal {
                if stop.load(Ordering::Relaxed) {
                    return false;
                }
            }
        }
        true
    })
}

/// Continuously dumps new entries from the ring buffer to the writer until `stop_event`
/// is signaled (`WaitForSingleObject` wakes immediately on stop).
#[cfg(windows)]
pub fn stream_mem_to_with_event<W: Write>(
    log: &LogMem,
    out: &mut W,
    poll_interval: Duration,
    stop_event: windows_sys::Win32::Foundation::HANDLE,
) -> Result<(), RinglogError> {
    use windows_sys::Win32::Foundation::{INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    let has_valid_event = !stop_event.is_null() && stop_event != INVALID_HANDLE_VALUE;
    let timeout_ms = poll_interval.as_millis().min(u32::MAX as u128 - 1) as u32;

    stream_mem_to_inner(log, out, |should_wait| {
        if has_valid_event {
            let wait_ms = if should_wait { timeout_ms } else { 0 };
            let res = unsafe { WaitForSingleObject(stop_event, wait_ms) };
            res != WAIT_OBJECT_0 && res != WAIT_FAILED
        } else {
            if should_wait && !poll_interval.is_zero() {
                std::thread::sleep(poll_interval);
            }
            true
        }
    })
}
