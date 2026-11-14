// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
//
// Rust port of WireGuard Windows memory-mapped binary ring logger (`ringlogger`).
// Provides thread-safe, circular log buffer with nanosecond timestamps,
// cursor tracking, Win32 file mapping, and dump utilities.

pub mod cursor;
pub mod dump;
pub mod logger;
pub mod mmap;
pub mod types;

#[cfg(windows)]
pub mod win32;

#[cfg(test)]
mod tests;

pub use cursor::{Cursor, FollowLine};
#[cfg(windows)]
pub use dump::stream_mem_to_with_event;
pub use dump::{stream_mem_to, write_mem_to};
pub use logger::{global, init_global_logger, is_global_logger_active, log, set_global_logger};
pub use mmap::Storage;
pub use types::{
    current_unix_nanos, format_timestamp, format_timestamp_sec, trim_space, unix_nanos_to_utc,
    write_formatted_timestamp, write_formatted_timestamp_sec, LogLine, LogMem, RinglogError,
    CURSOR_ALL, LOG_MEM_SIZE, MAGIC, MAX_LINES, MAX_LOG_LINE_LENGTH, MAX_TAG_LENGTH,
};

#[cfg(windows)]
pub use win32::SafeHandle;

#[cfg(windows)]
use windows_sys::Win32::Foundation::HANDLE;

use std::io::Write;
use std::path::Path;
use std::sync::atomic::Ordering;

/// Memory-mapped binary ring logger matching WireGuard Windows architecture.
pub struct RingLogger {
    tag: String,
    storage: Storage,
    read_only: bool,
}

impl RingLogger {
    /// Creates an in-memory ring logger (ideal for unit testing and non-persistent buffers).
    pub fn new_in_memory(tag: &str) -> Result<Self, RinglogError> {
        Self::validate_tag(tag)?;
        Ok(Self {
            tag: tag.to_owned(),
            storage: Storage::new_in_memory(),
            read_only: false,
        })
    }

    /// Creates or opens a writable file-backed ringlogger.
    ///
    /// On Windows, this creates a Win32 file mapping using `CreateFileMappingW` and `MapViewOfFile`.
    /// On non-Windows platforms, it falls back to `memmap2`.
    pub fn create<P: AsRef<Path>>(path: P, tag: &str) -> Result<Self, RinglogError> {
        Self::validate_tag(tag)?;

        #[cfg(windows)]
        {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(path)?;
            file.set_len(LOG_MEM_SIZE as u64)?;
            let win32_storage = win32::Win32Storage::new_file(file, false)?;
            Ok(Self {
                tag: tag.to_owned(),
                storage: Storage::Win32(win32_storage),
                read_only: false,
            })
        }

        #[cfg(not(windows))]
        {
            let storage = Storage::from_file(path, false)?;
            Ok(Self {
                tag: tag.to_owned(),
                storage,
                read_only: false,
            })
        }
    }

    /// Opens an existing ringlogger file for read-only inspection.
    pub fn open<P: AsRef<Path>>(path: P, tag: &str) -> Result<Self, RinglogError> {
        Self::validate_tag(tag)?;

        #[cfg(windows)]
        {
            let file = std::fs::File::open(path)?;
            let win32_storage = win32::Win32Storage::new_file(file, true)?;
            Ok(Self {
                tag: tag.to_owned(),
                storage: Storage::Win32(win32_storage),
                read_only: true,
            })
        }

        #[cfg(not(windows))]
        {
            let storage = Storage::from_file(path, true)?;
            Ok(Self {
                tag: tag.to_owned(),
                storage,
                read_only: true,
            })
        }
    }

    /// Opens or creates a file-backed ring logger using `memmap2`.
    pub fn from_file<P: AsRef<Path>>(
        path: P,
        tag: &str,
        read_only: bool,
    ) -> Result<Self, RinglogError> {
        Self::validate_tag(tag)?;
        let storage = Storage::from_file(path, read_only)?;
        Ok(Self {
            tag: tag.to_owned(),
            storage,
            read_only,
        })
    }

    /// Creates a ring logger from an existing mutable memory map.
    pub fn from_mmap_mut(mut mmap: memmap2::MmapMut, tag: &str) -> Result<Self, RinglogError> {
        Self::validate_tag(tag)?;
        if mmap.len() < LOG_MEM_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "mmap length is smaller than LOG_MEM_SIZE",
            )
            .into());
        }
        let log = unsafe { &mut *(mmap.as_mut_ptr() as *mut LogMem) };
        log.initialize_if_needed();
        mmap.flush()?;
        Ok(Self {
            tag: tag.to_owned(),
            storage: Storage::MmapMut {
                _file: None,
                mmap,
            },
            read_only: false,
        })
    }

    /// Creates a read-only ring logger from an existing immutable memory map.
    pub fn from_mmap(mmap: memmap2::Mmap, tag: &str) -> Result<Self, RinglogError> {
        Self::validate_tag(tag)?;
        if mmap.len() < LOG_MEM_SIZE {
            return Err(RinglogError::InvalidMagic {
                expected: MAGIC,
                actual: 0,
            });
        }
        let log = unsafe { &*(mmap.as_ptr() as *const LogMem) };
        if log.magic != MAGIC {
            return Err(RinglogError::InvalidMagic {
                expected: MAGIC,
                actual: log.magic,
            });
        }
        Ok(Self {
            tag: tag.to_owned(),
            storage: Storage::MmapRead {
                _file: None,
                mmap,
            },
            read_only: true,
        })
    }

    #[cfg(windows)]
    /// Creates a RingLogger from a raw Win32 mapping handle.
    pub fn from_mapping_handle(
        mapping_handle: HANDLE,
        tag: &str,
        read_only: bool,
    ) -> Result<Self, RinglogError> {
        Self::validate_tag(tag)?;
        let win32_storage = win32::Win32Storage::from_mapping_handle(mapping_handle, read_only)?;
        Ok(Self {
            tag: tag.to_owned(),
            storage: Storage::Win32(win32_storage),
            read_only,
        })
    }

    #[cfg(windows)]
    /// Creates a read-only RingLogger from an inherited handle string (e.g. from parent process).
    /// Matches WireGuard Go's `NewRingloggerFromInheritedMappingHandle(handleStr, tag string)`.
    pub fn from_inherited_handle_str(handle_str: &str, tag: &str) -> Result<Self, RinglogError> {
        let handle_val = handle_str
            .parse::<usize>()
            .map_err(|e| RinglogError::InvalidHandle(e.to_string()))?;
        Self::from_inherited_handle(handle_val as HANDLE, tag)
    }

    #[cfg(windows)]
    /// Creates a read-only RingLogger from an inherited raw Win32 HANDLE.
    pub fn from_inherited_handle(handle: HANDLE, tag: &str) -> Result<Self, RinglogError> {
        Self::from_mapping_handle(handle, tag, true)
    }

    #[cfg(windows)]
    /// Creates a named shared memory mapping backed by the system paging file.
    pub fn create_named(name: &str, tag: &str) -> Result<Self, RinglogError> {
        Self::validate_tag(tag)?;
        let win32_storage = win32::Win32Storage::create_named(name)?;
        Ok(Self {
            tag: tag.to_owned(),
            storage: Storage::Win32(win32_storage),
            read_only: false,
        })
    }

    #[cfg(windows)]
    /// Opens an existing named shared memory mapping.
    pub fn open_named(name: &str, tag: &str, read_only: bool) -> Result<Self, RinglogError> {
        Self::validate_tag(tag)?;
        let win32_storage = win32::Win32Storage::open_named(name, read_only)?;
        Ok(Self {
            tag: tag.to_owned(),
            storage: Storage::Win32(win32_storage),
            read_only,
        })
    }

    #[cfg(windows)]
    /// Exports an inheritable, read-only file mapping handle that can be passed to child processes.
    /// Matches WireGuard Go's `(*Ringlogger) ExportInheritableMappingHandle()`.
    pub fn export_inheritable_mapping_handle(&self) -> Result<HANDLE, RinglogError> {
        match &self.storage {
            Storage::Win32(w) => w.export_inheritable_mapping_handle(),
            _ => Err(RinglogError::InvalidHandle(
                "Storage backend is not Win32Storage".into(),
            )),
        }
    }

    /// Writes raw bytes to the ring logger using current timestamp.
    /// Thread-safe and lock-free across concurrent threads and processes.
    pub fn write_bytes(&self, p: &[u8]) -> Result<usize, RinglogError> {
        let ts = current_unix_nanos();
        self.write_with_timestamp(p, ts)
    }

    /// Writes a UTF-8 string to the ring logger using current timestamp.
    pub fn write_str(&self, msg: &str) -> Result<usize, RinglogError> {
        self.write_bytes(msg.as_bytes())
    }

    /// Writes a log line with an explicit 64-bit nanosecond timestamp,
    /// matching WireGuard Go's `(*Ringlogger) WriteWithTimestamp(p []byte, ts int64)`.
    pub fn write_with_timestamp(&self, p: &[u8], ts: i64) -> Result<usize, RinglogError> {
        if self.read_only {
            return Err(RinglogError::ReadOnly);
        }

        let ret = p.len();
        let trimmed = trim_space(p);
        if trimmed.is_empty() {
            return Ok(ret);
        }

        let log = self.log_mem();
        let index = log.next_index.fetch_add(1, Ordering::SeqCst);
        let slot = (index as usize) % MAX_LINES;
        let line = &log.lines[slot];

        line.write_text(&self.tag, trimmed, ts);

        Ok(ret)
    }

    /// Dumps all log entries in chronological order to the provided writer,
    /// matching WireGuard Go's `(*Ringlogger) WriteTo(out io.Writer)`.
    pub fn write_to<W: Write>(&self, out: &mut W) -> std::io::Result<u64> {
        write_mem_to(self.log_mem(), out)
    }

    /// Returns the atomic write index of the ring buffer without scanning lines.
    #[inline]
    pub fn next_index(&self) -> u32 {
        self.log_mem().next_index.load(Ordering::Acquire)
    }

    /// Follows log entries starting from a given cursor position,
    /// matching WireGuard Go's `(*Ringlogger) FollowFromCursor(cursor uint32)`.
    pub fn follow_from_cursor(&self, cursor: u32) -> (Vec<FollowLine>, u32) {
        cursor::follow_from_cursor_mem(self.log_mem(), cursor)
    }

    /// Creates a stateful cursor pointing to the current end of logs.
    pub fn cursor(&self) -> Cursor<'_> {
        Cursor::new(self.log_mem())
    }

    /// Fetches all lines currently stored in the buffer in chronological order.
    pub fn all_lines(&self) -> Vec<FollowLine> {
        let (lines, _) = self.follow_from_cursor(CURSOR_ALL);
        lines
    }

    /// Flushes dirty pages to the backing store.
    pub fn flush(&self) -> Result<(), RinglogError> {
        self.storage.flush()
    }

    /// Returns the tag associated with this logger.
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// Returns whether this ring logger is read-only.
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Returns a reference to the mapped `LogMem` buffer.
    #[inline]
    pub fn log_mem(&self) -> &LogMem {
        self.storage.as_log_mem()
    }

    fn validate_tag(tag: &str) -> Result<(), RinglogError> {
        if tag.len() > MAX_TAG_LENGTH {
            return Err(RinglogError::TagTooLong(tag.len(), MAX_TAG_LENGTH));
        }
        Ok(())
    }
}

impl Write for RingLogger {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write_bytes(buf).map_err(|e| match e {
            RinglogError::ReadOnly => std::io::Error::new(std::io::ErrorKind::PermissionDenied, e),
            RinglogError::Closed => std::io::Error::new(std::io::ErrorKind::UnexpectedEof, e),
            RinglogError::Io(err) => err,
            _ => std::io::Error::new(std::io::ErrorKind::Other, e),
        })
    }

    fn flush(&mut self) -> std::io::Result<()> {
        RingLogger::flush(self).map_err(|e| match e {
            RinglogError::Io(err) => err,
            _ => std::io::Error::new(std::io::ErrorKind::Other, e),
        })
    }
}

impl Write for &RingLogger {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write_bytes(buf).map_err(|e| match e {
            RinglogError::ReadOnly => std::io::Error::new(std::io::ErrorKind::PermissionDenied, e),
            RinglogError::Closed => std::io::Error::new(std::io::ErrorKind::UnexpectedEof, e),
            RinglogError::Io(err) => err,
            _ => std::io::Error::new(std::io::ErrorKind::Other, e),
        })
    }

    fn flush(&mut self) -> std::io::Result<()> {
        RingLogger::flush(self).map_err(|e| match e {
            RinglogError::Io(err) => err,
            _ => std::io::Error::new(std::io::ErrorKind::Other, e),
        })
    }
}

impl std::fmt::Debug for RingLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingLogger")
            .field("tag", &self.tag)
            .field("read_only", &self.read_only)
            .field("next_index", &self.next_index())
            .finish()
    }
}

/// Dumps a ringlogger file to an io::Writer, matching WireGuard Go's `DumpTo(inPath, out, continuous)`.
pub fn dump_to<P: AsRef<Path>, W: Write>(
    in_path: P,
    out: &mut W,
    continuous: bool,
) -> Result<(), RinglogError> {
    let logger = RingLogger::open(in_path, "DMP")?;
    if !continuous {
        logger.write_to(out).map_err(RinglogError::Io)?;
    } else {
        stream_mem_to(
            logger.log_mem(),
            out,
            std::time::Duration::from_millis(100),
            None,
        )?;
    }
    Ok(())
}
