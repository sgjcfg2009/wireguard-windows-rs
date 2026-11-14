// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
// Global logger and standard logging integration.

use crate::types::RinglogError;
use crate::RingLogger;
use std::path::Path;
use std::sync::OnceLock;

static GLOBAL_LOGGER: OnceLock<RingLogger> = OnceLock::new();

/// Initializes the global ringlogger with the given file path and tag,
/// matching WireGuard Go's `InitGlobalLogger(file, tag string) error`.
pub fn init_global_logger<P: AsRef<Path>>(path: P, tag: &str) -> Result<(), RinglogError> {
    if GLOBAL_LOGGER.get().is_some() {
        return Ok(());
    }

    let logger = RingLogger::create(path, tag)?;
    let _ = GLOBAL_LOGGER.set(logger);
    Ok(())
}

/// Sets an existing RingLogger instance as the global logger.
pub fn set_global_logger(logger: RingLogger) -> Result<(), RinglogError> {
    GLOBAL_LOGGER
        .set(logger)
        .map_err(|_| RinglogError::Closed)
}

/// Returns a reference to the global ringlogger, if initialized.
#[inline]
pub fn global() -> Option<&'static RingLogger> {
    GLOBAL_LOGGER.get()
}

/// Returns `true` if a global ringlogger has been initialized.
#[inline]
pub fn is_global_logger_active() -> bool {
    GLOBAL_LOGGER.get().is_some()
}

/// Logs a message to the global ringlogger, if initialized.
pub fn log(msg: &str) -> Result<usize, RinglogError> {
    if let Some(logger) = global() {
        logger.write_str(msg)
    } else {
        Err(RinglogError::Closed)
    }
}

struct StackFmtBuf<const N: usize> {
    buf: [u8; N],
    len: usize,
    overflowed: bool,
}

impl<const N: usize> StackFmtBuf<N> {
    #[inline]
    fn new() -> Self {
        Self {
            buf: [0u8; N],
            len: 0,
            overflowed: false,
        }
    }
}

impl<const N: usize> std::fmt::Write for StackFmtBuf<N> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        if self.overflowed {
            return Ok(());
        }
        let bytes = s.as_bytes();
        if self.len + bytes.len() <= N {
            self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
            self.len += bytes.len();
        } else {
            self.overflowed = true;
        }
        Ok(())
    }
}

/// Formats and writes directly to `logger` using a stack buffer, avoiding heap allocation
/// for messages up to 576 bytes.
#[doc(hidden)]
pub fn write_fmt(
    logger: &RingLogger,
    args: std::fmt::Arguments<'_>,
) -> Result<usize, RinglogError> {
    use std::fmt::Write as _;
    let mut stack = StackFmtBuf::<576>::new();
    let _ = stack.write_fmt(args);
    if !stack.overflowed {
        logger.write_bytes(&stack.buf[..stack.len])
    } else {
        let mut s = String::new();
        let _ = s.write_fmt(args);
        logger.write_str(&s)
    }
}

/// Formatted logging macro targeting the global ringlogger without allocating when inactive
/// or when the formatted output fits in the stack buffer.
#[macro_export]
macro_rules! ringlog {
    ($($arg:tt)*) => {
        if let Some(logger) = $crate::global() {
            let _ = $crate::logger::write_fmt(logger, format_args!($($arg)*));
        }
    };
}
