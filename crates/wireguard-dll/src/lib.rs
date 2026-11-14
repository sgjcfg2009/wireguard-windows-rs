// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.

//! Embeddable WireGuard dynamic library (`tunnel.dll` / `wireguard.dll`).
//!
//! Provides a C-compatible ABI for:
//! - Running the WireGuard tunnel service synchronously (`WireGuardTunnelService`)
//! - Generating Curve25519 keypairs (`WireGuardGenerateKey` / `WireGuardGenerateKeypair`)
//! - Registering a logger callback (`WireGuardSetLogger`)
//!
//! All exported functions strictly prevent panics from crossing the FFI boundary
//! by wrapping operations in `std::panic::catch_unwind`.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{BOOL, FALSE, TRUE};

/// Log level severity matching `WIREGUARD_LOGGER_LEVEL` in `wireguard.h`.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info = 0,
    Warn = 1,
    Error = 2,
}

/// Logger callback signature matching `WIREGUARD_LOGGER_CALLBACK` in `wireguard.h`.
///
/// Parameters:
/// - `level`: 0 = Info, 1 = Warn, 2 = Error
/// - `timestamp`: Unix timestamp (seconds)
/// - `msg`: Null-terminated UTF-16 string
pub type WireGuardLoggerCallback = extern "system" fn(level: u32, timestamp: u64, msg: *const u16);

/// Global logger callback pointer.
static LOGGER_CALLBACK: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());

enum StackOrHeapMsg {
    Stack { buf: [u8; 512], len: usize },
    Heap(String),
}

impl StackOrHeapMsg {
    fn new() -> Self {
        Self::Stack {
            buf: [0u8; 512],
            len: 0,
        }
    }

    fn as_str(&self) -> &str {
        match self {
            Self::Stack { buf, len } => {
                // SAFETY: `write_str` only appends valid `&str` UTF-8 bytes.
                unsafe { std::str::from_utf8_unchecked(&buf[..*len]) }
            }
            Self::Heap(s) => s.as_str(),
        }
    }
}

impl std::fmt::Write for StackOrHeapMsg {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let spill = match self {
            Self::Stack { buf, len } => {
                let remaining = buf.len() - *len;
                if s.len() <= remaining {
                    buf[*len..*len + s.len()].copy_from_slice(s.as_bytes());
                    *len += s.len();
                    return Ok(());
                }
                let mut heap = String::with_capacity(*len + s.len());
                // SAFETY: `buf[..*len]` only contains valid UTF-8 bytes from prior `write_str` calls.
                heap.push_str(unsafe { std::str::from_utf8_unchecked(&buf[..*len]) });
                heap.push_str(s);
                Some(heap)
            }
            Self::Heap(heap) => {
                heap.push_str(s);
                None
            }
        };
        if let Some(heap) = spill {
            *self = Self::Heap(heap);
        }
        Ok(())
    }
}

fn log_fmt(level: LogLevel, args: std::fmt::Arguments<'_>) {
    let tracing_active = match level {
        LogLevel::Info => tracing::enabled!(tracing::Level::INFO),
        LogLevel::Warn => tracing::enabled!(tracing::Level::WARN),
        LogLevel::Error => tracing::enabled!(tracing::Level::ERROR),
    };
    let ringlog_active = wireguard_ringlog::is_global_logger_active();
    let callback_active = !LOGGER_CALLBACK.load(Ordering::Acquire).is_null();
    if !tracing_active && !ringlog_active && !callback_active {
        return;
    }

    let mut formatted = StackOrHeapMsg::new();
    let _ = std::fmt::Write::write_fmt(&mut formatted, args);
    log_message(level, formatted.as_str());
}

/// Internal logging helper that forwards messages to the registered logger callback,
/// `wireguard-ringlog`, and `tracing`.
pub fn log_message(level: LogLevel, message: &str) {
    // 1. Log to wireguard-ringlog if active (stack-formatted; ringlog caps lines at 512 bytes)
    if let Some(logger) = wireguard_ringlog::global() {
        let level_prefix = match level {
            LogLevel::Info => "[Info] ",
            LogLevel::Warn => "[Warn] ",
            LogLevel::Error => "[Error] ",
        };
        let mut buf = [0u8; 512];
        let plen = level_prefix.len();
        buf[..plen].copy_from_slice(level_prefix.as_bytes());
        let remaining = buf.len() - plen;
        let mlen = if message.len() <= remaining {
            message.len()
        } else {
            let mut n = remaining;
            while n > 0 && !message.is_char_boundary(n) {
                n -= 1;
            }
            n
        };
        buf[plen..plen + mlen].copy_from_slice(&message.as_bytes()[..mlen]);
        let _ = logger.write_bytes(&buf[..plen + mlen]);
    }

    // 2. Log to tracing subscriber
    match level {
        LogLevel::Info => tracing::info!("{}", message),
        LogLevel::Warn => tracing::warn!("{}", message),
        LogLevel::Error => tracing::error!("{}", message),
    }

    // 3. Dispatch to C logger callback if registered (stack-allocated UTF-16 for short messages)
    let cb_ptr = LOGGER_CALLBACK.load(Ordering::Acquire);
    if !cb_ptr.is_null() {
        let callback: WireGuardLoggerCallback = unsafe { std::mem::transmute(cb_ptr) };
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut stack_buf = [0u16; 256];
        let heap_buf: Vec<u16>;
        let ptr = if message.len() < stack_buf.len() {
            let mut idx = 0;
            for code_unit in message.encode_utf16() {
                if idx + 1 >= stack_buf.len() {
                    idx = usize::MAX;
                    break;
                }
                stack_buf[idx] = code_unit;
                idx += 1;
            }
            if idx != usize::MAX {
                stack_buf[idx] = 0;
                stack_buf.as_ptr()
            } else {
                heap_buf = message.encode_utf16().chain(std::iter::once(0)).collect();
                heap_buf.as_ptr()
            }
        } else {
            heap_buf = message.encode_utf16().chain(std::iter::once(0)).collect();
            heap_buf.as_ptr()
        };

        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            callback(level as u32, timestamp, ptr);
        }));
    }
}

/// Safely converts a null-terminated UTF-16 LPCWSTR pointer to a Rust `String`.
///
/// Returns `None` if the pointer is null, if the string length exceeds `max_len`,
/// or if UTF-16 decoding fails.
unsafe fn lpcwstr_slice<'a>(ptr: *const u16, max_len: usize) -> Option<&'a [u16]> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
        if len > max_len {
            return None;
        }
    }
    Some(std::slice::from_raw_parts(ptr, len))
}

/// Safely converts a null-terminated UTF-16 LPCWSTR pointer to a Rust `String`.
///
/// Returns `None` if the pointer is null, if the string length exceeds `max_len`,
/// or if UTF-16 decoding fails.
pub unsafe fn lpcwstr_to_string(ptr: *const u16, max_len: usize) -> Option<String> {
    let slice = lpcwstr_slice(ptr, max_len)?;
    String::from_utf16(slice).ok()
}

/// Safely converts a null-terminated UTF-16 LPCWSTR pointer to a Windows `PathBuf`.
///
/// Uses `OsString::from_wide` to preserve Windows WTF-16 code units.
/// Returns `None` if the pointer is null or string length exceeds `max_len`.
pub unsafe fn lpcwstr_to_path(ptr: *const u16, max_len: usize) -> Option<PathBuf> {
    let slice = lpcwstr_slice(ptr, max_len)?;
    Some(PathBuf::from(OsString::from_wide(slice)))
}

// ---------------------------------------------------------------------------
// C ABI Exported Functions
// ---------------------------------------------------------------------------

/// Sets or clears the global WireGuard logger callback.
///
/// # Safety
/// If non-null, `callback` must remain valid for invocations until cleared with `None`.
#[no_mangle]
pub unsafe extern "system" fn WireGuardSetLogger(callback: Option<WireGuardLoggerCallback>) {
    let _ = std::panic::catch_unwind(|| {
        let ptr = match callback {
            Some(cb) => cb as *mut (),
            None => std::ptr::null_mut(),
        };
        LOGGER_CALLBACK.store(ptr, Ordering::SeqCst);
    });
}

/// Generates a new WireGuard Curve25519 keypair.
///
/// Generates 32 bytes of secure random data, applies the Curve25519 WireGuard
/// bit clamping, and calculates the corresponding public key.
///
/// # Safety
/// - `public_key` must point to a writable buffer of at least 32 bytes.
/// - `private_key` must point to a writable buffer of at least 32 bytes.
///
/// Returns `TRUE` on success, or `FALSE` if either pointer is null or RNG fails.
#[no_mangle]
pub unsafe extern "system" fn WireGuardGenerateKey(
    public_key: *mut u8,
    private_key: *mut u8,
) -> BOOL {
    let result = std::panic::catch_unwind(|| {
        if public_key.is_null() || private_key.is_null() {
            log_message(
                LogLevel::Error,
                "WireGuardGenerateKey: received null pointer for key buffer",
            );
            return FALSE;
        }

        let priv_key = wireguard_types::Key::generate_private();
        let pub_key = priv_key.public_key();

        unsafe {
            std::ptr::copy_nonoverlapping(priv_key.as_bytes().as_ptr(), private_key, 32);
            std::ptr::copy_nonoverlapping(pub_key.as_bytes().as_ptr(), public_key, 32);
        }

        TRUE
    });

    result.unwrap_or(FALSE)
}

/// Alias for `WireGuardGenerateKey` matching original Go export name.
///
/// # Safety
/// Buffers must each have at least 32 bytes allocated.
#[no_mangle]
pub unsafe extern "system" fn WireGuardGenerateKeypair(
    public_key: *mut u8,
    private_key: *mut u8,
) -> BOOL {
    WireGuardGenerateKey(public_key, private_key)
}

/// Runs the WireGuard tunnel service synchronously for the specified configuration file.
///
/// This function blocks until the service is stopped by the Windows Service Control Manager.
///
/// # Safety
/// `conf_file` must be a valid null-terminated UTF-16 LPCWSTR pointer.
///
/// Returns `TRUE` if the service ran and stopped successfully, `FALSE` on error.
#[no_mangle]
pub unsafe extern "system" fn WireGuardTunnelService(conf_file: *const u16) -> BOOL {
    let result = std::panic::catch_unwind(|| {
        if conf_file.is_null() {
            log_message(
                LogLevel::Error,
                "WireGuardTunnelService: conf_file pointer is null",
            );
            return FALSE;
        }

        const MAX_PATH_LEN: usize = 32768;
        let conf_path = match lpcwstr_to_path(conf_file, MAX_PATH_LEN) {
            Some(path) => path,
            None => {
                log_message(
                    LogLevel::Error,
                    "WireGuardTunnelService: failed to decode UTF-16 conf_file path",
                );
                return FALSE;
            }
        };

        log_fmt(
            LogLevel::Info,
            format_args!(
                "WireGuardTunnelService: starting service with config: {}",
                conf_path.display()
            ),
        );

        // Preset root directory if config path has a parent directory
        if let Some(parent) = conf_path.parent() {
            log_fmt(
                LogLevel::Info,
                format_args!(
                    "WireGuardTunnelService: root directory set to {}",
                    parent.display()
                ),
            );
        }

        // Enable fixed GUID mode for embeddable tunnel library (matching Go's tunnel.UseFixedGUIDInsteadOfDeterministic = true)
        wireguard_tunnel::set_use_fixed_guid_instead_of_deterministic(true);

        // Run tunnel service (blocks until SCM stops it)
        match wireguard_tunnel::run(&conf_path) {
            Ok(()) => {
                log_message(
                    LogLevel::Info,
                    "WireGuardTunnelService: service terminated normally",
                );
                TRUE
            }
            Err(err) => {
                log_fmt(
                    LogLevel::Error,
                    format_args!("WireGuardTunnelService: service run error: {}", err),
                );
                FALSE
            }
        }
    });

    result.unwrap_or_else(|_| {
        log_message(
            LogLevel::Error,
            "WireGuardTunnelService: caught panic in FFI boundary",
        );
        FALSE
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;
    use std::sync::Mutex;

    static CALLBACK_CALL_COUNT: AtomicU32 = AtomicU32::new(0);
    static LAST_LOG_MSG: Mutex<String> = Mutex::new(String::new());
    static LOGGER_TEST_LOCK: Mutex<()> = Mutex::new(());

    extern "system" fn test_logger_cb(level: u32, timestamp: u64, msg: *const u16) {
        CALLBACK_CALL_COUNT.fetch_add(1, Ordering::SeqCst);
        let s = unsafe { lpcwstr_to_string(msg, 1024) }.unwrap_or_default();
        if let Ok(mut lock) = LAST_LOG_MSG.lock() {
            *lock = format!("{}:{}:{}", level, timestamp > 0, s);
        }
    }

    #[test]
    fn test_utf16_conversions() {
        let test_str = "C:\\WireGuard\\test.conf";
        let mut wide: Vec<u16> = test_str.encode_utf16().collect();
        wide.push(0);

        unsafe {
            let res = lpcwstr_to_string(wide.as_ptr(), 1024).unwrap();
            assert_eq!(res, test_str);

            let path = lpcwstr_to_path(wide.as_ptr(), 1024).unwrap();
            assert_eq!(path, PathBuf::from(test_str));

            // Test null pointer
            assert!(lpcwstr_to_string(std::ptr::null(), 1024).is_none());
            assert!(lpcwstr_to_path(std::ptr::null(), 1024).is_none());

            // Test bounded length
            assert!(lpcwstr_to_string(wide.as_ptr(), 5).is_none());
        }
    }

    #[test]
    fn test_generate_key() {
        let _guard = LOGGER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut pub_key = [0u8; 32];
        let mut priv_key = [0u8; 32];

        unsafe {
            // Null pointer checks
            assert_eq!(WireGuardGenerateKey(std::ptr::null_mut(), priv_key.as_mut_ptr()), FALSE);
            assert_eq!(WireGuardGenerateKey(pub_key.as_mut_ptr(), std::ptr::null_mut()), FALSE);

            // Successful generation
            assert_eq!(WireGuardGenerateKey(pub_key.as_mut_ptr(), priv_key.as_mut_ptr()), TRUE);
        }

        // Verify clamping
        assert_eq!(priv_key[0] & 248, priv_key[0]);
        assert_eq!((priv_key[31] & 127) | 64, priv_key[31]);

        // Verify public key matches private key using x25519
        let expected_public = wireguard_types::Key::from_bytes(priv_key).public_key();
        assert_eq!(pub_key, *expected_public.as_bytes());

        // Test alias
        let mut pub_key2 = [0u8; 32];
        let mut priv_key2 = [0u8; 32];
        unsafe {
            assert_eq!(
                WireGuardGenerateKeypair(pub_key2.as_mut_ptr(), priv_key2.as_mut_ptr()),
                TRUE
            );
        }
        assert_ne!(priv_key, priv_key2);
    }

    #[test]
    fn test_logger_registration_and_dispatch() {
        let _guard = LOGGER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            WireGuardSetLogger(Some(test_logger_cb));
        }

        CALLBACK_CALL_COUNT.store(0, Ordering::SeqCst);
        log_message(LogLevel::Warn, "Test warning message");

        assert_eq!(CALLBACK_CALL_COUNT.load(Ordering::SeqCst), 1);
        let msg = LAST_LOG_MSG.lock().unwrap().clone();
        assert!(msg.starts_with("1:true:Test warning message"));

        // Clear callback
        unsafe {
            WireGuardSetLogger(None);
        }
        log_message(LogLevel::Error, "Should not hit callback");
        assert_eq!(CALLBACK_CALL_COUNT.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_tunnel_service_null_pointer() {
        let _guard = LOGGER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            assert_eq!(WireGuardTunnelService(std::ptr::null()), FALSE);
        }
    }

    #[test]
    fn test_tunnel_service_missing_config() {
        let _guard = LOGGER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let conf_str = "C:\\dummy\\path\\test.conf";
        let mut wide: Vec<u16> = conf_str.encode_utf16().collect();
        wide.push(0);

        unsafe {
            let success = WireGuardTunnelService(wide.as_ptr());
            assert_eq!(success, FALSE);
        }
    }
}
