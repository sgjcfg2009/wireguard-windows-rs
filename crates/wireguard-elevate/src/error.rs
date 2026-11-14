/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Rust implementation: 2026 WireGuard Rust Contributors.
 */

use thiserror::Error;

/// Result alias for operations in `wireguard-elevate`.
pub type Result<T> = std::result::Result<T, ElevateError>;

/// Errors that can occur during elevation, token operations, or impersonation.
#[derive(Error, Debug)]
pub enum ElevateError {
    #[error("Win32 OS error ({code}): {source}")]
    Win32 {
        code: u32,
        #[source]
        source: std::io::Error,
    },

    #[error("Invalid handle or null handle")]
    InvalidHandle,

    #[error("Privilege '{0}' not found on local system")]
    PrivilegeNotFound(String),

    #[error("Not all privileges were assigned or the token does not possess the privilege")]
    PrivilegesNotAssigned,

    #[error("Failed to query token information (class {0}): {1}")]
    TokenInformationQueryFailed(u32, String),

    #[error("Target process '{0}' not found")]
    ProcessNotFound(String),

    #[error("Service '{0}' is not running or process ID is 0")]
    ServiceNotRunning(String),

    #[error("Desktop shell window not found or invalid")]
    InvalidDesktopWindow,

    #[error("Token is not elevated and cannot be elevated via UAC")]
    NotElevatedOrElevatable,

    #[error("String contains invalid characters or null bytes: {0}")]
    InvalidString(String),

    #[error("ShellExecute failed with code: {0}")]
    ShellExecuteFailed(usize),
}

impl From<std::io::Error> for ElevateError {
    fn from(err: std::io::Error) -> Self {
        let code = err.raw_os_error().unwrap_or(0) as u32;
        ElevateError::Win32 { code, source: err }
    }
}

pub(crate) fn from_win32_code(code: u32) -> ElevateError {
    ElevateError::Win32 {
        code,
        source: std::io::Error::from_raw_os_error(code as i32),
    }
}

pub(crate) fn last_os_error() -> ElevateError {
    let err = std::io::Error::last_os_error();
    let code = err.raw_os_error().unwrap_or(0) as u32;
    ElevateError::Win32 { code, source: err }
}

/// Encodes `s` as NUL-terminated UTF-16 on a `[u16; N]` stack buffer (heap fallback if >= `N`)
/// and passes a `*const u16` pointer to `f`.
#[inline]
pub(crate) fn with_wide_null_cap<const N: usize, R>(
    s: &str,
    f: impl FnOnce(*const u16) -> R,
) -> R {
    let mut stack = [0u16; N];
    let mut len = 0usize;
    let mut iter = s.encode_utf16();
    while let Some(u) = iter.next() {
        if len + 1 >= N {
            let mut heap = Vec::with_capacity(len + 1 + iter.size_hint().0 + 1);
            heap.extend_from_slice(&stack[..len]);
            heap.push(u);
            heap.extend(iter);
            heap.push(0);
            return f(heap.as_ptr());
        }
        stack[len] = u;
        len += 1;
    }
    stack[len] = 0;
    f(stack.as_ptr())
}

/// Mutable variant of `with_wide_null_cap` for Win32 APIs such as `CreateProcess*`
/// that accept an `LPWSTR` (`*mut u16`) command line buffer.
#[inline]
pub(crate) fn with_wide_null_mut_cap<const N: usize, R>(
    s: &str,
    f: impl FnOnce(*mut u16) -> R,
) -> R {
    let mut stack = [0u16; N];
    let mut len = 0usize;
    let mut iter = s.encode_utf16();
    while let Some(u) = iter.next() {
        if len + 1 >= N {
            let mut heap = Vec::with_capacity(len + 1 + iter.size_hint().0 + 1);
            heap.extend_from_slice(&stack[..len]);
            heap.push(u);
            heap.extend(iter);
            heap.push(0);
            return f(heap.as_mut_ptr());
        }
        stack[len] = u;
        len += 1;
    }
    stack[len] = 0;
    f(stack.as_mut_ptr())
}

#[inline]
pub(crate) fn with_wide_null<R>(s: &str, f: impl FnOnce(*const u16) -> R) -> R {
    with_wide_null_cap::<260, R>(s, f)
}

#[inline]
pub(crate) fn with_opt_wide_null<R>(opt: Option<&str>, f: impl FnOnce(*const u16) -> R) -> R {
    match opt {
        Some(s) => with_wide_null(s, f),
        None => f(core::ptr::null()),
    }
}

#[inline]
pub(crate) fn with_opt_wide_null_mut<R>(opt: Option<&str>, f: impl FnOnce(*mut u16) -> R) -> R {
    match opt {
        Some(s) => with_wide_null_mut_cap::<512, R>(s, f),
        None => f(core::ptr::null_mut()),
    }
}

pub(crate) fn from_wide_null_terminated(wide: &[u16]) -> String {
    let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..len])
}
