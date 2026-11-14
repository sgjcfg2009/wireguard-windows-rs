//! Stack-buffered UTF-16 conversion helpers shared across `wireguard-service`.

use core::ptr;

use crate::error::ServiceError as DispatcherServiceError;

/// Stack buffer capacity in UTF-16 code units (matches Win32 `MAX_PATH`).
const STACK_WIDE_LEN: usize = 260;

fn with_wide_null_mut_inner<R>(s: &str, f: impl FnOnce(*mut u16) -> R) -> R {
    let mut buf = [0u16; STACK_WIDE_LEN];
    let mut len = 0usize;
    for unit in s.encode_utf16() {
        if len + 1 >= STACK_WIDE_LEN {
            let mut heap = Vec::with_capacity(s.len().saturating_add(1));
            heap.extend(s.encode_utf16());
            heap.push(0);
            return f(heap.as_mut_ptr());
        }
        buf[len] = unit;
        len += 1;
    }
    buf[len] = 0;
    f(buf.as_mut_ptr())
}

/// Converts `s` to null-terminated UTF-16 on the stack when `<= 259` code units,
/// falling back to the heap for longer strings, and passes the pointer to `f`.
pub(crate) fn with_wide_null<R>(s: &str, f: impl FnOnce(*const u16) -> R) -> R {
    with_wide_null_mut_inner(s, |p| f(p as *const u16))
}

/// Converts `opt` to null-terminated UTF-16 using [`with_wide_null`], or passes
/// `ptr::null()` when `None`.
pub(crate) fn with_opt_wide_null<R>(opt: Option<&str>, f: impl FnOnce(*const u16) -> R) -> R {
    match opt {
        Some(s) => with_wide_null(s, f),
        None => f(ptr::null()),
    }
}

/// Checked variant of [`with_wide_null`] that rejects interior NUL characters.
pub(crate) fn with_wide_null_checked<R>(
    s: &str,
    f: impl FnOnce(*const u16) -> R,
) -> Result<R, DispatcherServiceError> {
    if s.contains('\0') {
        return Err(DispatcherServiceError::InteriorNull);
    }
    Ok(with_wide_null(s, f))
}

/// Checked mutable-pointer variant of [`with_wide_null`] for Win32 `PWSTR` structs
/// (such as `SERVICE_TABLE_ENTRYW`) that do not mutate the buffer.
pub(crate) fn with_wide_null_checked_mut<R>(
    s: &str,
    f: impl FnOnce(*mut u16) -> R,
) -> Result<R, DispatcherServiceError> {
    if s.contains('\0') {
        return Err(DispatcherServiceError::InteriorNull);
    }
    Ok(with_wide_null_mut_inner(s, f))
}

/// Reads a null-terminated UTF-16 pointer into an owned `String`.
///
/// # Safety
/// If `ptr` is non-null, it must point to a valid null-terminated UTF-16 string.
pub(crate) unsafe fn from_wide_ptr(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let slice = core::slice::from_raw_parts(ptr, len);
    String::from_utf16_lossy(slice)
}
