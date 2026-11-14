//! Stack-buffered UTF-16 conversion helpers shared across `wireguard-manager`.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

/// Stack buffer capacity in UTF-16 code units (matches Win32 `MAX_PATH`).
const STACK_WIDE_LEN: usize = 260;

fn with_os_str_wide_null<R>(s: &OsStr, f: impl FnOnce(*const u16) -> R) -> R {
    let mut buf = [0u16; STACK_WIDE_LEN];
    let mut len = 0usize;
    for unit in s.encode_wide() {
        if len + 1 >= STACK_WIDE_LEN {
            let mut heap = Vec::with_capacity(s.len().saturating_add(1));
            heap.extend(s.encode_wide());
            heap.push(0);
            return f(heap.as_ptr());
        }
        buf[len] = unit;
        len += 1;
    }
    buf[len] = 0;
    f(buf.as_ptr())
}

/// Converts a UTF-8 string slice to null-terminated UTF-16 on the stack when
/// `<= 259` code units, falling back to a heap `Vec<u16>` otherwise.
pub(crate) fn with_wide_null<R>(s: &str, f: impl FnOnce(*const u16) -> R) -> R {
    with_os_str_wide_null(OsStr::new(s), f)
}

/// Converts a `Path` to null-terminated UTF-16 on the stack without intermediate
/// lossy UTF-8 allocation, falling back to the heap for paths `>= 260` units.
pub(crate) fn with_path_wide_null<R>(path: &Path, f: impl FnOnce(*const u16) -> R) -> R {
    with_os_str_wide_null(path.as_os_str(), f)
}
