// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
// Rust implementation: 2026 WireGuard Rust Contributors.

//! Shared Win32 UTF-16 conversion helpers and custom `WM_APP_*` message IDs
//! used internally across `wireguard-ui`.

use windows_sys::Win32::UI::WindowsAndMessaging::WM_APP;

/// Posted to the main window when the `Configurations` directory changes on disk.
pub(crate) const WM_APP_CONFIGS_CHANGED: u32 = WM_APP + 1;

/// Posted to the main window when Windows SCM reports a tunnel service state or
/// registration change.
pub(crate) const WM_APP_SERVICE_STATE_CHANGED: u32 = WM_APP + 2;

/// Posted when an asynchronous tunnel operation (activate, deactivate, delete,
/// import, or autostart) completes on a worker thread.
pub(crate) const WM_APP_TUNNEL_OP_DONE: u32 = WM_APP + 3;

/// Posted by `TunnelsPage` to its parent `ManageTunnelsWindow` to synchronize
/// the tray icon, tooltip, and context menu without polling.
pub(crate) const WM_APP_TRAY_SYNC: u32 = WM_APP + 5;

/// Encodes `s` as NUL-terminated UTF-16 into `buf`, clearing previous contents
/// while reusing `buf`'s heap allocation.
#[inline]
pub(crate) fn encode_wide_null_into(s: &str, buf: &mut Vec<u16>) {
    buf.clear();
    buf.reserve(s.len().saturating_add(1));
    buf.extend(s.encode_utf16());
    buf.push(0);
}

/// Allocates and returns a NUL-terminated UTF-16 `Vec<u16>` for `s`.
#[inline]
pub(crate) fn to_wide_null(s: &str) -> Vec<u16> {
    let mut buf = Vec::with_capacity(s.len().saturating_add(1));
    buf.extend(s.encode_utf16());
    buf.push(0);
    buf
}

/// Invokes `f` with a NUL-terminated UTF-16 pointer for `s`, using a `[u16; 260]`
/// stack buffer for short strings (< 260 UTF-16 code units including NUL) and
/// falling back to a heap `Vec<u16>` for longer strings.
#[inline]
pub(crate) fn with_wide_null<R>(s: &str, f: impl FnOnce(*const u16) -> R) -> R {
    let mut stack_buf = [0u16; 260];
    let mut len = 0usize;
    let mut overflow = false;

    for cu in s.encode_utf16() {
        if len >= stack_buf.len() - 1 {
            overflow = true;
            break;
        }
        stack_buf[len] = cu;
        len += 1;
    }

    if overflow {
        let heap = to_wide_null(s);
        f(heap.as_ptr())
    } else {
        stack_buf[len] = 0;
        f(stack_buf.as_ptr())
    }
}

/// Decodes a NUL-terminated (or slice-bounded) UTF-16 buffer into a `String`.
#[inline]
pub(crate) fn utf16_null_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Copies `s` into a fixed-size UTF-16 buffer `dst` with NUL termination,
/// truncating on character boundaries without splitting UTF-16 surrogate pairs.
#[inline]
pub(crate) fn encode_wide_null_fixed(s: &str, dst: &mut [u16]) {
    if dst.is_empty() {
        return;
    }
    let max_units = dst.len() - 1;
    let mut idx = 0usize;
    for ch in s.chars() {
        let mut tmp = [0u16; 2];
        let encoded = ch.encode_utf16(&mut tmp);
        if idx + encoded.len() > max_units {
            break;
        }
        dst[idx..idx + encoded.len()].copy_from_slice(encoded);
        idx += encoded.len();
    }
    dst[idx] = 0;
}
