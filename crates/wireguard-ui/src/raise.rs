// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
// Rust implementation: 2026 WireGuard Rust Contributors.

//! Window raising and activation utilities for WireGuard Windows UI.
//!
//! Faithfully ported from `wireguard-windows/ui/raise.go`.
//!
//! Provides routines to bring the WireGuard UI window to the foreground across
//! process boundaries, taking care of minimized states, Windows User Interface
//! Privilege Isolation (UIPI), thread input attachment, and custom
//! `WM_USER + 0x3510` message dispatching.

use std::ptr;
use tracing::{debug, info, warn};

use windows_sys::Win32::Foundation::{CloseHandle, HWND};
use windows_sys::Win32::Security::TOKEN_QUERY;
use windows_sys::Win32::System::Threading::{
    AttachThreadInput, GetCurrentThreadId, OpenProcess, OpenProcessToken, WaitForSingleObject,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, TerminateProcess,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{SetActiveWindow, SetFocus};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    FindWindowW, GetForegroundWindow, GetWindowThreadProcessId, IsHungAppWindow, IsIconic,
    IsWindowVisible, PostMessageW, SendMessageTimeoutW, SetForegroundWindow, SetWindowPos,
    ShowWindow, HWND_NOTOPMOST, HWND_TOPMOST, SMTO_ABORTIFHUNG, SWP_NOMOVE, SWP_NOSIZE,
    SWP_SHOWWINDOW, SW_RESTORE, SW_SHOW, WM_DESTROY, WM_USER,
};

/// Win32 Window Class name for the WireGuard Manage Tunnels window.
pub const MANAGE_WINDOW_CLASS: &str = "WireGuard UI - Manage Tunnels";

/// Custom message sent to notify the WireGuard UI window to raise and restore itself.
/// Corresponds to `win.WM_USER + 0x3510` (0x3910 / 14608).
pub const WM_RAISE_MSG: u32 = WM_USER + 0x3510;

/// Raises the specified window `hwnd` to the foreground within the same process.
///
/// If minimized, the window is restored to its normal size and state.
/// It uses the topmost z-order toggle technique to guarantee focus acquisition.
pub fn raise(hwnd: HWND) {
    if hwnd.is_null() {
        return;
    }

    unsafe {
        if IsWindowVisible(hwnd) == 0 {
            ShowWindow(hwnd, SW_SHOW);
        }
        if IsIconic(hwnd) != 0 {
            ShowWindow(hwnd, SW_RESTORE);
        }

        SetActiveWindow(hwnd);
        SetWindowPos(
            hwnd,
            HWND_TOPMOST,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW,
        );
        SetForegroundWindow(hwnd);
        SetWindowPos(
            hwnd,
            HWND_NOTOPMOST,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW,
        );
    }
}

/// Raises the window `hwnd` from a different thread or process.
///
/// Ported from `raiseRemote` in `wireguard-windows/ui/raise.go`:
/// 1. Sends the custom `WM_RAISE_MSG` message.
/// 2. Attaches thread input queues between the current foreground thread and this thread
///    to bypass Windows foreground lock restrictions.
/// 3. Flips window z-order to topmost then non-topmost and calls `SetForegroundWindow`.
/// 4. Detaches thread input and sets focus.
pub fn raise_remote(hwnd: HWND) -> bool {
    if hwnd.is_null() {
        return false;
    }

    unsafe {
        if IsHungAppWindow(hwnd) != 0 {
            warn!("Target WireGuard window is hung/unresponsive");
            return false;
        }

        // Send custom raise message with timeout to prevent blocking on deadlocked windows
        let mut msg_result: usize = 0;
        let sent = SendMessageTimeoutW(
            hwnd,
            WM_RAISE_MSG,
            0,
            0,
            SMTO_ABORTIFHUNG,
            1500,
            &mut msg_result,
        );

        if sent == 0 {
            warn!("SendMessageTimeoutW failed to reach target window");
            return false;
        }

        let current_foreground_hwnd = GetForegroundWindow();
        let current_foreground_thread_id =
            GetWindowThreadProcessId(current_foreground_hwnd, ptr::null_mut());
        let current_thread_id = GetCurrentThreadId();

        let attached = if current_foreground_thread_id != current_thread_id
            && current_foreground_thread_id != 0
        {
            AttachThreadInput(current_foreground_thread_id, current_thread_id, 1) != 0
        } else {
            false
        };

        SetWindowPos(
            hwnd,
            HWND_TOPMOST,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW,
        );
        SetWindowPos(
            hwnd,
            HWND_NOTOPMOST,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW,
        );
        SetForegroundWindow(hwnd);

        if attached {
            AttachThreadInput(current_foreground_thread_id, current_thread_id, 0);
        }

        SetFocus(hwnd);
        SetActiveWindow(hwnd);
        true
    }
}

/// Checks whether an elevated WireGuard UI window is already running, and optionally raises it.
///
/// Any stale unelevated WireGuard UI window matching [`MANAGE_WINDOW_CLASS`] is terminated cleanly
/// so a fresh elevated instance can take over. Returns `true` if a live elevated instance is
/// already running; only sends `WM_USER + 0x3510` and raises the window when `raise_existing == true`.
pub fn ensure_single_instance(raise_existing: bool) -> bool {
    let hwnd = crate::win32_util::with_wide_null(MANAGE_WINDOW_CLASS, |class_wide| unsafe {
        FindWindowW(class_wide, ptr::null())
    });

    if hwnd.is_null() {
        debug!("WireGuard UI window ('{}') not found", MANAGE_WINDOW_CLASS);
        return false;
    }

    unsafe {
        let mut pid: u32 = 0;
        let tid = GetWindowThreadProcessId(hwnd, &mut pid);
        if tid == 0 || pid == 0 || pid == std::process::id() {
            return false;
        }

        // Check whether the existing UI process is running elevated.
        // If it is NOT elevated, terminate it so a fresh elevated instance can take over.
        // Note: unelevated callers querying an elevated process fail OpenProcess here
        // (h_proc == null), which correctly indicates an elevated instance is already running.
        let h_proc = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE,
            0,
            pid,
        );
        if !h_proc.is_null() {
            let mut h_tok = ptr::null_mut();
            let mut is_elevated = true;
            if OpenProcessToken(h_proc, TOKEN_QUERY, &mut h_tok) != 0 {
                is_elevated = wireguard_elevate::is_token_elevated(h_tok).unwrap_or(false);
                CloseHandle(h_tok);
            }
            if !is_elevated {
                let _ = PostMessageW(hwnd, WM_DESTROY, 0, 0);
                let _ = TerminateProcess(h_proc, 0);
                let _ = WaitForSingleObject(h_proc, 1000);
                CloseHandle(h_proc);
                return false;
            }
            CloseHandle(h_proc);
        }

        if !raise_existing {
            debug!(
                "Existing WireGuard UI window found (HWND={:?}); keeping it in current state",
                hwnd
            );
            return true;
        }

        info!(
            "WireGuard UI window found (HWND={:?}), raising to foreground",
            hwnd
        );
        raise_remote(hwnd)
    }
}

/// Finds the running WireGuard UI window and brings it to the foreground.
///
/// Searches for a top-level window with class "WireGuard UI - Manage Tunnels".
/// If found, brings it to foreground using `SetForegroundWindow`, `AttachThreadInput`,
/// `SetWindowPos`, and sends `WM_USER + 0x3510`, returning `true`.
/// If no such window exists or the existing window is hung, returns `false`.
pub fn raise_ui() -> bool {
    ensure_single_instance(true)
}
