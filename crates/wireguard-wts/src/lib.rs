// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.

//! Windows Terminal Services (WTS) session enumeration, token retrieval, and session monitoring.
//!
//! Provides functions to query active user sessions and retrieve their primary user tokens
//! for launching user-interactive processes (e.g. WireGuard UI) from the Manager service daemon.

use std::ptr;
use thiserror::Error;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_INVALID_HANDLE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::RemoteDesktop::{
    WTSActive, WTSDisconnected, WTSEnumerateSessionsW, WTSFreeMemory, WTSQueryUserToken,
    WTS_CONNECTSTATE_CLASS, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW,
};

#[derive(Debug, Error)]
pub enum WtsError {
    #[error("failed to enumerate WTS sessions (Win32 error: {0})")]
    EnumerateSessions(u32),
    #[error("failed to query user token for session {session_id} (Win32 error: {code})")]
    QueryUserToken { session_id: u32, code: u32 },
    #[error("session {0} is not active or has no user logged on")]
    SessionNotActive(u32),
}

/// Represents an active or disconnected Windows user terminal session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WtsSession {
    pub session_id: u32,
    pub station_name: String,
    pub state: WTS_CONNECTSTATE_CLASS,
}

impl WtsSession {
    /// Checks if the session is currently active (user is interactively logged on at desktop).
    pub fn is_active(&self) -> bool {
        self.state == WTSActive
    }

    /// Checks if the session is disconnected.
    pub fn is_disconnected(&self) -> bool {
        self.state == WTSDisconnected
    }
}

struct WtsMemGuard(*mut WTS_SESSION_INFOW);

impl Drop for WtsMemGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                WTSFreeMemory(self.0 as _);
            }
            self.0 = ptr::null_mut();
        }
    }
}

/// Enumerates all existing Windows Terminal Services sessions on the local system.
pub fn enumerate_sessions() -> Result<Vec<WtsSession>, WtsError> {
    let mut session_info_ptr: *mut WTS_SESSION_INFOW = ptr::null_mut();
    let mut count: u32 = 0;

    let success = unsafe {
        WTSEnumerateSessionsW(
            WTS_CURRENT_SERVER_HANDLE,
            0,
            1,
            &mut session_info_ptr,
            &mut count,
        )
    };

    if success == 0 {
        let err = unsafe { GetLastError() };
        return Err(WtsError::EnumerateSessions(err));
    }

    let _mem_guard = WtsMemGuard(session_info_ptr);
    if session_info_ptr.is_null() || count == 0 {
        return Ok(Vec::new());
    }

    let raw_sessions = unsafe { std::slice::from_raw_parts(session_info_ptr, count as usize) };
    let mut sessions = Vec::with_capacity(raw_sessions.len());

    for info in raw_sessions {
        let station_name = if !info.pWinStationName.is_null() {
            let mut len = 0;
            while unsafe { *info.pWinStationName.add(len) } != 0 {
                len += 1;
            }
            let slice = unsafe { std::slice::from_raw_parts(info.pWinStationName, len) };
            String::from_utf16_lossy(slice)
        } else {
            String::new()
        };

        sessions.push(WtsSession {
            session_id: info.SessionId,
            station_name,
            state: info.State,
        });
    }

    Ok(sessions)
}

/// Safe RAII wrapper for a Win32 user token retrieved from WTS.
#[derive(Debug)]
pub struct UserToken(HANDLE);

unsafe impl Send for UserToken {}
unsafe impl Sync for UserToken {}

impl UserToken {
    /// Obtains the primary access token for the logged-on user in the specified WTS session.
    pub fn from_session(session_id: u32) -> Result<Self, WtsError> {
        let mut token: HANDLE = INVALID_HANDLE_VALUE;
        let success = unsafe { WTSQueryUserToken(session_id, &mut token) };

        if success == 0 {
            let err = unsafe { GetLastError() };
            return Err(WtsError::QueryUserToken {
                session_id,
                code: err,
            });
        }
        if token.is_null() || token == INVALID_HANDLE_VALUE {
            return Err(WtsError::QueryUserToken {
                session_id,
                code: ERROR_INVALID_HANDLE,
            });
        }

        Ok(Self(token))
    }

    /// Returns the raw Win32 HANDLE.
    pub fn as_raw(&self) -> HANDLE {
        self.0
    }

    /// Consumes the wrapper and yields the raw Win32 HANDLE without closing it.
    pub fn into_raw(mut self) -> HANDLE {
        let h = self.0;
        self.0 = INVALID_HANDLE_VALUE;
        h
    }
}

impl Drop for UserToken {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
            self.0 = INVALID_HANDLE_VALUE;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_sessions() {
        let res = enumerate_sessions();
        assert!(res.is_ok(), "enumerate_sessions should succeed on Windows");
        let sessions = res.unwrap();
        // At least session 0 (services) or interactive sessions should be present
        assert!(!sessions.is_empty());
    }
}
