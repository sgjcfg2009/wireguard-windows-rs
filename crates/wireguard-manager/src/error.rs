// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.

//! Error types for WireGuard Windows Manager service.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ManagerError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Win32 error ({function}): {code:#010x}")]
    Win32 { function: &'static str, code: u32 },

    #[error("SCM error: {0}")]
    Scm(#[from] wireguard_service::ServiceError),

    #[error("DPAPI error: {0}")]
    Dpapi(#[from] wireguard_dpapi::DpapiError),

    #[error("invalid tunnel name: {0}")]
    InvalidTunnelName(String),

    #[error("access denied: operation requires elevated administrator privileges")]
    AccessDenied,

    #[error("tunnel '{0}' is already installed and running")]
    TunnelAlreadyRunning(String),

    #[error("tunnel '{0}' is currently in transition; please allow it to finish activating")]
    TunnelInTransition(String),

    #[error("data directory error: {0}")]
    DataDirectory(String),

    #[error("registry error: {0}")]
    Registry(String),

    #[error("configuration parse error: {0}")]
    ConfigParse(String),

    #[error("service manager already running")]
    ManagerAlreadyRunning,
}

impl ManagerError {
    pub fn last_win32(function: &'static str) -> Self {
        let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        Self::Win32 { function, code }
    }
}
