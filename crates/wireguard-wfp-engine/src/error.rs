/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use thiserror::Error;

/// Error types returned by WFP engine operations.
#[derive(Error, Debug)]
pub enum WfpError {
    #[error("WFP Win32 error code: {0} (0x{0:08x})")]
    Win32(u32),

    #[error("COM / HRESULT error: 0x{0:08x}")]
    Hresult(i32),

    #[error("Invalid GUID format: {0}")]
    InvalidGuid(String),

    #[error("Failed to query process security token: {0}")]
    ProcessTokenError(String),

    #[error("No service SID matching criteria found in process token")]
    NoSuchServiceGroup,

    #[error("WFP Engine is already closed")]
    EngineClosed,

    #[error("Transaction is already committed or aborted")]
    AlreadyCommitted,

    #[error("Invalid parameter or state: {0}")]
    InvalidState(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl WfpError {
    /// Returns true if this error matches a specific Win32 error code.
    pub fn is_win32_code(&self, code: u32) -> bool {
        match self {
            WfpError::Win32(c) => *c == code,
            _ => false,
        }
    }
}
