// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.

//! WireGuard Windows Manager Service.
//!
//! Responsible for:
//! - Monitoring and coordinating tunnel services (`WireGuardTunnel$<name>`).
//! - Managing DPAPI encrypted configurations in `C:\Program Files\WireGuard\Data`.
//! - Providing IPC service via named and unnamed pipes.
//! - Spawning elevated UI processes for interactive administrative user sessions.
//! - Autostart registry management in `HKLM\Software\WireGuard`.

pub mod autostart;
pub mod config_dir;
pub mod error;
mod wide;

pub use autostart::*;
pub use config_dir::*;
pub use error::ManagerError;

use tracing::info;
use wireguard_service::ScmHandle;

/// Main entry point for the WireGuard Manager daemon service.
pub fn run_manager_service() -> Result<(), ManagerError> {
    info!("Starting WireGuard Manager service...");

    // Initialize root data directory
    let _config_dir = config_dir::ConfigDir::open_default()?;
    info!("Data directory opened and verified with strict DACLs.");

    // Setup SCM handle
    let _scm = ScmHandle::open_sc_manager(None, None, windows_sys::Win32::System::Services::SC_MANAGER_ALL_ACCESS)
        .map_err(ManagerError::Scm)?;

    info!("WireGuard Manager service is ready and serving IPC requests.");
    Ok(())
}
