/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

//! Windows Filtering Platform (WFP) engine session, transaction, provider and sublayer management.
//!
//! Provides safe RAII wrappers around the Windows User-Mode Filtering Platform (`fwpuclnt.dll`),
//! matching the architecture and security model of WireGuard for Windows.

pub mod error;
pub mod ffi;
pub mod guid;
pub mod session;
pub mod transaction;
pub mod provider;
pub mod app_id;
mod tests;

pub use error::WfpError;
pub use ffi::*;
pub use guid::*;
pub use session::{with_display_data, DisplayData, Engine};
pub use transaction::Transaction;
pub use provider::BaseObjects;
pub use app_id::{get_current_process_security_descriptor, AppIdBlob};
