/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use thiserror::Error;
use wireguard_wfp_engine::WfpError;

/// Error types returned by WFP rules operations.
#[derive(Error, Debug)]
pub enum RulesError {
    #[error("WFP Engine error: {0}")]
    Engine(#[from] WfpError),

    #[error("Firewall is already enabled")]
    AlreadyEnabled,

    #[error("Firewall is not currently enabled")]
    NotEnabled,

    #[error("Allow weight ({allow}) must be greater than deny weight ({deny})")]
    InvalidDnsWeights { allow: u8, deny: u8 },

    #[error("Invalid IP configuration: {0}")]
    InvalidIpConfig(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
