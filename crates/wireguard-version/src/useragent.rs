/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use std::fmt;
use crate::NUMBER;

/// CPU architecture matching WireGuard / Go GOARCH string representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Architecture {
    Amd64,
    Arm64,
    X86,
    Arm,
}

impl Architecture {
    /// Returns the active compile target architecture.
    pub const fn current() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Architecture::Amd64
        }
        #[cfg(target_arch = "aarch64")]
        {
            Architecture::Arm64
        }
        #[cfg(target_arch = "x86")]
        {
            Architecture::X86
        }
        #[cfg(target_arch = "arm")]
        {
            Architecture::Arm
        }
        #[cfg(not(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "x86",
            target_arch = "arm"
        )))]
        {
            compile_error!("Unsupported target architecture for wireguard-windows");
        }
    }

    /// Returns the string matching Go's runtime.GOARCH / WireGuard convention:
    /// "amd64", "arm64", "x86", "arm".
    pub const fn as_str(&self) -> &'static str {
        match self {
            Architecture::Amd64 => "amd64",
            Architecture::Arm64 => "arm64",
            Architecture::X86 => "x86",
            Architecture::Arm => "arm",
        }
    }

    /// Returns canonical Rust architecture name:
    /// "x86_64", "aarch64", "i686", "arm".
    pub const fn rust_target_arch(&self) -> &'static str {
        match self {
            Architecture::Amd64 => "x86_64",
            Architecture::Arm64 => "aarch64",
            Architecture::X86 => "i686",
            Architecture::Arm => "arm",
        }
    }
}

impl fmt::Display for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Returns the architecture string matching WireGuard's Arch() function.
/// Output is one of: "amd64", "arm64", "x86", "arm".
#[inline]
pub fn arch() -> &'static str {
    Architecture::current().as_str()
}

/// Returns the HTTP / IPC user agent string for WireGuard Windows.
/// Output format: "WireGuard/<Number> (<OsName>; <Arch>)"
/// e.g. "WireGuard/1.1.1 (Windows 10.0.19045; amd64)"
pub fn user_agent() -> String {
    let mut out = String::with_capacity(64);
    out.push_str("WireGuard/");
    out.push_str(NUMBER);
    out.push_str(" (");
    crate::os::write_os_name(&mut out);
    out.push_str("; ");
    out.push_str(arch());
    out.push(')');
    out
}
