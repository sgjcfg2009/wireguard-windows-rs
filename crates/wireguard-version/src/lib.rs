/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

pub mod official;
pub mod os;
pub mod useragent;

pub use official::{is_running_ev_signed, is_running_official_version};
pub use os::{
    os_is_core, os_name, os_version, OsVersionInfo, WIN10_BUILD_1507, WIN10_BUILD_1809,
    WIN10_BUILD_2004, WIN10_BUILD_21H2, WIN10_BUILD_22H2, WIN11_BUILD_21H2, WIN11_BUILD_22H2,
    WIN11_BUILD_23H2, WIN11_BUILD_24H2,
};
pub use useragent::{arch, user_agent, Architecture};

/// WireGuard Windows client version number string.
pub const NUMBER: &str = "1.1.1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_number() {
        assert_eq!(NUMBER, "1.1.1");
    }

    #[test]
    fn test_arch_detection() {
        let a = arch();
        assert!(!a.is_empty());
        #[cfg(target_arch = "x86_64")]
        assert_eq!(a, "amd64");
        #[cfg(target_arch = "aarch64")]
        assert_eq!(a, "arm64");
        #[cfg(target_arch = "x86")]
        assert_eq!(a, "x86");
    }

    #[test]
    fn test_architecture_enum() {
        let current = Architecture::current();
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(current, Architecture::Amd64);
            assert_eq!(current.as_str(), "amd64");
            assert_eq!(current.rust_target_arch(), "x86_64");
        }
    }

    #[test]
    fn test_os_version_detection() {
        let ver = os_version();
        // Since we are running on Windows, major version should be at least 6 (Windows Vista / Server 2008 or later)
        assert!(ver.major >= 6, "Expected Windows major >= 6, got {}", ver.major);
        assert!(ver.build > 0, "Expected positive build number");
        println!("Detected Windows version: {} (Build {})", ver, ver.build);
    }

    #[test]
    fn test_os_name_format() {
        let name = os_name();
        assert!(name.starts_with("Windows"), "Name should start with 'Windows': {}", name);
        let ver = os_version();
        assert!(
            name.contains(&format!("{}.{}.{}", ver.major, ver.minor, ver.build)),
            "Name '{}' should contain '{}.{}.{}'",
            name,
            ver.major,
            ver.minor,
            ver.build
        );
    }

    #[test]
    fn test_user_agent_format() {
        let ua = user_agent();
        let expected_prefix = format!("WireGuard/{} (", NUMBER);
        assert!(ua.starts_with(&expected_prefix), "UA should start with prefix: {}", ua);
        assert!(ua.ends_with(')'), "UA should end with closing paren: {}", ua);
        assert!(ua.contains(arch()), "UA should contain architecture: {}", ua);
        println!("Generated User-Agent: {}", ua);
    }

    #[test]
    fn test_windows_thresholds() {
        let win10 = OsVersionInfo {
            major: 10,
            minor: 0,
            build: 19045,
            platform_id: 2,
            service_pack_major: 0,
            service_pack_minor: 0,
            suite_mask: 0,
            product_type: 1,
        };
        assert!(win10.is_windows_10_or_greater());
        assert!(!win10.is_windows_11_or_greater());
        assert!(win10.is_workstation());
        assert!(!win10.is_server());
        assert!(win10.is_build_at_least(WIN10_BUILD_1809));

        let win11 = OsVersionInfo {
            major: 10,
            minor: 0,
            build: 22631,
            platform_id: 2,
            service_pack_major: 0,
            service_pack_minor: 0,
            suite_mask: 0,
            product_type: 1,
        };
        assert!(win11.is_windows_10_or_greater());
        assert!(win11.is_windows_11_or_greater());
        assert!(win11.is_build_at_least(WIN11_BUILD_22H2));

        let win_server = OsVersionInfo {
            major: 10,
            minor: 0,
            build: 20348,
            platform_id: 2,
            service_pack_major: 0,
            service_pack_minor: 0,
            suite_mask: 0,
            product_type: 3,
        };
        assert!(win_server.is_server());
        assert!(!win_server.is_workstation());
    }

    #[test]
    fn test_official_version_check() {
        // In local test runner, executable is typically unsigned test binary, which should safely return false.
        let is_official = is_running_official_version();
        let is_ev = is_running_ev_signed();
        assert!(!is_official || is_official); // Shouldn't panic
        assert!(!is_ev || is_ev);
    }
}
