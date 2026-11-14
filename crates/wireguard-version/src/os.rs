/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use std::fmt;

// Windows Product Types
pub const PRODUCT_UNDEFINED: u32 = 0x00000000;
pub const PRODUCT_ULTIMATE: u32 = 0x00000001;
pub const PRODUCT_HOME_BASIC: u32 = 0x00000002;
pub const PRODUCT_HOME_PREMIUM: u32 = 0x00000003;
pub const PRODUCT_ENTERPRISE: u32 = 0x00000004;
pub const PRODUCT_HOME_BASIC_N: u32 = 0x00000005;
pub const PRODUCT_BUSINESS: u32 = 0x00000006;
pub const PRODUCT_STANDARD_SERVER: u32 = 0x00000007;
pub const PRODUCT_DATACENTER_SERVER: u32 = 0x00000008;
pub const PRODUCT_SMALLBUSINESS_SERVER: u32 = 0x00000009;
pub const PRODUCT_ENTERPRISE_SERVER: u32 = 0x0000000A;
pub const PRODUCT_STARTER: u32 = 0x0000000B;
pub const PRODUCT_DATACENTER_SERVER_CORE: u32 = 0x0000000C;
pub const PRODUCT_STANDARD_SERVER_CORE: u32 = 0x0000000D;
pub const PRODUCT_ENTERPRISE_SERVER_CORE: u32 = 0x0000000E;
pub const PRODUCT_ENTERPRISE_SERVER_IA64: u32 = 0x0000000F;
pub const PRODUCT_BUSINESS_N: u32 = 0x00000010;
pub const PRODUCT_WEB_SERVER: u32 = 0x00000011;
pub const PRODUCT_CLUSTER_SERVER: u32 = 0x00000012;
pub const PRODUCT_HOME_SERVER: u32 = 0x00000013;
pub const PRODUCT_STORAGE_EXPRESS_SERVER: u32 = 0x00000014;
pub const PRODUCT_STORAGE_STANDARD_SERVER: u32 = 0x00000015;
pub const PRODUCT_STORAGE_WORKGROUP_SERVER: u32 = 0x00000016;
pub const PRODUCT_STORAGE_ENTERPRISE_SERVER: u32 = 0x00000017;
pub const PRODUCT_SERVER_FOR_SMALLBUSINESS: u32 = 0x00000018;
pub const PRODUCT_SMALLBUSINESS_SERVER_PREMIUM: u32 = 0x00000019;
pub const PRODUCT_HOME_PREMIUM_N: u32 = 0x0000001A;
pub const PRODUCT_ENTERPRISE_N: u32 = 0x0000001B;
pub const PRODUCT_ULTIMATE_N: u32 = 0x0000001C;
pub const PRODUCT_WEB_SERVER_CORE: u32 = 0x0000001D;
pub const PRODUCT_MEDIUMBUSINESS_SERVER_MANAGEMENT: u32 = 0x0000001E;
pub const PRODUCT_MEDIUMBUSINESS_SERVER_SECURITY: u32 = 0x0000001F;
pub const PRODUCT_MEDIUMBUSINESS_SERVER_MESSAGING: u32 = 0x00000020;
pub const PRODUCT_SERVER_FOUNDATION: u32 = 0x00000021;
pub const PRODUCT_HOME_PREMIUM_SERVER: u32 = 0x00000022;
pub const PRODUCT_SERVER_FOR_SMALLBUSINESS_V: u32 = 0x00000023;
pub const PRODUCT_STANDARD_SERVER_V: u32 = 0x00000024;
pub const PRODUCT_DATACENTER_SERVER_V: u32 = 0x00000025;
pub const PRODUCT_ENTERPRISE_SERVER_V: u32 = 0x00000026;
pub const PRODUCT_DATACENTER_SERVER_CORE_V: u32 = 0x00000027;
pub const PRODUCT_STANDARD_SERVER_CORE_V: u32 = 0x00000028;
pub const PRODUCT_ENTERPRISE_SERVER_CORE_V: u32 = 0x00000029;
pub const PRODUCT_HYPERV: u32 = 0x0000002A;
pub const PRODUCT_STORAGE_EXPRESS_SERVER_CORE: u32 = 0x0000002B;
pub const PRODUCT_STORAGE_STANDARD_SERVER_CORE: u32 = 0x0000002C;
pub const PRODUCT_STORAGE_WORKGROUP_SERVER_CORE: u32 = 0x0000002D;
pub const PRODUCT_STORAGE_ENTERPRISE_SERVER_CORE: u32 = 0x0000002E;
pub const PRODUCT_STARTER_N: u32 = 0x0000002F;
pub const PRODUCT_PROFESSIONAL: u32 = 0x00000030;
pub const PRODUCT_PROFESSIONAL_N: u32 = 0x00000031;
pub const PRODUCT_SB_SOLUTION_SERVER: u32 = 0x00000032;
pub const PRODUCT_SERVER_FOR_SB_SOLUTIONS: u32 = 0x00000033;
pub const PRODUCT_STANDARD_SERVER_SOLUTIONS: u32 = 0x00000034;
pub const PRODUCT_STANDARD_SERVER_SOLUTIONS_CORE: u32 = 0x00000035;
pub const PRODUCT_SB_SOLUTION_SERVER_EM: u32 = 0x00000036;
pub const PRODUCT_SERVER_FOR_SB_SOLUTIONS_EM: u32 = 0x00000037;
pub const PRODUCT_SOLUTION_EMBEDDEDSERVER: u32 = 0x00000038;
pub const PRODUCT_SOLUTION_EMBEDDEDSERVER_CORE: u32 = 0x00000039;
pub const PRODUCT_PROFESSIONAL_EMBEDDED: u32 = 0x0000003A;
pub const PRODUCT_ESSENTIALBUSINESS_SERVER_MGMT: u32 = 0x0000003B;
pub const PRODUCT_ESSENTIALBUSINESS_SERVER_ADDL: u32 = 0x0000003C;
pub const PRODUCT_ESSENTIALBUSINESS_SERVER_MGMTSVC: u32 = 0x0000003D;
pub const PRODUCT_ESSENTIALBUSINESS_SERVER_ADDLSVC: u32 = 0x0000003E;
pub const PRODUCT_SMALLBUSINESS_SERVER_PREMIUM_CORE: u32 = 0x0000003F;
pub const PRODUCT_CLUSTER_SERVER_V: u32 = 0x00000040;
pub const PRODUCT_EMBEDDED: u32 = 0x00000041;
pub const PRODUCT_STARTER_E: u32 = 0x00000042;
pub const PRODUCT_HOME_BASIC_E: u32 = 0x00000043;
pub const PRODUCT_HOME_PREMIUM_E: u32 = 0x00000044;
pub const PRODUCT_PROFESSIONAL_E: u32 = 0x00000045;
pub const PRODUCT_ENTERPRISE_E: u32 = 0x00000046;
pub const PRODUCT_ULTIMATE_E: u32 = 0x00000047;
pub const PRODUCT_ENTERPRISE_EVALUATION: u32 = 0x00000048;
pub const PRODUCT_MULTIPOINT_STANDARD_SERVER: u32 = 0x0000004C;
pub const PRODUCT_MULTIPOINT_PREMIUM_SERVER: u32 = 0x0000004D;
pub const PRODUCT_STANDARD_EVALUATION_SERVER: u32 = 0x0000004F;
pub const PRODUCT_DATACENTER_EVALUATION_SERVER: u32 = 0x00000050;
pub const PRODUCT_ENTERPRISE_N_EVALUATION: u32 = 0x00000054;
pub const PRODUCT_EMBEDDED_AUTOMOTIVE: u32 = 0x00000055;
pub const PRODUCT_EMBEDDED_INDUSTRY_A: u32 = 0x00000056;
pub const PRODUCT_THINPC: u32 = 0x00000057;
pub const PRODUCT_EMBEDDED_A: u32 = 0x00000058;
pub const PRODUCT_EMBEDDED_INDUSTRY: u32 = 0x00000059;
pub const PRODUCT_EMBEDDED_E: u32 = 0x0000005A;
pub const PRODUCT_EMBEDDED_INDUSTRY_E: u32 = 0x0000005B;
pub const PRODUCT_EMBEDDED_INDUSTRY_A_E: u32 = 0x0000005C;
pub const PRODUCT_STORAGE_WORKGROUP_EVALUATION_SERVER: u32 = 0x0000005F;
pub const PRODUCT_STORAGE_STANDARD_EVALUATION_SERVER: u32 = 0x00000060;
pub const PRODUCT_CORE_ARM: u32 = 0x00000061;
pub const PRODUCT_CORE_N: u32 = 0x00000062;
pub const PRODUCT_CORE_COUNTRYSPECIFIC: u32 = 0x00000063;
pub const PRODUCT_CORE_SINGLELANGUAGE: u32 = 0x00000064;
pub const PRODUCT_CORE: u32 = 0x00000065;
pub const PRODUCT_PROFESSIONAL_WMC: u32 = 0x00000067;
pub const PRODUCT_EMBEDDED_INDUSTRY_EVAL: u32 = 0x00000069;
pub const PRODUCT_EMBEDDED_INDUSTRY_E_EVAL: u32 = 0x0000006A;
pub const PRODUCT_EMBEDDED_EVAL: u32 = 0x0000006B;
pub const PRODUCT_EMBEDDED_E_EVAL: u32 = 0x0000006C;
pub const PRODUCT_NANO_SERVER: u32 = 0x0000006D;
pub const PRODUCT_CLOUD_STORAGE_SERVER: u32 = 0x0000006E;
pub const PRODUCT_CORE_CONNECTED: u32 = 0x0000006F;
pub const PRODUCT_PROFESSIONAL_STUDENT: u32 = 0x00000070;
pub const PRODUCT_CORE_CONNECTED_N: u32 = 0x00000071;
pub const PRODUCT_PROFESSIONAL_STUDENT_N: u32 = 0x00000072;
pub const PRODUCT_CORE_CONNECTED_SINGLELANGUAGE: u32 = 0x00000073;
pub const PRODUCT_CORE_CONNECTED_COUNTRYSPECIFIC: u32 = 0x00000074;
pub const PRODUCT_CONNECTED_CAR: u32 = 0x00000075;
pub const PRODUCT_INDUSTRY_HANDHELD: u32 = 0x00000076;
pub const PRODUCT_PPI_PRO: u32 = 0x00000077;
pub const PRODUCT_ARM64_SERVER: u32 = 0x00000078;
pub const PRODUCT_EDUCATION: u32 = 0x00000079;
pub const PRODUCT_EDUCATION_N: u32 = 0x0000007A;
pub const PRODUCT_IOTUAP: u32 = 0x0000007B;
pub const PRODUCT_CLOUD_HOST_INFRASTRUCTURE_SERVER: u32 = 0x0000007C;
pub const PRODUCT_ENTERPRISE_S: u32 = 0x0000007D;
pub const PRODUCT_ENTERPRISE_S_N: u32 = 0x0000007E;
pub const PRODUCT_PROFESSIONAL_S: u32 = 0x0000007F;
pub const PRODUCT_PROFESSIONAL_S_N: u32 = 0x00000080;
pub const PRODUCT_ENTERPRISE_S_EVALUATION: u32 = 0x00000081;
pub const PRODUCT_ENTERPRISE_S_N_EVALUATION: u32 = 0x00000082;
pub const PRODUCT_HOLOGRAPHIC: u32 = 0x00000087;
pub const PRODUCT_PRO_SINGLE_LANGUAGE: u32 = 0x0000008A;
pub const PRODUCT_PRO_CHINA: u32 = 0x0000008B;
pub const PRODUCT_ENTERPRISE_SUBSCRIPTION: u32 = 0x0000008C;
pub const PRODUCT_ENTERPRISE_SUBSCRIPTION_N: u32 = 0x0000008D;
pub const PRODUCT_DATACENTER_NANO_SERVER: u32 = 0x0000008F;
pub const PRODUCT_STANDARD_NANO_SERVER: u32 = 0x00000090;
pub const PRODUCT_DATACENTER_A_SERVER_CORE: u32 = 0x00000091;
pub const PRODUCT_STANDARD_A_SERVER_CORE: u32 = 0x00000092;
pub const PRODUCT_DATACENTER_WS_SERVER_CORE: u32 = 0x00000093;
pub const PRODUCT_STANDARD_WS_SERVER_CORE: u32 = 0x00000094;
pub const PRODUCT_UTILITY_VM: u32 = 0x00000095;
pub const PRODUCT_DATACENTER_EVALUATION_SERVER_CORE: u32 = 0x0000009F;
pub const PRODUCT_STANDARD_EVALUATION_SERVER_CORE: u32 = 0x000000A0;
pub const PRODUCT_PRO_WORKSTATION: u32 = 0x000000A1;
pub const PRODUCT_PRO_WORKSTATION_N: u32 = 0x000000A2;
pub const PRODUCT_PRO_FOR_EDUCATION: u32 = 0x000000A4;
pub const PRODUCT_PRO_FOR_EDUCATION_N: u32 = 0x000000A5;
pub const PRODUCT_AZURE_SERVER_CORE: u32 = 0x000000A8;
pub const PRODUCT_AZURE_NANO_SERVER: u32 = 0x000000A9;
pub const PRODUCT_ENTERPRISEG: u32 = 0x000000AB;
pub const PRODUCT_ENTERPRISEGN: u32 = 0x000000AC;
pub const PRODUCT_SERVERRDSH: u32 = 0x000000AF;
pub const PRODUCT_CLOUD: u32 = 0x000000B2;
pub const PRODUCT_CLOUDN: u32 = 0x000000B3;
pub const PRODUCT_HUBOS: u32 = 0x000000B4;
pub const PRODUCT_ONECOREUPDATEOS: u32 = 0x000000B6;
pub const PRODUCT_CLOUDE: u32 = 0x000000B7;
pub const PRODUCT_ANDROMEDA: u32 = 0x000000B8;
pub const PRODUCT_IOTOS: u32 = 0x000000B9;
pub const PRODUCT_CLOUDEN: u32 = 0x000000BA;
pub const PRODUCT_UNLICENSED: u32 = 0xABCDABCD;

// Common Windows Build Thresholds
pub const WIN10_BUILD_1507: u32 = 10240; // Initial release
pub const WIN10_BUILD_1511: u32 = 10586; // November Update
pub const WIN10_BUILD_1607: u32 = 14393; // Anniversary Update
pub const WIN10_BUILD_1703: u32 = 15063; // Creators Update
pub const WIN10_BUILD_1709: u32 = 16299; // Fall Creators Update
pub const WIN10_BUILD_1803: u32 = 17134; // April 2018 Update
pub const WIN10_BUILD_1809: u32 = 17763; // October 2018 Update
pub const WIN10_BUILD_1903: u32 = 18362; // May 2019 Update
pub const WIN10_BUILD_1909: u32 = 18363; // November 2019 Update
pub const WIN10_BUILD_2004: u32 = 19041; // May 2020 Update
pub const WIN10_BUILD_20H2: u32 = 19042; // October 2020 Update
pub const WIN10_BUILD_21H1: u32 = 19043; // May 2021 Update
pub const WIN10_BUILD_21H2: u32 = 19044; // November 2021 Update
pub const WIN10_BUILD_22H2: u32 = 19045; // 2022 Update

pub const WIN11_BUILD_21H2: u32 = 22000; // Windows 11 initial release
pub const WIN11_BUILD_22H2: u32 = 22621; // Windows 11 2022 Update
pub const WIN11_BUILD_23H2: u32 = 22631; // Windows 11 2023 Update
pub const WIN11_BUILD_24H2: u32 = 26100; // Windows 11 2024 Update

pub const WIN_SERVER_2016_BUILD: u32 = 14393;
pub const WIN_SERVER_2019_BUILD: u32 = 17763;
pub const WIN_SERVER_2022_BUILD: u32 = 20348;
pub const WIN_SERVER_2025_BUILD: u32 = 26100;

// Windows Product Type flags in OSVERSIONINFOEXW
pub const VER_NT_WORKSTATION: u8 = 1;
pub const VER_NT_DOMAIN_CONTROLLER: u8 = 2;
pub const VER_NT_SERVER: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OsVersionInfo {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub platform_id: u32,
    pub service_pack_major: u16,
    pub service_pack_minor: u16,
    pub suite_mask: u16,
    pub product_type: u8,
}

impl OsVersionInfo {
    /// Returns true if running on Windows 10 or greater (Build >= 10240 or Major > 10).
    pub fn is_windows_10_or_greater(&self) -> bool {
        self.major > 10 || (self.major == 10 && self.build >= WIN10_BUILD_1507)
    }

    /// Returns true if running on Windows 11 or greater (Build >= 22000 or Major > 10).
    pub fn is_windows_11_or_greater(&self) -> bool {
        self.major > 10 || (self.major == 10 && self.build >= WIN11_BUILD_21H2)
    }

    /// Returns true if running on Windows 8.1 or greater.
    pub fn is_windows_8_1_or_greater(&self) -> bool {
        self.major > 6 || (self.major == 6 && self.minor >= 3)
    }

    /// Returns true if running on Windows 8 or greater.
    pub fn is_windows_8_or_greater(&self) -> bool {
        self.major > 6 || (self.major == 6 && self.minor >= 2)
    }

    /// Returns true if running on Windows 7 or greater.
    pub fn is_windows_7_or_greater(&self) -> bool {
        self.major > 6 || (self.major == 6 && self.minor >= 1)
    }

    /// Returns true if the product type is a Server (Domain Controller or Standalone Server).
    pub fn is_server(&self) -> bool {
        self.product_type == VER_NT_SERVER || self.product_type == VER_NT_DOMAIN_CONTROLLER
    }

    /// Returns true if the product type is a Workstation.
    pub fn is_workstation(&self) -> bool {
        self.product_type == VER_NT_WORKSTATION
    }

    /// Returns true if the build meets or exceeds a specified minimum build number.
    pub fn is_build_at_least(&self, min_build: u32) -> bool {
        self.build >= min_build
    }
}

impl fmt::Display for OsVersionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.build)
    }
}

/// Retrieve the true Windows OS version using RtlGetVersion from ntdll.dll (cached process-wide).
/// Unlike GetVersionExW, RtlGetVersion is not subjected to application manifest compatibility shims.
pub fn os_version() -> OsVersionInfo {
    static CACHED_VERSION: std::sync::OnceLock<OsVersionInfo> = std::sync::OnceLock::new();
    *CACHED_VERSION.get_or_init(query_os_version_uncached)
}

fn query_os_version_uncached() -> OsVersionInfo {
    #[repr(C)]
    #[allow(non_snake_case)]
    struct OSVERSIONINFOEXW {
        dwOSVersionInfoSize: u32,
        dwMajorVersion: u32,
        dwMinorVersion: u32,
        dwBuildNumber: u32,
        dwPlatformId: u32,
        szCSDVersion: [u16; 128],
        wServicePackMajor: u16,
        wServicePackMinor: u16,
        wSuiteMask: u16,
        wProductType: u8,
        wReserved: u8,
    }

    type RtlGetVersionFn = unsafe extern "system" fn(*mut OSVERSIONINFOEXW) -> i32;

    let mut info: OSVERSIONINFOEXW = unsafe { std::mem::zeroed() };
    info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOEXW>() as u32;

    let success = unsafe {
        // ntdll.dll is always mapped into every Windows process.
        const NTDLL_W: &[u16] = &[
            b'n' as u16, b't' as u16, b'd' as u16, b'l' as u16, b'l' as u16, b'.' as u16,
            b'd' as u16, b'l' as u16, b'l' as u16, 0,
        ];
        let handle = windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(NTDLL_W.as_ptr());
        if !handle.is_null() {
            if let Some(func) = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                handle,
                b"RtlGetVersion\0".as_ptr(),
            ) {
                let rtl_get_version: RtlGetVersionFn = std::mem::transmute(func);
                rtl_get_version(&mut info) == 0
            } else {
                false
            }
        } else {
            false
        }
    };

    if success {
        OsVersionInfo {
            major: info.dwMajorVersion,
            minor: info.dwMinorVersion,
            build: info.dwBuildNumber,
            platform_id: info.dwPlatformId,
            service_pack_major: info.wServicePackMajor,
            service_pack_minor: info.wServicePackMinor,
            suite_mask: info.wSuiteMask,
            product_type: info.wProductType,
        }
    } else {
        // Safe fallback values if RtlGetVersion could not be queried
        OsVersionInfo {
            major: 10,
            minor: 0,
            build: 19041,
            platform_id: 2,
            service_pack_major: 0,
            service_pack_minor: 0,
            suite_mask: 0,
            product_type: VER_NT_WORKSTATION,
        }
    }
}

/// Detects whether the running OS is Windows Server Core or Nano Server (cached process-wide).
/// Equivalent to version.OsIsCore() in wireguard-windows.
pub fn os_is_core() -> bool {
    static CACHED_CORE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CACHED_CORE.get_or_init(|| {
        let version = os_version();

        if version.major > 6 || (version.major == 6 && version.minor >= 2) {
            if let Some((nano_server, server_core, server_gui)) = query_server_levels_registry() {
                return (nano_server || server_core) && !server_gui;
            }
        }

        match version.product_type as u32 {
            PRODUCT_DATACENTER_SERVER_CORE
            | PRODUCT_STANDARD_SERVER_CORE
            | PRODUCT_ENTERPRISE_SERVER_CORE
            | PRODUCT_WEB_SERVER_CORE
            | PRODUCT_DATACENTER_SERVER_CORE_V
            | PRODUCT_STANDARD_SERVER_CORE_V
            | PRODUCT_ENTERPRISE_SERVER_CORE_V
            | PRODUCT_STORAGE_EXPRESS_SERVER_CORE
            | PRODUCT_STORAGE_STANDARD_SERVER_CORE
            | PRODUCT_STORAGE_WORKGROUP_SERVER_CORE
            | PRODUCT_STORAGE_ENTERPRISE_SERVER_CORE
            | PRODUCT_DATACENTER_A_SERVER_CORE
            | PRODUCT_STANDARD_A_SERVER_CORE
            | PRODUCT_DATACENTER_WS_SERVER_CORE
            | PRODUCT_STANDARD_WS_SERVER_CORE
            | PRODUCT_DATACENTER_EVALUATION_SERVER_CORE
            | PRODUCT_STANDARD_EVALUATION_SERVER_CORE
            | PRODUCT_AZURE_SERVER_CORE
            | PRODUCT_NANO_SERVER
            | PRODUCT_DATACENTER_NANO_SERVER
            | PRODUCT_STANDARD_NANO_SERVER
            | PRODUCT_AZURE_NANO_SERVER => true,
            _ => false,
        }
    })
}

/// Helper to read ServerLevels from Windows Registry without heap allocations.
fn query_server_levels_registry() -> Option<(bool, bool, bool)> {
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ,
    };

    const SUBKEY_W: &[u16] = &[
        b'S' as u16, b'o' as u16, b'f' as u16, b't' as u16, b'w' as u16, b'a' as u16,
        b'r' as u16, b'e' as u16, b'\\' as u16, b'M' as u16, b'i' as u16, b'c' as u16,
        b'r' as u16, b'o' as u16, b's' as u16, b'o' as u16, b'f' as u16, b't' as u16,
        b'\\' as u16, b'W' as u16, b'i' as u16, b'n' as u16, b'd' as u16, b'o' as u16,
        b'w' as u16, b's' as u16, b' ' as u16, b'N' as u16, b'T' as u16, b'\\' as u16,
        b'C' as u16, b'u' as u16, b'r' as u16, b'r' as u16, b'e' as u16, b'n' as u16,
        b't' as u16, b'V' as u16, b'e' as u16, b'r' as u16, b's' as u16, b'i' as u16,
        b'o' as u16, b'n' as u16, b'\\' as u16, b'S' as u16, b'e' as u16, b'r' as u16,
        b'v' as u16, b'e' as u16, b'r' as u16, b'\\' as u16, b'S' as u16, b'e' as u16,
        b'r' as u16, b'v' as u16, b'e' as u16, b'r' as u16, b'L' as u16, b'e' as u16,
        b'v' as u16, b'e' as u16, b'l' as u16, b's' as u16, 0,
    ];
    const VAL_NANO_W: &[u16] = &[
        b'N' as u16, b'a' as u16, b'n' as u16, b'o' as u16, b'S' as u16, b'e' as u16,
        b'r' as u16, b'v' as u16, b'e' as u16, b'r' as u16, 0,
    ];
    const VAL_CORE_W: &[u16] = &[
        b'S' as u16, b'e' as u16, b'r' as u16, b'v' as u16, b'e' as u16, b'r' as u16,
        b'C' as u16, b'o' as u16, b'r' as u16, b'e' as u16, 0,
    ];
    const VAL_GUI_W: &[u16] = &[
        b'S' as u16, b'e' as u16, b'r' as u16, b'v' as u16, b'e' as u16, b'r' as u16,
        b'-' as u16, b'G' as u16, b'u' as u16, b'i' as u16, b'-' as u16, b'S' as u16,
        b'h' as u16, b'e' as u16, b'l' as u16, b'l' as u16, 0,
    ];

    unsafe {
        let mut hkey = std::mem::zeroed();
        let status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            SUBKEY_W.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        );
        if status != 0 {
            return None;
        }

        let read_dword = |name_wide: &[u16]| -> Option<u32> {
            let mut val: u32 = 0;
            let mut val_type: u32 = 0;
            let mut val_len = std::mem::size_of::<u32>() as u32;
            let res = RegQueryValueExW(
                hkey,
                name_wide.as_ptr(),
                std::ptr::null(),
                &mut val_type,
                &mut val as *mut u32 as *mut u8,
                &mut val_len,
            );
            if res == 0 && val_type == 4 && val_len == std::mem::size_of::<u32>() as u32 {
                Some(val)
            } else {
                None
            }
        };

        let nano_server = read_dword(VAL_NANO_W).is_some_and(|v| v == 1);
        let server_core = read_dword(VAL_CORE_W).is_some_and(|v| v == 1);
        let server_gui = read_dword(VAL_GUI_W).is_some_and(|v| v == 1);

        RegCloseKey(hkey);
        Some((nano_server, server_core, server_gui))
    }
}

/// Appends the operating system name string directly into `out`.
pub(crate) fn write_os_name(out: &mut String) {
    use std::fmt::Write;
    let version = os_version();
    out.push_str("Windows");

    match version.product_type {
        VER_NT_SERVER => out.push_str(" Server"),
        VER_NT_DOMAIN_CONTROLLER => out.push_str(" Controller"),
        _ => {}
    }

    if os_is_core() {
        out.push_str(" Core");
    }

    let _ = write!(out, " {}.{}.{}", version.major, version.minor, version.build);
}

/// Generates the operating system name string.
/// Equivalent to version.OsName() in wireguard-windows.
/// Output format: "Windows[ Server| Controller][ Core] <Major>.<Minor>.<Build>"
pub fn os_name() -> String {
    let mut out = String::with_capacity(48);
    write_os_name(&mut out);
    out
}
