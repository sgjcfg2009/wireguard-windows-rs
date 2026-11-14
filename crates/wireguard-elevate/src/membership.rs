/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Rust implementation: 2026 WireGuard Rust Contributors.
 */

use crate::error::{from_wide_null_terminated, last_os_error, ElevateError, Result};
use crate::handle::AutoHandle;
use windows_sys::Win32::Foundation::{
    ERROR_INVALID_WINDOW_HANDLE, HANDLE, HWND,
};
use windows_sys::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, DuplicateTokenEx, GetSidSubAuthority,
    GetSidSubAuthorityCount, GetTokenInformation, LookupAccountSidW, SecurityIdentification,
    TokenElevation, TokenImpersonation, TokenIntegrityLevel, TokenLinkedToken,
    WELL_KNOWN_SID_TYPE, WinBuiltinAdministratorsSid, WinBuiltinNetworkConfigurationOperatorsSid,
    PSID, TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_IMPERSONATE, TOKEN_LINKED_TOKEN,
    TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{GetShellWindow, GetWindowThreadProcessId};

/// Maximum possible size for a binary SID according to Win32 specifications.
const SECURITY_MAX_SID_SIZE: usize = 68;

/// Queries whether the given token has elevated privileges (`TokenElevation`) AND at least High
/// Mandatory Integrity Level (`SECURITY_MANDATORY_HIGH_RID = 0x3000 = 12288`).
///
/// Checking `TokenIntegrityLevel >= 0x3000` is essential because when `EnableLUA = 0`,
/// a process spawned from a Low-Mandatory-Label directory receives `TokenElevation = 1`
/// but `TokenIntegrityLevel = 0x1000` (Low), which strips all privileges and causes
/// `OpenSCManagerW` (`SC_MANAGER_ALL_ACCESS`) to fail with `ERROR_ACCESS_DENIED (5)`.
pub fn is_token_elevated(token: HANDLE) -> Result<bool> {
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut ret_len = 0u32;
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            core::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        )
    };
    if ok == 0 {
        return Err(last_os_error());
    }
    if elevation.TokenIsElevated == 0 {
        return Ok(false);
    }

    // Verify Mandatory Integrity Level >= 0x3000 (High or System).
    // Use u64 backing for 8-byte alignment required by TOKEN_MANDATORY_LABEL (contains PSID).
    let mut il_buf = [0u64; 16];
    let mut il_len = 0u32;
    let il_ok = unsafe {
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            il_buf.as_mut_ptr() as *mut _,
            core::mem::size_of_val(&il_buf) as u32,
            &mut il_len,
        )
    };
    if il_ok != 0 {
        let tml = unsafe { &*(il_buf.as_ptr() as *const TOKEN_MANDATORY_LABEL) };
        let sid = tml.Label.Sid;
        if !sid.is_null() {
            let count_ptr = unsafe { GetSidSubAuthorityCount(sid) };
            if !count_ptr.is_null() {
                let count = unsafe { *count_ptr } as u32;
                if count > 0 {
                    let rid_ptr = unsafe { GetSidSubAuthority(sid, count - 1) };
                    if !rid_ptr.is_null() {
                        let rid = unsafe { *rid_ptr };
                        if rid < 0x3000 {
                            return Ok(false);
                        }
                    }
                }
            }
        }
    }

    Ok(true)
}

/// Checks whether the current process is running with elevated administrator privileges.
pub fn is_current_process_elevated() -> bool {
    let mut token_raw = core::ptr::null_mut();
    let ok = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            &mut token_raw,
        )
    };
    if ok == 0 {
        return false;
    }
    let token = unsafe { AutoHandle::from_raw(token_raw) };
    is_token_elevated(token.as_raw()).unwrap_or(false)
}

/// Retrieves the linked elevated token from a filtered (standard user) UAC token.
///
/// On Windows Vista and later with UAC enabled, administrator accounts run with a filtered
/// standard user token that has a linked administrator token.
pub fn get_linked_token(token: HANDLE) -> Result<AutoHandle> {
    let mut linked = TOKEN_LINKED_TOKEN {
        LinkedToken: core::ptr::null_mut(),
    };
    let mut ret_len = 0u32;
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenLinkedToken,
            &mut linked as *mut _ as *mut _,
            core::mem::size_of::<TOKEN_LINKED_TOKEN>() as u32,
            &mut ret_len,
        )
    };
    if ok == 0 {
        return Err(last_os_error());
    }
    AutoHandle::new(linked.LinkedToken).ok_or(ElevateError::InvalidHandle)
}

/// Checks whether `token` is a member of the specified well-known SID group.
///
/// Automatically duplicates `token` as an impersonation token at `SecurityIdentification` level
/// as required by `CheckTokenMembership`.
pub fn is_token_member_of_well_known_sid(
    token: HANDLE,
    sid_type: WELL_KNOWN_SID_TYPE,
) -> Result<bool> {
    let mut sid_buffer = [0u64; (SECURITY_MAX_SID_SIZE + 7) / 8];
    let mut sid_size = core::mem::size_of_val(&sid_buffer) as u32;

    let ok = unsafe {
        CreateWellKnownSid(
            sid_type,
            core::ptr::null_mut(),
            sid_buffer.as_mut_ptr() as PSID,
            &mut sid_size,
        )
    };
    if ok == 0 {
        return Err(last_os_error());
    }

    let mut checkable_raw = core::ptr::null_mut();
    let ok = unsafe {
        DuplicateTokenEx(
            token,
            TOKEN_QUERY | TOKEN_IMPERSONATE,
            core::ptr::null(),
            SecurityIdentification,
            TokenImpersonation,
            &mut checkable_raw,
        )
    };
    if ok == 0 {
        return Err(last_os_error());
    }
    let checkable_token = unsafe { AutoHandle::from_raw(checkable_raw) };

    let mut is_member = 0i32;
    let ok = unsafe {
        CheckTokenMembership(
            checkable_token.as_raw(),
            sid_buffer.as_mut_ptr() as PSID,
            &mut is_member,
        )
    };
    if ok == 0 {
        return Err(last_os_error());
    }

    Ok(is_member != 0)
}

/// Checks if `token` belongs to the built-in Administrators group (`WinBuiltinAdministratorsSid`).
pub fn is_token_admin(token: HANDLE) -> Result<bool> {
    is_token_member_of_well_known_sid(token, WinBuiltinAdministratorsSid)
}

/// Checks if `token` belongs to the built-in Network Configuration Operators group (`WinBuiltinNetworkConfigurationOperatorsSid`).
pub fn is_token_network_configuration_operator(token: HANDLE) -> Result<bool> {
    is_token_member_of_well_known_sid(token, WinBuiltinNetworkConfigurationOperatorsSid)
}

/// Checks if `token` belongs to either the Administrators group or the Network Configuration Operators group.
pub fn is_token_admin_or_netops(token: HANDLE) -> Result<bool> {
    if is_token_admin(token).unwrap_or(false) {
        return Ok(true);
    }
    is_token_network_configuration_operator(token)
}

/// Checks whether `token` is currently elevated, or is a split UAC token that can be elevated.
///
/// Returns true if the token is already elevated and in the Administrators group,
/// or if it has a linked token that is elevated and in the Administrators group.
pub fn token_is_elevated_or_elevatable(token: HANDLE) -> bool {
    if is_token_elevated(token).unwrap_or(false) && is_token_admin(token).unwrap_or(false) {
        return true;
    }

    if let Ok(linked) = get_linked_token(token) {
        if is_token_elevated(linked.as_raw()).unwrap_or(false)
            && is_token_admin(linked.as_raw()).unwrap_or(false)
        {
            return true;
        }
    }

    false
}

/// Determines whether the user running the current desktop shell (e.g. explorer.exe)
/// is an administrator or has an elevatable token.
pub fn is_admin_desktop() -> Result<bool> {
    let hwnd = unsafe { GetShellWindow() };
    if hwnd.is_null() || hwnd == 0 as HWND {
        return Err(ElevateError::Win32 {
            code: ERROR_INVALID_WINDOW_HANDLE,
            source: std::io::Error::from_raw_os_error(ERROR_INVALID_WINDOW_HANDLE as i32),
        });
    }

    let mut pid = 0u32;
    unsafe {
        GetWindowThreadProcessId(hwnd, &mut pid);
    }
    if pid == 0 {
        return Err(last_os_error());
    }

    let process_raw = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid) };
    let process = AutoHandle::new(process_raw).ok_or(ElevateError::InvalidHandle)?;

    let mut token_raw = core::ptr::null_mut();
    let ok = unsafe {
        OpenProcessToken(
            process.as_raw(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut token_raw,
        )
    };
    if ok == 0 {
        return Err(last_os_error());
    }
    let token = unsafe { AutoHandle::from_raw(token_raw) };

    Ok(token_is_elevated_or_elevatable(token.as_raw()))
}

fn well_known_sid_account_name(sid_type: WELL_KNOWN_SID_TYPE, fallback: &str) -> String {
    let mut sid_buffer = [0u64; (SECURITY_MAX_SID_SIZE + 7) / 8];
    let mut sid_size = core::mem::size_of_val(&sid_buffer) as u32;

    let ok = unsafe {
        CreateWellKnownSid(
            sid_type,
            core::ptr::null_mut(),
            sid_buffer.as_mut_ptr() as PSID,
            &mut sid_size,
        )
    };
    if ok == 0 {
        return fallback.to_string();
    }

    let mut name = [0u16; 256];
    let mut name_len = name.len() as u32;
    let mut domain = [0u16; 256];
    let mut domain_len = domain.len() as u32;
    let mut sid_use = 0u32;

    let ok = unsafe {
        LookupAccountSidW(
            core::ptr::null(),
            sid_buffer.as_mut_ptr() as PSID,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut sid_use as *mut _ as *mut _,
        )
    };
    if ok == 0 {
        return fallback.to_string();
    }

    let s = from_wide_null_terminated(&name);
    if s.is_empty() {
        fallback.to_string()
    } else {
        s
    }
}

/// Retrieves the localized display name of the built-in Administrators group.
///
/// Falls back to `"Administrators"` if lookup fails.
pub fn admin_group_name() -> String {
    well_known_sid_account_name(WinBuiltinAdministratorsSid, "Administrators")
}

/// Retrieves the localized display name of the Network Configuration Operators group.
///
/// Falls back to `"Network Configuration Operators"` if lookup fails.
pub fn network_configuration_operators_group_name() -> String {
    well_known_sid_account_name(
        WinBuiltinNetworkConfigurationOperatorsSid,
        "Network Configuration Operators",
    )
}
