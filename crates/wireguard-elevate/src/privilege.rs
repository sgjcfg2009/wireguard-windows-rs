/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Rust implementation: 2026 WireGuard Rust Contributors.
 */

use crate::error::{last_os_error, with_wide_null, with_wide_null_cap, ElevateError, Result};
use crate::handle::AutoHandle;
use windows_sys::Win32::Foundation::{
    GetLastError, SetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_NOT_ALL_ASSIGNED,
    ERROR_SUCCESS, HANDLE, LUID,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueW,
    TokenPrivileges, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    SE_PRIVILEGE_REMOVED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_READ,
    TOKEN_WRITE,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

/// Enables a named privilege on the specified token.
///
/// Returns an error if the privilege name is invalid or if the token does not possess
/// the privilege (`ERROR_NOT_ALL_ASSIGNED`).
pub fn enable_privilege(token: HANDLE, privilege_name: &str) -> Result<()> {
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };

    let ok = with_wide_null_cap::<64, _>(privilege_name, |wide_ptr| unsafe {
        LookupPrivilegeValueW(core::ptr::null(), wide_ptr, &mut luid)
    });
    if ok == 0 {
        return Err(ElevateError::PrivilegeNotFound(privilege_name.to_string()));
    }

    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    unsafe {
        SetLastError(ERROR_SUCCESS);
        let ok = AdjustTokenPrivileges(
            token,
            0,
            &tp,
            core::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        if ok == 0 {
            return Err(last_os_error());
        }
        let err = GetLastError();
        if err == ERROR_NOT_ALL_ASSIGNED {
            return Err(ElevateError::PrivilegesNotAssigned);
        }
    }

    Ok(())
}

/// Enables a named privilege on the current process token.
pub fn enable_current_process_privilege(privilege_name: &str) -> Result<()> {
    let mut token_raw = core::ptr::null_mut();
    let ok = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
            &mut token_raw,
        )
    };
    if ok == 0 {
        return Err(last_os_error());
    }
    let token = unsafe { AutoHandle::from_raw(token_raw) };
    enable_privilege(token.as_raw(), privilege_name)
}

/// Enables a named privilege on the current thread token.
pub fn enable_current_thread_privilege(privilege_name: &str) -> Result<()> {
    let mut token_raw = core::ptr::null_mut();
    let ok = unsafe {
        OpenThreadToken(
            GetCurrentThread(),
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
            0,
            &mut token_raw,
        )
    };
    if ok == 0 {
        return Err(last_os_error());
    }
    let token = unsafe { AutoHandle::from_raw(token_raw) };
    enable_privilege(token.as_raw(), privilege_name)
}

/// Permanently removes all privileges from `token` except those specified in `keep_privileges`.
///
/// Any privilege not listed in `keep_privileges` is marked with `SE_PRIVILEGE_REMOVED`,
/// stripping it from the token permanently.
pub fn remove_privileges_except(token: HANDLE, keep_privileges: &[&str]) -> Result<()> {
    let mut stack_luids = [LUID {
        LowPart: 0,
        HighPart: 0,
    }; 8];
    let mut stack_len = 0usize;
    let mut heap_luids: Vec<LUID> = Vec::new();
    for &name in keep_privileges {
        let mut luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };
        let ok = with_wide_null(name, |wide_ptr| unsafe {
            LookupPrivilegeValueW(core::ptr::null(), wide_ptr, &mut luid)
        });
        if ok != 0 {
            if heap_luids.is_empty() && stack_len < stack_luids.len() {
                stack_luids[stack_len] = luid;
                stack_len += 1;
            } else {
                if heap_luids.is_empty() {
                    heap_luids.reserve(keep_privileges.len());
                    heap_luids.extend_from_slice(&stack_luids[..stack_len]);
                }
                heap_luids.push(luid);
            }
        }
    }
    let keep_luids = if !heap_luids.is_empty() {
        heap_luids.as_slice()
    } else {
        &stack_luids[..stack_len]
    };

    // Query token privileges into an 8-byte aligned stack buffer first (1 syscall in the common case).
    let mut stack_buf = [0u64; 64]; // 512 bytes, aligned for TOKEN_PRIVILEGES (align 4)
    let mut heap_buf: Vec<u64> = Vec::new();
    let mut written: u32 = 0;

    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenPrivileges,
            stack_buf.as_mut_ptr() as *mut _,
            core::mem::size_of_val(&stack_buf) as u32,
            &mut written,
        )
    };

    let tp = if ok != 0 {
        stack_buf.as_mut_ptr() as *mut TOKEN_PRIVILEGES
    } else {
        let err = unsafe { GetLastError() };
        if err != ERROR_INSUFFICIENT_BUFFER || written < core::mem::size_of::<u32>() as u32 {
            return Err(ElevateError::TokenInformationQueryFailed(
                TokenPrivileges as u32,
                format!("Win32 error {err}"),
            ));
        }
        let words = (written as usize + 7) / 8;
        heap_buf.resize(words, 0);
        let needed = written;
        written = 0;
        let ok2 = unsafe {
            GetTokenInformation(
                token,
                TokenPrivileges,
                heap_buf.as_mut_ptr() as *mut _,
                needed,
                &mut written,
            )
        };
        if ok2 == 0 {
            return Err(last_os_error());
        }
        heap_buf.as_mut_ptr() as *mut TOKEN_PRIVILEGES
    };

    if written < core::mem::size_of::<u32>() as u32 {
        return Err(ElevateError::TokenInformationQueryFailed(
            TokenPrivileges as u32,
            "incomplete buffer returned".into(),
        ));
    }

    let count = unsafe { (*tp).PrivilegeCount as usize };
    let required_bytes = core::mem::size_of::<u32>()
        .checked_add(count.saturating_mul(core::mem::size_of::<LUID_AND_ATTRIBUTES>()))
        .unwrap_or(usize::MAX);
    if (written as usize) < required_bytes {
        return Err(ElevateError::TokenInformationQueryFailed(
            TokenPrivileges as u32,
            "incomplete buffer returned".into(),
        ));
    }

    if count > 0 {
        let priv_slice = unsafe {
            core::slice::from_raw_parts_mut(
                &mut (*tp).Privileges[0] as *mut LUID_AND_ATTRIBUTES,
                count,
            )
        };

        for item in priv_slice {
            let keep = keep_luids.iter().any(|k| {
                k.LowPart == item.Luid.LowPart && k.HighPart == item.Luid.HighPart
            });
            if !keep {
                item.Attributes = SE_PRIVILEGE_REMOVED;
            }
        }
    }

    let ok = unsafe {
        AdjustTokenPrivileges(
            token,
            0,
            tp,
            0,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(last_os_error());
    }

    Ok(())
}

/// Permanently removes all privileges from the current process token except those in `keep_privileges`.
pub fn remove_process_privileges_except(keep_privileges: &[&str]) -> Result<()> {
    let mut token_raw = core::ptr::null_mut();
    let ok = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_READ | TOKEN_WRITE,
            &mut token_raw,
        )
    };
    if ok == 0 {
        return Err(last_os_error());
    }
    let token = unsafe { AutoHandle::from_raw(token_raw) };
    remove_privileges_except(token.as_raw(), keep_privileges)
}

/// Drops all privileges from the current process token.
///
/// If `retain_driver_loading` is true, the `SeLoadDriverPrivilege` is retained,
/// matching WireGuard's service privilege requirements.
pub fn drop_all_privileges(retain_driver_loading: bool) -> Result<()> {
    let keep: &[&str] = if retain_driver_loading {
        &["SeLoadDriverPrivilege"]
    } else {
        &[]
    };
    remove_process_privileges_except(keep)
}
