/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Rust implementation: 2026 WireGuard Rust Contributors.
 */

use crate::error::{last_os_error, with_wide_null, ElevateError, Result};
use crate::handle::{AutoHandle, AutoServiceHandle, ImpersonationGuard};
use crate::privilege::enable_privilege;
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::{
    DuplicateTokenEx, GetTokenInformation, ImpersonateSelf, IsWellKnownSid,
    SecurityImpersonation, TokenImpersonation, TokenUser,
    WinLocalSystemSid, TOKEN_ADJUST_PRIVILEGES, TOKEN_DUPLICATE, TOKEN_IMPERSONATE,
    TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Services::{
    OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
    SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken, SetThreadToken,
    PROCESS_QUERY_INFORMATION,
};

const WINLOGON_EXE_LOWER_W: [u16; 12] = [
    b'w' as u16,
    b'i' as u16,
    b'n' as u16,
    b'l' as u16,
    b'o' as u16,
    b'g' as u16,
    b'o' as u16,
    b'n' as u16,
    b'.' as u16,
    b'e' as u16,
    b'x' as u16,
    b'e' as u16,
];

#[inline]
fn eq_wide_ascii_ignore_case(wide: &[u16], ascii_lower_target: &[u16]) -> bool {
    let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    if len != ascii_lower_target.len() {
        return false;
    }
    wide[..len]
        .iter()
        .zip(ascii_lower_target.iter())
        .all(|(&a, &b)| {
            let lower = if (b'A' as u16..=b'Z' as u16).contains(&a) {
                a + 32
            } else {
                a
            };
            lower == b
        })
}

/// Checks if a token belongs to the `NT AUTHORITY\SYSTEM` (LocalSystem) account
/// without heap allocation in the common case (`TOKEN_USER` + SID fits in 128 bytes).
fn is_token_local_system(token: HANDLE) -> bool {
    let mut stack_buf = [0u64; 16]; // 128 bytes, 8-byte aligned for TOKEN_USER
    let mut heap_buf: Vec<u64>;
    let mut written: u32 = 0;
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            stack_buf.as_mut_ptr() as *mut _,
            core::mem::size_of_val(&stack_buf) as u32,
            &mut written,
        )
    };
    let buf_ptr = if ok != 0 {
        stack_buf.as_ptr()
    } else {
        if written as usize <= core::mem::size_of_val(&stack_buf) {
            return false;
        }
        let words = (written as usize + 7) / 8;
        heap_buf = vec![0u64; words];
        let mut written2: u32 = 0;
        let ok2 = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                heap_buf.as_mut_ptr() as *mut _,
                written,
                &mut written2,
            )
        };
        if ok2 == 0 {
            return false;
        }
        heap_buf.as_ptr()
    };
    let sid = unsafe { (*(buf_ptr as *const TOKEN_USER)).User.Sid };
    !sid.is_null() && unsafe { IsWellKnownSid(sid, WinLocalSystemSid) } != 0
}

#[inline]
fn duplicate_impersonation_token(src: HANDLE) -> Option<AutoHandle> {
    let mut dup_raw = core::ptr::null_mut();
    let dup_ok = unsafe {
        DuplicateTokenEx(
            src,
            0,
            core::ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &mut dup_raw,
        )
    };
    if dup_ok == 0 {
        return None;
    }
    AutoHandle::new(dup_raw)
}

/// Cached duplicated LocalSystem impersonation token (from `winlogon.exe`) so repeated
/// calls to `do_as_system` avoid expensive process snapshotting.
static CACHED_SYSTEM_TOKEN: OnceLock<usize> = OnceLock::new();

fn acquire_system_impersonation_token() -> Result<AutoHandle> {
    if let Some(&cached_raw) = CACHED_SYSTEM_TOKEN.get() {
        if let Some(dup) = duplicate_impersonation_token(cached_raw as HANDLE) {
            return Ok(dup);
        }
    }

    // Snapshot processes to find winlogon.exe
    let snapshot_raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    let snapshot = AutoHandle::new(snapshot_raw).ok_or(ElevateError::InvalidHandle)?;

    let mut entry: PROCESSENTRY32W = unsafe { core::mem::zeroed() };
    entry.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;

    let mut found_system_token = None;
    let mut last_error = None;

    let mut ok = unsafe { Process32FirstW(snapshot.as_raw(), &mut entry) };
    while ok != 0 {
        if eq_wide_ascii_ignore_case(&entry.szExeFile, &WINLOGON_EXE_LOWER_W) {
            let proc_raw = unsafe {
                OpenProcess(PROCESS_QUERY_INFORMATION, 0, entry.th32ProcessID)
            };
            if let Some(proc) = AutoHandle::new(proc_raw) {
                let mut token_raw = core::ptr::null_mut();
                let tok_ok = unsafe {
                    OpenProcessToken(
                        proc.as_raw(),
                        TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE,
                        &mut token_raw,
                    )
                };
                if tok_ok != 0 {
                    let winlogon_token = unsafe { AutoHandle::from_raw(token_raw) };
                    if is_token_local_system(winlogon_token.as_raw()) {
                        if let Some(dup) = duplicate_impersonation_token(winlogon_token.as_raw()) {
                            // Also cache a long-lived copy for subsequent calls; if another thread
                            // wins the race, drop the redundant AutoHandle so the handle is closed.
                            if CACHED_SYSTEM_TOKEN.get().is_none() {
                                if let Some(cache_handle) =
                                    duplicate_impersonation_token(winlogon_token.as_raw())
                                {
                                    let raw = cache_handle.as_raw() as usize;
                                    if CACHED_SYSTEM_TOKEN.set(raw).is_ok() {
                                        cache_handle.into_raw();
                                    }
                                }
                            }
                            found_system_token = Some(dup);
                            break;
                        }
                    }
                }
            } else {
                last_error = Some(last_os_error());
            }
        }
        ok = unsafe { Process32NextW(snapshot.as_raw(), &mut entry) };
    }
    drop(snapshot);

    match found_system_token {
        Some(t) => Ok(t),
        None => {
            if let Some(err) = last_error {
                Err(err)
            } else {
                Err(ElevateError::ProcessNotFound("winlogon.exe".into()))
            }
        }
    }
}

/// Executes a closure `f` while impersonating the `NT AUTHORITY\SYSTEM` (LocalSystem) security context.
///
/// Under the hood, this function:
/// 1. Self-impersonates and enables `SeDebugPrivilege` on the calling thread.
/// 2. If already running as LocalSystem, immediately invokes `f()`.
/// 3. Acquires a cached or freshly duplicated `winlogon.exe` LocalSystem impersonation token.
/// 4. Assigns the token to the calling thread with `SetThreadToken`.
/// 5. Executes `f()`.
/// 6. Automatically reverts thread impersonation upon exit, even if `f` panics or returns early.
pub fn do_as_system<F, R>(f: F) -> Result<R>
where
    F: FnOnce() -> Result<R>,
{
    // Self-impersonate so we have a thread token to modify
    let ok = unsafe { ImpersonateSelf(SecurityImpersonation) };
    if ok == 0 {
        return Err(last_os_error());
    }
    let mut guard = ImpersonationGuard::new();

    let mut thread_token_raw = core::ptr::null_mut();
    let ok = unsafe {
        OpenThreadToken(
            GetCurrentThread(),
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
            0,
            &mut thread_token_raw,
        )
    };
    if ok == 0 {
        return Err(last_os_error());
    }
    let thread_token = unsafe { AutoHandle::from_raw(thread_token_raw) };

    // If the thread is already LocalSystem, run f directly
    if is_token_local_system(thread_token.as_raw()) {
        return f();
    }

    // Enable SeDebugPrivilege to allow opening winlogon.exe if not yet cached
    if CACHED_SYSTEM_TOKEN.get().is_none() {
        enable_privilege(thread_token.as_raw(), "SeDebugPrivilege")?;
    }
    drop(thread_token);

    let system_token = acquire_system_impersonation_token()?;

    // Impersonate LocalSystem on current thread
    let ok = unsafe { SetThreadToken(core::ptr::null(), system_token.as_raw()) };
    if ok == 0 {
        return Err(last_os_error());
    }

    let result = f();
    guard.revert()?;
    result
}

/// Executes a closure `f` while impersonating the security token of a running Windows service.
///
/// Uses `do_as_system` to gain privileges to open the service process, duplicates its token,
/// sets it on the current thread, and runs `f()`.
pub fn do_as_service<F, R>(service_name: &str, f: F) -> Result<R>
where
    F: FnOnce() -> Result<R>,
{
    // Connect to SCM and query the target service status to get its process ID
    let scm_raw = unsafe {
        OpenSCManagerW(
            core::ptr::null(),
            core::ptr::null(),
            SC_MANAGER_CONNECT,
        )
    };
    let scm = AutoServiceHandle::new(scm_raw).ok_or(ElevateError::InvalidHandle)?;

    let service_raw = with_wide_null(service_name, |wide_service| unsafe {
        OpenServiceW(scm.as_raw(), wide_service, SERVICE_QUERY_STATUS)
    });
    let service = AutoServiceHandle::new(service_raw).ok_or(ElevateError::InvalidHandle)?;
    drop(scm);

    let mut status: SERVICE_STATUS_PROCESS = unsafe { core::mem::zeroed() };
    let mut needed: u32 = 0;
    let ok = unsafe {
        QueryServiceStatusEx(
            service.as_raw(),
            SC_STATUS_PROCESS_INFO,
            &mut status as *mut _ as *mut u8,
            core::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        )
    };
    drop(service);

    if ok == 0 {
        return Err(last_os_error());
    }

    if status.dwProcessId == 0 {
        return Err(ElevateError::ServiceNotRunning(service_name.to_string()));
    }

    let pid = status.dwProcessId;

    // Run as LocalSystem to duplicate the service process token
    do_as_system(move || {
        let proc_raw = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid) };
        let proc = AutoHandle::new(proc_raw).ok_or(ElevateError::InvalidHandle)?;

        let mut token_raw = core::ptr::null_mut();
        let tok_ok = unsafe {
            OpenProcessToken(
                proc.as_raw(),
                TOKEN_IMPERSONATE | TOKEN_DUPLICATE,
                &mut token_raw,
            )
        };
        drop(proc);
        if tok_ok == 0 {
            return Err(last_os_error());
        }
        let service_token = unsafe { AutoHandle::from_raw(token_raw) };

        let Some(dup_token) = duplicate_impersonation_token(service_token.as_raw()) else {
            return Err(last_os_error());
        };
        drop(service_token);

        let mut inner_guard = ImpersonationGuard::new();
        let ok = unsafe { SetThreadToken(core::ptr::null(), dup_token.as_raw()) };
        if ok == 0 {
            return Err(last_os_error());
        }

        let res = f();
        inner_guard.revert()?;
        res
    })
}
