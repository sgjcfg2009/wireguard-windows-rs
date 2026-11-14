/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Rust implementation: 2026 WireGuard Rust Contributors.
 */

use crate::error::{
    from_win32_code, last_os_error, with_opt_wide_null, with_opt_wide_null_mut, Result,
};
use crate::handle::AutoHandle;
use core::ffi::c_void;
use std::path::Path;
use windows_sys::Win32::Foundation::{BOOL, HANDLE, WAIT_FAILED, WAIT_OBJECT_0};
use windows_sys::Win32::Security::{
    DuplicateTokenEx, SecurityImpersonation, TokenPrimary,
    TOKEN_ALL_ACCESS,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, CreateProcessWithTokenW, GetExitCodeProcess, TerminateProcess, WaitForSingleObject,
    PROCESS_INFORMATION, STARTUPINFOW,
};

#[inline]
fn default_startup_info() -> STARTUPINFOW {
    let mut si: STARTUPINFOW = unsafe { core::mem::zeroed() };
    si.cb = core::mem::size_of::<STARTUPINFOW>() as u32;
    si
}

fn format_command_line(executable: &Path, args: &[&str]) -> String {
    let args_cap: usize = args.iter().map(|a| a.len() + 3).sum();
    let mut cmd = String::with_capacity(64 + args_cap);
    cmd.push('"');
    if let Some(exe_str) = executable.to_str() {
        cmd.push_str(exe_str);
    } else {
        use std::fmt::Write;
        let _ = write!(&mut cmd, "{}", executable.display());
    }
    cmd.push('"');
    for &arg in args {
        cmd.push(' ');
        if arg.contains(' ') {
            cmd.push('"');
            cmd.push_str(arg);
            cmd.push('"');
        } else {
            cmd.push_str(arg);
        }
    }
    cmd
}

/// Log on, then load the user's profile in the HKEY_USERS registry key.
pub const LOGON_WITH_PROFILE: u32 = 0x00000001;

/// Log on for network credentials only.
pub const LOGON_NETCREDENTIALS_ONLY: u32 = 0x00000002;

/// Process creation flag: Use Unicode characters for environment block.
pub const CREATE_UNICODE_ENVIRONMENT: u32 = 0x00000400;

/// Process creation flag: Run process without creating a console window.
pub const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Process creation flag: Run process with a new console window.
pub const CREATE_NEW_CONSOLE: u32 = 0x00000010;

/// Infinite wait timeout for synchronization functions.
pub const INFINITE: u32 = 0xFFFFFFFF;

/// Information about a newly spawned process with owned RAII handles.
#[derive(Debug)]
pub struct SpawnedProcess {
    /// RAII handle to the spawned process.
    pub process: AutoHandle,
    /// RAII handle to the primary thread of the spawned process.
    pub thread: AutoHandle,
    /// System process identifier.
    pub process_id: u32,
    /// System thread identifier of the primary thread.
    pub thread_id: u32,
}

impl SpawnedProcess {
    /// Waits for the process to exit, with an optional timeout in milliseconds.
    ///
    /// If `timeout_ms` is `None`, waits indefinitely.
    /// Returns the process exit code on success.
    pub fn wait(&self, timeout_ms: Option<u32>) -> Result<u32> {
        let timeout = timeout_ms.unwrap_or(INFINITE);
        let wait_res = unsafe { WaitForSingleObject(self.process.as_raw(), timeout) };
        if wait_res == WAIT_FAILED {
            return Err(last_os_error());
        }
        if wait_res != WAIT_OBJECT_0 {
            return Err(from_win32_code(wait_res));
        }

        let mut exit_code: u32 = 0;
        let ok = unsafe { GetExitCodeProcess(self.process.as_raw(), &mut exit_code) };
        if ok == 0 {
            return Err(last_os_error());
        }
        Ok(exit_code)
    }

    /// Queries the current exit code of the process without blocking.
    ///
    /// Returns `259` (`STILL_ACTIVE`) if the process is currently running.
    pub fn exit_code(&self) -> Result<u32> {
        let mut exit_code: u32 = 0;
        let ok = unsafe { GetExitCodeProcess(self.process.as_raw(), &mut exit_code) };
        if ok == 0 {
            return Err(last_os_error());
        }
        Ok(exit_code)
    }

    /// Terminates the process with the given exit code.
    pub fn terminate(&self, exit_code: u32) -> Result<()> {
        let ok = unsafe { TerminateProcess(self.process.as_raw(), exit_code) };
        if ok == 0 {
            return Err(last_os_error());
        }
        Ok(())
    }
}

/// Spawns a new process running under the security context of the specified user token
/// using the Win32 `CreateProcessWithTokenW` API.
///
/// Requires `SeImpersonatePrivilege` in the caller's process token.
pub fn create_process_with_token(
    token: HANDLE,
    logon_flags: u32,
    application_name: Option<&str>,
    command_line: Option<&str>,
    creation_flags: u32,
    environment: Option<*const c_void>,
    current_directory: Option<&str>,
    startup_info: Option<&STARTUPINFOW>,
) -> Result<SpawnedProcess> {
    let default_si = default_startup_info();
    let si_ptr = startup_info.unwrap_or(&default_si);

    let mut pi = PROCESS_INFORMATION {
        hProcess: core::ptr::null_mut(),
        hThread: core::ptr::null_mut(),
        dwProcessId: 0,
        dwThreadId: 0,
    };

    let ok = with_opt_wide_null(application_name, |app_ptr| {
        with_opt_wide_null_mut(command_line, |cmd_ptr| {
            with_opt_wide_null(current_directory, |dir_ptr| unsafe {
                CreateProcessWithTokenW(
                    token,
                    logon_flags,
                    app_ptr,
                    cmd_ptr,
                    creation_flags,
                    environment.unwrap_or(core::ptr::null()),
                    dir_ptr,
                    si_ptr,
                    &mut pi,
                )
            })
        })
    });

    if ok == 0 {
        return Err(last_os_error());
    }

    Ok(SpawnedProcess {
        process: unsafe { AutoHandle::from_raw(pi.hProcess) },
        thread: unsafe { AutoHandle::from_raw(pi.hThread) },
        process_id: pi.dwProcessId,
        thread_id: pi.dwThreadId,
    })
}

/// Spawns a new process and its primary thread running in the security context
/// of the specified primary token using `CreateProcessAsUserW`.
///
/// If `token` is an impersonation token, this function will automatically duplicate
/// it into a `TokenPrimary` token.
///
/// Requires `SeAssignPrimaryTokenPrivilege` and `SeIncreaseQuotaPrivilege` in the caller.
pub fn create_process_as_user(
    token: HANDLE,
    application_name: Option<&str>,
    command_line: Option<&str>,
    inherit_handles: bool,
    creation_flags: u32,
    environment: Option<*const c_void>,
    current_directory: Option<&str>,
    startup_info: Option<&STARTUPINFOW>,
) -> Result<SpawnedProcess> {
    // Ensure we hold a primary token
    let mut primary_token_raw = core::ptr::null_mut();
    let dup_ok = unsafe {
        DuplicateTokenEx(
            token,
            TOKEN_ALL_ACCESS,
            core::ptr::null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut primary_token_raw,
        )
    };

    let _primary_guard = if dup_ok != 0 {
        AutoHandle::new(primary_token_raw)
    } else {
        None
    };
    let htoken = _primary_guard.as_ref().map_or(token, |g| g.as_raw());

    let default_si = default_startup_info();
    let si_ptr = startup_info.unwrap_or(&default_si);

    let mut pi = PROCESS_INFORMATION {
        hProcess: core::ptr::null_mut(),
        hThread: core::ptr::null_mut(),
        dwProcessId: 0,
        dwThreadId: 0,
    };

    let ok = with_opt_wide_null(application_name, |app_ptr| {
        with_opt_wide_null_mut(command_line, |cmd_ptr| {
            with_opt_wide_null(current_directory, |dir_ptr| unsafe {
                CreateProcessAsUserW(
                    htoken,
                    app_ptr,
                    cmd_ptr,
                    core::ptr::null(),
                    core::ptr::null(),
                    if inherit_handles { 1 } else { 0 } as BOOL,
                    creation_flags,
                    environment.unwrap_or(core::ptr::null()),
                    dir_ptr,
                    si_ptr,
                    &mut pi,
                )
            })
        })
    });

    if ok == 0 {
        return Err(last_os_error());
    }

    Ok(SpawnedProcess {
        process: unsafe { AutoHandle::from_raw(pi.hProcess) },
        thread: unsafe { AutoHandle::from_raw(pi.hThread) },
        process_id: pi.dwProcessId,
        thread_id: pi.dwThreadId,
    })
}

/// Convenience function to spawn a command line with the specified token via `CreateProcessWithTokenW`.
pub fn spawn_command_with_token(token: HANDLE, command_line: &str) -> Result<SpawnedProcess> {
    create_process_with_token(
        token,
        LOGON_WITH_PROFILE,
        None,
        Some(command_line),
        0,
        None,
        None,
        None,
    )
}

/// Convenience function to spawn an executable path with arguments using `CreateProcessWithTokenW`.
pub fn spawn_with_token(
    token: HANDLE,
    executable: &Path,
    args: &[&str],
) -> Result<SpawnedProcess> {
    let cmd = format_command_line(executable, args);
    spawn_command_with_token(token, &cmd)
}

/// Convenience function to spawn a command line with the specified token via `CreateProcessAsUserW`.
pub fn spawn_command_as_user(token: HANDLE, command_line: &str) -> Result<SpawnedProcess> {
    create_process_as_user(
        token,
        None,
        Some(command_line),
        false,
        0,
        None,
        None,
        None,
    )
}

/// Convenience function to spawn an executable path with arguments using `CreateProcessAsUserW`.
pub fn spawn_as_user(
    token: HANDLE,
    executable: &Path,
    args: &[&str],
) -> Result<SpawnedProcess> {
    let cmd = format_command_line(executable, args);
    spawn_command_as_user(token, &cmd)
}
