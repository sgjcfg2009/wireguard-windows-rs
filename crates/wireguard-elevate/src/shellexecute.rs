/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Rust implementation: 2026 WireGuard Rust Contributors.
 */

use crate::error::{with_opt_wide_null, with_wide_null, ElevateError, Result};
use crate::handle::AutoHandle;
use crate::membership::{is_token_elevated, token_is_elevated_or_elevatable};
use std::path::Path;
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::Security::{TOKEN_DUPLICATE, TOKEN_QUERY};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::{SW_HIDE, SW_SHOW, SW_SHOWNORMAL};

/// Re-export standard window display commands for ShellExecute.
pub const SHOW_NORMAL: i32 = SW_SHOWNORMAL;
pub const SHOW_DEFAULT: i32 = SW_SHOW;
pub const SHOW_HIDDEN: i32 = SW_HIDE;

fn shell_execute_verb(
    verb_wide: &[u16],
    program: &str,
    arguments: &str,
    directory: Option<&str>,
    show_cmd: i32,
) -> Result<()> {
    let args_opt = (!arguments.is_empty()).then_some(arguments);
    let ret = with_wide_null(program, |prog_ptr| {
        with_opt_wide_null(args_opt, |args_ptr| {
            with_opt_wide_null(directory, |dir_ptr| unsafe {
                ShellExecuteW(
                    0 as HWND,
                    verb_wide.as_ptr(),
                    prog_ptr,
                    args_ptr,
                    dir_ptr,
                    show_cmd,
                )
            })
        })
    });

    if (ret as usize) <= 32 {
        return Err(ElevateError::ShellExecuteFailed(ret as usize));
    }

    Ok(())
}

/// Spawns an executable with administrator privileges using the Windows Shell `runas` verb.
///
/// This triggers the Windows UAC consent or credential prompt if necessary.
pub fn shell_execute_runas(
    program: &str,
    arguments: &str,
    directory: Option<&str>,
    show_cmd: i32,
) -> Result<()> {
    const RUNAS_W: [u16; 6] = [b'r' as u16, b'u' as u16, b'n' as u16, b'a' as u16, b's' as u16, 0];
    shell_execute_verb(&RUNAS_W, program, arguments, directory, show_cmd)
}

/// Spawns an executable, elevating via UAC (`runas`) only if the current process is not already elevated.
///
/// If already running elevated, launches normally with verb `open`.
pub fn shell_execute(
    program: &str,
    arguments: &str,
    directory: Option<&str>,
    show_cmd: i32,
) -> Result<()> {
    const OPEN_W: [u16; 5] = [b'o' as u16, b'p' as u16, b'e' as u16, b'n' as u16, 0];

    let mut token_raw = core::ptr::null_mut();
    let ok = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut token_raw,
        )
    };
    if ok != 0 {
        let token = unsafe { AutoHandle::from_raw(token_raw) };
        if is_token_elevated(token.as_raw()).unwrap_or(false) {
            return shell_execute_verb(&OPEN_W, program, arguments, directory, show_cmd);
        }

        if !token_is_elevated_or_elevatable(token.as_raw()) {
            return Err(ElevateError::NotElevatedOrElevatable);
        }
    }

    let computed_dir = directory.or_else(|| Path::new(program).parent().and_then(|p| p.to_str()));

    shell_execute_runas(program, arguments, computed_dir, show_cmd)
}
