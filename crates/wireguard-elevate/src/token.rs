/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Rust implementation: 2026 WireGuard Rust Contributors.
 */

use crate::error::{last_os_error, Result};
use crate::handle::AutoHandle;
use crate::membership::{
    get_linked_token, is_token_admin, is_token_admin_or_netops, is_token_elevated,
    is_token_member_of_well_known_sid, is_token_network_configuration_operator,
    token_is_elevated_or_elevatable,
};
use crate::privilege::{enable_privilege, remove_privileges_except};
use crate::spawn::{create_process_as_user, create_process_with_token, LOGON_WITH_PROFILE, SpawnedProcess};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::{
    DuplicateTokenEx,
    SecurityImpersonation, TokenImpersonation, TokenPrimary, WELL_KNOWN_SID_TYPE,
    SECURITY_IMPERSONATION_LEVEL, TOKEN_ALL_ACCESS, TOKEN_TYPE,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

/// High-level, safe wrapper around a Win32 access token (`HANDLE`).
#[derive(Debug)]
pub struct Token {
    handle: AutoHandle,
}

impl Token {
    /// Creates a `Token` from a raw Win32 `HANDLE` if valid.
    pub fn new(handle: HANDLE) -> Option<Self> {
        AutoHandle::new(handle).map(|h| Self { handle: h })
    }

    /// Creates a `Token` from an existing `AutoHandle`.
    pub fn from_auto_handle(handle: AutoHandle) -> Self {
        Self { handle }
    }

    /// Creates a `Token` from a raw Win32 `HANDLE` without checks.
    ///
    /// # Safety
    /// Caller must ensure `handle` is a valid open token handle.
    pub unsafe fn from_raw(handle: HANDLE) -> Self {
        Self {
            handle: AutoHandle::from_raw(handle),
        }
    }

    /// Returns the underlying raw Win32 `HANDLE`.
    pub fn as_raw(&self) -> HANDLE {
        self.handle.as_raw()
    }

    /// Borrow the underlying `AutoHandle`.
    pub fn handle(&self) -> &AutoHandle {
        &self.handle
    }

    /// Consumes this `Token` and returns the inner `AutoHandle`.
    pub fn into_handle(self) -> AutoHandle {
        self.handle
    }

    /// Opens the access token associated with a given process.
    pub fn open_process(process: HANDLE, desired_access: u32) -> Result<Self> {
        let mut h = core::ptr::null_mut();
        let ok = unsafe { OpenProcessToken(process, desired_access, &mut h) };
        if ok == 0 {
            return Err(last_os_error());
        }
        Ok(unsafe { Self::from_raw(h) })
    }

    /// Opens the access token for the current process.
    pub fn open_current_process(desired_access: u32) -> Result<Self> {
        Self::open_process(unsafe { GetCurrentProcess() }, desired_access)
    }

    /// Opens the access token associated with a thread (impersonation token).
    pub fn open_thread(thread: HANDLE, desired_access: u32, open_as_self: bool) -> Result<Self> {
        let mut h = core::ptr::null_mut();
        let ok = unsafe {
            OpenThreadToken(
                thread,
                desired_access,
                if open_as_self { 1 } else { 0 },
                &mut h,
            )
        };
        if ok == 0 {
            return Err(last_os_error());
        }
        Ok(unsafe { Self::from_raw(h) })
    }

    /// Opens the access token for the calling thread.
    pub fn open_current_thread(desired_access: u32, open_as_self: bool) -> Result<Self> {
        Self::open_thread(unsafe { GetCurrentThread() }, desired_access, open_as_self)
    }

    /// Duplicates this token with specified access, impersonation level, and type.
    pub fn duplicate(
        &self,
        desired_access: u32,
        impersonation_level: SECURITY_IMPERSONATION_LEVEL,
        token_type: TOKEN_TYPE,
    ) -> Result<Self> {
        let mut dup_raw = core::ptr::null_mut();
        let ok = unsafe {
            DuplicateTokenEx(
                self.as_raw(),
                desired_access,
                core::ptr::null(),
                impersonation_level,
                token_type,
                &mut dup_raw,
            )
        };
        if ok == 0 {
            return Err(last_os_error());
        }
        Ok(unsafe { Self::from_raw(dup_raw) })
    }

    /// Duplicates this token into an impersonation token at `SecurityImpersonation` level.
    pub fn duplicate_impersonation(&self) -> Result<Self> {
        self.duplicate(
            TOKEN_ALL_ACCESS,
            SecurityImpersonation,
            TokenImpersonation,
        )
    }

    /// Duplicates this token into a primary token (`TokenPrimary`).
    pub fn duplicate_primary(&self) -> Result<Self> {
        self.duplicate(
            TOKEN_ALL_ACCESS,
            SecurityImpersonation,
            TokenPrimary,
        )
    }

    /// Queries whether this token is elevated (`TokenElevation`).
    pub fn is_elevated(&self) -> Result<bool> {
        is_token_elevated(self.as_raw())
    }

    /// Retrieves the linked elevated token (`TokenLinkedToken`).
    pub fn get_linked_token(&self) -> Result<Self> {
        let h = get_linked_token(self.as_raw())?;
        Ok(Self::from_auto_handle(h))
    }

    /// Checks if this token is elevated or elevatable via UAC.
    pub fn is_elevated_or_elevatable(&self) -> bool {
        token_is_elevated_or_elevatable(self.as_raw())
    }

    /// Checks if this token belongs to the built-in Administrators group.
    pub fn is_admin(&self) -> Result<bool> {
        is_token_admin(self.as_raw())
    }

    /// Checks if this token belongs to the built-in Network Configuration Operators group.
    pub fn is_network_configuration_operator(&self) -> Result<bool> {
        is_token_network_configuration_operator(self.as_raw())
    }

    /// Checks if this token is either an Administrator or Network Configuration Operator.
    pub fn is_admin_or_netops(&self) -> Result<bool> {
        is_token_admin_or_netops(self.as_raw())
    }

    /// Checks membership in any well-known SID group.
    pub fn is_member_of_sid(&self, sid_type: WELL_KNOWN_SID_TYPE) -> Result<bool> {
        is_token_member_of_well_known_sid(self.as_raw(), sid_type)
    }

    /// Enables a named privilege on this token.
    pub fn enable_privilege(&self, privilege_name: &str) -> Result<()> {
        enable_privilege(self.as_raw(), privilege_name)
    }

    /// Permanently removes all privileges from this token except those in `keep_privileges`.
    pub fn remove_privileges_except(&self, keep_privileges: &[&str]) -> Result<()> {
        remove_privileges_except(self.as_raw(), keep_privileges)
    }

    /// Drops all privileges from this token, optionally retaining `SeLoadDriverPrivilege`.
    pub fn drop_all_privileges(&self, retain_driver_loading: bool) -> Result<()> {
        let keep: &[&str] = if retain_driver_loading {
            &["SeLoadDriverPrivilege"]
        } else {
            &[]
        };
        self.remove_privileges_except(keep)
    }

    /// Spawns a process with this token using `CreateProcessWithTokenW`.
    pub fn spawn_process_with_token(&self, command_line: &str) -> Result<SpawnedProcess> {
        create_process_with_token(
            self.as_raw(),
            LOGON_WITH_PROFILE,
            None,
            Some(command_line),
            0,
            None,
            None,
            None,
        )
    }

    /// Spawns a process with this token using `CreateProcessAsUserW`.
    pub fn spawn_process_as_user(&self, command_line: &str) -> Result<SpawnedProcess> {
        create_process_as_user(
            self.as_raw(),
            None,
            Some(command_line),
            false,
            0,
            None,
            None,
            None,
        )
    }
}
