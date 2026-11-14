/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Rust implementation: 2026 WireGuard Rust Contributors.
 */

use crate::error::{last_os_error, Result};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::RevertToSelf;
use windows_sys::Win32::System::Services::{CloseServiceHandle, SC_HANDLE};

/// RAII wrapper for a Win32 `HANDLE`.
///
/// Automatically invokes `CloseHandle` upon drop if the handle is valid.
#[derive(Debug)]
pub struct AutoHandle(HANDLE);

impl AutoHandle {
    /// Creates a new `AutoHandle` if `handle` is not NULL and not `INVALID_HANDLE_VALUE`.
    #[inline]
    pub fn new(handle: HANDLE) -> Option<Self> {
        if handle.is_null() || handle == -1isize as HANDLE {
            None
        } else {
            Some(Self(handle))
        }
    }

    /// Wraps a raw Win32 `HANDLE` without validity checks.
    ///
    /// # Safety
    /// The caller must ensure `handle` is either a valid open handle or null/invalid.
    #[inline]
    pub unsafe fn from_raw(handle: HANDLE) -> Self {
        Self(handle)
    }

    /// Returns the raw Win32 `HANDLE`.
    #[inline]
    pub fn as_raw(&self) -> HANDLE {
        self.0
    }

    /// Checks if the underlying handle is non-null and not `INVALID_HANDLE_VALUE`.
    #[inline]
    pub fn is_valid(&self) -> bool {
        !self.0.is_null() && self.0 != -1isize as HANDLE
    }

    /// Consumes the wrapper and returns the raw handle without closing it.
    #[inline]
    pub fn into_raw(mut self) -> HANDLE {
        let raw = self.0;
        self.0 = core::ptr::null_mut();
        core::mem::forget(self);
        raw
    }
}

impl Drop for AutoHandle {
    fn drop(&mut self) {
        if self.is_valid() {
            unsafe {
                CloseHandle(self.0);
            }
            self.0 = core::ptr::null_mut();
        }
    }
}

unsafe impl Send for AutoHandle {}
unsafe impl Sync for AutoHandle {}

/// RAII wrapper for a Service Control Manager `SC_HANDLE`.
///
/// Automatically invokes `CloseServiceHandle` upon drop if the handle is non-null.
#[derive(Debug)]
pub struct AutoServiceHandle(SC_HANDLE);

impl AutoServiceHandle {
    /// Creates a new `AutoServiceHandle` if `handle` is non-null.
    #[inline]
    pub fn new(handle: SC_HANDLE) -> Option<Self> {
        if handle.is_null() {
            None
        } else {
            Some(Self(handle))
        }
    }

    /// Wraps a raw `SC_HANDLE`.
    ///
    /// # Safety
    /// Caller must ensure `handle` is a valid service handle or null.
    #[inline]
    pub unsafe fn from_raw(handle: SC_HANDLE) -> Self {
        Self(handle)
    }

    /// Returns the raw `SC_HANDLE`.
    #[inline]
    pub fn as_raw(&self) -> SC_HANDLE {
        self.0
    }

    /// Returns true if the service handle is non-null.
    #[inline]
    pub fn is_valid(&self) -> bool {
        !self.0.is_null()
    }

    /// Consumes the wrapper and returns the raw handle without closing it.
    #[inline]
    pub fn into_raw(mut self) -> SC_HANDLE {
        let raw = self.0;
        self.0 = core::ptr::null_mut();
        core::mem::forget(self);
        raw
    }
}

impl Drop for AutoServiceHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseServiceHandle(self.0);
            }
            self.0 = core::ptr::null_mut();
        }
    }
}

unsafe impl Send for AutoServiceHandle {}
unsafe impl Sync for AutoServiceHandle {}

/// RAII guard for thread impersonation.
///
/// Calls `RevertToSelf` when dropped to guarantee that the current thread
/// does not inadvertently leak impersonated credentials.
#[derive(Debug)]
pub struct ImpersonationGuard {
    active: bool,
}

impl ImpersonationGuard {
    /// Creates an active impersonation guard.
    pub fn new() -> Self {
        Self { active: true }
    }

    /// Manually reverts impersonation, returning any Win32 error.
    pub fn revert(&mut self) -> Result<()> {
        if self.active {
            let res = unsafe { RevertToSelf() };
            self.active = false;
            if res == 0 {
                return Err(last_os_error());
            }
        }
        Ok(())
    }

    /// Dismisses the guard without calling `RevertToSelf`.
    pub fn dismiss(mut self) {
        self.active = false;
    }
}

impl Default for ImpersonationGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                RevertToSelf();
            }
            self.active = false;
        }
    }
}
