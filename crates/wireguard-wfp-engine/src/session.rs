/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use std::ffi::c_void;
use std::ptr;
use tracing::{debug, error, info};

use crate::error::WfpError;
use crate::ffi::*;
use crate::guid::Guid;

const EMPTY_W: [u16; 1] = [0];

#[inline]
fn with_wide_null<R>(s: &str, f: impl FnOnce(*const u16) -> R) -> R {
    if s.is_empty() {
        return f(EMPTY_W.as_ptr());
    }
    const STACK_CAP: usize = 96;
    let mut stack = [0u16; STACK_CAP];
    let mut len = 0usize;
    let mut heap: Option<Vec<u16>> = None;

    for unit in s.encode_utf16() {
        if let Some(ref mut v) = heap {
            v.push(unit);
        } else if len + 1 < STACK_CAP {
            stack[len] = unit;
            len += 1;
        } else {
            let mut v = Vec::with_capacity(STACK_CAP + s.len() + 1);
            v.extend_from_slice(&stack[..len]);
            v.push(unit);
            heap = Some(v);
        }
    }

    if let Some(ref mut v) = heap {
        v.push(0);
        f(v.as_ptr())
    } else {
        stack[len] = 0;
        f(stack.as_ptr())
    }
}

/// Encodes display name and description into stack UTF-16 buffers (falling back to heap only
/// if longer than 95 code units) and passes an `FwpmDisplayData0` to `f`.
///
/// The pointers inside `FwpmDisplayData0` remain valid strictly for the duration of `f`.
pub fn with_display_data<R>(
    name: &str,
    description: &str,
    f: impl FnOnce(FwpmDisplayData0) -> R,
) -> R {
    with_wide_null(name, |name_ptr| {
        with_wide_null(description, |desc_ptr| {
            f(FwpmDisplayData0 {
                name: name_ptr,
                description: desc_ptr,
            })
        })
    })
}

/// RAII wrapper for Display Data (name and description wchar strings).
pub struct DisplayData {
    name_u16: Vec<u16>,
    desc_u16: Vec<u16>,
}

impl DisplayData {
    pub fn new(name: &str, description: &str) -> Self {
        let name_u16: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let desc_u16: Vec<u16> = description.encode_utf16().chain(std::iter::once(0)).collect();
        Self { name_u16, desc_u16 }
    }

    pub fn as_raw(&self) -> FwpmDisplayData0 {
        FwpmDisplayData0 {
            name: self.name_u16.as_ptr(),
            description: self.desc_u16.as_ptr(),
        }
    }
}

/// An open Windows Filtering Platform session handle.
///
/// Implements RAII: when `Engine` is dropped or `close()` is called,
/// `FwpmEngineClose0` is invoked. When opened with `dynamic = true`,
/// all dynamic objects (providers, sublayers, filters) registered
/// under this session are automatically purged by the Windows kernel
/// upon engine close or process termination.
pub struct Engine {
    handle: *mut c_void,
    dynamic: bool,
}

unsafe impl Send for Engine {}
unsafe impl Sync for Engine {}

impl Engine {
    /// Opens a new WFP engine session.
    ///
    /// # Arguments
    /// * `name` - Display name for the session.
    /// * `description` - Description of the session purpose.
    /// * `dynamic` - If true, sets `FWPM_SESSION_FLAG_DYNAMIC`.
    pub fn open(name: &str, description: &str, dynamic: bool) -> Result<Self, WfpError> {
        let mut handle: *mut c_void = ptr::null_mut();
        debug!("Opening WFP Engine session '{}' (dynamic={})", name, dynamic);

        let status = with_display_data(name, description, |display_data| {
            let mut session = FwpmSession0::default();
            session.display_data = display_data;
            session.txn_wait_timeout_in_msec = INFINITE_TIMEOUT;

            if dynamic {
                session.flags = FWPM_SESSION_FLAG_DYNAMIC;
            }

            unsafe {
                FwpmEngineOpen0(
                    ptr::null(),
                    RPC_C_AUTHN_WINNT,
                    ptr::null(),
                    &session,
                    &mut handle,
                )
            }
        });

        if status != 0 {
            error!("FwpmEngineOpen0 failed with error code: 0x{:08x}", status);
            return Err(WfpError::Win32(status));
        }

        info!("Opened WFP Engine session successfully, handle={:p}", handle);
        Ok(Self { handle, dynamic })
    }

    /// Returns the raw underlying WFP engine handle.
    pub fn handle(&self) -> *mut c_void {
        self.handle
    }

    /// Returns true if the engine handle is valid.
    pub fn is_valid(&self) -> bool {
        !self.handle.is_null()
    }

    /// Returns true if this session was opened as dynamic.
    pub fn is_dynamic(&self) -> bool {
        self.dynamic
    }

    /// Closes the WFP engine session explicitly.
    pub fn close(&mut self) -> Result<(), WfpError> {
        if !self.handle.is_null() {
            debug!("Closing WFP Engine session {:p}", self.handle);
            let status = unsafe { FwpmEngineClose0(self.handle) };
            self.handle = ptr::null_mut();
            if status != 0 {
                error!("FwpmEngineClose0 failed: 0x{:08x}", status);
                return Err(WfpError::Win32(status));
            }
        }
        Ok(())
    }

    /// Deletes a filter by its 64-bit filter ID.
    pub fn delete_filter_by_id(&self, filter_id: u64) -> Result<(), WfpError> {
        if self.handle.is_null() {
            return Err(WfpError::EngineClosed);
        }
        let status = unsafe { FwpmFilterDeleteById0(self.handle, filter_id) };
        if status != 0 {
            return Err(WfpError::Win32(status));
        }
        Ok(())
    }

    /// Deletes a filter by its GUID key.
    pub fn delete_filter_by_key(&self, key: &Guid) -> Result<(), WfpError> {
        if self.handle.is_null() {
            return Err(WfpError::EngineClosed);
        }
        let status = unsafe { FwpmFilterDeleteByKey0(self.handle, key) };
        if status != 0 {
            return Err(WfpError::Win32(status));
        }
        Ok(())
    }

    /// Deletes a sublayer by its GUID key.
    pub fn delete_sublayer(&self, key: &Guid) -> Result<(), WfpError> {
        if self.handle.is_null() {
            return Err(WfpError::EngineClosed);
        }
        let status = unsafe { FwpmSubLayerDeleteByKey0(self.handle, key) };
        if status != 0 {
            return Err(WfpError::Win32(status));
        }
        Ok(())
    }

    /// Deletes a provider by its GUID key.
    pub fn delete_provider(&self, key: &Guid) -> Result<(), WfpError> {
        if self.handle.is_null() {
            return Err(WfpError::EngineClosed);
        }
        let status = unsafe { FwpmProviderDeleteByKey0(self.handle, key) };
        if status != 0 {
            return Err(WfpError::Win32(status));
        }
        Ok(())
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
