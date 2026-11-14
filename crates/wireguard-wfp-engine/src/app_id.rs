/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use tracing::{debug, error};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::{
    GetSidIdentifierAuthority, GetSidSubAuthority, GetSidSubAuthorityCount,
    GetTokenInformation, InitializeSecurityDescriptor, IsValidSid, MakeSelfRelativeSD,
    SetSecurityDescriptorDacl, TokenGroups,
    SECURITY_DESCRIPTOR, SECURITY_NT_AUTHORITY, TOKEN_GROUPS, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

use crate::error::WfpError;
use crate::ffi::*;

// Advapi32 explicit access definitions for ACL manipulation
const NO_MULTIPLE_TRUSTEE: u32 = 0;
const TRUSTEE_IS_SID: u32 = 0;
const TRUSTEE_IS_GROUP: u32 = 2;
const GRANT_ACCESS: u32 = 1;
const NO_INHERITANCE: u32 = 0;

const SE_GROUP_ENABLED: u32 = 0x00000004;
const SE_GROUP_ENABLED_BY_DEFAULT: u32 = 0x00000002;
const SE_GROUP_OWNER: u32 = 0x00000008;

#[repr(C)]
#[allow(non_snake_case)]
struct TRUSTEE_W {
    pMultipleTrustee: *mut c_void,
    MultipleTrusteeOperation: u32,
    TrusteeForm: u32,
    TrusteeType: u32,
    ptstrName: *mut u16,
}

#[repr(C)]
#[allow(non_snake_case)]
struct EXPLICIT_ACCESS_W {
    grfAccessPermissions: u32,
    grfAccessMode: u32,
    grfInheritance: u32,
    Trustee: TRUSTEE_W,
}

#[link(name = "advapi32")]
extern "system" {
    fn SetEntriesInAclW(
        cCountOfExplicitEntries: u32,
        pListOfExplicitEntries: *const EXPLICIT_ACCESS_W,
        OldAcl: *mut c_void,
        NewAcl: *mut *mut c_void,
    ) -> u32;
}

/// Safe RAII wrapper for an Application ID byte blob returned by `FwpmGetAppIdFromFileName0`.
pub struct AppIdBlob {
    raw: *mut FwpByteBlob,
}

impl AppIdBlob {
    fn from_wide_iter(iter: impl Iterator<Item = u16>) -> Result<Self, WfpError> {
        const STACK_CAP: usize = 260;
        let mut stack = [0u16; STACK_CAP];
        let mut len = 0usize;
        let mut heap: Option<Vec<u16>> = None;

        for unit in iter {
            if let Some(ref mut v) = heap {
                v.push(unit);
            } else if len + 1 < STACK_CAP {
                stack[len] = unit;
                len += 1;
            } else {
                let mut v = Vec::with_capacity(STACK_CAP * 2);
                v.extend_from_slice(&stack[..len]);
                v.push(unit);
                heap = Some(v);
            }
        }

        let wide_slice: &[u16] = if let Some(ref mut v) = heap {
            v.push(0);
            v.as_slice()
        } else {
            stack[len] = 0;
            &stack[..=len]
        };

        let mut app_id: *mut FwpByteBlob = ptr::null_mut();
        let status = unsafe { FwpmGetAppIdFromFileName0(wide_slice.as_ptr(), &mut app_id) };

        if status != 0 {
            error!("FwpmGetAppIdFromFileName0 failed: 0x{:08x}", status);
            return Err(WfpError::Win32(status));
        }

        Ok(Self { raw: app_id })
    }

    /// Obtains an AppID blob for the executable at the given file path.
    pub fn from_path(path: &str) -> Result<Self, WfpError> {
        Self::from_wide_iter(path.encode_utf16())
    }

    /// Obtains the AppID blob for the currently executing process.
    pub fn current_process() -> Result<Self, WfpError> {
        let current_exe = std::env::current_exe()?;
        debug!("Retrieving WFP AppID for current process: {}", current_exe.display());
        Self::from_wide_iter(current_exe.as_os_str().encode_wide())
    }

    /// Returns the raw pointer to the `FwpByteBlob`.
    pub fn as_raw(&self) -> *const FwpByteBlob {
        self.raw
    }

    /// Returns a reference to the inner `FwpByteBlob`.
    pub fn as_blob(&self) -> &FwpByteBlob {
        unsafe { &*self.raw }
    }
}

impl Drop for AppIdBlob {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe {
                let mut ptr = self.raw as *mut c_void;
                FwpmFreeMemory0(&mut ptr);
            }
            self.raw = ptr::null_mut();
        }
    }
}

/// Retrieves a self-relative Security Descriptor for the current process's Service SID.
///
/// Looks for a group SID in the process token with `SECURITY_NT_AUTHORITY`,
/// sub-authority count >= 6, and initial sub-authority 80 (`SECURITY_SERVICE_ID_BASE_RID`).
/// Constructs a self-relative Security Descriptor granting `FWP_ACTRL_MATCH_FILTER` to that SID.
pub fn get_current_process_security_descriptor() -> Result<Vec<u8>, WfpError> {
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        let ok = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token);
        if ok == 0 || token.is_null() || token == INVALID_HANDLE_VALUE {
            return Err(WfpError::ProcessTokenError(format!("OpenProcessToken failed: {}", GetLastError())));
        }

        // RAII handle wrapper
        struct HandleGuard(HANDLE);
        impl Drop for HandleGuard {
            fn drop(&mut self) {
                if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                    unsafe { CloseHandle(self.0); }
                }
            }
        }
        let _guard = HandleGuard(token);

        // Query token groups using an 8-byte aligned 1 KiB stack buffer; spill to aligned Vec<u64> only if needed.
        let mut stack_buf = [0u64; 128];
        let mut heap_buf: Vec<u64> = Vec::new();
        let mut req_len: u32 = 0;

        let ok = GetTokenInformation(
            token,
            TokenGroups,
            stack_buf.as_mut_ptr() as *mut c_void,
            (stack_buf.len() * std::mem::size_of::<u64>()) as u32,
            &mut req_len,
        );

        let groups_ptr: *const TOKEN_GROUPS = if ok != 0 {
            stack_buf.as_ptr() as *const TOKEN_GROUPS
        } else {
            let err = GetLastError();
            if err != ERROR_INSUFFICIENT_BUFFER || req_len == 0 {
                return Err(WfpError::ProcessTokenError(format!(
                    "GetTokenInformation failed: {}",
                    err
                )));
            }
            heap_buf.resize((req_len as usize + 7) / 8, 0);
            let ok2 = GetTokenInformation(
                token,
                TokenGroups,
                heap_buf.as_mut_ptr() as *mut c_void,
                (heap_buf.len() * std::mem::size_of::<u64>()) as u32,
                &mut req_len,
            );
            if ok2 == 0 {
                return Err(WfpError::ProcessTokenError(format!(
                    "GetTokenInformation failed: {}",
                    GetLastError()
                )));
            }
            heap_buf.as_ptr() as *const TOKEN_GROUPS
        };

        let groups = &*groups_ptr;
        let count = groups.GroupCount as usize;
        let groups_slice = std::slice::from_raw_parts(groups.Groups.as_ptr(), count);

        let required_attrs = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_OWNER;
        let mut service_sid: *mut c_void = ptr::null_mut();

        for g in groups_slice {
            if (g.Attributes & required_attrs) != required_attrs {
                continue;
            }

            let sid = g.Sid;
            if IsValidSid(sid) == 0 {
                continue;
            }

            let auth = GetSidIdentifierAuthority(sid);
            if auth.is_null() || (*auth).Value != SECURITY_NT_AUTHORITY.Value {
                continue;
            }

            let sub_auth_count = GetSidSubAuthorityCount(sid);
            if sub_auth_count.is_null() || *sub_auth_count < 6 {
                continue;
            }

            let first_sub_auth = GetSidSubAuthority(sid, 0);
            if first_sub_auth.is_null() || *first_sub_auth != 80 {
                continue;
            }

            service_sid = sid;
            break;
        }

        if service_sid.is_null() {
            return Err(WfpError::NoSuchServiceGroup);
        }

        // Build EXPLICIT_ACCESS_W granting FWP_ACTRL_MATCH_FILTER to the service SID
        let explicit_access = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FWP_ACTRL_MATCH_FILTER,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_GROUP,
                ptstrName: service_sid as *mut u16,
            },
        };

        let mut dacl: *mut c_void = ptr::null_mut();
        let status = SetEntriesInAclW(1, &explicit_access, ptr::null_mut(), &mut dacl);
        if status != 0 {
            return Err(WfpError::Win32(status));
        }

        struct AclGuard(*mut c_void);
        impl Drop for AclGuard {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    unsafe { LocalFree(self.0); }
                }
            }
        }
        let _dacl_guard = AclGuard(dacl);

        // Initialize absolute Security Descriptor with full struct alignment
        let mut abs_sd = MaybeUninit::<SECURITY_DESCRIPTOR>::uninit();
        let ok = InitializeSecurityDescriptor(
            abs_sd.as_mut_ptr() as *mut c_void,
            SECURITY_DESCRIPTOR_REVISION,
        );
        if ok == 0 {
            return Err(WfpError::Win32(GetLastError()));
        }

        let ok = SetSecurityDescriptorDacl(
            abs_sd.as_mut_ptr() as *mut c_void,
            1, // bDaclPresent = TRUE
            dacl as *const _,
            0, // bDaclDefaulted = FALSE
        );
        if ok == 0 {
            return Err(WfpError::Win32(GetLastError()));
        }

        // Convert to self-relative Security Descriptor
        let mut rel_sd_len = 0;
        let _ = MakeSelfRelativeSD(
            abs_sd.as_mut_ptr() as *mut c_void,
            ptr::null_mut(),
            &mut rel_sd_len,
        );

        if rel_sd_len == 0 {
            return Err(WfpError::Win32(GetLastError()));
        }

        let mut rel_sd = vec![0u8; rel_sd_len as usize];
        let ok = MakeSelfRelativeSD(
            abs_sd.as_mut_ptr() as *mut c_void,
            rel_sd.as_mut_ptr() as *mut c_void,
            &mut rel_sd_len,
        );
        if ok == 0 {
            return Err(WfpError::Win32(GetLastError()));
        }

        debug!("Created self-relative security descriptor ({} bytes)", rel_sd.len());
        Ok(rel_sd)
    }
}
