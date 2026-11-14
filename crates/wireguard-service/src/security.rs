use crate::error::ServiceError;
use crate::wide::{from_wide_ptr, with_wide_null_checked};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Authorization::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::System::Services::*;

/// Standard SDDL string that grants:
/// - Local System (`SY`): Full Access (`FA`)
/// - Built-in Administrators (`BA`): Full Access (`FA`)
/// - Network Configuration Operators (`NO`): Query Status, Query Config, Start, Stop, Interrogate (`CCLCSWRPWPLORC`)
/// - Interactive Users (`IU`): Read/Query rights (`CCLCSWLOCRRC`)
pub const NETWORK_CONFIGURATION_OPERATORS_SDDL: &str =
    "O:SYG:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;CCLCSWRPWPLORC;;;NO)(A;;CCLCSWLOCRRC;;;IU)";

/// Simpler SDDL string granting full access to System/Admins and Start/Stop/Query to Network Configuration Operators.
pub const NETWORK_CONFIGURATION_OPERATORS_SDDL_COMPACT: &str =
    "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;CCLCSWRPWPLO;;;NO)";

/// RAII wrapper for a Win32 `PSECURITY_DESCRIPTOR`.
///
/// When dropped, safely calls `LocalFree` on the allocated security descriptor.
#[derive(Debug)]
pub struct SecurityDescriptor {
    raw: PSECURITY_DESCRIPTOR,
}

unsafe impl Send for SecurityDescriptor {}
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    /// Creates a new `SecurityDescriptor` by parsing an SDDL string using `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
    pub fn from_sddl(sddl: &str) -> Result<Self, ServiceError> {
        let mut p_sd: PSECURITY_DESCRIPTOR = core::ptr::null_mut();
        let mut size: u32 = 0;

        let ok = with_wide_null_checked(sddl, |wide_sddl| unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide_sddl,
                SDDL_REVISION_1,
                &mut p_sd,
                &mut size,
            )
        })?;

        if ok == 0 || p_sd.is_null() {
            return Err(ServiceError::SecurityDescriptor(format!(
                "Failed to parse SDDL '{}': {}",
                sddl,
                ServiceError::last_win32_error()
            )));
        }

        Ok(Self { raw: p_sd })
    }

    /// Converts this security descriptor back to an SDDL string using `ConvertSecurityDescriptorToStringSecurityDescriptorW`.
    pub fn to_sddl(&self, requested_info: u32) -> Result<String, ServiceError> {
        if self.raw.is_null() {
            return Err(ServiceError::SecurityDescriptor("Null security descriptor pointer".into()));
        }

        let mut p_str: *mut u16 = core::ptr::null_mut();
        let mut len: u32 = 0;

        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                self.raw,
                SDDL_REVISION_1,
                requested_info,
                &mut p_str,
                &mut len,
            )
        };

        if ok == 0 || p_str.is_null() {
            return Err(ServiceError::SecurityDescriptor(format!(
                "Failed to convert security descriptor to string: {}",
                ServiceError::last_win32_error()
            )));
        }

        let sddl = unsafe { from_wide_ptr(p_str) };
        unsafe {
            LocalFree(p_str as _);
        }
        Ok(sddl)
    }

    /// Returns the raw `PSECURITY_DESCRIPTOR` pointer.
    pub fn as_raw(&self) -> PSECURITY_DESCRIPTOR {
        self.raw
    }

    /// Creates the standard WireGuard security descriptor granting Network Configuration Operators and Administrators access.
    pub fn for_network_operators() -> Result<Self, ServiceError> {
        Self::from_sddl(NETWORK_CONFIGURATION_OPERATORS_SDDL)
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe {
                LocalFree(self.raw as _);
            }
            self.raw = core::ptr::null_mut();
        }
    }
}

/// Applies a security descriptor to an open service handle using `SetServiceObjectSecurity`.
pub fn apply_service_security(
    service_handle: SC_HANDLE,
    security_descriptor: &SecurityDescriptor,
) -> Result<(), ServiceError> {
    let ok = unsafe {
        SetServiceObjectSecurity(
            service_handle,
            DACL_SECURITY_INFORMATION,
            security_descriptor.as_raw(),
        )
    };
    if ok == 0 {
        return Err(ServiceError::last_win32_error());
    }
    Ok(())
}
