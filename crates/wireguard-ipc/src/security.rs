use std::ptr;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

use crate::error::{with_wide_null, IpcError};

/// Strict SDDL granting full access only to SYSTEM (`SY`) and Built-in Administrators (`BA`),
/// with protected DACL preventing inheritance (`D:P`).
pub const STRICT_PIPE_SDDL: &str = "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)";

/// Safe RAII wrapper for a Win32 security descriptor created from SDDL.
pub struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

unsafe impl Send for SecurityDescriptor {}
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    /// Creates a security descriptor by parsing an SDDL string.
    pub fn from_sddl(sddl: &str) -> Result<Self, IpcError> {
        let mut p_sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let success = with_wide_null(sddl, |wide_ptr| unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide_ptr,
                SDDL_REVISION_1,
                &mut p_sd,
                ptr::null_mut(),
            )
        });

        if success == 0 || p_sd.is_null() {
            return Err(IpcError::last_win32_error(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            ));
        }

        Ok(Self(p_sd))
    }

    /// Creates a security descriptor with the default strict SDDL.
    pub fn strict() -> Result<Self, IpcError> {
        Self::from_sddl(STRICT_PIPE_SDDL)
    }

    /// Returns the raw `PSECURITY_DESCRIPTOR` pointer.
    pub fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0
    }

    /// Constructs a `SECURITY_ATTRIBUTES` struct referencing this descriptor.
    ///
    /// # Safety
    /// The returned `SECURITY_ATTRIBUTES` borrows the underlying security descriptor
    /// and must not outlive `self`.
    pub fn to_security_attributes(&self, inherit: bool) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: if inherit { 1 } else { 0 },
        }
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0 as _);
            }
            self.0 = ptr::null_mut();
        }
    }
}
