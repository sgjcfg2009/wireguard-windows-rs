/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::sync::OnceLock;
use windows_sys::Win32::Security::Cryptography::{
    CertCloseStore, CertEnumCertificatesInStore, CertFindExtension, CertGetNameStringW,
    CryptDecodeObject, CryptQueryObject,
};

pub const OFFICIAL_COMMON_NAME: &str = "WireGuard LLC";
pub const EV_POLICY_OID: &str = "2.23.140.1.3";
pub const POLICY_EXTENSION_OID: &str = "2.5.29.32";

// Constants from Windows CryptoAPI
const CERT_QUERY_OBJECT_FILE: u32 = 0x00000001;
const CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED: u32 = 1 << 10;
const CERT_QUERY_FORMAT_FLAG_ALL: u32 = 0x0000000E;
const CERT_NAME_SIMPLE_DISPLAY_TYPE: u32 = 4;
const X509_ASN_ENCODING: u32 = 0x00000001;
const PKCS_7_ASN_ENCODING: u32 = 0x00010000;
const CRYPT_E_NOT_FOUND: u32 = 0x80092004;

#[repr(C)]
struct CertPolicyInfo {
    psz_policy_identifier: *mut u8,
    c_policy_qualifier: u32,
    rg_policy_qualifier: *mut c_void,
}

#[repr(C)]
struct CertPoliciesInfo {
    c_policy_info: u32,
    rg_policy_info: *mut CertPolicyInfo,
}

struct CertStoreGuard(*mut c_void);

impl Drop for CertStoreGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CertCloseStore(self.0, 0);
            }
        }
    }
}

fn with_wide_path<R>(path: &Path, f: impl FnOnce(*const u16) -> R) -> R {
    let mut stack = [0u16; 260];
    let mut len = 0usize;
    for unit in path.as_os_str().encode_wide() {
        if len + 1 >= stack.len() {
            let heap: Vec<u16> = path
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            return f(heap.as_ptr());
        }
        stack[len] = unit;
        len += 1;
    }
    stack[len] = 0;
    f(stack.as_ptr())
}

fn with_c_str<R>(s: &str, f: impl FnOnce(*const u8) -> R) -> Result<R, u32> {
    let bytes = s.as_bytes();
    if bytes.contains(&0) {
        return Err(87); // ERROR_INVALID_PARAMETER
    }
    if bytes.len() < 64 {
        let mut stack = [0u8; 64];
        stack[..bytes.len()].copy_from_slice(bytes);
        stack[bytes.len()] = 0;
        return Ok(f(stack.as_ptr()));
    }
    let c = std::ffi::CString::new(bytes).map_err(|_| 87u32)?;
    Ok(f(c.as_ptr() as *const u8))
}

fn open_embedded_cert_store(path: &Path) -> Result<CertStoreGuard, u32> {
    with_wide_path(path, |path_ptr| unsafe {
        let mut cert_store: *mut c_void = std::ptr::null_mut();
        let res = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            path_ptr as *const c_void,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_ALL,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut cert_store,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        if res == 0 || cert_store.is_null() {
            Err(windows_sys::Win32::Foundation::GetLastError())
        } else {
            Ok(CertStoreGuard(cert_store))
        }
    })
}

fn visit_certificate_names(
    path: &Path,
    mut visitor: impl FnMut(&[u16]),
) -> Result<bool, u32> {
    let store = open_embedded_cert_store(path)?;
    let mut stack_buf = [0u16; 256];
    let mut heap_buf = Vec::new();
    let mut any = false;

    unsafe {
        let mut cert = std::ptr::null_mut();
        loop {
            cert = CertEnumCertificatesInStore(store.0, cert);
            if cert.is_null() {
                break;
            }

            let name_len = CertGetNameStringW(
                cert,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                std::ptr::null(),
                std::ptr::null_mut(),
                0,
            );

            if name_len > 1 {
                let needed = name_len as usize;
                let buf: &mut [u16] = if needed <= stack_buf.len() {
                    &mut stack_buf[..needed]
                } else {
                    heap_buf.resize(needed, 0);
                    &mut heap_buf[..needed]
                };

                let written = CertGetNameStringW(
                    cert,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0,
                    std::ptr::null(),
                    buf.as_mut_ptr(),
                    name_len,
                );
                if written > 1 {
                    let slice_len = (written as usize - 1).min(buf.len());
                    any = true;
                    visitor(&buf[..slice_len]);
                }
            }
        }
    }

    Ok(any)
}

fn visit_certificate_policies(
    path: &Path,
    oid: &str,
    mut visitor: impl FnMut(&str),
) -> Result<bool, u32> {
    with_c_str(oid, |oid_ptr| {
        let store = open_embedded_cert_store(path)?;
        let mut stack_buf = [0u64; 128];
        let mut heap_buf: Vec<u64> = Vec::new();
        let mut any = false;

        unsafe {
            let mut cert = std::ptr::null_mut();
            loop {
                cert = CertEnumCertificatesInStore(store.0, cert);
                if cert.is_null() {
                    break;
                }

                let cert_info = (*cert).pCertInfo;
                if cert_info.is_null() {
                    continue;
                }

                let ext = CertFindExtension(
                    oid_ptr,
                    (*cert_info).cExtension,
                    (*cert_info).rgExtension,
                );

                if ext.is_null() {
                    continue;
                }

                let mut decoded_len = 0u32;
                let decode_res = CryptDecodeObject(
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    (*ext).pszObjId,
                    (*ext).Value.pbData,
                    (*ext).Value.cbData,
                    0,
                    std::ptr::null_mut(),
                    &mut decoded_len,
                );

                if decode_res == 0 || (decoded_len as usize) < std::mem::size_of::<CertPoliciesInfo>() {
                    continue;
                }

                // Use 8-byte aligned u64 storage matching CertPoliciesInfo pointer alignment.
                let words = (decoded_len as usize + 7) / 8;
                let buf_ptr = if words <= stack_buf.len() {
                    stack_buf.as_mut_ptr()
                } else {
                    heap_buf.resize(words, 0);
                    heap_buf.as_mut_ptr()
                };

                let decode_res2 = CryptDecodeObject(
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    (*ext).pszObjId,
                    (*ext).Value.pbData,
                    (*ext).Value.cbData,
                    0,
                    buf_ptr as *mut c_void,
                    &mut decoded_len,
                );

                if decode_res2 == 0 {
                    continue;
                }

                let policies_info = buf_ptr as *const CertPoliciesInfo;
                let count = (*policies_info).c_policy_info;
                let policy_infos = (*policies_info).rg_policy_info;
                if policy_infos.is_null() {
                    continue;
                }

                for i in 0..count {
                    let info = policy_infos.add(i as usize);
                    let id_ptr = (*info).psz_policy_identifier;
                    if !id_ptr.is_null() {
                        let c_str = std::ffi::CStr::from_ptr(id_ptr as *const std::ffi::c_char);
                        if let Ok(s) = c_str.to_str() {
                            any = true;
                            visitor(s);
                        }
                    }
                }
            }
        }

        Ok(any)
    })?
}

/// Checks if the currently running executable was signed by "WireGuard LLC" (cached process-wide).
/// Note: Easily bypassable check; do not use for security boundary enforcement.
pub fn is_running_official_version() -> bool {
    static CACHED_OFFICIAL: OnceLock<bool> = OnceLock::new();
    *CACHED_OFFICIAL.get_or_init(|| {
        let Ok(path) = std::env::current_exe() else {
            return false;
        };
        let mut matched = false;
        let _ = visit_certificate_names(&path, |units| {
            if !matched && units.iter().copied().eq(OFFICIAL_COMMON_NAME.encode_utf16()) {
                matched = true;
            }
        });
        matched
    })
}

/// Checks if the currently running executable has an Extended Validation (EV) certificate policy (cached process-wide).
pub fn is_running_ev_signed() -> bool {
    static CACHED_EV: OnceLock<bool> = OnceLock::new();
    *CACHED_EV.get_or_init(|| {
        let Ok(path) = std::env::current_exe() else {
            return false;
        };
        let mut matched = false;
        let _ = visit_certificate_policies(&path, POLICY_EXTENSION_OID, |s| {
            if !matched && s == EV_POLICY_OID {
                matched = true;
            }
        });
        matched
    })
}

/// Extracts certificate subject display names from an embedded PKCS#7 signature in a PE file.
pub fn extract_certificate_names(path: &Path) -> Result<Vec<String>, u32> {
    let mut names = Vec::new();
    visit_certificate_names(path, |units| {
        let s = String::from_utf16_lossy(units);
        if !s.is_empty() {
            names.push(s);
        }
    })?;

    if names.is_empty() {
        Err(CRYPT_E_NOT_FOUND)
    } else {
        Ok(names)
    }
}

/// Extracts certificate policy OIDs from a PE file.
pub fn extract_certificate_policies(path: &Path, oid: &str) -> Result<Vec<String>, u32> {
    let mut policies = Vec::new();
    visit_certificate_policies(path, oid, |s| {
        policies.push(s.to_owned());
    })?;

    if policies.is_empty() {
        Err(CRYPT_E_NOT_FOUND)
    } else {
        Ok(policies)
    }
}
