// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
// Rust port: Antigravity Contributors.

//! Windows Data Protection API (DPAPI) wrapper for WireGuard.
//!
//! Provides symmetric-like encryption and decryption tied to the current Windows user
//! or machine credentials using Win32 `CryptProtectData` and `CryptUnprotectData`.
//!
//! Reference Go implementation: `wireguard-windows/conf/dpapi/dpapi_windows.go`.

use std::fmt;
use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    FormatMessageW, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS,
};

/// Error conditions that can occur during DPAPI operations.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum DpapiError {
    /// Win32 `CryptProtectData` call failed.
    #[error("unable to encrypt DPAPI protected data (Win32 error {code:#010x}): {message}")]
    ProtectFailed { code: u32, message: String },

    /// Win32 `CryptUnprotectData` call failed.
    #[error("unable to decrypt DPAPI protected data (Win32 error {code:#010x}): {message}")]
    UnprotectFailed { code: u32, message: String },

    /// The decrypted blob did not contain an associated description/name.
    #[error("decrypted data has no associated description")]
    MissingDescription,

    /// The description stored in the encrypted blob does not match what was expected.
    #[error("input name does not match the stored name: expected '{expected}', found '{actual}'")]
    DescriptionMismatch { expected: String, actual: String },

    /// The input data exceeds 4GB (maximum size supported by DPAPI `u32` length).
    #[error("data too large for DPAPI: {0} bytes (max supported is 4GB)")]
    DataTooLarge(usize),

    /// The provided description contains an interior NUL byte, which is invalid in Win32 strings.
    #[error("description contains an interior NUL character: '{0}'")]
    InvalidDescription(String),
}

impl DpapiError {
    /// Returns the Win32 error code if this error originated from a Win32 API call.
    #[must_use]
    pub fn win32_code(&self) -> Option<u32> {
        match self {
            Self::ProtectFailed { code, .. } | Self::UnprotectFailed { code, .. } => Some(*code),
            _ => None,
        }
    }
}

/// Formats a Win32 error code into a human-readable string using `FormatMessageW`.
fn format_win32_error(code: u32) -> String {
    let mut buffer = [0u16; 512];
    let len = unsafe {
        FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            core::ptr::null(),
            code,
            0, // default language
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            core::ptr::null_mut(),
        )
    };

    if len > 0 {
        let mut end = len as usize;
        while end > 0 && matches!(buffer[end - 1], 0x000D | 0x000A | 0x0020) {
            end -= 1;
        }
        String::from_utf16_lossy(&buffer[..end])
    } else {
        format!("Unknown Win32 error code {code:#010x}")
    }
}

/// Securely zeroes out memory in the given slice.
///
/// Uses volatile writes and a sequential consistency compiler fence
/// to ensure the zeroing operation cannot be optimized away by the compiler.
#[inline]
pub fn secure_zero(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        unsafe {
            core::ptr::write_volatile(byte, 0);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// An RAII container that securely zeroes its contents when dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct ProtectedBuffer {
    data: Vec<u8>,
}

impl ProtectedBuffer {
    /// Creates a new `ProtectedBuffer` wrapping the given vector.
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Returns a shared slice to the underlying data.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Unwraps the inner `Vec<u8>`, bypassing automatic zeroization on drop.
    #[must_use]
    pub fn into_vec(mut self) -> Vec<u8> {
        let vec = core::mem::take(&mut self.data);
        vec
    }
}

impl Drop for ProtectedBuffer {
    fn drop(&mut self) {
        secure_zero(&mut self.data);
    }
}

impl core::ops::Deref for ProtectedBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl fmt::Debug for ProtectedBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ProtectedBuffer")
            .field(&format_args!("[{} bytes redacted]", self.data.len()))
            .finish()
    }
}

/// Helper RAII guard that safely zeroes and frees memory allocated by DPAPI with `LocalAlloc`.
struct BlobGuard(CRYPT_INTEGER_BLOB);

impl Drop for BlobGuard {
    fn drop(&mut self) {
        if !self.0.pbData.is_null() {
            unsafe {
                if self.0.cbData > 0 {
                    let slice =
                        core::slice::from_raw_parts_mut(self.0.pbData, self.0.cbData as usize);
                    secure_zero(slice);
                }
                LocalFree(self.0.pbData as _);
            }
        }
    }
}

/// Helper RAII guard that frees memory allocated by Win32 via `LocalFree`.
struct LocalFreeGuard<T>(*mut T);

impl<T> Drop for LocalFreeGuard<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0 as _);
            }
        }
    }
}

/// Converts a byte slice into a Win32 `CRYPT_INTEGER_BLOB`.
fn bytes_to_blob(bytes: &[u8]) -> Result<CRYPT_INTEGER_BLOB, DpapiError> {
    let len: u32 = bytes
        .len()
        .try_into()
        .map_err(|_| DpapiError::DataTooLarge(bytes.len()))?;

    // Even if len == 0, Windows DPAPI requires pbData to be a non-null valid pointer,
    // otherwise CryptProtectData/CryptUnprotectData fails with ERROR_INVALID_PARAMETER (87).
    static EMPTY_DUMMY: u8 = 0;
    let ptr = if len > 0 {
        bytes.as_ptr() as *mut u8
    } else {
        &EMPTY_DUMMY as *const u8 as *mut u8
    };

    Ok(CRYPT_INTEGER_BLOB {
        cbData: len,
        pbData: ptr,
    })
}

/// Passes an optional NUL-terminated UTF-16 description pointer into `f` using a stack buffer
/// (falling back to heap allocation only if >= 256 UTF-16 code units).
///
/// Returns `Err(DpapiError::InvalidDescription)` if `description` contains an interior NUL character.
fn with_optional_wide_null<R>(
    description: Option<&str>,
    f: impl FnOnce(*const u16) -> R,
) -> Result<R, DpapiError> {
    let Some(s) = description else {
        return Ok(f(core::ptr::null()));
    };
    if s.contains('\0') {
        return Err(DpapiError::InvalidDescription(s.to_string()));
    }

    const STACK_CAP: usize = 256;
    let mut stack = [0u16; STACK_CAP];
    let mut len = 0usize;
    let mut iter = s.encode_utf16();
    while let Some(u) = iter.next() {
        if len + 1 >= STACK_CAP {
            let mut heap = Vec::with_capacity(len + 1 + iter.size_hint().0 + 1);
            heap.extend_from_slice(&stack[..len]);
            heap.push(u);
            heap.extend(iter);
            heap.push(0);
            return Ok(f(heap.as_ptr()));
        }
        stack[len] = u;
        len += 1;
    }
    stack[len] = 0;
    Ok(f(stack.as_ptr()))
}

/// Encrypts `plaintext` using the Windows Data Protection API (DPAPI).
///
/// Wraps Win32 `CryptProtectData` with `CRYPTPROTECT_UI_FORBIDDEN`.
///
/// # Arguments
/// * `plaintext` - The raw byte data to be encrypted.
/// * `description` - An optional string label to associate with the encrypted data.
///
/// # Errors
/// Returns `DpapiError::ProtectFailed` if the underlying Win32 API fails.
pub fn encrypt(plaintext: &[u8], description: Option<&str>) -> Result<Vec<u8>, DpapiError> {
    let in_blob = bytes_to_blob(plaintext)?;

    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: core::ptr::null_mut(),
    };

    let success = with_optional_wide_null(description, |desc_ptr| unsafe {
        CryptProtectData(
            &in_blob,
            desc_ptr,
            core::ptr::null(), // pOptionalEntropy
            core::ptr::null(), // pvReserved
            core::ptr::null(), // pPromptStruct
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    })?;

    if success == 0 {
        let err_code = unsafe { GetLastError() };
        let err_msg = format_win32_error(err_code);
        return Err(DpapiError::ProtectFailed {
            code: err_code,
            message: err_msg,
        });
    }

    // Wrap the returned blob in RAII guard for secure zeroization and deallocation
    let guard = BlobGuard(out_blob);

    let ciphertext = if guard.0.cbData > 0 && !guard.0.pbData.is_null() {
        unsafe {
            core::slice::from_raw_parts(guard.0.pbData, guard.0.cbData as usize).to_vec()
        }
    } else {
        Vec::new()
    };

    Ok(ciphertext)
}

/// Decrypts `ciphertext` using the Windows Data Protection API (DPAPI).
///
/// Wraps Win32 `CryptUnprotectData` with `CRYPTPROTECT_UI_FORBIDDEN`.
/// Does not enforce or return any stored description.
///
/// # Errors
/// Returns `DpapiError::UnprotectFailed` if the DPAPI ciphertext is invalid or corrupted.
pub fn decrypt(ciphertext: &[u8]) -> Result<Vec<u8>, DpapiError> {
    let (data, _) = decrypt_internal(ciphertext, DescriptionMode::Ignore)?;
    Ok(data)
}

/// Decrypts `ciphertext` and returns a `ProtectedBuffer` that automatically
/// zeroizes its plaintext memory upon being dropped.
pub fn decrypt_protected(ciphertext: &[u8]) -> Result<ProtectedBuffer, DpapiError> {
    let data = decrypt(ciphertext)?;
    Ok(ProtectedBuffer::new(data))
}

/// Decrypts `ciphertext` using Windows DPAPI and returns both the decrypted data
/// and the optional description string attached during encryption.
///
/// # Errors
/// Returns `DpapiError::UnprotectFailed` if decryption fails.
pub fn decrypt_with_description(
    ciphertext: &[u8],
) -> Result<(Vec<u8>, Option<String>), DpapiError> {
    decrypt_internal(ciphertext, DescriptionMode::Retrieve)
}

/// Decrypts `ciphertext` using Windows DPAPI and verifies that the associated description
/// exactly matches `expected_description`.
///
/// This matches the exact behavior of WireGuard's Go `dpapi.Decrypt(bytes, name)` function.
///
/// # Errors
/// * `DpapiError::MissingDescription` if the ciphertext has no associated description.
/// * `DpapiError::DescriptionMismatch` if the description does not match `expected_description`.
/// * `DpapiError::UnprotectFailed` if decryption fails.
pub fn decrypt_with_expected_description(
    ciphertext: &[u8],
    expected_description: &str,
) -> Result<Vec<u8>, DpapiError> {
    let (data, _) = decrypt_internal(ciphertext, DescriptionMode::Expect(expected_description))?;
    Ok(data)
}

enum DescriptionMode<'a> {
    Ignore,
    Retrieve,
    Expect(&'a str),
}

/// Internal decryption implementation that optionally retrieves or validates the description.
fn decrypt_internal(
    ciphertext: &[u8],
    mode: DescriptionMode<'_>,
) -> Result<(Vec<u8>, Option<String>), DpapiError> {
    let in_blob = bytes_to_blob(ciphertext)?;

    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: core::ptr::null_mut(),
    };
    let mut out_name: *mut u16 = core::ptr::null_mut();
    let want_name = !matches!(mode, DescriptionMode::Ignore);

    let success = unsafe {
        CryptUnprotectData(
            &in_blob,
            if want_name {
                &mut out_name
            } else {
                core::ptr::null_mut()
            },
            core::ptr::null_mut(), // pOptionalEntropy
            core::ptr::null_mut(), // pvReserved
            core::ptr::null_mut(), // pPromptStruct
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };

    if success == 0 {
        let err_code = unsafe { GetLastError() };
        let err_msg = format_win32_error(err_code);
        return Err(DpapiError::UnprotectFailed {
            code: err_code,
            message: err_msg,
        });
    }

    // Wrap both pointers in RAII guards
    let _blob_guard = BlobGuard(out_blob);
    let _name_guard = LocalFreeGuard(out_name);

    let description = match mode {
        DescriptionMode::Ignore => None,
        DescriptionMode::Retrieve => {
            if out_name.is_null() {
                None
            } else {
                let slice = unsafe { wide_null_slice(out_name) };
                Some(String::from_utf16_lossy(slice))
            }
        }
        DescriptionMode::Expect(expected) => {
            if out_name.is_null() {
                return Err(DpapiError::MissingDescription);
            }
            let slice = unsafe { wide_null_slice(out_name) };
            // Compare UTF-16 code units directly on the happy path with zero String allocation,
            // and fail before copying plaintext out of `out_blob`.
            if !slice.iter().copied().eq(expected.encode_utf16()) {
                return Err(DpapiError::DescriptionMismatch {
                    expected: expected.to_string(),
                    actual: String::from_utf16_lossy(slice),
                });
            }
            None
        }
    };

    let plaintext = if out_blob.cbData > 0 && !out_blob.pbData.is_null() {
        unsafe {
            core::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec()
        }
    } else {
        Vec::new()
    };

    Ok((plaintext, description))
}

unsafe fn wide_null_slice<'a>(ptr: *const u16) -> &'a [u16] {
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    core::slice::from_raw_parts(ptr, len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_with_description() {
        let name = "golang test";
        let original = b"The quick brown fox jumped over the lazy dog";

        let encrypted = encrypt(original, Some(name)).expect("encryption failed");
        assert!(
            encrypted.len() > original.len(),
            "encrypted data should be larger than original"
        );

        let decrypted = decrypt(&encrypted).expect("decryption failed");
        assert_eq!(decrypted, original);

        let decrypted_verified =
            decrypt_with_expected_description(&encrypted, name).expect("verified decryption failed");
        assert_eq!(decrypted_verified, original);
    }

    #[test]
    fn test_roundtrip_without_description() {
        let original = b"Secret data without label";
        let encrypted = encrypt(original, None).expect("encryption failed");
        let decrypted = decrypt(&encrypted).expect("decryption failed");
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_roundtrip_empty_data() {
        let original = b"";
        let encrypted = encrypt(original, Some("empty")).expect("encryption failed");
        let decrypted = decrypt(&encrypted).expect("decryption failed");
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_description_mismatch() {
        let name = "tunnel_wg0";
        let original = b"Interface private key and peer config";

        let encrypted = encrypt(original, Some(name)).expect("encryption failed");

        let err = decrypt_with_expected_description(&encrypted, "wrong_tunnel_wg1")
            .expect_err("should have detected description mismatch");

        match err {
            DpapiError::DescriptionMismatch { expected, actual } => {
                assert_eq!(expected, "wrong_tunnel_wg1");
                assert_eq!(actual, "tunnel_wg0");
            }
            other => panic!("expected DescriptionMismatch, got {other:?}"),
        }
    }

    #[test]
    fn test_ciphertext_corruption() {
        let name = "corrupt_test";
        let original = b"Sensitive wireguard tunnel data";

        let mut encrypted = encrypt(original, Some(name)).expect("encryption failed");
        assert!(!encrypted.is_empty());

        // Corrupt a byte in the payload
        let corrupt_idx = encrypted.len() / 2;
        encrypted[corrupt_idx] ^= 0xFF;

        let err = decrypt(&encrypted).expect_err("decryption should fail on corrupted data");
        assert!(matches!(err, DpapiError::UnprotectFailed { .. }));
        assert!(err.win32_code().is_some());
    }

    #[test]
    fn test_invalid_description_interior_null() {
        let invalid_desc = "foo\0bar";
        let err = encrypt(b"data", Some(invalid_desc))
            .expect_err("should reject description with interior null");
        assert!(matches!(err, DpapiError::InvalidDescription(_)));
    }

    #[test]
    fn test_secure_zero() {
        let mut secret = vec![0x42u8; 64];
        assert!(secret.iter().all(|&b| b == 0x42));

        secure_zero(&mut secret);
        assert!(secret.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_protected_buffer_drop() {
        let buf = ProtectedBuffer::new(vec![0xAA; 32]);
        assert_eq!(buf.len(), 32);
        assert_eq!(&buf[..], &[0xAA; 32][..]);

        let slice = buf.as_slice();
        assert_eq!(slice[0], 0xAA);

        // Test into_vec
        let vec = buf.into_vec();
        assert_eq!(vec.len(), 32);
        assert_eq!(vec[0], 0xAA);
    }

    #[test]
    fn test_large_payload_roundtrip() {
        // Test 128KB payload
        let mut large_data = Vec::with_capacity(128 * 1024);
        for i in 0..(128 * 1024) {
            large_data.push((i % 251) as u8);
        }

        let encrypted = encrypt(&large_data, Some("large_payload")).expect("encryption failed");
        let decrypted = decrypt(&encrypted).expect("decryption failed");
        assert_eq!(decrypted, large_data);
    }
}
