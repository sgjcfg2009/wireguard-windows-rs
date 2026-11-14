/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use std::ffi::CStr;

use windows_sys::Win32::Foundation::{FreeLibrary, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LoadLibraryW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

use crate::error::MemModError;
use crate::pe::{ImageDataDirectory, ImageImportDescriptor};

#[cfg(target_pointer_width = "64")]
const IMAGE_ORDINAL_FLAG: usize = 0x8000_0000_0000_0000;
#[cfg(target_pointer_width = "32")]
const IMAGE_ORDINAL_FLAG: usize = 0x8000_0000;

#[inline]
fn is_snap_by_ordinal(thunk: usize) -> bool {
    (thunk & IMAGE_ORDINAL_FLAG) != 0
}

#[inline]
fn get_ordinal(thunk: usize) -> u16 {
    (thunk & 0xffff) as u16
}

/// Frees already-loaded dependency modules if `build_import_table` fails partway through.
struct LoadedModulesGuard(Vec<HMODULE>);

impl LoadedModulesGuard {
    fn into_inner(mut self) -> Vec<HMODULE> {
        core::mem::take(&mut self.0)
    }
}

impl Drop for LoadedModulesGuard {
    fn drop(&mut self) {
        for handle in self.0.drain(..) {
            unsafe {
                FreeLibrary(handle);
            }
        }
    }
}

/// Converts a C string to null-terminated UTF-16 using a stack buffer for typical DLL names.
#[inline]
fn with_cstr_wide_null<R>(cstr: &CStr, f: impl FnOnce(*const u16) -> R) -> R {
    let bytes = cstr.to_bytes();
    let mut stack = [0u16; 128];
    let heap: Vec<u16>;
    let ptr = if bytes.is_ascii() && bytes.len() < stack.len() {
        for (dst, &src) in stack.iter_mut().zip(bytes.iter()) {
            *dst = src as u16;
        }
        stack[bytes.len()] = 0;
        stack.as_ptr()
    } else {
        let s = cstr.to_string_lossy();
        let mut idx = 0usize;
        if s.len() < stack.len() {
            for u in s.encode_utf16() {
                if idx + 1 >= stack.len() {
                    idx = usize::MAX;
                    break;
                }
                stack[idx] = u;
                idx += 1;
            }
        } else {
            idx = usize::MAX;
        }
        if idx != usize::MAX {
            stack[idx] = 0;
            stack.as_ptr()
        } else {
            heap = s.encode_utf16().chain(std::iter::once(0)).collect();
            heap.as_ptr()
        }
    };
    f(ptr)
}

/// Resolves the PE Import Address Table (IAT) by loading required dependent libraries
/// and binding imported function pointers.
///
/// # Safety
/// The caller must ensure that `code_base` points to committed writable memory
/// containing the mapped image.
pub unsafe fn build_import_table(
    code_base: *mut u8,
    directory: &ImageDataDirectory,
) -> Result<Vec<HMODULE>, MemModError> {
    if directory.size == 0 || directory.virtual_address == 0 {
        return Ok(Vec::new());
    }

    let mut loaded_modules = LoadedModulesGuard(Vec::new());
    let mut import_desc_ptr = code_base.add(directory.virtual_address as usize)
        as *const ImageImportDescriptor;

    while (*import_desc_ptr).name != 0 {
        let desc = *import_desc_ptr;
        let lib_name_ptr = code_base.add(desc.name as usize) as *const i8;
        let lib_name_cstr = CStr::from_ptr(lib_name_ptr);

        let handle = with_cstr_wide_null(lib_name_cstr, |lib_name_wide_ptr| {
            // Load dependency strictly from System32 when possible for security
            let mut h = LoadLibraryExW(
                lib_name_wide_ptr,
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            );
            if h.is_null() {
                // Fallback to standard library search (e.g. for side-by-side or application DLLs)
                h = LoadLibraryW(lib_name_wide_ptr);
            }
            h
        });

        if handle.is_null() {
            let err = windows_sys::Win32::Foundation::GetLastError();
            return Err(MemModError::DependencyLoadFailed(
                lib_name_cstr.to_string_lossy().into_owned(),
                err,
            ));
        }

        loaded_modules.0.push(handle);

        let mut thunk_ref: *mut usize = if desc.original_first_thunk != 0 {
            code_base.add(desc.original_first_thunk as usize) as *mut usize
        } else {
            code_base.add(desc.first_thunk as usize) as *mut usize
        };

        let mut func_ref: *mut usize = code_base.add(desc.first_thunk as usize) as *mut usize;

        while *thunk_ref != 0 {
            let thunk_val = *thunk_ref;
            let proc = if is_snap_by_ordinal(thunk_val) {
                let ord = get_ordinal(thunk_val);
                GetProcAddress(handle, ord as usize as *const u8)
            } else {
                let import_by_name = code_base.add(thunk_val);
                // Skip the 2-byte Hint field to get the function name
                let func_name_ptr = import_by_name.add(2) as *const u8;
                GetProcAddress(handle, func_name_ptr)
            };

            let Some(proc_fn) = proc else {
                let err = windows_sys::Win32::Foundation::GetLastError();
                let symbol = if is_snap_by_ordinal(thunk_val) {
                    format!("#{}", get_ordinal(thunk_val))
                } else {
                    let func_name_ptr = code_base.add(thunk_val).add(2) as *const i8;
                    CStr::from_ptr(func_name_ptr).to_string_lossy().into_owned()
                };
                return Err(MemModError::FunctionNotFound {
                    module: lib_name_cstr.to_string_lossy().into_owned(),
                    symbol,
                    code: err,
                });
            };

            *func_ref = proc_fn as usize;

            thunk_ref = thunk_ref.add(1);
            func_ref = func_ref.add(1);
        }

        import_desc_ptr = import_desc_ptr.add(1);
    }

    Ok(loaded_modules.into_inner())
}
