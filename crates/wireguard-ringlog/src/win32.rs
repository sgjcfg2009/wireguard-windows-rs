// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
// Windows Win32 memory mapping support for WireGuard ringlogger.

#![cfg(windows)]

use crate::types::{LogMem, RinglogError, LOG_MEM_SIZE, MAGIC};
use std::fs::File;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, FlushViewOfFile, MapViewOfFile, OpenFileMappingW, UnmapViewOfFile,
    FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS, PAGE_READONLY, PAGE_READWRITE,
};

/// Converts a Rust string to a null-terminated UTF-16 vector for Win32 API.
pub fn to_wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Encodes `s` as null-terminated UTF-16 into a stack `[u16; 128]` buffer when possible,
/// falling back to a heap `Vec<u16>` only for longer strings.
fn with_wide_null<R>(s: &str, f: impl FnOnce(*const u16) -> R) -> R {
    let mut stack = [0u16; 128];
    let mut len = 0usize;
    for unit in s.encode_utf16() {
        if len + 1 >= stack.len() {
            let heap = to_wide(s);
            return f(heap.as_ptr());
        }
        stack[len] = unit;
        len += 1;
    }
    stack[len] = 0;
    f(stack.as_ptr())
}

/// RAII wrapper for a Win32 HANDLE.
pub struct SafeHandle(pub HANDLE);

impl SafeHandle {
    pub fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    pub fn is_valid(&self) -> bool {
        !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE
    }

    pub fn raw(&self) -> HANDLE {
        self.0
    }

    pub fn into_raw(mut self) -> HANDLE {
        let h = self.0;
        self.0 = null_mut();
        h
    }
}

impl Drop for SafeHandle {
    fn drop(&mut self) {
        if self.is_valid() {
            unsafe {
                CloseHandle(self.0);
            }
            self.0 = null_mut();
        }
    }
}

/// Win32 memory-mapped storage backend.
pub struct Win32Storage {
    _file: Option<File>,
    _mapping: SafeHandle,
    view: *mut LogMem,
    read_only: bool,
}

// LogMem is internally thread-safe and safe to access across threads.
unsafe impl Send for Win32Storage {}
unsafe impl Sync for Win32Storage {}

impl Win32Storage {
    /// Maps a file mapping handle into memory and initializes or validates `LogMem`.
    fn map_and_init(
        file: Option<File>,
        mapping: SafeHandle,
        read_only: bool,
    ) -> Result<Self, RinglogError> {
        let access = if read_only {
            FILE_MAP_READ
        } else {
            FILE_MAP_WRITE
        };

        let view_address = unsafe { MapViewOfFile(mapping.raw(), access, 0, 0, LOG_MEM_SIZE) };

        let view_ptr = view_address.Value as *mut LogMem;
        if view_ptr.is_null() {
            let err = unsafe { GetLastError() };
            return Err(RinglogError::Windows(err));
        }

        let storage = Self {
            _file: file,
            _mapping: mapping,
            view: view_ptr,
            read_only,
        };

        if !read_only {
            unsafe {
                if (*view_ptr).magic != MAGIC {
                    (*view_ptr).reset();
                    storage.flush()?;
                }
            }
        } else {
            unsafe {
                if (*view_ptr).magic != MAGIC {
                    return Err(RinglogError::InvalidMagic {
                        expected: MAGIC,
                        actual: (*view_ptr).magic,
                    });
                }
            }
        }

        Ok(storage)
    }

    /// Creates or opens a memory mapped file using Win32 API.
    pub fn new_file(file: File, read_only: bool) -> Result<Self, RinglogError> {
        let handle = file.as_raw_handle() as HANDLE;
        let protect = if read_only {
            PAGE_READONLY
        } else {
            PAGE_READWRITE
        };

        let mapping_handle =
            unsafe { CreateFileMappingW(handle, null(), protect, 0, 0, null()) };

        if mapping_handle.is_null() || mapping_handle == INVALID_HANDLE_VALUE {
            return Err(RinglogError::Windows(unsafe { GetLastError() }));
        }

        Self::map_and_init(Some(file), SafeHandle::new(mapping_handle), read_only)
    }

    /// Creates a mapping view from an existing Win32 mapping handle.
    pub fn from_mapping_handle(
        mapping_handle: HANDLE,
        read_only: bool,
    ) -> Result<Self, RinglogError> {
        Self::map_and_init(None, SafeHandle::new(mapping_handle), read_only)
    }

    /// Opens an existing Win32 named shared memory mapping.
    pub fn open_named(name: &str, read_only: bool) -> Result<Self, RinglogError> {
        let access = if read_only {
            FILE_MAP_READ
        } else {
            FILE_MAP_WRITE | FILE_MAP_READ
        };

        let mapping_handle = with_wide_null(name, |wide_ptr| unsafe {
            OpenFileMappingW(access, 0, wide_ptr)
        });

        if mapping_handle.is_null() || mapping_handle == INVALID_HANDLE_VALUE {
            return Err(RinglogError::Windows(unsafe { GetLastError() }));
        }

        Self::from_mapping_handle(mapping_handle, read_only)
    }

    /// Creates a named shared memory mapping backed by the system paging file.
    pub fn create_named(name: &str) -> Result<Self, RinglogError> {
        let size_u64 = LOG_MEM_SIZE as u64;
        let mapping_handle = with_wide_null(name, |wide_ptr| unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                null(),
                PAGE_READWRITE,
                (size_u64 >> 32) as u32,
                (size_u64 & 0xFFFF_FFFF) as u32,
                wide_ptr,
            )
        });

        if mapping_handle.is_null() || mapping_handle == INVALID_HANDLE_VALUE {
            return Err(RinglogError::Windows(unsafe { GetLastError() }));
        }

        Self::from_mapping_handle(mapping_handle, false)
    }

    /// Exports an inheritable, read-only file mapping handle that can be shared with child processes.
    /// Matches WireGuard Go's `(*Ringlogger) ExportInheritableMappingHandle()`.
    pub fn export_inheritable_mapping_handle(&self) -> Result<HANDLE, RinglogError> {
        let file = self._file.as_ref().ok_or_else(|| {
            RinglogError::InvalidHandle("No backing file available to export handle".into())
        })?;

        let file_handle = file.as_raw_handle() as HANDLE;
        let handle_to_close =
            unsafe { CreateFileMappingW(file_handle, null(), PAGE_READONLY, 0, 0, null()) };

        if handle_to_close.is_null() || handle_to_close == INVALID_HANDLE_VALUE {
            return Err(RinglogError::Windows(unsafe { GetLastError() }));
        }

        let ret = unsafe {
            SetHandleInformation(handle_to_close, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
        };

        if ret == 0 {
            let err = unsafe { GetLastError() };
            unsafe {
                CloseHandle(handle_to_close);
            }
            return Err(RinglogError::Windows(err));
        }

        Ok(handle_to_close)
    }

    /// Flushes view pages to disk.
    pub fn flush(&self) -> Result<(), RinglogError> {
        if self.view.is_null() {
            return Ok(());
        }
        let ret = unsafe { FlushViewOfFile(self.view as *const _, LOG_MEM_SIZE) };
        if ret == 0 {
            let err = unsafe { GetLastError() };
            return Err(RinglogError::Windows(err));
        }
        Ok(())
    }

    /// Returns a shared reference to the mapped LogMem structure.
    pub fn as_log_mem(&self) -> &LogMem {
        unsafe { &*self.view }
    }

    /// Returns whether this mapping is read-only.
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }
}

impl Drop for Win32Storage {
    fn drop(&mut self) {
        if !self.view.is_null() {
            unsafe {
                let addr = MEMORY_MAPPED_VIEW_ADDRESS {
                    Value: self.view as *mut _,
                };
                UnmapViewOfFile(addr);
            }
            self.view = null_mut();
        }
        // self._mapping and self._file will be dropped automatically
    }
}
