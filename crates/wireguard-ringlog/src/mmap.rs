// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
// Memory mapping abstraction supporting Win32 native, memmap2, and in-memory backends.

use crate::types::{LogMem, RinglogError, LOG_MEM_SIZE, MAGIC};
use memmap2::{Mmap, MmapMut, MmapOptions};
use std::fs::File;
use std::path::Path;

#[cfg(windows)]
use crate::win32::Win32Storage;

pub enum Storage {
    #[cfg(windows)]
    Win32(Win32Storage),
    MmapMut {
        _file: Option<File>,
        mmap: MmapMut,
    },
    MmapRead {
        _file: Option<File>,
        mmap: Mmap,
    },
    InMemory(Box<LogMem>),
}

// LogMem consists solely of atomic fields, which are safe for multithreaded access.
unsafe impl Send for Storage {}
unsafe impl Sync for Storage {}

impl Storage {
    /// Creates an in-memory storage buffer allocated on the heap.
    pub fn new_in_memory() -> Self {
        let boxed = LogMem::new_boxed();
        Storage::InMemory(boxed)
    }

    /// Creates or opens a file-backed mapping using memmap2.
    pub fn from_file<P: AsRef<Path>>(path: P, read_only: bool) -> Result<Self, RinglogError> {
        let file = if read_only {
            File::open(path)?
        } else {
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(path)?;
            f.set_len(LOG_MEM_SIZE as u64)?;
            f
        };

        if read_only {
            let mmap = unsafe { MmapOptions::new().map(&file)? };
            if mmap.len() < LOG_MEM_SIZE {
                return Err(RinglogError::InvalidMagic {
                    expected: MAGIC,
                    actual: 0,
                });
            }
            let log = unsafe { &*(mmap.as_ptr() as *const LogMem) };
            if log.magic != MAGIC {
                return Err(RinglogError::InvalidMagic {
                    expected: MAGIC,
                    actual: log.magic,
                });
            }
            Ok(Storage::MmapRead {
                _file: Some(file),
                mmap,
            })
        } else {
            let mut mmap = unsafe { MmapMut::map_mut(&file)? };
            if mmap.len() < LOG_MEM_SIZE {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "mmap length less than LOG_MEM_SIZE",
                )
                .into());
            }
            let log = unsafe { &mut *(mmap.as_mut_ptr() as *mut LogMem) };
            log.initialize_if_needed();
            mmap.flush()?;
            Ok(Storage::MmapMut {
                _file: Some(file),
                mmap,
            })
        }
    }

    /// Returns a reference to the underlying LogMem structure.
    #[inline]
    pub fn as_log_mem(&self) -> &LogMem {
        match self {
            #[cfg(windows)]
            Storage::Win32(w) => w.as_log_mem(),
            Storage::MmapMut { mmap, .. } => {
                unsafe { &*(mmap.as_ptr() as *const LogMem) }
            }
            Storage::MmapRead { mmap, .. } => {
                unsafe { &*(mmap.as_ptr() as *const LogMem) }
            }
            Storage::InMemory(boxed) => boxed.as_ref(),
        }
    }

    /// Flushes dirty pages to backing storage.
    pub fn flush(&self) -> Result<(), RinglogError> {
        match self {
            #[cfg(windows)]
            Storage::Win32(w) => w.flush(),
            Storage::MmapMut { mmap, .. } => {
                mmap.flush()?;
                Ok(())
            }
            Storage::MmapRead { .. } => Ok(()),
            Storage::InMemory(_) => Ok(()),
        }
    }

    /// Returns true if this storage is read-only.
    pub fn is_read_only(&self) -> bool {
        match self {
            #[cfg(windows)]
            Storage::Win32(w) => w.is_read_only(),
            Storage::MmapMut { .. } => false,
            Storage::MmapRead { .. } => true,
            Storage::InMemory(_) => false,
        }
    }
}
