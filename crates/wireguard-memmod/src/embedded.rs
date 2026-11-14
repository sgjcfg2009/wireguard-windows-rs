/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use std::sync::{Mutex, OnceLock};

use crate::error::MemModError;
use crate::module::MemoryModule;

/// Safe abstraction for an embedded DLL (e.g. Wintun or WireGuard-NT driver DLL)
/// compiled directly into binary buffers or loaded from Windows resources.
pub struct EmbeddedDll {
    bytes: &'static [u8],
    module: OnceLock<MemoryModule>,
    init_lock: Mutex<()>,
}

unsafe impl Send for EmbeddedDll {}
unsafe impl Sync for EmbeddedDll {}

impl EmbeddedDll {
    /// Creates a new EmbeddedDll wrapping a static slice of PE DLL bytes.
    ///
    /// # Example
    /// ```ignore
    /// use wireguard_memmod::EmbeddedDll;
    /// static WINTUN_DLL: EmbeddedDll = EmbeddedDll::new(include_bytes!("../resources/wintun.dll"));
    /// ```
    pub const fn new(bytes: &'static [u8]) -> Self {
        EmbeddedDll {
            bytes,
            module: OnceLock::new(),
            init_lock: Mutex::new(()),
        }
    }

    /// Loads the embedded DLL into memory if not already loaded, returning a reference.
    pub fn load(&self) -> Result<&MemoryModule, MemModError> {
        if let Some(m) = self.module.get() {
            return Ok(m);
        }

        let _guard = self.init_lock.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(m) = self.module.get() {
            return Ok(m);
        }

        let module = unsafe { MemoryModule::load(self.bytes)? };
        let _ = self.module.set(module);
        Ok(self.module.get().unwrap())
    }

    /// Returns true if the DLL has already been loaded into memory.
    pub fn is_loaded(&self) -> bool {
        self.module.get().is_some()
    }

    /// Returns the base address of the loaded DLL in memory.
    pub fn base_address(&self) -> Result<usize, MemModError> {
        Ok(self.load()?.base_address())
    }

    /// Resolves an exported procedure address by name.
    pub fn proc_address(&self, name: &str) -> Result<usize, MemModError> {
        self.load()?.proc_address_by_name(name)
    }

    /// Resolves an exported procedure address and casts it to a function pointer.
    ///
    /// # Safety
    /// The caller must ensure that the function pointer type `T` matches the signature
    /// and calling convention (`extern "system"` for Win32 API functions) of the exported symbol.
    pub unsafe fn get_proc<T: Copy>(&self, name: &str) -> Result<T, MemModError> {
        self.load()?.get_proc(name)
    }
}

/// A lazily resolved procedure symbol from an embedded DLL.
pub struct LazyProc<T: Copy + 'static> {
    dll: &'static EmbeddedDll,
    name: &'static str,
    proc: OnceLock<T>,
}

unsafe impl<T: Copy + 'static> Send for LazyProc<T> {}
unsafe impl<T: Copy + 'static> Sync for LazyProc<T> {}

impl<T: Copy + 'static> LazyProc<T> {
    /// Constructs a new lazy procedure reference.
    pub const fn new(dll: &'static EmbeddedDll, name: &'static str) -> Self {
        LazyProc {
            dll,
            name,
            proc: OnceLock::new(),
        }
    }

    /// Returns the resolved function pointer, loading the parent DLL if needed.
    ///
    /// # Safety
    /// The caller must ensure type `T` is a valid function pointer type for the procedure.
    pub unsafe fn get(&self) -> Result<T, MemModError> {
        if let Some(p) = self.proc.get() {
            return Ok(*p);
        }

        let p: T = self.dll.get_proc(self.name)?;
        let _ = self.proc.set(p);
        Ok(*self.proc.get().unwrap())
    }
}
