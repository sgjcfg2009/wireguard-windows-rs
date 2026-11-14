/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use std::ffi::c_void;

use windows_sys::Win32::Foundation::{FreeLibrary, HMODULE};
use windows_sys::Win32::System::Diagnostics::Debug::{RtlAddFunctionTable, RtlDeleteFunctionTable};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualProtect, MEM_COMMIT, MEM_DECOMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_NOCACHE,
    PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
};

use crate::error::MemModError;
use crate::export::ExportTable;
use crate::hook::{register_address_range, unregister_address_range};
use crate::import::build_import_table;
use crate::pe::{
    align_down, parse_and_validate_pe, ImageSectionHeader, IMAGE_DIRECTORY_ENTRY_BASERELOC,
    IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_CNT_UNINITIALIZED_DATA,
    IMAGE_SCN_MEM_DISCARDABLE, IMAGE_SCN_MEM_NOT_CACHED,
};
use crate::reloc::perform_base_relocation;

type DllEntryFn = unsafe extern "system" fn(
    instance: *mut c_void,
    reason: u32,
    reserved: *mut c_void,
) -> i32;

type TlsCallbackFn = unsafe extern "system" fn(
    instance: *mut c_void,
    reason: u32,
    reserved: *mut c_void,
);

const DLL_PROCESS_DETACH: u32 = 0;
const DLL_PROCESS_ATTACH: u32 = 1;

/// Represents an in-memory loaded PE dynamic library or executable.
pub struct MemoryModule {
    code_base: *mut u8,
    is_dll: bool,
    initialized: bool,
    entry: Option<DllEntryFn>,
    loaded_modules: Vec<HMODULE>,
    blocked_memory: Vec<*mut u8>,
    runtime_funcs: *const c_void,
    exports: Option<ExportTable>,
}

// In-memory module functions can be invoked across threads
unsafe impl Send for MemoryModule {}
unsafe impl Sync for MemoryModule {}

impl MemoryModule {
    /// Loads a PE binary image directly from an in-memory buffer without writing to disk.
    ///
    /// # Safety
    /// Loading and executing in-memory code involves executing binary entrypoints and TLS callbacks.
    /// The caller must ensure that `data` comes from a trusted, authentic source (such as embedded driver DLLs).
    pub unsafe fn load(data: &[u8]) -> Result<Self, MemModError> {
        let parsed = parse_and_validate_pe(data)?;

        if data.len() < parsed.size_of_headers as usize
            || (parsed.size_of_headers as usize) > parsed.aligned_image_size
        {
            return Err(MemModError::IncompleteDosHeader(data.len()));
        }

        let mut blocked_memory: Vec<*mut u8> = Vec::new();

        // 1. Reserve and commit memory for image
        let mut code_base = VirtualAlloc(
            parsed.image_base as usize as *const c_void,
            parsed.aligned_image_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        ) as *mut u8;

        if code_base.is_null() {
            // Allocate at arbitrary position
            code_base = VirtualAlloc(
                std::ptr::null(),
                parsed.aligned_image_size,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
            ) as *mut u8;

            if code_base.is_null() {
                let err = windows_sys::Win32::Foundation::GetLastError();
                return Err(MemModError::VirtualAllocFailed(err));
            }
        }

        // On 64-bit systems, ensure memory does not cross 4GB boundary
        #[cfg(target_pointer_width = "64")]
        {
            while (code_base as usize >> 32)
                < ((code_base as usize + parsed.aligned_image_size) >> 32)
            {
                blocked_memory.push(code_base);
                code_base = VirtualAlloc(
                    std::ptr::null(),
                    parsed.aligned_image_size,
                    MEM_RESERVE | MEM_COMMIT,
                    PAGE_READWRITE,
                ) as *mut u8;

                if code_base.is_null() {
                    let err = windows_sys::Win32::Foundation::GetLastError();
                    for b in blocked_memory {
                        VirtualFree(b as *mut c_void, 0, MEM_RELEASE);
                    }
                    return Err(MemModError::VirtualAllocFailed(err));
                }
            }
        }

        let mut module = MemoryModule {
            code_base,
            is_dll: parsed.is_dll,
            initialized: false,
            entry: None,
            loaded_modules: Vec::new(),
            blocked_memory,
            runtime_funcs: std::ptr::null(),
            exports: None,
        };

        // 2. Commit memory for headers and copy
        let headers_alloc = VirtualAlloc(
            code_base as *const c_void,
            parsed.size_of_headers as usize,
            MEM_COMMIT,
            PAGE_READWRITE,
        );
        if headers_alloc.is_null() {
            let err = windows_sys::Win32::Foundation::GetLastError();
            return Err(MemModError::VirtualAllocFailed(err));
        }

        std::ptr::copy_nonoverlapping(data.as_ptr(), code_base, parsed.size_of_headers as usize);

        // Update in-memory ImageBase in optional header
        let opt_hdr_offset = parsed.e_lfanew + 4 + std::mem::size_of::<crate::pe::ImageFileHeader>();
        #[cfg(target_pointer_width = "64")]
        {
            let opt = &mut *(code_base.add(opt_hdr_offset) as *mut crate::pe::ImageOptionalHeader64);
            opt.image_base = code_base as u64;
        }
        #[cfg(target_pointer_width = "32")]
        {
            let opt = &mut *(code_base.add(opt_hdr_offset) as *mut crate::pe::ImageOptionalHeader32);
            opt.image_base = code_base as u32;
        }

        // 3. Copy sections
        module.copy_sections(data, &parsed)?;

        // 4. Perform base relocations if base address differs
        let location_delta = (code_base as usize as isize) - (parsed.image_base as usize as isize);
        if location_delta != 0 {
            let reloc_res = perform_base_relocation(
                code_base,
                &parsed.data_directories[IMAGE_DIRECTORY_ENTRY_BASERELOC],
                location_delta,
            )?;
            if !reloc_res {
                return Err(MemModError::RelocationFailed(
                    "Module could not be relocated".into(),
                ));
            }
        }

        // 5. Build import table
        let loaded = build_import_table(
            code_base,
            &parsed.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT],
        )?;
        module.loaded_modules = loaded;

        // 6. Finalize section memory permissions
        module.finalize_sections(&parsed)?;

        // 7. Register exception handlers on 64-bit
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            let ex_dir = &parsed.data_directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            if ex_dir.size > 0 && ex_dir.virtual_address != 0 {
                let funcs_ptr = code_base.add(ex_dir.virtual_address as usize)
                    as *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_RUNTIME_FUNCTION_ENTRY;
                let count = ex_dir.size as usize
                    / std::mem::size_of::<windows_sys::Win32::System::Diagnostics::Debug::IMAGE_RUNTIME_FUNCTION_ENTRY>();
                if RtlAddFunctionTable(funcs_ptr as *mut _, count as u32, code_base as u64) != 0 {
                    module.runtime_funcs = funcs_ptr as *const c_void;
                }
            }
        }

        // 8. Register address range with hook for RtlPcToFileHeader
        register_address_range(code_base as usize, code_base as usize + parsed.aligned_image_size)?;

        // 9. Execute TLS callbacks
        module.execute_tls(&parsed);

        // 10. Execute entry point if defined
        if parsed.address_of_entry_point != 0 {
            let entry_ptr = code_base.add(parsed.address_of_entry_point as usize);
            let entry_fn: DllEntryFn = std::mem::transmute(entry_ptr);
            module.entry = Some(entry_fn);

            if module.is_dll {
                let success = entry_fn(code_base as *mut c_void, DLL_PROCESS_ATTACH, std::ptr::null_mut());
                if success == 0 {
                    return Err(MemModError::DllInitializationFailed);
                }
                module.initialized = true;
            }
        }

        // 11. Parse exports
        let exp_dir = &parsed.data_directories[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if exp_dir.size > 0 && exp_dir.virtual_address != 0 {
            if let Ok(exp_table) = ExportTable::parse(code_base, exp_dir) {
                module.exports = Some(exp_table);
            }
        }

        Ok(module)
    }

    /// Returns the module base memory address.
    pub fn base_address(&self) -> usize {
        self.code_base as usize
    }

    /// Resolves an exported symbol by name.
    pub fn proc_address_by_name(&self, name: &str) -> Result<usize, MemModError> {
        let exports = self.exports.as_ref().ok_or(MemModError::NoExportTable)?;
        unsafe { exports.proc_address_by_name(self.code_base, name) }
    }

    /// Resolves an exported symbol by ordinal.
    pub fn proc_address_by_ordinal(&self, ordinal: u16) -> Result<usize, MemModError> {
        let exports = self.exports.as_ref().ok_or(MemModError::NoExportTable)?;
        unsafe { exports.proc_address_by_ordinal(self.code_base, ordinal) }
    }

    /// Returns a typed function pointer for an exported symbol.
    ///
    /// # Safety
    /// The caller must ensure type `T` matches the function signature of the exported procedure.
    pub unsafe fn get_proc<T: Copy>(&self, name: &str) -> Result<T, MemModError> {
        let addr = self.proc_address_by_name(name)?;
        Ok(std::mem::transmute_copy(&addr))
    }

    /// Returns a typed function pointer for an exported ordinal.
    ///
    /// # Safety
    /// The caller must ensure type `T` matches the function signature of the exported procedure.
    pub unsafe fn get_proc_by_ordinal<T: Copy>(&self, ordinal: u16) -> Result<T, MemModError> {
        let addr = self.proc_address_by_ordinal(ordinal)?;
        Ok(std::mem::transmute_copy(&addr))
    }

    unsafe fn copy_sections(
        &mut self,
        data: &[u8],
        parsed: &crate::pe::ParsedPe,
    ) -> Result<(), MemModError> {
        for sec in &parsed.sections {
            if sec.size_of_raw_data == 0 {
                let section_size = parsed.section_alignment as usize;
                if section_size == 0 {
                    continue;
                }
                let dest = VirtualAlloc(
                    self.code_base.add(sec.virtual_address as usize) as *const c_void,
                    section_size,
                    MEM_COMMIT,
                    PAGE_READWRITE,
                );
                if dest.is_null() {
                    let err = windows_sys::Win32::Foundation::GetLastError();
                    return Err(MemModError::VirtualAllocFailed(err));
                }
                std::ptr::write_bytes(dest as *mut u8, 0, section_size);
                continue;
            }

            let raw_end = (sec.pointer_to_raw_data as usize)
                .checked_add(sec.size_of_raw_data as usize)
                .ok_or_else(|| {
                    MemModError::IncompleteSectionData(format!(
                        "Section requires {} bytes at offset {}",
                        sec.size_of_raw_data, sec.pointer_to_raw_data
                    ))
                })?;
            if data.len() < raw_end {
                return Err(MemModError::IncompleteSectionData(format!(
                    "Section requires {} bytes at offset {}",
                    sec.size_of_raw_data, sec.pointer_to_raw_data
                )));
            }

            let dest = VirtualAlloc(
                self.code_base.add(sec.virtual_address as usize) as *const c_void,
                sec.size_of_raw_data as usize,
                MEM_COMMIT,
                PAGE_READWRITE,
            );
            if dest.is_null() {
                let err = windows_sys::Win32::Foundation::GetLastError();
                return Err(MemModError::VirtualAllocFailed(err));
            }

            std::ptr::copy_nonoverlapping(
                data.as_ptr().add(sec.pointer_to_raw_data as usize),
                self.code_base.add(sec.virtual_address as usize),
                sec.size_of_raw_data as usize,
            );
        }
        Ok(())
    }

    unsafe fn real_section_size(
        &self,
        sec: &ImageSectionHeader,
        parsed: &crate::pe::ParsedPe,
    ) -> usize {
        if sec.size_of_raw_data != 0 {
            return sec.size_of_raw_data as usize;
        }
        if (sec.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0 {
            return parsed.size_of_initialized_data as usize;
        }
        if (sec.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0 {
            return parsed.size_of_uninitialized_data as usize;
        }
        0
    }

    unsafe fn finalize_section(
        &self,
        address: usize,
        aligned_address: usize,
        size: usize,
        characteristics: u32,
        last: bool,
        section_alignment: usize,
    ) -> Result<(), MemModError> {
        if size == 0 {
            return Ok(());
        }

        if (characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0 {
            if address == aligned_address && (last || (size % section_alignment) == 0) {
                VirtualFree(address as *mut c_void, size, MEM_DECOMMIT);
            }
            return Ok(());
        }

        const PROTECTION_FLAGS: [u32; 8] = [
            PAGE_NOACCESS,
            PAGE_EXECUTE,
            PAGE_READONLY,
            PAGE_EXECUTE_READ,
            PAGE_WRITECOPY,
            PAGE_EXECUTE_WRITECOPY,
            PAGE_READWRITE,
            PAGE_EXECUTE_READWRITE,
        ];

        let mut protect = PROTECTION_FLAGS[(characteristics >> 29) as usize];
        if (characteristics & IMAGE_SCN_MEM_NOT_CACHED) != 0 {
            protect |= PAGE_NOCACHE;
        }

        let mut old_protect = 0u32;
        let res = VirtualProtect(
            address as *const c_void,
            size,
            protect,
            &mut old_protect,
        );

        if res == 0 {
            let err = windows_sys::Win32::Foundation::GetLastError();
            return Err(MemModError::VirtualProtectFailed(err));
        }

        Ok(())
    }

    unsafe fn finalize_sections(&self, parsed: &crate::pe::ParsedPe) -> Result<(), MemModError> {
        if parsed.sections.is_empty() {
            return Ok(());
        }

        let sec_alignment = parsed.section_alignment as usize;
        #[cfg(target_pointer_width = "64")]
        let image_offset = (self.code_base as usize) & 0xffff_ffff_0000_0000;
        #[cfg(target_pointer_width = "32")]
        let image_offset = 0usize;

        let first = &parsed.sections[0];
        let mut sec_addr = (self.code_base as usize + first.virtual_address as usize) | image_offset;
        let mut aligned_addr = align_down(sec_addr, sec_alignment);
        let mut sec_size = self.real_section_size(first, parsed);
        let mut characteristics = first.characteristics;

        for i in 1..parsed.sections.len() {
            let sec = &parsed.sections[i];
            let next_addr = (self.code_base as usize + sec.virtual_address as usize) | image_offset;
            let next_aligned = align_down(next_addr, sec_alignment);
            let next_size = self.real_section_size(sec, parsed);

            if aligned_addr == next_aligned || (sec_addr + sec_size > next_aligned) {
                if (sec.characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0
                    || (characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0
                {
                    characteristics = (characteristics | sec.characteristics)
                        & !IMAGE_SCN_MEM_DISCARDABLE;
                } else {
                    characteristics |= sec.characteristics;
                }
                sec_size = next_addr + next_size - sec_addr;
                continue;
            }

            self.finalize_section(
                sec_addr,
                aligned_addr,
                sec_size,
                characteristics,
                false,
                sec_alignment,
            )?;

            sec_addr = next_addr;
            aligned_addr = next_aligned;
            sec_size = next_size;
            characteristics = sec.characteristics;
        }

        self.finalize_section(
            sec_addr,
            aligned_addr,
            sec_size,
            characteristics,
            true,
            sec_alignment,
        )?;

        Ok(())
    }

    unsafe fn execute_tls(&self, parsed: &crate::pe::ParsedPe) {
        let tls_dir = &parsed.data_directories[IMAGE_DIRECTORY_ENTRY_TLS];
        if tls_dir.virtual_address == 0 {
            return;
        }

        let tls_ptr = self.code_base.add(tls_dir.virtual_address as usize);

        #[cfg(target_pointer_width = "64")]
        let callbacks_addr = {
            let tls = &*(tls_ptr as *const crate::pe::ImageTlsDirectory64);
            tls.address_of_callbacks as usize
        };

        #[cfg(target_pointer_width = "32")]
        let callbacks_addr = {
            let tls = &*(tls_ptr as *const crate::pe::ImageTlsDirectory32);
            tls.address_of_callbacks as usize
        };

        if callbacks_addr != 0 {
            let mut cb_ptr = callbacks_addr as *const usize;
            while *cb_ptr != 0 {
                let func: TlsCallbackFn = std::mem::transmute(*cb_ptr);
                func(self.code_base as *mut c_void, DLL_PROCESS_ATTACH, std::ptr::null_mut());
                cb_ptr = cb_ptr.add(1);
            }
        }
    }
}

impl Drop for MemoryModule {
    fn drop(&mut self) {
        unsafe {
            if self.initialized && self.is_dll {
                if let Some(entry) = self.entry {
                    entry(self.code_base as *mut c_void, DLL_PROCESS_DETACH, std::ptr::null_mut());
                }
                self.initialized = false;
            }

            for handle in self.loaded_modules.drain(..) {
                FreeLibrary(handle);
            }

            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            if !self.runtime_funcs.is_null() {
                RtlDeleteFunctionTable(self.runtime_funcs as *mut _);
                self.runtime_funcs = std::ptr::null();
            }

            if !self.code_base.is_null() {
                unregister_address_range(self.code_base as usize);
                VirtualFree(self.code_base as *mut c_void, 0, MEM_RELEASE);
                self.code_base = std::ptr::null_mut();
            }

            for blocked in self.blocked_memory.drain(..) {
                VirtualFree(blocked as *mut c_void, 0, MEM_RELEASE);
            }
        }
    }
}
