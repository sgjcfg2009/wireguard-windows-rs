/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use std::ffi::{c_void, CStr};
use std::sync::{Once, RwLock};

use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleHandleExW, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
};
use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_READWRITE};

use crate::error::MemModError;
use crate::pe::{
    ImageDosHeader, ImageFileHeader, ImageImportDescriptor, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
};

#[cfg(target_pointer_width = "64")]
const IMAGE_ORDINAL_FLAG: usize = 0x8000_0000_0000_0000;
#[cfg(target_pointer_width = "32")]
const IMAGE_ORDINAL_FLAG: usize = 0x8000_0000;

static LOADED_ADDRESS_RANGES: RwLock<Vec<(usize, usize)>> = RwLock::new(Vec::new());
static HOOK_ONCE: Once = Once::new();
static mut HOOK_RESULT: Result<(), String> = Ok(());

static mut ORIGINAL_RTL_PC_TO_FILE_HEADER: usize = 0;
static mut HOOK_THUNK_ADDRESS: usize = 0;

/// Register an in-memory module range so that Windows exception unwinding recognizes it.
pub fn register_address_range(start: usize, end: usize) -> Result<(), MemModError> {
    if let Ok(mut ranges) = LOADED_ADDRESS_RANGES.write() {
        ranges.push((start, end));
    }

    unsafe {
        HOOK_ONCE.call_once(|| {
            HOOK_RESULT = hook_rtl_pc_to_file_header();
        });

        match &raw const HOOK_RESULT {
            ptr if (*ptr).is_ok() => Ok(()),
            ptr => {
                if let Err(e) = &*ptr {
                    tracing::warn!("Hooking RtlPcToFileHeader failed: {}. Continuing without hook.", e);
                }
                Ok(())
            }
        }
    }
}

/// Unregister an in-memory module range on drop.
pub fn unregister_address_range(start: usize) {
    if let Ok(mut ranges) = LOADED_ADDRESS_RANGES.write() {
        if let Some(pos) = ranges.iter().position(|r| r.0 == start) {
            ranges.remove(pos);
        }
    }
}

/// Trampoline callback invoked by kernelbase.dll during SEH unwinding.
unsafe extern "system" fn hooked_rtl_pc_to_file_header(
    mut pc_value: usize,
    base_of_image: *mut usize,
) -> usize {
    if let Ok(ranges) = LOADED_ADDRESS_RANGES.read() {
        for &(start, end) in ranges.iter() {
            if pc_value >= start && pc_value < end {
                // Point PC to kernelbase code address to satisfy SEH unwinder
                pc_value = HOOK_THUNK_ADDRESS;
                break;
            }
        }
    }

    if ORIGINAL_RTL_PC_TO_FILE_HEADER == 0 {
        return 0;
    }
    let orig_fn: unsafe extern "system" fn(usize, *mut usize) -> usize =
        std::mem::transmute(ORIGINAL_RTL_PC_TO_FILE_HEADER);
    orig_fn(pc_value, base_of_image)
}

/// Hooks kernelbase.dll's IAT entry for ntdll.dll!RtlPcToFileHeader.
unsafe fn hook_rtl_pc_to_file_header() -> Result<(), String> {
    let kernelbase_name: [u16; 15] = [
        b'k' as u16, b'e' as u16, b'r' as u16, b'n' as u16, b'e' as u16, b'l' as u16,
        b'b' as u16, b'a' as u16, b's' as u16, b'e' as u16, b'.' as u16, b'd' as u16,
        b'l' as u16, b'l' as u16, 0,
    ];

    let mut kernel_base: HMODULE = std::ptr::null_mut();
    let res = GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        kernelbase_name.as_ptr(),
        &mut kernel_base,
    );

    if res == 0 || kernel_base.is_null() {
        return Err("Could not get kernelbase.dll module handle".into());
    }

    let image_base = kernel_base as *const u8;
    let dos_header = &*(image_base as *const ImageDosHeader);
    if dos_header.e_magic != IMAGE_DOS_SIGNATURE || dos_header.e_lfanew <= 0 {
        return Err("Invalid DOS header in kernelbase.dll".into());
    }

    let nt_sig_ptr = image_base.add(dos_header.e_lfanew as usize) as *const u32;
    if *nt_sig_ptr != IMAGE_NT_SIGNATURE {
        return Err("Invalid NT signature in kernelbase.dll".into());
    }

    let opt_hdr_offset = dos_header.e_lfanew as usize + 4 + std::mem::size_of::<ImageFileHeader>();

    // Locate Import Directory in Optional Header
    #[cfg(target_pointer_width = "64")]
    let import_dir = {
        let opt_hdr = &*(image_base.add(opt_hdr_offset) as *const crate::pe::ImageOptionalHeader64);
        opt_hdr.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT]
    };

    #[cfg(target_pointer_width = "32")]
    let import_dir = {
        let opt_hdr = &*(image_base.add(opt_hdr_offset) as *const crate::pe::ImageOptionalHeader32);
        opt_hdr.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT]
    };

    if import_dir.virtual_address == 0 || import_dir.size == 0 {
        return Err("kernelbase.dll has no import directory".into());
    }

    let mut import_desc = image_base.add(import_dir.virtual_address as usize)
        as *const ImageImportDescriptor;

    while (*import_desc).name != 0 {
        let name_ptr = image_base.add((*import_desc).name as usize) as *const i8;
        if CStr::from_ptr(name_ptr).to_bytes().eq_ignore_ascii_case(b"ntdll.dll") {
            break;
        }
        import_desc = import_desc.add(1);
    }

    if (*import_desc).name == 0 {
        return Err("ntdll.dll import not found in kernelbase.dll".into());
    }

    let orig_thunk_rva = if (*import_desc).original_first_thunk != 0 {
        (*import_desc).original_first_thunk
    } else {
        (*import_desc).first_thunk
    };

    let mut orig_thunk = image_base.add(orig_thunk_rva as usize) as *const usize;
    let mut thunk = image_base.add((*import_desc).first_thunk as usize) as *mut usize;

    let target_symbol = b"RtlPcToFileHeader\0";

    while *orig_thunk != 0 {
        let val = *orig_thunk;
        if (val & IMAGE_ORDINAL_FLAG) == 0 {
            let func_name_ptr = image_base.add(val + 2) as *const u8;
            let c_str = CStr::from_ptr(func_name_ptr as *const i8);
            if c_str.to_bytes_with_nul() == target_symbol {
                break;
            }
        }
        orig_thunk = orig_thunk.add(1);
        thunk = thunk.add(1);
    }

    if *orig_thunk == 0 {
        return Err("RtlPcToFileHeader not found in kernelbase.dll imports".into());
    }

    let mut old_protect = 0u32;
    let protect_res = VirtualProtect(
        thunk as *const c_void,
        std::mem::size_of::<usize>(),
        PAGE_READWRITE,
        &mut old_protect,
    );

    if protect_res == 0 {
        return Err("VirtualProtect PAGE_READWRITE failed on kernelbase.dll IAT".into());
    }

    ORIGINAL_RTL_PC_TO_FILE_HEADER = *thunk;
    HOOK_THUNK_ADDRESS = thunk as usize;
    *thunk = hooked_rtl_pc_to_file_header as *const () as usize;

    let mut dummy = 0u32;
    VirtualProtect(
        thunk as *const c_void,
        std::mem::size_of::<usize>(),
        old_protect,
        &mut dummy,
    );

    Ok(())
}
