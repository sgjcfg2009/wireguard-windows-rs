/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use crate::error::MemModError;

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
pub const IMAGE_NT_SIGNATURE: u32 = 0x00004550; // "PE\0\0"

pub const IMAGE_FILE_MACHINE_UNKNOWN: u16 = 0;
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
pub const IMAGE_FILE_MACHINE_ARM: u16 = 0x01c0;
pub const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01c4;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;

#[cfg(target_arch = "x86_64")]
pub const HOST_MACHINE: u16 = IMAGE_FILE_MACHINE_AMD64;
#[cfg(target_arch = "aarch64")]
pub const HOST_MACHINE: u16 = IMAGE_FILE_MACHINE_ARM64;
#[cfg(target_arch = "x86")]
pub const HOST_MACHINE: u16 = IMAGE_FILE_MACHINE_I386;
#[cfg(target_arch = "arm")]
pub const HOST_MACHINE: u16 = IMAGE_FILE_MACHINE_ARM;

pub const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
pub const IMAGE_FILE_32BIT_MACHINE: u16 = 0x0100;
pub const IMAGE_FILE_DLL: u16 = 0x2000;

pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
pub const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: usize = 7;
pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR: usize = 8;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

pub const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
pub const IMAGE_REL_BASED_HIGH: u16 = 1;
pub const IMAGE_REL_BASED_LOW: u16 = 2;
pub const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
pub const IMAGE_REL_BASED_HIGHADJ: u16 = 4;
pub const IMAGE_REL_BASED_ARM_MOV32: u16 = 5;
pub const IMAGE_REL_BASED_THUMB_MOV32: u16 = 7;
pub const IMAGE_REL_BASED_DIR64: u16 = 10;

pub const IMAGE_SCN_CNT_CODE: u32 = 0x00000020;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
pub const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x02000000;
pub const IMAGE_SCN_MEM_NOT_CACHED: u32 = 0x04000000;
pub const IMAGE_SCN_MEM_NOT_PAGED: u32 = 0x08000000;
pub const IMAGE_SCN_MEM_SHARED: u32 = 0x10000000;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

pub const DLL_PROCESS_DETACH: u32 = 0;
pub const DLL_PROCESS_ATTACH: u32 = 1;
pub const DLL_THREAD_ATTACH: u32 = 2;
pub const DLL_THREAD_DETACH: u32 = 3;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageDosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageOptionalHeader64 {
    pub magic: u16, // 0x20b
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageOptionalHeader32 {
    pub magic: u16, // 0x10b
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageBaseRelocation {
    pub virtual_address: u32,
    pub size_of_block: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageImportDescriptor {
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,
    pub first_thunk: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_name_ordinals: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageTlsDirectory64 {
    pub start_address_of_raw_data: u64,
    pub end_address_of_raw_data: u64,
    pub address_of_index: u64,
    pub address_of_callbacks: u64,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageTlsDirectory32 {
    pub start_address_of_raw_data: u32,
    pub end_address_of_raw_data: u32,
    pub address_of_index: u32,
    pub address_of_callbacks: u32,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RuntimeFunction {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_data: u32,
}

/// Parsed metadata extracted and validated from a raw PE image buffer.
#[derive(Debug, Clone)]
pub struct ParsedPe {
    pub e_lfanew: usize,
    pub machine: u16,
    pub is_dll: bool,
    pub number_of_sections: u16,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub address_of_entry_point: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub data_directories: [ImageDataDirectory; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
    pub sections: Vec<ImageSectionHeader>,
    pub aligned_image_size: usize,
}

/// Helper to round an integer down to a multiple of alignment.
#[inline]
pub fn align_down(value: usize, alignment: usize) -> usize {
    value & !(alignment - 1)
}

/// Helper to round an integer up to a multiple of alignment.
#[inline]
pub fn align_up(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

/// Validates and parses raw bytes into a `ParsedPe` descriptor.
pub fn parse_and_validate_pe(data: &[u8]) -> Result<ParsedPe, MemModError> {
    let size = data.len();
    if size < std::mem::size_of::<ImageDosHeader>() {
        return Err(MemModError::IncompleteDosHeader(size));
    }

    // Read DOS header
    let dos_header: ImageDosHeader = unsafe {
        std::ptr::read_unaligned(data.as_ptr() as *const ImageDosHeader)
    };

    if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
        return Err(MemModError::InvalidDosSignature(dos_header.e_magic));
    }

    if dos_header.e_lfanew < 0 {
        return Err(MemModError::IncompleteNtHeaders(dos_header.e_lfanew, size));
    }

    let e_lfanew = dos_header.e_lfanew as usize;
    // Check space for signature (4 bytes) + FileHeader (20 bytes)
    let opt_hdr_offset = e_lfanew
        .checked_add(4 + std::mem::size_of::<ImageFileHeader>())
        .ok_or(MemModError::IncompleteNtHeaders(dos_header.e_lfanew, size))?;
    if size < opt_hdr_offset {
        return Err(MemModError::IncompleteNtHeaders(dos_header.e_lfanew, size));
    }

    let nt_sig: u32 = unsafe {
        std::ptr::read_unaligned(data.as_ptr().add(e_lfanew) as *const u32)
    };

    if nt_sig != IMAGE_NT_SIGNATURE {
        return Err(MemModError::InvalidNtSignature(nt_sig));
    }

    let file_header: ImageFileHeader = unsafe {
        std::ptr::read_unaligned(
            data.as_ptr().add(e_lfanew + 4) as *const ImageFileHeader
        )
    };

    if file_header.machine != HOST_MACHINE {
        return Err(MemModError::ForeignPlatform(file_header.machine, HOST_MACHINE));
    }

    if file_header.number_of_sections == 0 {
        return Err(MemModError::NoSections);
    }

    let (
        image_base,
        section_alignment,
        file_alignment,
        size_of_image,
        size_of_headers,
        address_of_entry_point,
        size_of_initialized_data,
        size_of_uninitialized_data,
        data_directories,
    ) = {
        #[cfg(target_pointer_width = "64")]
        {
            if (file_header.size_of_optional_header as usize) < std::mem::size_of::<ImageOptionalHeader64>() {
                return Err(MemModError::IncompleteOptionalHeader(file_header.size_of_optional_header));
            }
            if size < opt_hdr_offset + std::mem::size_of::<ImageOptionalHeader64>() {
                return Err(MemModError::IncompleteOptionalHeader(file_header.size_of_optional_header));
            }
            let opt: ImageOptionalHeader64 = unsafe {
                std::ptr::read_unaligned(data.as_ptr().add(opt_hdr_offset) as *const ImageOptionalHeader64)
            };
            if opt.number_of_rva_and_sizes < IMAGE_NUMBEROF_DIRECTORY_ENTRIES as u32 {
                return Err(MemModError::IncompleteDataDirectory(opt.number_of_rva_and_sizes));
            }
            (
                opt.image_base,
                opt.section_alignment,
                opt.file_alignment,
                opt.size_of_image,
                opt.size_of_headers,
                opt.address_of_entry_point,
                opt.size_of_initialized_data,
                opt.size_of_uninitialized_data,
                opt.data_directory,
            )
        }

        #[cfg(target_pointer_width = "32")]
        {
            if (file_header.size_of_optional_header as usize) < std::mem::size_of::<ImageOptionalHeader32>() {
                return Err(MemModError::IncompleteOptionalHeader(file_header.size_of_optional_header));
            }
            if size < opt_hdr_offset + std::mem::size_of::<ImageOptionalHeader32>() {
                return Err(MemModError::IncompleteOptionalHeader(file_header.size_of_optional_header));
            }
            let opt: ImageOptionalHeader32 = unsafe {
                std::ptr::read_unaligned(data.as_ptr().add(opt_hdr_offset) as *const ImageOptionalHeader32)
            };
            if opt.number_of_rva_and_sizes < IMAGE_NUMBEROF_DIRECTORY_ENTRIES as u32 {
                return Err(MemModError::IncompleteDataDirectory(opt.number_of_rva_and_sizes));
            }
            (
                opt.image_base as u64,
                opt.section_alignment,
                opt.file_alignment,
                opt.size_of_image,
                opt.size_of_headers,
                opt.address_of_entry_point,
                opt.size_of_initialized_data,
                opt.size_of_uninitialized_data,
                opt.data_directory,
            )
        }
    };

    if section_alignment == 0 || (section_alignment & (section_alignment - 1)) != 0 {
        return Err(MemModError::UnalignedSection(section_alignment));
    }

    let section_headers_offset = opt_hdr_offset
        .checked_add(file_header.size_of_optional_header as usize)
        .ok_or(MemModError::IncompleteSectionHeaders)?;
    let total_sections_size =
        file_header.number_of_sections as usize * std::mem::size_of::<ImageSectionHeader>();
    let sections_end = section_headers_offset
        .checked_add(total_sections_size)
        .ok_or(MemModError::IncompleteSectionHeaders)?;
    if size < sections_end {
        return Err(MemModError::IncompleteSectionHeaders);
    }

    let mut sections = Vec::with_capacity(file_header.number_of_sections as usize);
    let mut last_section_end = 0usize;

    for i in 0..file_header.number_of_sections as usize {
        let sec_ptr = unsafe {
            data.as_ptr().add(section_headers_offset + i * std::mem::size_of::<ImageSectionHeader>())
                as *const ImageSectionHeader
        };
        let sec: ImageSectionHeader = unsafe { std::ptr::read_unaligned(sec_ptr) };

        let end_of_section = if sec.size_of_raw_data == 0 {
            sec.virtual_address as usize + section_alignment as usize
        } else {
            sec.virtual_address as usize + sec.size_of_raw_data as usize
        };

        if end_of_section > last_section_end {
            last_section_end = end_of_section;
        }

        sections.push(sec);
    }

    let aligned_image_size = align_up(size_of_image as usize, section_alignment as usize);
    let expected_last_end = align_up(last_section_end, section_alignment as usize);

    if aligned_image_size != expected_last_end {
        return Err(MemModError::SectionNotPageAligned);
    }

    Ok(ParsedPe {
        e_lfanew,
        machine: file_header.machine,
        is_dll: (file_header.characteristics & IMAGE_FILE_DLL) != 0,
        number_of_sections: file_header.number_of_sections,
        size_of_optional_header: file_header.size_of_optional_header,
        characteristics: file_header.characteristics,
        image_base,
        section_alignment,
        file_alignment,
        size_of_image,
        size_of_headers,
        address_of_entry_point,
        size_of_initialized_data,
        size_of_uninitialized_data,
        data_directories,
        sections,
        aligned_image_size,
    })
}
