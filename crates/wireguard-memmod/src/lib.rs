/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

pub mod embedded;
pub mod error;
pub mod export;
pub mod hook;
pub mod import;
pub mod module;
pub mod pe;
pub mod reloc;

pub use embedded::{EmbeddedDll, LazyProc};
pub use error::MemModError;
pub use export::ExportTable;
pub use module::MemoryModule;
pub use pe::{
    align_down, align_up, parse_and_validate_pe, ParsedPe, HOST_MACHINE, IMAGE_DOS_SIGNATURE,
    IMAGE_FILE_DLL, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_I386,
    IMAGE_NT_SIGNATURE,
};

#[cfg(test)]
mod tests {
    use super::*;
    use pe::*;

    #[test]
    fn test_align_helpers() {
        assert_eq!(align_down(0x1050, 0x1000), 0x1000);
        assert_eq!(align_down(0x1000, 0x1000), 0x1000);
        assert_eq!(align_down(0x0fff, 0x1000), 0x0000);

        assert_eq!(align_up(0x1050, 0x1000), 0x2000);
        assert_eq!(align_up(0x1000, 0x1000), 0x1000);
        assert_eq!(align_up(0x0001, 0x1000), 0x1000);
        assert_eq!(align_up(0x0000, 0x1000), 0x0000);
    }

    #[test]
    fn test_parse_truncated_dos_header() {
        let buf = [0u8; 16];
        let res = parse_and_validate_pe(&buf);
        match res {
            Err(MemModError::IncompleteDosHeader(len)) => assert_eq!(len, 16),
            other => panic!("Expected IncompleteDosHeader, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_invalid_dos_signature() {
        let mut buf = vec![0u8; 128];
        buf[0] = b'X';
        buf[1] = b'Y';
        let res = parse_and_validate_pe(&buf);
        match res {
            Err(MemModError::InvalidDosSignature(magic)) => assert_eq!(magic, 0x5958),
            other => panic!("Expected InvalidDosSignature, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_invalid_nt_signature() {
        let mut buf = vec![0u8; 512];
        let dos = ImageDosHeader {
            e_magic: IMAGE_DOS_SIGNATURE,
            e_cblp: 0,
            e_cp: 0,
            e_crlc: 0,
            e_cparhdr: 4,
            e_minalloc: 0,
            e_maxalloc: 0,
            e_ss: 0,
            e_sp: 0,
            e_csum: 0,
            e_ip: 0,
            e_cs: 0,
            e_lfarlc: 0,
            e_ovno: 0,
            e_res: [0; 4],
            e_oemid: 0,
            e_oeminfo: 0,
            e_res2: [0; 10],
            e_lfanew: 64,
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                &dos as *const _ as *const u8,
                buf.as_mut_ptr(),
                std::mem::size_of::<ImageDosHeader>(),
            );
        }
        // Write invalid NT sig (not "PE\0\0")
        buf[64] = b'N';
        buf[65] = b'E';
        buf[66] = 0;
        buf[67] = 0;

        let res = parse_and_validate_pe(&buf);
        match res {
            Err(MemModError::InvalidNtSignature(sig)) => assert_eq!(sig, 0x0000454E),
            other => panic!("Expected InvalidNtSignature, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_foreign_platform() {
        let mut buf = vec![0u8; 1024];
        let dos = ImageDosHeader {
            e_magic: IMAGE_DOS_SIGNATURE,
            e_cblp: 0,
            e_cp: 0,
            e_crlc: 0,
            e_cparhdr: 4,
            e_minalloc: 0,
            e_maxalloc: 0,
            e_ss: 0,
            e_sp: 0,
            e_csum: 0,
            e_ip: 0,
            e_cs: 0,
            e_lfarlc: 0,
            e_ovno: 0,
            e_res: [0; 4],
            e_oemid: 0,
            e_oeminfo: 0,
            e_res2: [0; 10],
            e_lfanew: 64,
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                &dos as *const _ as *const u8,
                buf.as_mut_ptr(),
                std::mem::size_of::<ImageDosHeader>(),
            );
        }
        // Write PE signature
        let pe_sig = IMAGE_NT_SIGNATURE;
        unsafe {
            std::ptr::copy_nonoverlapping(
                &pe_sig as *const _ as *const u8,
                buf.as_mut_ptr().add(64),
                4,
            );
        }
        // Write FileHeader with mismatched machine
        let mismatched_machine = if HOST_MACHINE == IMAGE_FILE_MACHINE_AMD64 {
            IMAGE_FILE_MACHINE_ARM64
        } else {
            IMAGE_FILE_MACHINE_AMD64
        };
        let file_hdr = ImageFileHeader {
            machine: mismatched_machine,
            number_of_sections: 1,
            time_date_stamp: 0,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            size_of_optional_header: 240,
            characteristics: IMAGE_FILE_DLL,
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                &file_hdr as *const _ as *const u8,
                buf.as_mut_ptr().add(68),
                std::mem::size_of::<ImageFileHeader>(),
            );
        }

        let res = parse_and_validate_pe(&buf);
        match res {
            Err(MemModError::ForeignPlatform(machine, expected)) => {
                assert_eq!(machine, mismatched_machine);
                assert_eq!(expected, HOST_MACHINE);
            }
            other => panic!("Expected ForeignPlatform, got {:?}", other),
        }
    }

    #[test]
    fn test_valid_synthetic_pe_parsing() {
        let section_alignment = 0x1000u32;
        let file_alignment = 0x200u32;
        let size_of_headers = 0x400u32;
        let raw_data_size = 0x200u32;
        let total_file_size = (size_of_headers + raw_data_size) as usize;
        let mut buf = vec![0u8; total_file_size];

        let dos = ImageDosHeader {
            e_magic: IMAGE_DOS_SIGNATURE,
            e_cblp: 0,
            e_cp: 0,
            e_crlc: 0,
            e_cparhdr: 4,
            e_minalloc: 0,
            e_maxalloc: 0,
            e_ss: 0,
            e_sp: 0,
            e_csum: 0,
            e_ip: 0,
            e_cs: 0,
            e_lfarlc: 0,
            e_ovno: 0,
            e_res: [0; 4],
            e_oemid: 0,
            e_oeminfo: 0,
            e_res2: [0; 10],
            e_lfanew: 64,
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                &dos as *const _ as *const u8,
                buf.as_mut_ptr(),
                std::mem::size_of::<ImageDosHeader>(),
            );
        }

        let pe_sig = IMAGE_NT_SIGNATURE;
        unsafe {
            std::ptr::copy_nonoverlapping(
                &pe_sig as *const _ as *const u8,
                buf.as_mut_ptr().add(64),
                4,
            );
        }

        #[cfg(target_pointer_width = "64")]
        let opt_size = std::mem::size_of::<ImageOptionalHeader64>() as u16;
        #[cfg(target_pointer_width = "32")]
        let opt_size = std::mem::size_of::<ImageOptionalHeader32>() as u16;

        let file_hdr = ImageFileHeader {
            machine: HOST_MACHINE,
            number_of_sections: 1,
            time_date_stamp: 0x12345678,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            size_of_optional_header: opt_size,
            characteristics: IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE,
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                &file_hdr as *const _ as *const u8,
                buf.as_mut_ptr().add(68),
                std::mem::size_of::<ImageFileHeader>(),
            );
        }

        let opt_offset = 68 + std::mem::size_of::<ImageFileHeader>();

        #[cfg(target_pointer_width = "64")]
        {
            let mut opt: ImageOptionalHeader64 = unsafe { std::mem::zeroed() };
            opt.magic = 0x20b;
            opt.image_base = 0x180000000;
            opt.section_alignment = section_alignment;
            opt.file_alignment = file_alignment;
            opt.size_of_image = 0x2000;
            opt.size_of_headers = size_of_headers;
            opt.number_of_rva_and_sizes = 16;
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &opt as *const _ as *const u8,
                    buf.as_mut_ptr().add(opt_offset),
                    std::mem::size_of::<ImageOptionalHeader64>(),
                );
            }
        }

        #[cfg(target_pointer_width = "32")]
        {
            let mut opt: ImageOptionalHeader32 = unsafe { std::mem::zeroed() };
            opt.magic = 0x10b;
            opt.image_base = 0x10000000;
            opt.section_alignment = section_alignment;
            opt.file_alignment = file_alignment;
            opt.size_of_image = 0x2000;
            opt.size_of_headers = size_of_headers;
            opt.number_of_rva_and_sizes = 16;
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &opt as *const _ as *const u8,
                    buf.as_mut_ptr().add(opt_offset),
                    std::mem::size_of::<ImageOptionalHeader32>(),
                );
            }
        }

        let sec_offset = opt_offset + opt_size as usize;
        let mut sec: ImageSectionHeader = unsafe { std::mem::zeroed() };
        sec.name = *b".text\0\0\0";
        sec.virtual_size = 0x1000;
        sec.virtual_address = 0x1000;
        sec.size_of_raw_data = raw_data_size;
        sec.pointer_to_raw_data = size_of_headers;
        sec.characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

        unsafe {
            std::ptr::copy_nonoverlapping(
                &sec as *const _ as *const u8,
                buf.as_mut_ptr().add(sec_offset),
                std::mem::size_of::<ImageSectionHeader>(),
            );
        }

        let parsed = parse_and_validate_pe(&buf).expect("Failed to parse valid synthetic PE");
        assert_eq!(parsed.machine, HOST_MACHINE);
        assert!(parsed.is_dll);
        assert_eq!(parsed.number_of_sections, 1);
        assert_eq!(parsed.section_alignment, section_alignment);
        assert_eq!(parsed.sections.len(), 1);
        assert_eq!(&parsed.sections[0].name[..5], b".text");
        assert_eq!(parsed.aligned_image_size, 0x2000);
    }
}
