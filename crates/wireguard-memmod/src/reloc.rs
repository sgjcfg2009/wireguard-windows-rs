/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use crate::error::MemModError;
use crate::pe::{
    ImageDataDirectory, ImageBaseRelocation, IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_DIR64,
    IMAGE_REL_BASED_HIGH, IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_LOW,
    IMAGE_REL_BASED_THUMB_MOV32,
};

/// Performs base relocations on an in-memory mapped PE image.
///
/// # Safety
/// The caller must ensure that `code_base` points to committed writable memory
/// containing the mapped image of size at least encompassing the relocation directory.
pub unsafe fn perform_base_relocation(
    code_base: *mut u8,
    directory: &ImageDataDirectory,
    delta: isize,
) -> Result<bool, MemModError> {
    if directory.size == 0 || directory.virtual_address == 0 {
        return Ok(delta == 0);
    }

    let reloc_base = code_base.add(directory.virtual_address as usize);
    let reloc_end = reloc_base.add(directory.size as usize);

    let mut current_hdr_ptr = reloc_base;
    let hdr_size = std::mem::size_of::<ImageBaseRelocation>();

    while current_hdr_ptr.add(hdr_size) <= reloc_end {
        let hdr = &*(current_hdr_ptr as *const ImageBaseRelocation);
        if hdr.virtual_address == 0 {
            break;
        }

        if (hdr.size_of_block as usize) < hdr_size {
            return Err(MemModError::RelocationFailed(
                "Invalid relocation block size: smaller than header".into(),
            ));
        }

        let block_end = current_hdr_ptr.add(hdr.size_of_block as usize);
        if block_end > reloc_end {
            return Err(MemModError::RelocationFailed(
                "Relocation block exceeds directory bounds".into(),
            ));
        }

        let dest = code_base.add(hdr.virtual_address as usize);
        let entry_count = (hdr.size_of_block as usize - hdr_size) / std::mem::size_of::<u16>();
        let entries_ptr = current_hdr_ptr.add(hdr_size) as *const u16;

        for i in 0..entry_count {
            let rel_info = *entries_ptr.add(i);
            let rel_type = rel_info >> 12;
            let rel_offset = (rel_info & 0x0fff) as usize;
            let target_addr = dest.add(rel_offset);

            match rel_type {
                IMAGE_REL_BASED_ABSOLUTE => {
                    // Skip relocation padding
                }
                IMAGE_REL_BASED_LOW => {
                    let ptr = target_addr as *mut u16;
                    *ptr = (*ptr).wrapping_add((delta as usize & 0xffff) as u16);
                }
                IMAGE_REL_BASED_HIGH => {
                    let ptr = target_addr as *mut u16;
                    *ptr = (*ptr).wrapping_add(((delta as usize as u32) >> 16) as u16);
                }
                IMAGE_REL_BASED_HIGHLOW => {
                    let ptr = target_addr as *mut u32;
                    *ptr = (*ptr).wrapping_add(delta as usize as u32);
                }
                IMAGE_REL_BASED_DIR64 => {
                    let ptr = target_addr as *mut u64;
                    *ptr = (*ptr).wrapping_add(delta as usize as u64);
                }
                IMAGE_REL_BASED_THUMB_MOV32 => {
                    let ptr = target_addr as *mut u32;
                    let inst = *ptr;
                    let mut imm16 = ((inst << 1) & 0x0800)
                        | ((inst << 12) & 0xf000)
                        | ((inst >> 20) & 0x0700)
                        | ((inst >> 16) & 0x00ff);

                    if (inst & 0x8000fbf0) != 0x0000f240 {
                        return Err(MemModError::RelocationFailed(format!(
                            "Wrong Thumb2 instruction 0x{:08x}, expected MOVW",
                            inst
                        )));
                    }

                    imm16 = imm16.wrapping_add((delta as usize as u32) & 0xffff);
                    let hi_delta = (((delta as usize as u32) & 0xffff0000) >> 16)
                        .wrapping_add((imm16 & 0xffff0000) >> 16);

                    *ptr = (inst & 0x8f00fbf0)
                        | ((imm16 >> 1) & 0x0400)
                        | ((imm16 >> 12) & 0x000f)
                        | ((imm16 << 20) & 0x70000000)
                        | ((imm16 << 16) & 0x00ff0000);

                    if hi_delta != 0 {
                        let ptr2 = target_addr.add(4) as *mut u32;
                        let inst2 = *ptr2;
                        let mut imm16_2 = ((inst2 << 1) & 0x0800)
                            | ((inst2 << 12) & 0xf000)
                            | ((inst2 >> 20) & 0x0700)
                            | ((inst2 >> 16) & 0x00ff);

                        if (inst2 & 0x8000fbf0) != 0x0000f2c0 {
                            return Err(MemModError::RelocationFailed(format!(
                                "Wrong Thumb2 instruction 0x{:08x}, expected MOVT",
                                inst2
                            )));
                        }

                        imm16_2 = imm16_2.wrapping_add(hi_delta);
                        if imm16_2 > 0xffff {
                            return Err(MemModError::RelocationFailed(format!(
                                "Resulting immediate value won't fit: 0x{:08x}",
                                imm16_2
                            )));
                        }

                        *ptr2 = (inst2 & 0x8f00fbf0)
                            | ((imm16_2 >> 1) & 0x0400)
                            | ((imm16_2 >> 12) & 0x000f)
                            | ((imm16_2 << 20) & 0x70000000)
                            | ((imm16_2 << 16) & 0x00ff0000);
                    }
                }
                other => {
                    return Err(MemModError::RelocationFailed(format!(
                        "Unsupported relocation type: {}",
                        other
                    )));
                }
            }
        }

        current_hdr_ptr = block_end;
    }

    Ok(true)
}
