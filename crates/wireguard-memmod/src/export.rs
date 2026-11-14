/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use std::collections::HashMap;
use std::ffi::CStr;

use crate::error::MemModError;
use crate::pe::{ImageDataDirectory, ImageExportDirectory};

/// Parsed export directory metadata allowing fast O(1) lookup of exports.
#[derive(Debug, Clone)]
pub struct ExportTable {
    pub directory_rva: u32,
    pub directory_size: u32,
    pub base: u32,
    pub number_of_functions: u32,
    pub address_of_functions_rva: u32,
    pub name_to_ordinal: HashMap<String, u16>,
}

impl ExportTable {
    /// Builds the export index from an in-memory mapped PE image.
    ///
    /// # Safety
    /// The caller must ensure `code_base` points to the valid mapped image in memory.
    pub unsafe fn parse(
        code_base: *const u8,
        directory: &ImageDataDirectory,
    ) -> Result<Self, MemModError> {
        if directory.size == 0 || directory.virtual_address == 0 {
            return Err(MemModError::NoExportTable);
        }

        let export_dir = &*(code_base.add(directory.virtual_address as usize)
            as *const ImageExportDirectory);

        if export_dir.number_of_functions == 0 {
            return Err(MemModError::NoFunctionsExported);
        }

        let mut name_to_ordinal = HashMap::with_capacity(export_dir.number_of_names as usize);

        if export_dir.number_of_names > 0
            && export_dir.address_of_names != 0
            && export_dir.address_of_name_ordinals != 0
        {
            let names_rva_ptr = code_base.add(export_dir.address_of_names as usize) as *const u32;
            let ordinals_ptr = code_base.add(export_dir.address_of_name_ordinals as usize) as *const u16;

            for i in 0..export_dir.number_of_names as usize {
                let name_rva = *names_rva_ptr.add(i);
                let ord = *ordinals_ptr.add(i);
                let name_ptr = code_base.add(name_rva as usize) as *const i8;
                let c_name = CStr::from_ptr(name_ptr);
                if let Ok(name_str) = c_name.to_str() {
                    name_to_ordinal.insert(name_str.to_string(), ord);
                }
            }
        }

        Ok(ExportTable {
            directory_rva: directory.virtual_address,
            directory_size: directory.size,
            base: export_dir.base,
            number_of_functions: export_dir.number_of_functions,
            address_of_functions_rva: export_dir.address_of_functions,
            name_to_ordinal,
        })
    }

    /// Resolves an exported symbol by name.
    ///
    /// # Safety
    /// The caller must ensure `code_base` is valid mapped memory.
    pub unsafe fn proc_address_by_name(
        &self,
        code_base: *const u8,
        name: &str,
    ) -> Result<usize, MemModError> {
        let ordinal_idx = self
            .name_to_ordinal
            .get(name)
            .copied()
            .ok_or_else(|| MemModError::ExportNotFound(name.to_string()))?;

        if (ordinal_idx as u32) >= self.number_of_functions {
            return Err(MemModError::OrdinalOutOfBounds(
                ordinal_idx,
                self.base,
                self.number_of_functions,
            ));
        }

        let funcs_ptr = code_base.add(self.address_of_functions_rva as usize) as *const u32;
        let func_rva = *funcs_ptr.add(ordinal_idx as usize);

        Ok(code_base.add(func_rva as usize) as usize)
    }

    /// Resolves an exported symbol by ordinal.
    ///
    /// # Safety
    /// The caller must ensure `code_base` is valid mapped memory.
    pub unsafe fn proc_address_by_ordinal(
        &self,
        code_base: *const u8,
        ordinal: u16,
    ) -> Result<usize, MemModError> {
        let ord_u32 = ordinal as u32;
        if ord_u32 < self.base {
            return Err(MemModError::OrdinalOutOfBounds(
                ordinal,
                self.base,
                self.number_of_functions,
            ));
        }

        let idx = ord_u32 - self.base;
        if idx >= self.number_of_functions {
            return Err(MemModError::OrdinalOutOfBounds(
                ordinal,
                self.base,
                self.number_of_functions,
            ));
        }

        let funcs_ptr = code_base.add(self.address_of_functions_rva as usize) as *const u32;
        let func_rva = *funcs_ptr.add(idx as usize);

        Ok(code_base.add(func_rva as usize) as usize)
    }
}
