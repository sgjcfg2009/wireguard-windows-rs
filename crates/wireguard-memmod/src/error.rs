/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MemModError {
    #[error("Incomplete IMAGE_DOS_HEADER: buffer too small ({0} bytes)")]
    IncompleteDosHeader(usize),

    #[error("Not an MS-DOS binary (magic: 0x{0:04x}, expected: 0x5a4d)")]
    InvalidDosSignature(u16),

    #[error("Incomplete IMAGE_NT_HEADERS: e_lfanew ({0}) points outside image bounds ({1} bytes)")]
    IncompleteNtHeaders(i32, usize),

    #[error("Not an NT binary (signature: 0x{0:08x}, expected: 0x00004550)")]
    InvalidNtSignature(u32),

    #[error("Foreign platform (machine: 0x{0:04x}, host expected: 0x{1:04x})")]
    ForeignPlatform(u16, u16),

    #[error("Unaligned section: SectionAlignment 0x{0:x} is not a power of 2")]
    UnalignedSection(u32),

    #[error("No sections in PE file")]
    NoSections,

    #[error("Incomplete optional header: size {0} is smaller than required")]
    IncompleteOptionalHeader(u16),

    #[error("Incomplete data directory: count {0} < 16")]
    IncompleteDataDirectory(u32),

    #[error("Incomplete section headers")]
    IncompleteSectionHeaders,

    #[error("Section is not page-aligned")]
    SectionNotPageAligned,

    #[error("Incomplete section data: {0}")]
    IncompleteSectionData(String),

    #[error("Memory allocation failed (VirtualAlloc error code {0})")]
    VirtualAllocFailed(u32),

    #[error("Memory protection failed (VirtualProtect error code {0})")]
    VirtualProtectFailed(u32),

    #[error("Module relocation failed: {0}")]
    RelocationFailed(String),

    #[error("Failed to load dependency library '{0}' (error code {1})")]
    DependencyLoadFailed(String, u32),

    #[error("Failed to resolve function '{symbol}' from module '{module}' (error code {code})")]
    FunctionNotFound {
        module: String,
        symbol: String,
        code: u32,
    },

    #[error("DLL initialization (DllMain PROCESS_ATTACH) returned failure")]
    DllInitializationFailed,

    #[error("No export table found")]
    NoExportTable,

    #[error("No functions exported")]
    NoFunctionsExported,

    #[error("No functions exported by name")]
    NoNameExports,

    #[error("Exported function '{0}' not found")]
    ExportNotFound(String),

    #[error("Export ordinal {0} is out of bounds (base {1}, count {2})")]
    OrdinalOutOfBounds(u16, u32, u32),

    #[error("Hooking RtlPcToFileHeader failed: {0}")]
    HookFailed(String),

    #[error("Windows error {0}")]
    Windows(u32),
}
