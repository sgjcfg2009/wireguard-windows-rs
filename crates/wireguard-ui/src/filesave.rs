// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
// Rust implementation: 2026 WireGuard Rust Contributors.

//! File Open / Save and Configuration Import / Export helpers for WireGuard Windows.
//!
//! Faithful Rust port of `wireguard-windows/ui/filesave.go` and the import/export
//! handlers in `wireguard-windows/ui/tunnelspage.go`.
//! Uses native Win32 common dialogs (`GetOpenFileNameW`, `GetSaveFileNameW`) and
//! pure-Rust ZIP compression / extraction with Win32 decompressor fallback.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tracing::{debug, info};

use windows_sys::Win32::Foundation::{FreeLibrary, BOOL, HWND};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::Win32::UI::Controls::Dialogs::{
    GetOpenFileNameW, GetSaveFileNameW, OFN_ALLOWMULTISELECT, OFN_EXPLORER, OFN_FILEMUSTEXIST,
    OFN_NOCHANGEDIR, OFN_OVERWRITEPROMPT, OFN_PATHMUSTEXIST, OPENFILENAMEW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, IDYES, MB_DEFBUTTON2, MB_ICONWARNING, MB_OK, MB_YESNO,
};

use wireguard_conf::parser::from_wg_quick_with_unknown_encoding;
use wireguard_conf::writer::to_wg_quick;
use wireguard_conf::{tunnel_name_is_valid, TunnelConfig};
use wireguard_manager::ConfigDir;

use crate::win32_util::{encode_wide_null_fixed, utf16_null_to_string, with_wide_null};

/// Converts a double-null-terminated filter string (separated by null characters) to UTF-16.
fn filter_to_wide(filters: &[(&str, &str)]) -> Vec<u16> {
    let mut out = Vec::new();
    for (label, pattern) in filters {
        out.extend(label.encode_utf16());
        out.push(0);
        out.extend(pattern.encode_utf16());
        out.push(0);
    }
    out.push(0); // terminating second null
    out
}

/// Displays a warning `MessageBoxW` with OK button.
fn show_warning_message(parent: HWND, title: &str, msg: &str) {
    with_wide_null(title, |title_ptr| {
        with_wide_null(msg, |msg_ptr| unsafe {
            MessageBoxW(parent, msg_ptr, title_ptr, MB_OK | MB_ICONWARNING);
        });
    });
}

/// Displays a Yes/No warning `MessageBoxW` defaulting to No and returns `true` if `IDYES`.
fn confirm_warning_yes_no(parent: HWND, title: &str, msg: &str) -> bool {
    let res = with_wide_null(title, |title_ptr| {
        with_wide_null(msg, |msg_ptr| unsafe {
            MessageBoxW(
                parent,
                msg_ptr,
                title_ptr,
                MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING,
            )
        })
    });
    res == IDYES
}

/// Prompts the user to select one or more tunnel configuration files (`*.conf`, `*.zip`).
///
/// Matches `(*TunnelsPage).onImport()` from `tunnelspage.go`.
/// Returns a list of paths selected by the user. If the user cancels, returns an empty `Vec`.
pub fn select_import_config_files(parent: HWND) -> Vec<PathBuf> {
    const BUFFER_SIZE: usize = 65536;
    let mut file_buf = vec![0u16; BUFFER_SIZE];

    let filter = filter_to_wide(&[
        ("Configuration Files (*.zip, *.conf)", "*.zip;*.conf"),
        ("All Files (*.*)", "*.*"),
    ]);

    let success = with_wide_null("Import tunnel(s) from file", |title_ptr| {
        let mut ofn: OPENFILENAMEW = unsafe { std::mem::zeroed() };
        ofn.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
        ofn.hwndOwner = parent;
        ofn.lpstrFilter = filter.as_ptr();
        ofn.lpstrFile = file_buf.as_mut_ptr();
        ofn.nMaxFile = BUFFER_SIZE as u32;
        ofn.lpstrTitle = title_ptr;
        ofn.Flags = OFN_EXPLORER
            | OFN_ALLOWMULTISELECT
            | OFN_FILEMUSTEXIST
            | OFN_PATHMUSTEXIST
            | OFN_NOCHANGEDIR;

        unsafe { GetOpenFileNameW(&mut ofn) }
    });
    if success == 0 {
        return Vec::new();
    }

    parse_multi_select_buffer(&file_buf)
}

/// Parses the Win32 multi-select null-separated UTF-16 buffer.
///
/// In Explorer-style multi-select dialogs:
/// - Single file: `C:\path\to\file.conf\0\0`
/// - Multiple files: `C:\path\to\dir\0file1.conf\0file2.conf\0\0`
fn parse_multi_select_buffer(buf: &[u16]) -> Vec<PathBuf> {
    let mut strings = Vec::new();
    let mut current = Vec::new();

    for &code in buf {
        if code == 0 {
            if current.is_empty() {
                break;
            }
            if let Ok(s) = String::from_utf16(&current) {
                strings.push(s);
            }
            current.clear();
        } else {
            current.push(code);
        }
    }

    if strings.is_empty() {
        return Vec::new();
    }

    if strings.len() == 1 {
        // Single file selected
        return vec![PathBuf::from(&strings[0])];
    }

    // Multiple files selected: strings[0] is the directory
    let dir = Path::new(&strings[0]);
    strings[1..]
        .iter()
        .map(|name| dir.join(name))
        .collect()
}

/// Shared save-file dialog helper enforcing `required_ext`.
fn select_save_path(
    parent: HWND,
    default_name: &str,
    filters: &[(&str, &str)],
    title: &str,
    required_ext: &str,
) -> Option<PathBuf> {
    const BUFFER_SIZE: usize = 1024;
    let mut file_buf = vec![0u16; BUFFER_SIZE];
    encode_wide_null_fixed(default_name, &mut file_buf);

    let filter = filter_to_wide(filters);

    let success = with_wide_null(title, |title_ptr| {
        with_wide_null(required_ext, |def_ext_ptr| {
            let mut ofn: OPENFILENAMEW = unsafe { std::mem::zeroed() };
            ofn.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
            ofn.hwndOwner = parent;
            ofn.lpstrFilter = filter.as_ptr();
            ofn.lpstrFile = file_buf.as_mut_ptr();
            ofn.nMaxFile = BUFFER_SIZE as u32;
            ofn.lpstrTitle = title_ptr;
            ofn.lpstrDefExt = def_ext_ptr;
            ofn.Flags = OFN_EXPLORER | OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

            unsafe { GetSaveFileNameW(&mut ofn) }
        })
    });
    if success == 0 {
        return None;
    }

    let mut path = PathBuf::from(utf16_null_to_string(&file_buf));
    if let Some(ext) = path.extension() {
        if !ext.eq_ignore_ascii_case(required_ext) {
            let mut name = path.file_name().unwrap_or_default().to_os_string();
            name.push(".");
            name.push(required_ext);
            path.set_file_name(name);
        }
    } else {
        path.set_extension(required_ext);
    }

    Some(path)
}

/// Prompts the user for a destination path to export all tunnels into a ZIP archive.
///
/// Matches `(*TunnelsPage).onExportTunnels()` from `tunnelspage.go`.
pub fn select_export_zip_path(parent: HWND) -> Option<PathBuf> {
    select_save_path(
        parent,
        "wireguard-export.zip",
        &[
            ("Configuration ZIP Files (*.zip)", "*.zip"),
            ("All Files (*.*)", "*.*"),
        ],
        "Export tunnels to zip",
        "zip",
    )
}

/// Prompts the user for a destination path to export log output as a text file (`*.txt`).
///
/// Matches `(*LogPage).onSave()` from `logpage.go`.
pub fn select_save_log_path(parent: HWND) -> Option<PathBuf> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let default_name = format!("wireguard-log-{}.txt", secs);

    select_save_path(
        parent,
        &default_name,
        &[("Text Files (*.txt)", "*.txt"), ("All Files (*.*)", "*.*")],
        "Export log to file",
        "txt",
    )
}

/// Helper that prompts the user with a Win32 `MessageBoxW` if `file_path` already exists,
/// and executes the writing closure once confirmed.
///
/// Faithful port of `writeFileWithOverwriteHandling` from `filesave.go`.
pub fn write_file_with_overwrite_handling<F>(
    parent: HWND,
    file_path: &Path,
    write: F,
) -> bool
where
    F: FnOnce(&mut fs::File) -> io::Result<()>,
{
    if file_path.exists() {
        let msg = format!(
            "File ‘{}’ already exists.\n\nDo you want to overwrite it?",
            file_path.display()
        );
        if !confirm_warning_yes_no(parent, "Writing file failed", &msg) {
            return false;
        }
    }

    match fs::File::create(file_path) {
        Ok(mut f) => match write(&mut f) {
            Ok(()) => true,
            Err(e) => {
                let err_msg = format!("Could not write to file: {}", e);
                show_warning_message(parent, "Writing file failed", &err_msg);
                false
            }
        },
        Err(e) => {
            let err_msg = format!("Could not create file: {}", e);
            show_warning_message(parent, "Writing file failed", &err_msg);
            false
        }
    }
}

/// Collects all `.conf` files from the configurations directory and zips them into `dest_zip`.
///
/// Matches `(*TunnelsPage).exportTunnels` from `tunnelspage.go`.
pub fn export_tunnels_to_zip(dest_zip: &Path) -> io::Result<()> {
    let mut zip_writer = ZipArchiveWriter::new();
    let mut exported_count = 0;

    // First attempt to load configurations via ConfigDir manager
    if let Ok(config_dir) = ConfigDir::open_default() {
        if let Ok(tunnel_names) = config_dir.list_tunnel_names() {
            for name in tunnel_names {
                if let Ok(cfg) = config_dir.load_config(&name) {
                    let quick_conf = to_wg_quick(&cfg);
                    let entry_name = format!("{}.conf", name);
                    zip_writer.add_file(&entry_name, quick_conf.as_bytes());
                    exported_count += 1;
                }
            }
        }
    }

    // Fallback: search directory for raw unencrypted .conf files
    if exported_count == 0 {
        if let Ok(root) = wireguard_manager::ConfigDir::resolve_data_directory(false) {
            let conf_dir = root.join("Configurations");
            if conf_dir.exists() {
                if let Ok(entries) = fs::read_dir(&conf_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_file() {
                            if let Some(ext) = path.extension() {
                                if ext.eq_ignore_ascii_case("conf") {
                                    if let Ok(bytes) = fs::read(&path) {
                                        let name = path
                                            .file_name()
                                            .unwrap_or_default()
                                            .to_string_lossy()
                                            .into_owned();
                                        zip_writer.add_file(&name, &bytes);
                                        exported_count += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if exported_count == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No tunnel configurations found to export",
        ));
    }

    let zip_bytes = zip_writer.finish();
    fs::write(dest_zip, zip_bytes)?;
    info!(
        "Exported {} tunnel configuration(s) to {:?}",
        exported_count, dest_zip
    );
    Ok(())
}

/// Copies or extracts a `.conf` or `.zip` configuration file into the configurations directory.
///
/// Prompts the user before overwriting existing tunnels with the same name.
/// Parses one or more tunnel configurations from a `.conf` or `.zip` file without
/// prompting or writing to disk.
pub(crate) fn collect_import_configs(file_path: &Path) -> io::Result<Vec<TunnelConfig>> {
    let ext = file_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    match ext.as_str() {
        "conf" => Ok(vec![parse_single_conf(file_path)?]),
        "zip" => parse_from_zip(file_path),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Unsupported configuration file format: .{}", other),
        )),
    }
}

/// Imports one or more tunnel configurations from a `.conf` or `.zip` file.
///
/// Returns the name of the imported tunnel (or primary tunnel).
pub fn import_tunnel_file(file_path: &Path) -> io::Result<String> {
    let configs = collect_import_configs(file_path)?;
    let mut imported_names = Vec::new();
    let mut last_err = None;

    for parsed in configs {
        match save_tunnel_with_overwrite_prompt(parsed) {
            Ok(imported) => imported_names.push(imported),
            Err(e) => last_err = Some(e),
        }
    }

    if imported_names.is_empty() {
        if let Some(e) = last_err {
            return Err(e);
        }
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Could not import any configuration files",
        ));
    }

    if imported_names.len() == 1 {
        Ok(imported_names.remove(0))
    } else {
        Ok(format!(
            "Imported {} tunnels: {}",
            imported_names.len(),
            imported_names.join(", ")
        ))
    }
}

/// Parses a single `.conf` file into a `TunnelConfig`.
fn parse_single_conf(path: &Path) -> io::Result<TunnelConfig> {
    let raw_name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid file name"))?;

    let name = raw_name.trim();
    if !tunnel_name_is_valid(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("‘{}’ is not a valid tunnel name", name),
        ));
    }

    let bytes = fs::read(path)?;
    let content = String::from_utf8_lossy(&bytes);

    from_wg_quick_with_unknown_encoding(content.as_bytes(), name)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Parse error: {}", e)))
}

/// Parses one or more `.conf` files from a `.zip` archive.
fn parse_from_zip(zip_path: &Path) -> io::Result<Vec<TunnelConfig>> {
    let zip_data = fs::read(zip_path)?;
    let entries = read_zip_entries(&zip_data)?;

    let mut conf_entries: Vec<ZipFileEntry> = entries
        .into_iter()
        .filter(|e| {
            Path::new(&e.name)
                .extension()
                .map(|ext| ext.eq_ignore_ascii_case("conf"))
                .unwrap_or(false)
        })
        .collect();

    if conf_entries.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No .conf configuration files found in ZIP archive",
        ));
    }

    // Sort to keep consistent order
    conf_entries.sort_by(|a, b| a.name.cmp(&b.name));

    let mut parsed_configs = Vec::new();
    let mut last_err = None;

    for entry in conf_entries {
        let entry_path = Path::new(&entry.name);
        let raw_stem = match entry_path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s,
            None => continue,
        };

        let name = raw_stem.trim();
        if !tunnel_name_is_valid(name) {
            continue;
        }

        let content = String::from_utf8_lossy(&entry.data);
        match from_wg_quick_with_unknown_encoding(content.as_bytes(), name) {
            Ok(parsed) => parsed_configs.push(parsed),
            Err(e) => {
                last_err = Some(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Parse error in {}: {}", entry.name, e),
                ));
            }
        }
    }

    if parsed_configs.is_empty() {
        if let Some(e) = last_err {
            return Err(e);
        }
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Could not import any configuration files from ZIP",
        ));
    }

    Ok(parsed_configs)
}

/// Saves a parsed tunnel configuration to disk with overwrite confirmation.
fn save_tunnel_with_overwrite_prompt(config: TunnelConfig) -> io::Result<String> {
    let config_dir = ConfigDir::open_default().map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to open config directory: {}", e),
        )
    })?;

    let existing_names = config_dir.list_tunnel_names().unwrap_or_default();
    let name_lower = config.name.to_lowercase();
    let exists = existing_names
        .iter()
        .any(|existing| existing.to_lowercase() == name_lower);

    if exists {
        let msg = format!(
            "Another tunnel already exists with the name ‘{}’.\n\nDo you want to overwrite it?",
            config.name
        );
        if !confirm_warning_yes_no(std::ptr::null_mut(), "Tunnel already exists", &msg) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("Tunnel ‘{}’ already exists; overwrite cancelled", config.name),
            ));
        }
    }

    let name = config.name.clone();
    config_dir
        .save_config(&config, true)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Save config error: {}", e)))?;

    info!("Successfully imported tunnel ‘{}’", name);
    Ok(name)
}

// =========================================================================
// Pure Rust ZIP Archive Creator and Reader
// =========================================================================

/// Compile-time IEEE 802.3 CRC-32 table generator.
const fn make_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut j = 0;
        while j < 8 {
            if (c & 1) != 0 {
                c = 0xEDB8_8320 ^ (c >> 1);
            } else {
                c >>= 1;
            }
            j += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

static CRC32_TABLE: [u32; 256] = make_crc_table();

/// Calculates the standard CRC-32 checksum of a byte slice.
pub fn calculate_crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        let idx = ((crc ^ (b as u32)) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[idx];
    }
    !crc
}

/// Metadata entry recorded for each file stored in the ZIP archive.
struct ZipCdEntry {
    name: String,
    crc32: u32,
    size: u32,
    offset: u32,
}

/// Pure-Rust standard ZIP archive writer (compression method 0 = STORE).
pub struct ZipArchiveWriter {
    data: Vec<u8>,
    entries: Vec<ZipCdEntry>,
}

impl Default for ZipArchiveWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl ZipArchiveWriter {
    /// Creates a new in-memory ZIP writer.
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            entries: Vec::new(),
        }
    }

    /// Adds a file entry to the ZIP archive.
    pub fn add_file(&mut self, name: &str, content: &[u8]) {
        let offset = self.data.len() as u32;
        let crc = calculate_crc32(content);
        let size = content.len() as u32;
        let name_bytes = name.as_bytes();

        // Local file header signature: PK\x03\x04
        self.data.extend_from_slice(&0x04034b50u32.to_le_bytes());
        self.data.extend_from_slice(&20u16.to_le_bytes()); // version needed: 2.0
        self.data.extend_from_slice(&0x0800u16.to_le_bytes()); // flags: UTF-8 filename
        self.data.extend_from_slice(&0u16.to_le_bytes()); // compression method: 0 (store)
        self.data.extend_from_slice(&0u16.to_le_bytes()); // dos time
        self.data.extend_from_slice(&0u16.to_le_bytes()); // dos date
        self.data.extend_from_slice(&crc.to_le_bytes());
        self.data.extend_from_slice(&size.to_le_bytes()); // compressed size
        self.data.extend_from_slice(&size.to_le_bytes()); // uncompressed size
        self.data.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        self.data.extend_from_slice(&0u16.to_le_bytes()); // extra field length
        self.data.extend_from_slice(name_bytes);
        self.data.extend_from_slice(content);

        self.entries.push(ZipCdEntry {
            name: name.to_string(),
            crc32: crc,
            size,
            offset,
        });
    }

    /// Finalizes the central directory and writes the End of Central Directory record.
    pub fn finish(mut self) -> Vec<u8> {
        let cd_offset = self.data.len() as u32;

        for entry in &self.entries {
            let name_bytes = entry.name.as_bytes();
            // Central directory file header signature: PK\x01\x02
            self.data.extend_from_slice(&0x02014b50u32.to_le_bytes());
            self.data.extend_from_slice(&20u16.to_le_bytes()); // version made by
            self.data.extend_from_slice(&20u16.to_le_bytes()); // version needed
            self.data.extend_from_slice(&0x0800u16.to_le_bytes()); // UTF-8
            self.data.extend_from_slice(&0u16.to_le_bytes()); // method 0 (store)
            self.data.extend_from_slice(&0u16.to_le_bytes()); // dos time
            self.data.extend_from_slice(&0u16.to_le_bytes()); // dos date
            self.data.extend_from_slice(&entry.crc32.to_le_bytes());
            self.data.extend_from_slice(&entry.size.to_le_bytes());
            self.data.extend_from_slice(&entry.size.to_le_bytes());
            self.data.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            self.data.extend_from_slice(&0u16.to_le_bytes()); // extra field length
            self.data.extend_from_slice(&0u16.to_le_bytes()); // comment length
            self.data.extend_from_slice(&0u16.to_le_bytes()); // disk number start
            self.data.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
            self.data.extend_from_slice(&0x81b60020u32.to_le_bytes()); // external attributes
            self.data.extend_from_slice(&entry.offset.to_le_bytes());
            self.data.extend_from_slice(name_bytes);
        }

        let cd_size = (self.data.len() as u32) - cd_offset;
        let count = self.entries.len() as u16;

        // End of central directory record signature: PK\x05\x06
        self.data.extend_from_slice(&0x06054b50u32.to_le_bytes());
        self.data.extend_from_slice(&0u16.to_le_bytes()); // disk number
        self.data.extend_from_slice(&0u16.to_le_bytes()); // start disk
        self.data.extend_from_slice(&count.to_le_bytes()); // records on this disk
        self.data.extend_from_slice(&count.to_le_bytes()); // total records
        self.data.extend_from_slice(&cd_size.to_le_bytes());
        self.data.extend_from_slice(&cd_offset.to_le_bytes());
        self.data.extend_from_slice(&0u16.to_le_bytes()); // zip comment length

        self.data
    }
}

/// An extracted file entry from a ZIP archive.
#[derive(Debug, Clone)]
pub struct ZipFileEntry {
    pub name: String,
    pub data: Vec<u8>,
}

/// Reads all entries from a standard ZIP archive buffer.
pub fn read_zip_entries(zip_bytes: &[u8]) -> io::Result<Vec<ZipFileEntry>> {
    if zip_bytes.len() < 22 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "ZIP file is too small to contain an EOCD record",
        ));
    }

    // Locate EOCD record signature: PK\x05\x06 (0x06054b50)
    let mut eocd_pos = None;
    let max_comment = 65535.min(zip_bytes.len() - 22);
    for i in 0..=max_comment {
        let pos = zip_bytes.len() - 22 - i;
        if &zip_bytes[pos..pos + 4] == b"PK\x05\x06" {
            eocd_pos = Some(pos);
            break;
        }
    }

    let eocd = match eocd_pos {
        Some(pos) => pos,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Could not find End of Central Directory in ZIP file",
            ))
        }
    };

    let total_records = u16::from_le_bytes([zip_bytes[eocd + 10], zip_bytes[eocd + 11]]) as usize;
    let cd_offset = u32::from_le_bytes([
        zip_bytes[eocd + 16],
        zip_bytes[eocd + 17],
        zip_bytes[eocd + 18],
        zip_bytes[eocd + 19],
    ]) as usize;

    let mut cursor = cd_offset;
    let mut results = Vec::with_capacity(total_records);

    for _ in 0..total_records {
        if cursor + 46 > zip_bytes.len() {
            break;
        }
        if &zip_bytes[cursor..cursor + 4] != b"PK\x01\x02" {
            break;
        }

        let compression = u16::from_le_bytes([zip_bytes[cursor + 10], zip_bytes[cursor + 11]]);
        let comp_size = u32::from_le_bytes([
            zip_bytes[cursor + 20],
            zip_bytes[cursor + 21],
            zip_bytes[cursor + 22],
            zip_bytes[cursor + 23],
        ]) as usize;
        let uncomp_size = u32::from_le_bytes([
            zip_bytes[cursor + 24],
            zip_bytes[cursor + 25],
            zip_bytes[cursor + 26],
            zip_bytes[cursor + 27],
        ]) as usize;
        let name_len = u16::from_le_bytes([zip_bytes[cursor + 28], zip_bytes[cursor + 29]]) as usize;
        let extra_len = u16::from_le_bytes([zip_bytes[cursor + 30], zip_bytes[cursor + 31]]) as usize;
        let comment_len =
            u16::from_le_bytes([zip_bytes[cursor + 32], zip_bytes[cursor + 33]]) as usize;
        let local_offset = u32::from_le_bytes([
            zip_bytes[cursor + 42],
            zip_bytes[cursor + 43],
            zip_bytes[cursor + 44],
            zip_bytes[cursor + 45],
        ]) as usize;

        cursor += 46;
        if cursor + name_len > zip_bytes.len() {
            break;
        }
        let name = String::from_utf8_lossy(&zip_bytes[cursor..cursor + name_len]).into_owned();
        cursor += name_len + extra_len + comment_len;

        // Parse Local File Header to reach payload data
        if local_offset + 30 > zip_bytes.len() {
            continue;
        }
        if &zip_bytes[local_offset..local_offset + 4] != b"PK\x03\x04" {
            continue;
        }
        let local_name_len =
            u16::from_le_bytes([zip_bytes[local_offset + 26], zip_bytes[local_offset + 27]]) as usize;
        let local_extra_len =
            u16::from_le_bytes([zip_bytes[local_offset + 28], zip_bytes[local_offset + 29]]) as usize;
        let data_start = local_offset + 30 + local_name_len + local_extra_len;

        if data_start + comp_size > zip_bytes.len() {
            continue;
        }
        let raw_payload = &zip_bytes[data_start..data_start + comp_size];

        let extracted_data = match compression {
            0 => raw_payload.to_vec(), // STORE
            8 => decompress_deflate(raw_payload, uncomp_size)?, // DEFLATE
            other => {
                debug!("Skipping entry '{}': unsupported compression method {}", name, other);
                continue;
            }
        };

        results.push(ZipFileEntry {
            name,
            data: extracted_data,
        });
    }

    Ok(results)
}

type CreateDecompressorFn = unsafe extern "system" fn(
    u32,
    *const core::ffi::c_void,
    *mut isize,
) -> BOOL;
type DecompressFn = unsafe extern "system" fn(
    isize,
    *const u8,
    usize,
    *mut u8,
    usize,
    *mut usize,
) -> BOOL;
type CloseDecompressorFn = unsafe extern "system" fn(isize) -> BOOL;

#[derive(Clone, Copy)]
struct CabinetDecompressorApi {
    _module: usize,
    create_decompressor: CreateDecompressorFn,
    decompress: DecompressFn,
    close_decompressor: CloseDecompressorFn,
}

#[derive(Clone, Copy)]
enum CabinetLoadError {
    DllNotFound,
    MissingExports,
}

/// Loads `cabinet.dll` and resolves the Compression API functions once for the
/// lifetime of the process.
fn cabinet_decompressor_api() -> io::Result<&'static CabinetDecompressorApi> {
    static CABINET_API: OnceLock<Result<CabinetDecompressorApi, CabinetLoadError>> =
        OnceLock::new();

    match CABINET_API.get_or_init(|| unsafe {
        let h_module = with_wide_null("cabinet.dll", |dll_ptr| LoadLibraryW(dll_ptr));
        if h_module.is_null() {
            return Err(CabinetLoadError::DllNotFound);
        }

        let p_create = GetProcAddress(h_module, b"CreateDecompressor\0".as_ptr());
        let p_decompress = GetProcAddress(h_module, b"Decompress\0".as_ptr());
        let p_close = GetProcAddress(h_module, b"CloseDecompressor\0".as_ptr());

        let (Some(p_create), Some(p_decompress), Some(p_close)) =
            (p_create, p_decompress, p_close)
        else {
            FreeLibrary(h_module);
            return Err(CabinetLoadError::MissingExports);
        };

        Ok(CabinetDecompressorApi {
            _module: h_module as usize,
            create_decompressor: std::mem::transmute(p_create),
            decompress: std::mem::transmute(p_decompress),
            close_decompressor: std::mem::transmute(p_close),
        })
    }) {
        Ok(api) => Ok(api),
        Err(CabinetLoadError::DllNotFound) => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "cabinet.dll could not be loaded for DEFLATE decompression",
        )),
        Err(CabinetLoadError::MissingExports) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Compression API functions not found in cabinet.dll",
        )),
    }
}

/// Decompresses raw DEFLATE bytes using the native Win32 Compression API in `Cabinet.dll`.
fn decompress_deflate(compressed: &[u8], expected_size: usize) -> io::Result<Vec<u8>> {
    let api = cabinet_decompressor_api()?;

    unsafe {
        let mut dec_handle: isize = 0;
        // COMPRESS_ALGORITHM_RAW_DEFLATE = 2 | 0x20000000, COMPRESS_ALGORITHM_DEFLATE = 2
        const COMPRESS_ALGORITHM_RAW_DEFLATE: u32 = 2 | 0x20000000;
        const COMPRESS_ALGORITHM_DEFLATE: u32 = 2;

        let ok = (api.create_decompressor)(
            COMPRESS_ALGORITHM_RAW_DEFLATE,
            std::ptr::null(),
            &mut dec_handle,
        );

        let handle = if ok != 0 {
            dec_handle
        } else {
            let ok2 = (api.create_decompressor)(
                COMPRESS_ALGORITHM_DEFLATE,
                std::ptr::null(),
                &mut dec_handle,
            );
            if ok2 == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "CreateDecompressor failed",
                ));
            }
            dec_handle
        };

        let mut out_buf = vec![0u8; expected_size.max(4096)];
        let mut actual_size: usize = 0;

        let decomp_ok = (api.decompress)(
            handle,
            compressed.as_ptr(),
            compressed.len(),
            out_buf.as_mut_ptr(),
            out_buf.len(),
            &mut actual_size,
        );

        (api.close_decompressor)(handle);

        if decomp_ok == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Win32 Decompress failed on DEFLATE stream",
            ));
        }

        out_buf.truncate(actual_size);
        Ok(out_buf)
    }
}
