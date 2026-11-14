// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.

use crate::name::tunnel_name_is_valid;
use crate::parser::{parse_config_bytes, ParseError};
use crate::path::{name_from_path, path_is_encrypted, split_config_file_name, PathError};
use std::fs;
use std::path::Path;
use thiserror::Error;
use wireguard_types::TunnelConfig;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Path error: {0}")]
    Path(#[from] PathError),
    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),
    #[error("Decryption error: {0}")]
    Decryption(String),
}

#[inline]
pub(crate) fn zeroize_slice(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        unsafe {
            core::ptr::write_volatile(b, 0);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Enumerates all valid tunnel configuration names in a directory.
///
/// Looks for regular files matching `<name>.conf` or `<name>.conf.dpapi`.
pub fn list_config_names(dir: &Path) -> std::io::Result<Vec<String>> {
    let mut result = Vec::new();
    let entries = fs::read_dir(dir)?;

    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }

        let file_name = entry.file_name();
        if let Some(file_name_str) = file_name.to_str() {
            if let Some((name, _)) = split_config_file_name(file_name_str) {
                if tunnel_name_is_valid(name) {
                    result.push(name.to_owned());
                }
            }
        }
    }

    result.sort();
    result.dedup();
    Ok(result)
}

/// Loads a tunnel configuration from a file path.
///
/// If the file is encrypted (`.conf.dpapi`), `decrypt_fn` is invoked to decrypt the ciphertext.
pub fn load_from_path<D>(path: &Path, decrypt_fn: Option<D>) -> Result<TunnelConfig, StoreError>
where
    D: Fn(&[u8], &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>,
{
    let name = name_from_path(path)?;
    let mut bytes = fs::read(path)?;

    if path_is_encrypted(path) {
        let decrypt = decrypt_fn.ok_or_else(|| {
            StoreError::Decryption("file is encrypted but no decryptor was provided".to_string())
        })?;
        let decrypted = decrypt(&bytes, &name).map_err(|e| StoreError::Decryption(e.to_string()))?;
        bytes = decrypted;
    }

    let config_res = parse_config_bytes(&bytes, &name);
    zeroize_slice(&mut bytes);
    Ok(config_res?)
}
