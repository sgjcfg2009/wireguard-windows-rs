// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.

use crate::name::tunnel_name_is_valid;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const CONFIG_FILE_SUFFIX: &str = ".conf.dpapi";
pub const CONFIG_FILE_UNENCRYPTED_SUFFIX: &str = ".conf";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PathError {
    #[error("path must end in either {CONFIG_FILE_SUFFIX} or {CONFIG_FILE_UNENCRYPTED_SUFFIX}: {0}")]
    InvalidExtension(String),
    #[error("tunnel name derived from path is invalid: {0}")]
    InvalidTunnelName(String),
    #[error("path contains invalid component: {0}")]
    InvalidPath(String),
}

/// Splits a config file name into `(tunnel_name_slice, is_encrypted)` if it ends in
/// `.conf.dpapi` or `.conf` with a non-empty stem.
#[inline]
pub(crate) fn split_config_file_name(file_name: &str) -> Option<(&str, bool)> {
    if file_name.len() > CONFIG_FILE_SUFFIX.len() && file_name.ends_with(CONFIG_FILE_SUFFIX) {
        Some((&file_name[..file_name.len() - CONFIG_FILE_SUFFIX.len()], true))
    } else if file_name.len() > CONFIG_FILE_UNENCRYPTED_SUFFIX.len()
        && file_name.ends_with(CONFIG_FILE_UNENCRYPTED_SUFFIX)
    {
        Some((
            &file_name[..file_name.len() - CONFIG_FILE_UNENCRYPTED_SUFFIX.len()],
            false,
        ))
    } else {
        None
    }
}

/// Checks whether a given configuration file path is DPAPI encrypted.
pub fn path_is_encrypted(path: &Path) -> bool {
    path.file_name()
        .and_then(|f| f.to_str())
        .is_some_and(|name| name.ends_with(CONFIG_FILE_SUFFIX))
}

/// Extracts and validates the tunnel name from a file path.
///
/// The file must end in either `.conf.dpapi` or `.conf`.
pub fn name_from_path(path: &Path) -> Result<String, PathError> {
    let file_name = path
        .file_name()
        .and_then(|f| f.to_str())
        .ok_or_else(|| PathError::InvalidPath(path.to_string_lossy().to_string()))?;

    let (name, _) = split_config_file_name(file_name)
        .ok_or_else(|| PathError::InvalidExtension(file_name.to_string()))?;

    if !tunnel_name_is_valid(name) {
        return Err(PathError::InvalidTunnelName(name.to_string()));
    }

    Ok(name.to_string())
}

/// Joins `dir` and `<name><suffix>` without intermediate `String` allocation for valid tunnel names.
#[inline]
pub(crate) fn config_path_unchecked(dir: &Path, name: &str, encrypted: bool) -> PathBuf {
    let suffix = if encrypted {
        CONFIG_FILE_SUFFIX
    } else {
        CONFIG_FILE_UNENCRYPTED_SUFFIX
    };
    let total = name.len() + suffix.len();
    let mut out = PathBuf::with_capacity(dir.as_os_str().len() + 1 + total);
    out.push(dir);
    // Valid tunnel names are <= 32 ASCII bytes, so total <= 43 fits on stack.
    if total <= 48 {
        let mut fname = [0u8; 48];
        fname[..name.len()].copy_from_slice(name.as_bytes());
        fname[name.len()..total].copy_from_slice(suffix.as_bytes());
        if let Ok(file_name) = std::str::from_utf8(&fname[..total]) {
            out.push(file_name);
            return out;
        }
    }
    let mut fallback = String::with_capacity(total);
    fallback.push_str(name);
    fallback.push_str(suffix);
    out.push(fallback);
    out
}

/// Constructs a safe, sanitized configuration file path within the specified directory.
///
/// Prevents path traversal and validates the tunnel name.
pub fn config_path(dir: &Path, name: &str, encrypted: bool) -> Result<PathBuf, PathError> {
    if !tunnel_name_is_valid(name) {
        return Err(PathError::InvalidTunnelName(name.to_string()));
    }
    Ok(config_path_unchecked(dir, name, encrypted))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_from_path() {
        assert_eq!(
            name_from_path(Path::new("C:\\Data\\Configurations\\wg0.conf.dpapi")).unwrap(),
            "wg0"
        );
        assert_eq!(
            name_from_path(Path::new("/etc/wireguard/office.conf")).unwrap(),
            "office"
        );
        assert_eq!(
            name_from_path(Path::new("my-tunnel.conf.dpapi")).unwrap(),
            "my-tunnel"
        );
    }

    #[test]
    fn test_name_from_path_invalid() {
        // Not .conf or .conf.dpapi
        assert!(matches!(
            name_from_path(Path::new("wg0.txt")),
            Err(PathError::InvalidExtension(_))
        ));
        // Valid extension but invalid tunnel name (e.g., spaces or empty)
        assert!(matches!(
            name_from_path(Path::new("invalid tunnel.conf")),
            Err(PathError::InvalidTunnelName(_))
        ));
        assert!(matches!(
            name_from_path(Path::new(".conf")),
            Err(PathError::InvalidExtension(_))
        ));
    }

    #[test]
    fn test_path_is_encrypted() {
        assert!(path_is_encrypted(Path::new("test.conf.dpapi")));
        assert!(!path_is_encrypted(Path::new("test.conf")));
        assert!(!path_is_encrypted(Path::new("test.conf.dpapi.bak")));
    }

    #[test]
    fn test_config_path() {
        let dir = Path::new("C:\\WireGuard\\Configurations");
        let enc = config_path(dir, "wg0", true).unwrap();
        assert_eq!(enc, dir.join("wg0.conf.dpapi"));

        let unenc = config_path(dir, "wg0", false).unwrap();
        assert_eq!(unenc, dir.join("wg0.conf"));

        // Invalid name rejection
        assert!(config_path(dir, "invalid name", true).is_err());
    }
}
