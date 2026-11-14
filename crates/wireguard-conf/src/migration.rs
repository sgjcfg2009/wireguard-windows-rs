// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.

use crate::name::tunnel_name_is_valid;
use crate::parser::parse_config_bytes;
use crate::path::{config_path_unchecked, CONFIG_FILE_SUFFIX, CONFIG_FILE_UNENCRYPTED_SUFFIX};
use crate::store::zeroize_slice;
use crate::writer::to_wg_conf;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationRecord {
    pub name: String,
    pub old_path: PathBuf,
    pub new_path: PathBuf,
}

#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error for {0}: {1}")]
    Parse(String, crate::parser::ParseError),
    #[error("Encryption error for {0}: {1}")]
    Encryption(String, String),
}

/// Migrates unencrypted legacy `.conf` files in `config_dir` to encrypted `.conf.dpapi` files.
///
/// For each regular file ending in `.conf` (and not `.conf.dpapi`):
/// 1. Reads file contents (handles UTF-8, BOM, UTF-16).
/// 2. Parses into a valid configuration.
/// 3. Re-serializes the configuration to standard WireGuard format.
/// 4. Calls `encrypt_fn(serialized_bytes, tunnel_name)` to encrypt the data.
/// 5. Writes the encrypted bytes to `<name>.conf.dpapi`.
/// 6. Deletes the old unencrypted `<name>.conf`.
/// 7. Invokes `callback(name, old_path, new_path)`.
pub fn migrate_unencrypted_configs<E, F>(
    config_dir: &Path,
    encrypt_fn: E,
    mut callback: F,
) -> Result<Vec<MigrationRecord>, MigrationError>
where
    E: Fn(&[u8], &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>,
    F: FnMut(&str, &Path, &Path),
{
    let mut records = Vec::new();
    let entries = fs::read_dir(config_dir)?;

    for entry in entries {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if !file_type.is_file() {
            continue;
        }

        let file_name_os = entry.file_name();
        let file_name = match file_name_os.to_str() {
            Some(name) => name,
            None => continue,
        };

        // Must end in .conf and NOT .conf.dpapi
        if !file_name.ends_with(CONFIG_FILE_UNENCRYPTED_SUFFIX)
            || file_name.ends_with(CONFIG_FILE_SUFFIX)
        {
            continue;
        }

        let tunnel_name = &file_name[..file_name.len() - CONFIG_FILE_UNENCRYPTED_SUFFIX.len()];
        if !tunnel_name_is_valid(tunnel_name) {
            continue;
        }

        let path = entry.path();
        let mut bytes = fs::read(&path)?;
        let config_res = parse_config_bytes(&bytes, tunnel_name)
            .map_err(|e| MigrationError::Parse(tunnel_name.to_string(), e));
        zeroize_slice(&mut bytes);
        let config = config_res?;

        let mut serialized = to_wg_conf(&config);
        let encrypted_res = encrypt_fn(serialized.as_bytes(), tunnel_name)
            .map_err(|e| MigrationError::Encryption(tunnel_name.to_string(), e.to_string()));
        // SAFETY: zeroize_slice writes 0 bytes which are valid UTF-8.
        zeroize_slice(unsafe { serialized.as_bytes_mut() });
        let encrypted_bytes = encrypted_res?;

        let new_path = config_path_unchecked(config_dir, tunnel_name, true);

        fs::write(&new_path, &encrypted_bytes)?;
        let _ = fs::remove_file(&path);

        callback(tunnel_name, &path, &new_path);

        records.push(MigrationRecord {
            name: tunnel_name.to_string(),
            old_path: path,
            new_path,
        });
    }

    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn test_migrate_unencrypted_configs() {
        let temp_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("wg_test_migration");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let conf_content = "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.0.0.1/24\n\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 0.0.0.0/0\n";
        let old_conf_path = temp_dir.join("office.conf");
        {
            let mut f = File::create(&old_conf_path).unwrap();
            f.write_all(conf_content.as_bytes()).unwrap();
        }

        // Mock encryptor that just reverses bytes
        let encrypt = |data: &[u8], _name: &str| -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
            let mut out = data.to_vec();
            out.reverse();
            Ok(out)
        };

        let mut migrated_calls = Vec::new();
        let records = migrate_unencrypted_configs(&temp_dir, encrypt, |name, old_p, new_p| {
            migrated_calls.push((name.to_string(), old_p.to_path_buf(), new_p.to_path_buf()));
        })
        .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "office");
        assert!(!old_conf_path.exists());
        assert!(temp_dir.join("office.conf.dpapi").exists());
        assert_eq!(migrated_calls.len(), 1);

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
