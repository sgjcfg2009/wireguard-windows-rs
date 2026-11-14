// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.

//! Autostart tunnel and administrative registry management.
//!
//! Provides functions to query and modify WireGuard configuration in `HKLM\Software\WireGuard`:
//! - Tunnel service autostart configuration (`SERVICE_AUTO_START` vs `SERVICE_DEMAND_START`).
//! - Policy flags (`LimitedOperatorUI`, `DangerousScriptExecution`).
//! - Tunnel autostart registry list (`AutoStart`).

use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::ptr;
use tracing::info;

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY,
    REG_DWORD, REG_MULTI_SZ, REG_OPTION_NON_VOLATILE,
};
use windows_sys::Win32::System::Services::{SERVICE_AUTO_START, SERVICE_DEMAND_START, SERVICE_QUERY_CONFIG};

use wireguard_conf::{service_name_of_tunnel, tunnel_name_is_valid};
use wireguard_service::ScmHandle;

use crate::error::ManagerError;
use crate::wide::with_wide_null;

/// WireGuard registry root key under `HKEY_LOCAL_MACHINE`.
pub const WIREGUARD_REG_KEY: &str = r"Software\WireGuard";

/// Registry value name for the autostart tunnel list.
pub const AUTOSTART_VAL_NAME: &str = "AutoStart";

/// Registry value name for the LimitedOperatorUI policy flag.
pub const LIMITED_OPERATOR_UI_VAL: &str = "LimitedOperatorUI";

/// Registry value name for the DangerousScriptExecution policy flag.
pub const DANGEROUS_SCRIPT_EXEC_VAL: &str = "DangerousScriptExecution";

/// Safe RAII wrapper for a Win32 Registry Key (`HKEY`).
pub struct RegKey(HKEY);

impl RegKey {
    /// Opens a subkey of HKLM with 64-bit view.
    pub fn open_hklm(sub_key: &str, desired_access: u32) -> Result<Self, ManagerError> {
        let mut hkey: HKEY = ptr::null_mut();
        let status = with_wide_null(sub_key, |wide| unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                wide,
                0,
                desired_access | KEY_WOW64_64KEY,
                &mut hkey,
            )
        });
        if status != ERROR_SUCCESS {
            return Err(ManagerError::Registry(format!(
                "failed to open HKLM\\{sub_key} (error {status:#010x})"
            )));
        }
        Ok(Self(hkey))
    }

    /// Creates or opens a subkey of HKLM with 64-bit view.
    pub fn create_hklm(sub_key: &str, desired_access: u32) -> Result<Self, ManagerError> {
        let mut hkey: HKEY = ptr::null_mut();
        let mut disposition: u32 = 0;
        let status = with_wide_null(sub_key, |wide| unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                wide,
                0,
                ptr::null_mut(),
                REG_OPTION_NON_VOLATILE,
                desired_access | KEY_WOW64_64KEY,
                ptr::null_mut(),
                &mut hkey,
                &mut disposition,
            )
        });
        if status != ERROR_SUCCESS {
            return Err(ManagerError::Registry(format!(
                "failed to create HKLM\\{sub_key} (error {status:#010x})"
            )));
        }
        Ok(Self(hkey))
    }

    /// Reads a DWORD (u32) value. Returns Ok(None) if not found.
    pub fn get_dword(&self, val_name: &str) -> Result<Option<u32>, ManagerError> {
        let mut val_type: u32 = 0;
        let mut data: u32 = 0;
        let mut data_len = std::mem::size_of::<u32>() as u32;

        let status = with_wide_null(val_name, |wide| unsafe {
            RegQueryValueExW(
                self.0,
                wide,
                ptr::null_mut(),
                &mut val_type,
                &mut data as *mut u32 as *mut u8,
                &mut data_len,
            )
        });

        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(ManagerError::Registry(format!(
                "failed to query value '{val_name}' (error {status:#010x})"
            )));
        }
        if val_type != REG_DWORD {
            return Ok(None);
        }

        Ok(Some(data))
    }

    /// Writes a DWORD (u32) value.
    pub fn set_dword(&self, val_name: &str, val: u32) -> Result<(), ManagerError> {
        let status = with_wide_null(val_name, |wide| unsafe {
            RegSetValueExW(
                self.0,
                wide,
                0,
                REG_DWORD,
                &val as *const u32 as *const u8,
                std::mem::size_of::<u32>() as u32,
            )
        });
        if status != ERROR_SUCCESS {
            return Err(ManagerError::Registry(format!(
                "failed to set DWORD '{val_name}' (error {status:#010x})"
            )));
        }
        Ok(())
    }

    /// Reads a REG_MULTI_SZ (list of strings). Returns Ok(None) if not found.
    pub fn get_multi_sz(&self, val_name: &str) -> Result<Option<Vec<String>>, ManagerError> {
        with_wide_null(val_name, |wide| {
            let mut val_type: u32 = 0;
            let mut stack_buf = [0u16; 256];
            let mut heap_buf: Vec<u16> = Vec::new();
            let mut data_len = std::mem::size_of_val(&stack_buf) as u32;

            let mut status = unsafe {
                RegQueryValueExW(
                    self.0,
                    wide,
                    ptr::null_mut(),
                    &mut val_type,
                    stack_buf.as_mut_ptr() as *mut u8,
                    &mut data_len,
                )
            };

            while status == ERROR_MORE_DATA {
                let needed_u16 = (data_len as usize)
                    .div_ceil(std::mem::size_of::<u16>())
                    .max(1);
                heap_buf.resize(needed_u16, 0);
                data_len = (heap_buf.len() * std::mem::size_of::<u16>()) as u32;
                status = unsafe {
                    RegQueryValueExW(
                        self.0,
                        wide,
                        ptr::null_mut(),
                        &mut val_type,
                        heap_buf.as_mut_ptr() as *mut u8,
                        &mut data_len,
                    )
                };
            }

            if status == ERROR_FILE_NOT_FOUND || data_len == 0 {
                return Ok(None);
            }
            if status != ERROR_SUCCESS {
                return Err(ManagerError::Registry(format!(
                    "failed to query multi-string '{val_name}' (error {status:#010x})"
                )));
            }
            if val_type != REG_MULTI_SZ {
                return Ok(None);
            }

            let u16_len = (data_len as usize) / std::mem::size_of::<u16>();
            let u16_slice = if heap_buf.is_empty() {
                &stack_buf[..u16_len.min(stack_buf.len())]
            } else {
                &heap_buf[..u16_len.min(heap_buf.len())]
            };

            let result = u16_slice
                .split(|&ch| ch == 0)
                .filter(|part| !part.is_empty())
                .map(String::from_utf16_lossy)
                .collect();

            Ok(Some(result))
        })
    }

    /// Writes a REG_MULTI_SZ (list of null-separated strings terminated by double null).
    pub fn set_multi_sz(&self, val_name: &str, strings: &[String]) -> Result<(), ManagerError> {
        let needed_units = strings
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| s.encode_utf16().count() + 1)
            .sum::<usize>()
            + 1;

        let encode_into = |dst: &mut [u16]| {
            let mut idx = 0usize;
            for s in strings {
                if !s.is_empty() {
                    for unit in s.encode_utf16() {
                        dst[idx] = unit;
                        idx += 1;
                    }
                    dst[idx] = 0;
                    idx += 1;
                }
            }
            dst[idx] = 0;
        };

        let mut stack_buf = [0u16; 256];
        let mut heap_buf: Vec<u16> = Vec::new();
        let wide_data: &[u16] = if needed_units <= stack_buf.len() {
            encode_into(&mut stack_buf);
            &stack_buf[..needed_units]
        } else {
            heap_buf.resize(needed_units, 0);
            encode_into(&mut heap_buf);
            &heap_buf[..needed_units]
        };

        let byte_len = std::mem::size_of_val(wide_data) as u32;
        let status = with_wide_null(val_name, |wide| unsafe {
            RegSetValueExW(
                self.0,
                wide,
                0,
                REG_MULTI_SZ,
                wide_data.as_ptr() as *const u8,
                byte_len,
            )
        });

        if status != ERROR_SUCCESS {
            return Err(ManagerError::Registry(format!(
                "failed to set multi-string '{val_name}' (error {status:#010x})"
            )));
        }
        Ok(())
    }

    /// Deletes a value under this key.
    pub fn delete_value(&self, val_name: &str) -> Result<(), ManagerError> {
        let status = with_wide_null(val_name, |wide| unsafe { RegDeleteValueW(self.0, wide) });
        if status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND {
            return Err(ManagerError::Registry(format!(
                "failed to delete value '{val_name}' (error {status:#010x})"
            )));
        }
        Ok(())
    }
}

impl Drop for RegKey {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                RegCloseKey(self.0);
            }
            self.0 = ptr::null_mut();
        }
    }
}

/// Checks whether an administrative boolean flag is enabled in `HKLM\Software\WireGuard`.
/// Returns false if key or value does not exist.
pub fn admin_bool(val_name: &str) -> bool {
    match RegKey::open_hklm(WIREGUARD_REG_KEY, KEY_QUERY_VALUE) {
        Ok(key) => key.get_dword(val_name).unwrap_or(None).unwrap_or(0) != 0,
        Err(_) => false,
    }
}

/// Sets an administrative boolean flag in `HKLM\Software\WireGuard`.
pub fn set_admin_bool(val_name: &str, val: bool) -> Result<(), ManagerError> {
    let key = RegKey::create_hklm(WIREGUARD_REG_KEY, KEY_SET_VALUE)?;
    key.set_dword(val_name, if val { 1 } else { 0 })
}

/// Queries whether a tunnel service is configured for automatic start (`SERVICE_AUTO_START`).
pub fn is_tunnel_service_autostart(tunnel_name: &str) -> Result<bool, ManagerError> {
    if !tunnel_name_is_valid(tunnel_name) {
        return Err(ManagerError::InvalidTunnelName(tunnel_name.to_string()));
    }

    let service_name = service_name_of_tunnel(tunnel_name)
        .map_err(|e| ManagerError::InvalidTunnelName(e.to_string()))?;

    let scm = ScmHandle::open(windows_sys::Win32::System::Services::SC_MANAGER_CONNECT)?;
    let service = scm.open_service(&service_name, SERVICE_QUERY_CONFIG)?;
    let is_auto = service.is_auto_start()?;
    Ok(is_auto)
}

/// Sets a tunnel service start type to `SERVICE_AUTO_START` or `SERVICE_DEMAND_START`.
pub fn set_tunnel_service_autostart(
    tunnel_name: &str,
    autostart: bool,
) -> Result<(), ManagerError> {
    if !tunnel_name_is_valid(tunnel_name) {
        return Err(ManagerError::InvalidTunnelName(tunnel_name.to_string()));
    }

    let service_name = service_name_of_tunnel(tunnel_name)
        .map_err(|e| ManagerError::InvalidTunnelName(e.to_string()))?;

    let scm = ScmHandle::open(windows_sys::Win32::System::Services::SC_MANAGER_ALL_ACCESS)?;
    let service = scm.open_service(
        &service_name,
        windows_sys::Win32::System::Services::SERVICE_CHANGE_CONFIG,
    )?;

    let start_type = if autostart {
        SERVICE_AUTO_START
    } else {
        SERVICE_DEMAND_START
    };

    service.set_start_type(start_type)?;
    info!(
        "Updated service start type for tunnel '{}' ({}) to {}",
        tunnel_name,
        service_name,
        if autostart { "AUTO_START" } else { "DEMAND_START" }
    );
    Ok(())
}

/// Retrieves the list of autostart tunnel names from `HKLM\Software\WireGuard\AutoStart`.
pub fn get_autostart_tunnels() -> Result<Vec<String>, ManagerError> {
    let key = match RegKey::open_hklm(WIREGUARD_REG_KEY, KEY_QUERY_VALUE) {
        Ok(k) => k,
        Err(_) => return Ok(Vec::new()),
    };

    let list = key.get_multi_sz(AUTOSTART_VAL_NAME)?.unwrap_or_default();
    Ok(list)
}

/// Sets the list of autostart tunnels in `HKLM\Software\WireGuard\AutoStart`.
pub fn set_autostart_tunnels(tunnels: &[String]) -> Result<(), ManagerError> {
    let key = RegKey::create_hklm(WIREGUARD_REG_KEY, KEY_SET_VALUE)?;
    if tunnels.is_empty() {
        let _ = key.delete_value(AUTOSTART_VAL_NAME);
    } else {
        key.set_multi_sz(AUTOSTART_VAL_NAME, tunnels)?;
    }
    info!("Updated registry autostart tunnel list: {:?}", tunnels);
    Ok(())
}

/// Adds a tunnel name to the autostart registry list.
pub fn add_autostart_tunnel(tunnel_name: &str) -> Result<(), ManagerError> {
    if !tunnel_name_is_valid(tunnel_name) {
        return Err(ManagerError::InvalidTunnelName(tunnel_name.to_string()));
    }

    let mut list = get_autostart_tunnels()?;
    if !list.iter().any(|t| t.eq_ignore_ascii_case(tunnel_name)) {
        list.push(tunnel_name.to_string());
        set_autostart_tunnels(&list)?;
    }
    Ok(())
}

/// Removes a tunnel name from the autostart registry list.
pub fn remove_autostart_tunnel(tunnel_name: &str) -> Result<(), ManagerError> {
    let mut list = get_autostart_tunnels()?;
    let prev_len = list.len();
    list.retain(|t| !t.eq_ignore_ascii_case(tunnel_name));
    if list.len() != prev_len {
        set_autostart_tunnels(&list)?;
    }
    Ok(())
}

/// Checks whether a tunnel is present in the autostart registry list.
pub fn is_tunnel_in_autostart_registry(tunnel_name: &str) -> bool {
    match get_autostart_tunnels() {
        Ok(list) => list.iter().any(|t| t.eq_ignore_ascii_case(tunnel_name)),
        Err(_) => false,
    }
}

const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Resolves the absolute path to `wireguard.exe`.
/// Prefers `C:\Program Files\WireGuard\wireguard.exe` if it exists, otherwise falls back to current exe.
pub fn get_wireguard_exe_path() -> PathBuf {
    let program_files_exe = Path::new(r"C:\Program Files\WireGuard\wireguard.exe");
    if program_files_exe.exists() {
        program_files_exe.to_path_buf()
    } else {
        std::env::current_exe().unwrap_or_else(|_| PathBuf::from("wireguard.exe"))
    }
}

/// Enables or disables automatic logon launch of `wireguard.exe` via Windows Task Scheduler.
///
/// When enabled:
/// - Creates a Scheduled Task named `WireGuard` that triggers `ONLOGON` with `HIGHEST` privileges.
/// - This ensures `wireguard.exe` runs elevated without any interactive UAC prompts on Windows logon.
///
/// When disabled:
/// - Deletes the Scheduled Task named `WireGuard` and clears any legacy `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` entries.
pub fn set_windows_logon_autostart(enabled: bool) -> Result<(), ManagerError> {
    if enabled {
        let exe_path = get_wireguard_exe_path();
        let exe_str = exe_path.to_string_lossy();
        let tr_arg = format!("\"{}\" /tray", exe_str);

        let status = std::process::Command::new("schtasks.exe")
            .args(["/create", "/tn", "WireGuard", "/tr", &tr_arg, "/sc", "onlogon", "/rl", "highest", "/f"])
            .creation_flags(CREATE_NO_WINDOW)
            .status()
            .map_err(|e| ManagerError::Registry(format!("failed to execute schtasks: {e}")))?;

        if !status.success() {
            return Err(ManagerError::Registry(format!(
                "schtasks create failed with code {:?}",
                status.code()
            )));
        }
        info!("Windows logon auto-start enabled via Task Scheduler for '{}'", exe_str);
    } else {
        let _ = std::process::Command::new("schtasks.exe")
            .args(["/delete", "/tn", "WireGuard", "/f"])
            .creation_flags(CREATE_NO_WINDOW)
            .status();

        // Also clean up any legacy Run registry entry if present
        let mut hkey: HKEY = ptr::null_mut();
        with_wide_null(r"Software\Microsoft\Windows\CurrentVersion\Run", |wide_run| unsafe {
            if RegOpenKeyExW(
                HKEY_CURRENT_USER,
                wide_run,
                0,
                KEY_SET_VALUE,
                &mut hkey,
            ) == ERROR_SUCCESS {
                with_wide_null("WireGuard", |wide_val| {
                    RegDeleteValueW(hkey, wide_val);
                });
                RegCloseKey(hkey);
            }
        });
        info!("Windows logon auto-start disabled (Task Scheduler task & Run key removed)");
    }
    Ok(())
}
