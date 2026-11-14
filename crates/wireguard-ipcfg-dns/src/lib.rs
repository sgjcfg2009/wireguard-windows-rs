// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.

//! Win32 IP Helper DNS configuration and NDIS network change notifications for WireGuard.
//!
//! Features:
//! - Setting DNS servers and search domains via `SetInterfaceDnsSettings` (Windows 10 1809+)
//!   with fallback to Registry (`Tcpip\\Parameters\\Interfaces`) and `dnscache` service signal.
//! - Network change notifications wrapping `NotifyIpInterfaceChange` and `NotifyRouteChange2`.

pub mod error;

pub use error::{DnsError, Result};
use std::fmt::{self, Write as _};
use std::net::IpAddr;
use std::ptr;
use std::sync::OnceLock;
use wireguard_ipcfg_core::{Guid, Luid};

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW};
use windows_sys::Win32::System::Registry::*;
use windows_sys::Win32::System::Services::*;

const DNS_INTERFACE_SETTINGS_VERSION1: u32 = 1;
const DNS_SETTING_IPV6: u64 = 0x0001;
const DNS_SETTING_NAMESERVER: u64 = 0x0002;
const DNS_SETTING_SEARCHLIST: u64 = 0x0004;
const DNS_SETTING_DOMAIN: u64 = 0x0020;

/// Exact C ABI layout of `_DNS_INTERFACE_SETTINGS` from `<netioapi.h>`.
#[repr(C)]
struct DNS_INTERFACE_SETTINGS {
    version: u32,
    flags: u64,
    domain: *const u16,
    name_server: *const u16,
    search_list: *const u16,
    registration_enabled: u32,
    register_adapter_name: u32,
    enable_llmnr: u32,
    query_adapter_name: u32,
    profile_name_server: *const u16,
}

const IPHLPAPI_DLL: &[u16] = &[
    b'i' as u16, b'p' as u16, b'h' as u16, b'l' as u16, b'p' as u16, b'a' as u16,
    b'p' as u16, b'i' as u16, b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16, 0,
];
const REG_VAL_NAMESERVER: &[u16] = &[
    b'N' as u16, b'a' as u16, b'm' as u16, b'e' as u16, b'S' as u16,
    b'e' as u16, b'r' as u16, b'v' as u16, b'e' as u16, b'r' as u16, 0,
];
const REG_VAL_SEARCHLIST: &[u16] = &[
    b'S' as u16, b'e' as u16, b'a' as u16, b'r' as u16, b'c' as u16,
    b'h' as u16, b'L' as u16, b'i' as u16, b's' as u16, b't' as u16, 0,
];
const SVC_DNSCACHE: &[u16] = &[
    b'd' as u16, b'n' as u16, b's' as u16, b'c' as u16,
    b'a' as u16, b'c' as u16, b'h' as u16, b'e' as u16, 0,
];

/// Stack-backed null-terminated UTF-16 writer that spills to `Vec<u16>` only for long lists.
struct WideBuf<const STACK: usize> {
    stack: [u16; STACK],
    len: usize,
    heap: Option<Vec<u16>>,
    terminated: bool,
}

impl<const STACK: usize> WideBuf<STACK> {
    fn new() -> Self {
        Self {
            stack: [0; STACK],
            len: 0,
            heap: None,
            terminated: false,
        }
    }

    #[inline]
    fn is_empty(&self) -> bool {
        match &self.heap {
            Some(heap) => {
                let effective = if self.terminated { heap.len().saturating_sub(1) } else { heap.len() };
                effective == 0
            }
            None => self.len == 0,
        }
    }

    #[inline]
    fn push_u16(&mut self, unit: u16) {
        if let Some(ref mut heap) = self.heap {
            if self.terminated {
                heap.pop();
                self.terminated = false;
            }
            heap.push(unit);
            return;
        }
        if self.len + 1 < STACK {
            self.stack[self.len] = unit;
            self.len += 1;
        } else {
            let mut heap = Vec::with_capacity(STACK * 2);
            heap.extend_from_slice(&self.stack[..self.len]);
            heap.push(unit);
            self.heap = Some(heap);
        }
        self.terminated = false;
    }

    fn as_wide_slice(&mut self) -> &[u16] {
        if !self.terminated {
            if let Some(ref mut heap) = self.heap {
                heap.push(0);
            } else {
                self.stack[self.len] = 0;
            }
            self.terminated = true;
        }
        match &self.heap {
            Some(heap) => heap.as_slice(),
            None => &self.stack[..=self.len],
        }
    }
}

impl<const STACK: usize> fmt::Write for WideBuf<STACK> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for unit in s.encode_utf16() {
            self.push_u16(unit);
        }
        Ok(())
    }
}

struct RegKeyGuard(HKEY);

impl Drop for RegKeyGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }
}

struct ScHandleGuard(SC_HANDLE);

impl Drop for ScHandleGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseServiceHandle(self.0);
            }
        }
    }
}

/// Sets DNS servers and search domains for the interface associated with the given LUID.
pub fn set_dns(
    luid: Luid,
    dns_servers: &[IpAddr],
    search_domains: &[String],
) -> Result<()> {
    let guid = luid.to_guid().map_err(DnsError::IpCfg)?;

    // Encode comma-separated IPv4, IPv6, and search domain lists directly into stack UTF-16 buffers.
    let mut v4_w = WideBuf::<128>::new();
    let mut v6_w = WideBuf::<256>::new();
    for ip in dns_servers {
        match ip {
            IpAddr::V4(v4) => {
                if !v4_w.is_empty() {
                    v4_w.push_u16(b',' as u16);
                }
                let _ = write!(&mut v4_w, "{}", v4);
            }
            IpAddr::V6(v6) => {
                if !v6_w.is_empty() {
                    v6_w.push_u16(b',' as u16);
                }
                let _ = write!(&mut v6_w, "{}", v6);
            }
        }
    }

    let mut search_w = WideBuf::<256>::new();
    for (idx, domain) in search_domains.iter().enumerate() {
        if idx > 0 {
            search_w.push_u16(b',' as u16);
        }
        let _ = search_w.write_str(domain);
    }

    let search_slice = search_w.as_wide_slice();
    let v4_slice = v4_w.as_wide_slice();
    let v6_slice = v6_w.as_wide_slice();
    let empty_w: [u16; 1] = [0];

    // Configure IPv4 DNS settings (or clear IPv4 DNS + set search list)
    let mut v4_settings = DNS_INTERFACE_SETTINGS {
        version: DNS_INTERFACE_SETTINGS_VERSION1,
        flags: DNS_SETTING_NAMESERVER | DNS_SETTING_SEARCHLIST | DNS_SETTING_DOMAIN,
        domain: empty_w.as_ptr(),
        name_server: v4_slice.as_ptr(),
        search_list: search_slice.as_ptr(),
        registration_enabled: 0,
        register_adapter_name: 0,
        enable_llmnr: 0,
        query_adapter_name: 0,
        profile_name_server: ptr::null(),
    };

    let mut used_registry_fallback = false;
    if set_interface_dns_settings_fallback(guid, &mut v4_settings).is_err() {
        set_dns_registry(guid, AF_INET as u16, v4_slice, search_slice)?;
        used_registry_fallback = true;
    }

    // Configure IPv6 DNS settings
    let mut v6_settings = DNS_INTERFACE_SETTINGS {
        version: DNS_INTERFACE_SETTINGS_VERSION1,
        flags: DNS_SETTING_IPV6 | DNS_SETTING_NAMESERVER | DNS_SETTING_SEARCHLIST | DNS_SETTING_DOMAIN,
        domain: empty_w.as_ptr(),
        name_server: v6_slice.as_ptr(),
        search_list: search_slice.as_ptr(),
        registration_enabled: 0,
        register_adapter_name: 0,
        enable_llmnr: 0,
        query_adapter_name: 0,
        profile_name_server: ptr::null(),
    };

    if set_interface_dns_settings_fallback(guid, &mut v6_settings).is_err() {
        set_dns_registry(guid, AF_INET6 as u16, v6_slice, search_slice)?;
        used_registry_fallback = true;
    }

    if used_registry_fallback {
        notify_dnscache_service();
    }
    Ok(())
}

type SetInterfaceDnsSettingsFn = unsafe extern "system" fn(
    interface_guid: windows_sys::core::GUID,
    settings: *const DNS_INTERFACE_SETTINGS,
) -> u32;

fn get_set_interface_dns_settings_fn() -> Option<SetInterfaceDnsSettingsFn> {
    static FUNC: OnceLock<Option<SetInterfaceDnsSettingsFn>> = OnceLock::new();
    *FUNC.get_or_init(|| unsafe {
        let lib = GetModuleHandleW(IPHLPAPI_DLL.as_ptr());
        let lib = if lib.is_null() {
            LoadLibraryW(IPHLPAPI_DLL.as_ptr())
        } else {
            lib
        };
        if lib.is_null() {
            return None;
        }
        let proc = GetProcAddress(lib, b"SetInterfaceDnsSettings\0".as_ptr())?;
        Some(std::mem::transmute(proc))
    })
}

fn set_interface_dns_settings_fallback(
    guid: Guid,
    settings: &mut DNS_INTERFACE_SETTINGS,
) -> Result<()> {
    let func = get_set_interface_dns_settings_fn()
        .ok_or_else(|| DnsError::from_win32(ERROR_PROC_NOT_FOUND))?;
    let err = unsafe { func(guid.0, settings) };
    if err == NO_ERROR {
        Ok(())
    } else {
        Err(DnsError::from_win32(err))
    }
}

fn set_dns_registry(
    guid: Guid,
    family: u16,
    nameservers_w: &[u16],
    search_list_w: &[u16],
) -> Result<()> {
    let prefix = if family == AF_INET as u16 {
        "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\"
    } else {
        "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\"
    };

    let mut subkey_w = WideBuf::<128>::new();
    let _ = subkey_w.write_str(prefix);
    let _ = write!(&mut subkey_w, "{}", guid);
    let subkey_slice = subkey_w.as_wide_slice();

    let mut hkey: HKEY = ptr::null_mut();
    let err = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey_slice.as_ptr(),
            0,
            ptr::null(),
            0,
            KEY_SET_VALUE,
            ptr::null(),
            &mut hkey,
            ptr::null_mut(),
        )
    };

    if err != NO_ERROR {
        return Err(DnsError::from_win32(err));
    }
    let _key_guard = RegKeyGuard(hkey);

    let err_ns = unsafe {
        RegSetValueExW(
            hkey,
            REG_VAL_NAMESERVER.as_ptr(),
            0,
            REG_SZ,
            nameservers_w.as_ptr() as _,
            (nameservers_w.len() * std::mem::size_of::<u16>()) as u32,
        )
    };
    if err_ns != NO_ERROR {
        return Err(DnsError::from_win32(err_ns));
    }

    let err_search = unsafe {
        RegSetValueExW(
            hkey,
            REG_VAL_SEARCHLIST.as_ptr(),
            0,
            REG_SZ,
            search_list_w.as_ptr() as _,
            (search_list_w.len() * std::mem::size_of::<u16>()) as u32,
        )
    };
    if err_search != NO_ERROR {
        return Err(DnsError::from_win32(err_search));
    }

    Ok(())
}

fn notify_dnscache_service() {
    unsafe {
        let scm = OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return;
        }
        let _scm_guard = ScHandleGuard(scm);

        let svc = OpenServiceW(scm, SVC_DNSCACHE.as_ptr(), SERVICE_PAUSE_CONTINUE);
        if !svc.is_null() {
            let _svc_guard = ScHandleGuard(svc);
            let mut status: SERVICE_STATUS = std::mem::zeroed();
            ControlService(svc, SERVICE_CONTROL_PARAMCHANGE, &mut status);
        }
    }
}

/// RAII handle to cancel network change notifications upon drop.
pub struct NotificationHandle {
    handle: HANDLE,
}

impl NotificationHandle {
    pub fn new(handle: HANDLE) -> Self {
        Self { handle }
    }
}

impl Drop for NotificationHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() && self.handle != INVALID_HANDLE_VALUE {
            unsafe {
                CancelMibChangeNotify2(self.handle);
            }
        }
    }
}

unsafe impl Send for NotificationHandle {}
unsafe impl Sync for NotificationHandle {}
