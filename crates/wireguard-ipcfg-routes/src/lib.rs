// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.

//! Unicast IP address and routing table management for WireGuard on Windows.
//!
//! Wraps Win32 IP Helper APIs:
//! - `CreateUnicastIpAddressEntry`, `DeleteUnicastIpAddressEntry`, `GetUnicastIpAddressTable`
//! - `CreateIpForwardEntry2`, `DeleteIpForwardEntry2`, `GetIpForwardTable2`, `SetIpForwardEntry2`

pub mod error;

pub use error::{Result, RouteError};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use wireguard_ipcfg_core::Luid;

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN6_ADDR, IN_ADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0,
    SOCKADDR_INET, IpDadStatePreferred, MIB_IPPROTO_NETMGMT,
};

struct MibTableGuard(*const std::ffi::c_void);

impl Drop for MibTableGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                FreeMibTable(self.0 as _);
            }
        }
    }
}

#[inline]
fn init_unicast_row(luid: Luid, ip: IpAddr) -> MIB_UNICASTIPADDRESS_ROW {
    let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
    unsafe {
        InitializeUnicastIpAddressEntry(&mut row);
    }
    row.InterfaceLuid = luid.0;
    row.Address = ip_to_sockaddr_inet(ip);
    row
}

#[inline]
fn init_forward_row(
    luid: Luid,
    destination: IpAddr,
    prefix_len: u8,
    next_hop: Option<IpAddr>,
) -> MIB_IPFORWARD_ROW2 {
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    unsafe {
        InitializeIpForwardEntry(&mut row);
    }
    row.InterfaceLuid = luid.0;
    row.DestinationPrefix.Prefix = ip_to_sockaddr_inet(destination);
    row.DestinationPrefix.PrefixLength = prefix_len;
    if let Some(hop) = next_hop {
        row.NextHop = ip_to_sockaddr_inet(hop);
    }
    row
}

/// Helper to convert std::net::IpAddr into Windows SOCKADDR_INET.
pub fn ip_to_sockaddr_inet(ip: IpAddr) -> SOCKADDR_INET {
    let mut addr: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    match ip {
        IpAddr::V4(ipv4) => {
            addr.Ipv4 = SOCKADDR_IN {
                sin_family: AF_INET as u16,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    S_un: windows_sys::Win32::Networking::WinSock::IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(ipv4.octets()),
                    },
                },
                sin_zero: [0; 8],
            };
        }
        IpAddr::V6(ipv6) => {
            addr.Ipv6 = SOCKADDR_IN6 {
                sin6_family: AF_INET6 as u16,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: windows_sys::Win32::Networking::WinSock::IN6_ADDR_0 {
                        Byte: ipv6.octets(),
                    },
                },
                Anonymous: SOCKADDR_IN6_0 {
                    sin6_scope_id: 0,
                },
            };
        }
    }
    addr
}

/// Helper to convert Windows SOCKADDR_INET into std::net::IpAddr.
pub fn sockaddr_inet_to_ip(addr: &SOCKADDR_INET) -> Option<IpAddr> {
    unsafe {
        match addr.si_family {
            AF_INET => {
                let octets = addr.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes();
                Some(IpAddr::V4(Ipv4Addr::from(octets)))
            }
            AF_INET6 => {
                let bytes = addr.Ipv6.sin6_addr.u.Byte;
                Some(IpAddr::V6(Ipv6Addr::from(bytes)))
            }
            _ => None,
        }
    }
}

/// Adds a unicast IP address and subnet prefix to the given network interface.
pub fn add_unicast_address(luid: Luid, ip: IpAddr, prefix_len: u8) -> Result<()> {
    let mut row = init_unicast_row(luid, ip);
    row.OnLinkPrefixLength = prefix_len;
    row.DadState = IpDadStatePreferred;

    let err = unsafe { CreateUnicastIpAddressEntry(&row) };
    if err == NO_ERROR || err == ERROR_OBJECT_ALREADY_EXISTS {
        Ok(())
    } else {
        Err(RouteError::from_win32(err))
    }
}

/// Deletes a unicast IP address from the given network interface.
pub fn delete_unicast_address(luid: Luid, ip: IpAddr) -> Result<()> {
    let row = init_unicast_row(luid, ip);

    let err = unsafe { DeleteUnicastIpAddressEntry(&row) };
    if err == NO_ERROR || err == ERROR_NOT_FOUND || err == ERROR_FILE_NOT_FOUND {
        Ok(())
    } else {
        Err(RouteError::from_win32(err))
    }
}

/// Representation of an IPv4 or IPv6 route entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    pub destination: IpAddr,
    pub prefix_len: u8,
    pub next_hop: Option<IpAddr>,
    pub metric: u32,
    pub interface_luid: Luid,
}

/// Adds an IPv4 or IPv6 route entry to the Windows routing table.
pub fn add_route(
    luid: Luid,
    destination: IpAddr,
    prefix_len: u8,
    next_hop: Option<IpAddr>,
    metric: u32,
) -> Result<()> {
    let mut row = init_forward_row(luid, destination, prefix_len, next_hop);
    row.Metric = metric;
    row.Protocol = MIB_IPPROTO_NETMGMT;

    let err = unsafe { CreateIpForwardEntry2(&row) };
    if err == NO_ERROR || err == ERROR_OBJECT_ALREADY_EXISTS {
        Ok(())
    } else {
        Err(RouteError::from_win32(err))
    }
}

/// Deletes an IPv4 or IPv6 route entry from the Windows routing table.
pub fn delete_route(
    luid: Luid,
    destination: IpAddr,
    prefix_len: u8,
    next_hop: Option<IpAddr>,
) -> Result<()> {
    let row = init_forward_row(luid, destination, prefix_len, next_hop);

    let err = unsafe { DeleteIpForwardEntry2(&row) };
    if err == NO_ERROR || err == ERROR_NOT_FOUND || err == ERROR_FILE_NOT_FOUND {
        Ok(())
    } else {
        Err(RouteError::from_win32(err))
    }
}

/// Retrieves all routes associated with a specific interface LUID.
pub fn get_routes_for_interface(luid: Luid) -> Result<Vec<RouteEntry>> {
    let mut table_ptr: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();
    let err = unsafe { GetIpForwardTable2(0, &mut table_ptr) };
    if err != NO_ERROR {
        return Err(RouteError::from_win32(err));
    }
    if table_ptr.is_null() {
        return Err(RouteError::NullPointer);
    }

    let _guard = MibTableGuard(table_ptr as *const std::ffi::c_void);
    let target_luid = luid.as_u64();

    let count = unsafe { (*table_ptr).NumEntries as usize };
    if count == 0 {
        return Ok(Vec::new());
    }
    let table_slice = unsafe { std::slice::from_raw_parts((*table_ptr).Table.as_ptr(), count) };

    let match_count = table_slice
        .iter()
        .filter(|row| unsafe { row.InterfaceLuid.Value } == target_luid)
        .count();
    let mut routes = Vec::with_capacity(match_count);

    for row in table_slice {
        if unsafe { row.InterfaceLuid.Value } == target_luid {
            if let Some(dest) = sockaddr_inet_to_ip(&row.DestinationPrefix.Prefix) {
                let next_hop = sockaddr_inet_to_ip(&row.NextHop);
                routes.push(RouteEntry {
                    destination: dest,
                    prefix_len: row.DestinationPrefix.PrefixLength,
                    next_hop,
                    metric: row.Metric,
                    interface_luid: luid,
                });
            }
        }
    }

    Ok(routes)
}

/// Synchronizes a set of allowed IP prefixes into the Windows routing table for this interface.
pub fn sync_routes(
    luid: Luid,
    allowed_ips: impl IntoIterator<Item = (IpAddr, u8)>,
    metric: u32,
) -> Result<()> {
    for (ip, prefix_len) in allowed_ips {
        add_route(luid, ip, prefix_len, None, metric)?;
    }
    Ok(())
}

/// Removes any of the specified unicast IP addresses from other non-Up network adapters,
/// matching official WireGuard for Windows (`cleanupAddressesOnDisconnectedInterfaces`).
pub fn cleanup_addresses_on_disconnected_interfaces(
    active_luid: Luid,
    addresses: &[IpAddr],
) {
    if addresses.is_empty() {
        return;
    }

    let mut table_ptr: *mut MIB_UNICASTIPADDRESS_TABLE = ptr::null_mut();
    let err = unsafe { GetUnicastIpAddressTable(0, &mut table_ptr) };
    if err != NO_ERROR || table_ptr.is_null() {
        return;
    }
    let _guard = MibTableGuard(table_ptr as *const std::ffi::c_void);

    let count = unsafe { (*table_ptr).NumEntries as usize };
    if count == 0 {
        return;
    }
    let rows = unsafe { std::slice::from_raw_parts((*table_ptr).Table.as_ptr(), count) };

    let active_val = active_luid.as_u64();
    let mut cached_status: Option<(u64, bool)> = None;

    for row in rows {
        let row_luid = unsafe { row.InterfaceLuid.Value };
        if row_luid == active_val {
            continue;
        }
        let Some(row_ip) = sockaddr_inet_to_ip(&row.Address) else {
            continue;
        };
        if !addresses.contains(&row_ip) {
            continue;
        }

        let is_up = match cached_status {
            Some((cached_luid, up)) if cached_luid == row_luid => up,
            _ => {
                let mut if_row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
                if_row.InterfaceLuid = row.InterfaceLuid;
                let up = if wireguard_ipcfg_core::get_if_entry2(&mut if_row).is_ok() {
                    wireguard_ipcfg_core::OperStatus::from_raw(if_row.OperStatus)
                        == wireguard_ipcfg_core::OperStatus::Up
                } else {
                    // Interface disappeared concurrently or cannot be queried; skip deletion.
                    true
                };
                cached_status = Some((row_luid, up));
                up
            }
        };

        if !is_up {
            unsafe {
                DeleteUnicastIpAddressEntry(row);
            }
        }
    }
}
