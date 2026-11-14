use std::ffi::CStr;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};

use crate::error::{IpCfgError, Result};
use crate::interface::IfTable2;
use crate::luid::Luid;
use crate::types::{AddressFamily, AdminStatus, GaaFlags, OperStatus};
use crate::util::decode_utf16_null_terminated;

struct MibTableGuard(*const std::ffi::c_void);

impl Drop for MibTableGuard {
    fn drop(&mut self) {
        free_mib_table(self.0);
    }
}

fn wrap_if_table2(ret: u32, table_ptr: *mut MIB_IF_TABLE2, fn_name: &str) -> Result<IfTable2> {
    if ret != ERROR_SUCCESS {
        return Err(IpCfgError::from_win32(ret));
    }
    if table_ptr.is_null() {
        return Err(IpCfgError::Other(format!(
            "{} returned success but table pointer was null",
            fn_name
        )));
    }
    Ok(unsafe { IfTable2::from_raw(table_ptr) })
}

/// Information about a network adapter retrieved from `GetAdaptersAddresses`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterAddresses {
    pub adapter_name: String,
    pub description: String,
    pub friendly_name: String,
    pub luid: Luid,
    pub if_index: u32,
    pub ipv6_if_index: u32,
    pub if_type: u32,
    pub oper_status: OperStatus,
    pub ipv4_metric: u32,
    pub ipv6_metric: u32,
    pub compartment_id: u32,
    pub mtu: u32,
    pub physical_address: Vec<u8>,
}

/// Safe wrapper around Win32 `GetIfTable2`.
///
/// Retrieves the MIB-II network interface table.
/// Memory is automatically freed when the returned `IfTable2` is dropped.
pub fn get_if_table2() -> Result<IfTable2> {
    let mut table_ptr: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    let ret = unsafe { GetIfTable2(&mut table_ptr) };
    wrap_if_table2(ret, table_ptr, "GetIfTable2")
}

/// Safe wrapper around Win32 `GetIfTable2Ex`.
///
/// Retrieves the MIB-II network interface table with the specified detail level.
pub fn get_if_table2_ex(level: i32) -> Result<IfTable2> {
    let mut table_ptr: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    let ret = unsafe { GetIfTable2Ex(level, &mut table_ptr) };
    wrap_if_table2(ret, table_ptr, "GetIfTable2Ex")
}

/// Safe wrapper around Win32 `GetIfEntry2`.
///
/// Retrieves information for the specified interface entry.
/// The caller must specify either `row.InterfaceLuid` or `row.InterfaceIndex` before calling.
pub fn get_if_entry2(row: &mut MIB_IF_ROW2) -> Result<()> {
    let ret = unsafe { GetIfEntry2(row) };
    if ret != ERROR_SUCCESS {
        return Err(IpCfgError::from_win32(ret));
    }
    Ok(())
}

/// Safe wrapper around Win32 `SetIfEntry`.
///
/// Sets administrative status or configuration on a network interface.
pub fn set_if_entry(row: &MIB_IFROW) -> Result<()> {
    let ret = unsafe { SetIfEntry(row) };
    if ret != ERROR_SUCCESS {
        return Err(IpCfgError::from_win32(ret));
    }
    Ok(())
}

/// Safe wrapper around `SetIfEntry2`.
///
/// Converts the specified `MIB_IF_ROW2` entry to the underlying Win32 interface
/// update call, applying administrative status and configuration.
pub fn set_if_entry2(row: &MIB_IF_ROW2) -> Result<()> {
    let admin_status = AdminStatus::from_raw(row.AdminStatus);
    set_interface_admin_status(row.InterfaceIndex, admin_status)
}

/// Safe wrapper around Win32 `FreeMibTable`.
pub fn free_mib_table(ptr: *const std::ffi::c_void) {
    if !ptr.is_null() {
        unsafe {
            FreeMibTable(ptr);
        }
    }
}

// Windows bug fix: sanitize SitePrefixLength
// https://stackoverflow.com/questions/54857292/setipinterfaceentry-returns-error-invalid-parameter
#[inline]
fn sanitize_site_prefix_length(row: &mut MIB_IPINTERFACE_ROW) {
    match row.Family {
        AF_INET => {
            if row.SitePrefixLength > 32 {
                row.SitePrefixLength = 0;
            }
        }
        AF_INET6 => {
            if row.SitePrefixLength > 128 {
                row.SitePrefixLength = 128;
            }
        }
        _ => {}
    }
}

/// Safe wrapper around Win32 `GetIpInterfaceEntry`.
pub fn get_ip_interface_entry(row: &mut MIB_IPINTERFACE_ROW) -> Result<()> {
    let ret = unsafe { GetIpInterfaceEntry(row) };
    if ret != ERROR_SUCCESS {
        return Err(IpCfgError::from_win32(ret));
    }

    sanitize_site_prefix_length(row);
    Ok(())
}

/// Safe wrapper around Win32 `SetIpInterfaceEntry`.
pub fn set_ip_interface_entry(row: &mut MIB_IPINTERFACE_ROW) -> Result<()> {
    sanitize_site_prefix_length(row);

    let ret = unsafe { SetIpInterfaceEntry(row) };
    if ret != ERROR_SUCCESS {
        return Err(IpCfgError::from_win32(ret));
    }
    Ok(())
}

/// Safe wrapper around Win32 `InitializeIpInterfaceEntry`.
pub fn initialize_ip_interface_entry(row: &mut MIB_IPINTERFACE_ROW) {
    unsafe {
        InitializeIpInterfaceEntry(row);
    }
}

fn with_raw_adapters_addresses<R>(
    family: AddressFamily,
    flags: GaaFlags,
    f: impl FnOnce(*const IP_ADAPTER_ADDRESSES_LH) -> R,
) -> Result<R> {
    let win_family = match family {
        AddressFamily::Unspecified => AF_UNSPEC as u32,
        AddressFamily::Ipv4 => AF_INET as u32,
        AddressFamily::Ipv6 => AF_INET6 as u32,
    };

    const STACK_U64S: usize = 1024; // 8 KiB 8-byte aligned stack buffer
    let mut stack_buf = [0u64; STACK_U64S];
    let mut size = (STACK_U64S * std::mem::size_of::<u64>()) as u32;

    let ret = unsafe {
        GetAdaptersAddresses(
            win_family,
            flags.0,
            std::ptr::null_mut(),
            stack_buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
            &mut size,
        )
    };

    if ret == ERROR_SUCCESS {
        let head = if size == 0 {
            std::ptr::null()
        } else {
            stack_buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH
        };
        return Ok(f(head));
    }
    if ret != ERROR_BUFFER_OVERFLOW {
        return Err(IpCfgError::from_win32(ret));
    }

    let mut heap_buf: Vec<u64> = vec![0; (size as usize + 7) / 8];
    loop {
        let ret = unsafe {
            GetAdaptersAddresses(
                win_family,
                flags.0,
                std::ptr::null_mut(),
                heap_buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            )
        };

        if ret == ERROR_SUCCESS {
            let head = if size == 0 {
                std::ptr::null()
            } else {
                heap_buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH
            };
            return Ok(f(head));
        } else if ret == ERROR_BUFFER_OVERFLOW {
            heap_buf.resize((size as usize + 7) / 8, 0);
        } else {
            return Err(IpCfgError::from_win32(ret));
        }
    }
}

/// Retrieves adapter addresses using Win32 `GetAdaptersAddresses`.
pub fn get_adapters_addresses(family: AddressFamily, flags: GaaFlags) -> Result<Vec<AdapterAddresses>> {
    with_raw_adapters_addresses(family, flags, |head| {
        let mut count = 0usize;
        let mut p = head;
        while !p.is_null() {
            count += 1;
            p = unsafe { (*p).Next };
        }

        let mut result = Vec::with_capacity(count);
        let mut curr = head;

        while !curr.is_null() {
            let entry = unsafe { &*curr };

            let adapter_name = if !entry.AdapterName.is_null() {
                unsafe { CStr::from_ptr(entry.AdapterName as *const i8) }
                    .to_string_lossy()
                    .into_owned()
            } else {
                String::new()
            };

            let description = decode_pwstr(entry.Description);
            let friendly_name = decode_pwstr(entry.FriendlyName);

            let phys_len = (entry.PhysicalAddressLength as usize).min(entry.PhysicalAddress.len());
            let physical_address = entry.PhysicalAddress[..phys_len].to_vec();

            result.push(AdapterAddresses {
                adapter_name,
                description,
                friendly_name,
                luid: Luid(entry.Luid),
                if_index: unsafe { entry.Anonymous1.Anonymous.IfIndex },
                ipv6_if_index: entry.Ipv6IfIndex,
                if_type: entry.IfType,
                oper_status: OperStatus::from_raw(entry.OperStatus),
                ipv4_metric: entry.Ipv4Metric,
                ipv6_metric: entry.Ipv6Metric,
                compartment_id: entry.CompartmentId,
                mtu: entry.Mtu,
                physical_address,
            });

            curr = entry.Next;
        }

        result
    })
}

pub(crate) fn collect_adapter_compartments() -> Vec<(u64, u32)> {
    with_raw_adapters_addresses(AddressFamily::Unspecified, GaaFlags::SKIP_ALL, |mut curr| {
        let mut count = 0usize;
        let mut p = curr;
        while !p.is_null() {
            count += 1;
            p = unsafe { (*p).Next };
        }
        let mut out = Vec::with_capacity(count);
        while !curr.is_null() {
            let entry = unsafe { &*curr };
            out.push((unsafe { entry.Luid.Value }, entry.CompartmentId));
            curr = entry.Next;
        }
        out.sort_unstable_by_key(|&(luid, _)| luid);
        out
    })
    .unwrap_or_default()
}

pub(crate) fn collect_ipv4_metrics() -> Vec<(u64, u32)> {
    let mut table_ptr: *mut MIB_IPINTERFACE_TABLE = std::ptr::null_mut();
    let ret = unsafe { GetIpInterfaceTable(AF_INET, &mut table_ptr) };
    if ret != ERROR_SUCCESS || table_ptr.is_null() {
        return Vec::new();
    }
    let _guard = MibTableGuard(table_ptr as *const std::ffi::c_void);
    let table = unsafe { &*table_ptr };
    let num = table.NumEntries as usize;
    if num == 0 {
        return Vec::new();
    }
    let rows = unsafe { std::slice::from_raw_parts(table.Table.as_ptr(), num) };
    let mut out = Vec::with_capacity(num);
    for row in rows {
        out.push((unsafe { row.InterfaceLuid.Value }, row.Metric));
    }
    out.sort_unstable_by_key(|&(luid, _)| luid);
    out
}

/// Configures an IPv4 or IPv6 `MIB_IPINTERFACE_ROW` in a single atomic `GetIpInterfaceEntry` +
/// `SetIpInterfaceEntry` pass matching official WireGuard for Windows (`addressconfig.go`):
/// - `ForwardingEnabled = 0`
/// - `RouterDiscoveryBehavior = 0` (`RouterDiscoveryDisabled`)
/// - `DadTransmits = 0` (immediate `IpDadStatePreferred`, 0ms Duplicate Address Detection delay)
/// - `ManagedAddressConfigurationSupported = 0`
/// - `OtherStatefulConfigurationSupported = 0`
/// - `NlMtu = mtu`
/// - `SitePrefixLength = 0`
/// - If `found_default_route`: `UseAutomaticMetric = 0` and `Metric = 0`
pub fn configure_ip_interface_family(
    luid: Luid,
    family: AddressFamily,
    mtu: u32,
    found_default_route: bool,
) -> Result<()> {
    let win_family = match family {
        AddressFamily::Ipv4 => AF_INET,
        AddressFamily::Ipv6 => AF_INET6,
        AddressFamily::Unspecified => AF_INET,
    };

    let mut row = unsafe { std::mem::zeroed::<MIB_IPINTERFACE_ROW>() };
    initialize_ip_interface_entry(&mut row);
    row.Family = win_family;
    row.InterfaceLuid = luid.0;

    get_ip_interface_entry(&mut row)?;

    row.ForwardingEnabled = 0;
    row.RouterDiscoveryBehavior = 0; // RouterDiscoveryDisabled
    row.DadTransmits = 0;
    row.ManagedAddressConfigurationSupported = 0;
    row.OtherStatefulConfigurationSupported = 0;
    if mtu > 0 {
        row.NlMtu = mtu;
    }
    if found_default_route {
        row.UseAutomaticMetric = 0;
        row.Metric = 0;
    }
    row.SitePrefixLength = 0;

    set_ip_interface_entry(&mut row)
}

/// Sets the MTU for the specified interface across both IPv4 and IPv6 stacks.
pub fn set_interface_mtu(luid: Luid, mtu: u32) -> Result<()> {
    let mut updated = false;
    let mut last_err = None;

    for family in [AF_INET, AF_INET6] {
        let mut row = unsafe { std::mem::zeroed::<MIB_IPINTERFACE_ROW>() };
        initialize_ip_interface_entry(&mut row);
        row.Family = family;
        row.InterfaceLuid = luid.0;

        if get_ip_interface_entry(&mut row).is_ok() {
            row.NlMtu = mtu;
            match set_ip_interface_entry(&mut row) {
                Ok(()) => updated = true,
                Err(e) => last_err = Some(e),
            }
        }
    }

    if updated {
        Ok(())
    } else if let Some(err) = last_err {
        Err(err)
    } else {
        Err(IpCfgError::NotFound)
    }
}

/// Sets the routing metric for the specified interface and address family.
pub fn set_interface_metric(luid: Luid, family: AddressFamily, metric: u32) -> Result<()> {
    let win_family = match family {
        AddressFamily::Ipv4 => AF_INET,
        AddressFamily::Ipv6 => AF_INET6,
        AddressFamily::Unspecified => AF_INET,
    };

    let mut row = unsafe { std::mem::zeroed::<MIB_IPINTERFACE_ROW>() };
    initialize_ip_interface_entry(&mut row);
    row.Family = win_family;
    row.InterfaceLuid = luid.0;

    get_ip_interface_entry(&mut row)?;
    row.UseAutomaticMetric = 0; // FALSE
    row.Metric = metric;
    set_ip_interface_entry(&mut row)?;

    Ok(())
}

/// Sets the administrative status (Up/Down) of an interface using `SetIfEntry`.
pub fn set_interface_admin_status(index: u32, status: AdminStatus) -> Result<()> {
    let mut row: MIB_IFROW = unsafe { std::mem::zeroed() };
    row.dwIndex = index;

    let ret = unsafe { GetIfEntry(&mut row) };
    if ret != ERROR_SUCCESS {
        return Err(IpCfgError::from_win32(ret));
    }

    row.dwAdminStatus = status.to_raw() as u32;
    set_if_entry(&row)?;

    Ok(())
}

/// Queries the compartment ID for the given interface.
pub fn get_interface_compartment_id(luid: Luid) -> Result<u32> {
    let target = luid.as_u64();
    let found = with_raw_adapters_addresses(
        AddressFamily::Unspecified,
        GaaFlags::SKIP_ALL,
        |mut curr| {
            while !curr.is_null() {
                let entry = unsafe { &*curr };
                if unsafe { entry.Luid.Value } == target {
                    return Some(entry.CompartmentId);
                }
                curr = entry.Next;
            }
            None
        },
    )?;
    // Default network compartment on Windows is 1
    Ok(found.unwrap_or(1))
}

/// Sets the compartment ID for the current thread or interface session.
pub fn set_interface_compartment_id(_luid: Luid, compartment_id: u32) -> Result<()> {
    // Windows sets compartment ID at the thread or network level
    let ret = unsafe { SetCurrentThreadCompartmentId(compartment_id) };
    if ret != ERROR_SUCCESS {
        return Err(IpCfgError::from_win32(ret));
    }
    Ok(())
}

fn decode_pwstr(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0;
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        decode_utf16_null_terminated(slice)
    }
}
