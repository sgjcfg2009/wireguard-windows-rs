use std::fmt;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

use crate::error::{IpCfgError, Result};
use crate::guid::Guid;
use crate::interface::Interface;
use crate::ip_helper::{
    get_if_entry2, get_interface_compartment_id, get_ip_interface_entry,
    initialize_ip_interface_entry, set_interface_admin_status, set_interface_compartment_id,
    set_interface_metric, set_interface_mtu,
};
use crate::types::{AddressFamily, AdminStatus, OperStatus};
use crate::util::{decode_utf16_strict, with_wide_null};

/// A type-safe wrapper around the Windows `NET_LUID_LH` (Locally Unique Identifier) union.
///
/// An interface LUID uniquely identifies a network interface on the local computer across reboots.
#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct Luid(pub NET_LUID_LH);

impl Default for Luid {
    fn default() -> Self {
        Self(NET_LUID_LH { Value: 0 })
    }
}

impl Luid {
    /// Creates a `Luid` from a raw 64-bit unsigned integer value.
    pub const fn from_u64(value: u64) -> Self {
        Self(NET_LUID_LH { Value: value })
    }

    /// Returns the raw 64-bit integer representation of this LUID.
    pub const fn as_u64(&self) -> u64 {
        unsafe { self.0.Value }
    }

    /// Converts an interface alias (friendly name, e.g. "Ethernet" or "wg0") to a LUID.
    ///
    /// Corresponds to Win32 `ConvertInterfaceAliasToLuid`.
    pub fn from_alias(alias: &str) -> Result<Self> {
        let mut luid = NET_LUID_LH { Value: 0 };
        let ret = with_wide_null(alias, |ptr| unsafe {
            ConvertInterfaceAliasToLuid(ptr, &mut luid)
        });
        if ret != ERROR_SUCCESS {
            return Err(IpCfgError::from_win32(ret));
        }
        Ok(Self(luid))
    }

    /// Converts an interface name (e.g. `\DEVICE\TCPIP_{GUID}` or `ethernet_0`) to a LUID.
    ///
    /// Corresponds to Win32 `ConvertInterfaceNameToLuidW`.
    pub fn from_name(name: &str) -> Result<Self> {
        let mut luid = NET_LUID_LH { Value: 0 };
        let ret = with_wide_null(name, |ptr| unsafe {
            ConvertInterfaceNameToLuidW(ptr, &mut luid)
        });
        if ret != ERROR_SUCCESS {
            return Err(IpCfgError::from_win32(ret));
        }
        Ok(Self(luid))
    }

    /// Converts an interface GUID to a LUID.
    ///
    /// Corresponds to Win32 `ConvertInterfaceGuidToLuid`.
    pub fn from_guid(guid: &Guid) -> Result<Self> {
        let mut luid = NET_LUID_LH { Value: 0 };
        let ret = unsafe { ConvertInterfaceGuidToLuid(&guid.0, &mut luid) };
        if ret != ERROR_SUCCESS {
            return Err(IpCfgError::from_win32(ret));
        }
        Ok(Self(luid))
    }

    /// Converts an interface index to a LUID.
    ///
    /// Corresponds to Win32 `ConvertInterfaceIndexToLuid`.
    pub fn from_index(index: u32) -> Result<Self> {
        let mut luid = NET_LUID_LH { Value: 0 };
        let ret = unsafe { ConvertInterfaceIndexToLuid(index, &mut luid) };
        if ret != ERROR_SUCCESS {
            return Err(IpCfgError::from_win32(ret));
        }
        Ok(Self(luid))
    }

    /// Converts the LUID to an interface alias (friendly name, e.g. "Local Area Connection").
    ///
    /// Corresponds to Win32 `ConvertInterfaceLuidToAlias`.
    pub fn to_alias(&self) -> Result<String> {
        // NDIS_IF_MAX_STRING_SIZE is 256 (+ 1 for null terminator)
        let mut buf = [0u16; 257];
        let ret = unsafe { ConvertInterfaceLuidToAlias(&self.0, buf.as_mut_ptr(), buf.len()) };
        if ret != ERROR_SUCCESS {
            return Err(IpCfgError::from_win32(ret));
        }
        decode_utf16_strict(&buf)
    }

    /// Converts the LUID to an interface device name.
    ///
    /// Corresponds to Win32 `ConvertInterfaceLuidToNameW`.
    pub fn to_name(&self) -> Result<String> {
        let mut buf = [0u16; 257];
        let ret = unsafe { ConvertInterfaceLuidToNameW(&self.0, buf.as_mut_ptr(), buf.len()) };
        if ret != ERROR_SUCCESS {
            return Err(IpCfgError::from_win32(ret));
        }
        decode_utf16_strict(&buf)
    }

    /// Converts the LUID to an interface GUID.
    ///
    /// Corresponds to Win32 `ConvertInterfaceLuidToGuid`.
    pub fn to_guid(&self) -> Result<Guid> {
        let mut guid = GUID {
            data1: 0,
            data2: 0,
            data3: 0,
            data4: [0; 8],
        };
        let ret = unsafe { ConvertInterfaceLuidToGuid(&self.0, &mut guid) };
        if ret != ERROR_SUCCESS {
            return Err(IpCfgError::from_win32(ret));
        }
        Ok(Guid(guid))
    }

    /// Converts the LUID to an interface index.
    ///
    /// Corresponds to Win32 `ConvertInterfaceLuidToIndex`.
    pub fn to_index(&self) -> Result<u32> {
        let mut index = 0u32;
        let ret = unsafe { ConvertInterfaceLuidToIndex(&self.0, &mut index) };
        if ret != ERROR_SUCCESS {
            return Err(IpCfgError::from_win32(ret));
        }
        Ok(index)
    }

    /// Retrieves interface information for this LUID.
    pub fn interface(&self) -> Result<Interface> {
        Interface::get(*self)
    }

    /// Retrieves the low-level Win32 `MIB_IF_ROW2` for this LUID.
    pub fn raw_interface(&self) -> Result<MIB_IF_ROW2> {
        let mut row = unsafe { std::mem::zeroed::<MIB_IF_ROW2>() };
        row.InterfaceLuid = self.0;
        get_if_entry2(&mut row)?;
        Ok(row)
    }

    /// Retrieves the interface MTU.
    pub fn mtu(&self) -> Result<u32> {
        let row = self.raw_interface()?;
        Ok(row.Mtu)
    }

    /// Sets the interface MTU for both IPv4 and IPv6 stacks.
    pub fn set_mtu(&self, mtu: u32) -> Result<()> {
        set_interface_mtu(*self, mtu)
    }

    /// Retrieves the metric of the interface for the specified address family.
    pub fn metric(&self, family: AddressFamily) -> Result<u32> {
        use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

        let mut row = unsafe { std::mem::zeroed::<MIB_IPINTERFACE_ROW>() };
        initialize_ip_interface_entry(&mut row);
        row.Family = match family {
            AddressFamily::Ipv4 => AF_INET,
            AddressFamily::Ipv6 => AF_INET6,
            AddressFamily::Unspecified => AF_INET,
        };
        row.InterfaceLuid = self.0;
        get_ip_interface_entry(&mut row)?;
        Ok(row.Metric)
    }

    /// Sets the metric of the interface for the specified address family.
    pub fn set_metric(&self, family: AddressFamily, metric: u32) -> Result<()> {
        set_interface_metric(*self, family, metric)
    }

    /// Retrieves the operational status of the interface.
    pub fn oper_status(&self) -> Result<OperStatus> {
        let row = self.raw_interface()?;
        Ok(OperStatus::from_raw(row.OperStatus))
    }

    /// Retrieves the administrative status of the interface.
    pub fn admin_status(&self) -> Result<AdminStatus> {
        let row = self.raw_interface()?;
        Ok(AdminStatus::from_raw(row.AdminStatus))
    }

    /// Sets the administrative status (Up/Down) of the interface.
    pub fn set_admin_status(&self, status: AdminStatus) -> Result<()> {
        let index = self.to_index()?;
        set_interface_admin_status(index, status)
    }

    /// Retrieves the compartment ID of the interface.
    pub fn compartment_id(&self) -> Result<u32> {
        get_interface_compartment_id(*self)
    }

    /// Sets the compartment ID of the interface.
    pub fn set_compartment_id(&self, compartment_id: u32) -> Result<()> {
        set_interface_compartment_id(*self, compartment_id)
    }
}

impl PartialEq for Luid {
    fn eq(&self, other: &Self) -> bool {
        self.as_u64() == other.as_u64()
    }
}

impl Eq for Luid {}

impl PartialOrd for Luid {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Luid {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_u64().cmp(&other.as_u64())
    }
}

impl std::hash::Hash for Luid {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_u64().hash(state);
    }
}

impl fmt::Display for Luid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Luid(0x{:016x})", self.as_u64())
    }
}

impl fmt::Debug for Luid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Luid(0x{:016x})", self.as_u64())
    }
}

impl From<NET_LUID_LH> for Luid {
    fn from(luid: NET_LUID_LH) -> Self {
        Self(luid)
    }
}

impl From<Luid> for NET_LUID_LH {
    fn from(luid: Luid) -> Self {
        luid.0
    }
}

impl From<u64> for Luid {
    fn from(val: u64) -> Self {
        Self::from_u64(val)
    }
}

impl From<Luid> for u64 {
    fn from(luid: Luid) -> Self {
        luid.as_u64()
    }
}
