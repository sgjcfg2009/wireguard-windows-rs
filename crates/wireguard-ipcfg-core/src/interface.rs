use std::ops::Deref;
use windows_sys::Win32::NetworkManagement::IpHelper::*;

use crate::error::Result;
use crate::guid::Guid;
use crate::ip_helper::{
    collect_adapter_compartments, collect_ipv4_metrics, free_mib_table, get_if_entry2,
    get_if_table2, get_interface_compartment_id, set_interface_admin_status,
    set_interface_compartment_id, set_interface_metric, set_interface_mtu,
};
use crate::luid::Luid;
use crate::types::{AddressFamily, AdminStatus, OperStatus};
use crate::util::decode_utf16_null_terminated;

/// RAII wrapper around a pointer to `MIB_IF_TABLE2` returned by `GetIfTable2`.
///
/// Automatically frees the allocated memory table when dropped via `FreeMibTable`.
pub struct IfTable2 {
    ptr: *mut MIB_IF_TABLE2,
}

impl IfTable2 {
    /// Creates an `IfTable2` wrapper taking ownership of the raw pointer.
    ///
    /// # Safety
    /// The caller must ensure `ptr` was allocated by `GetIfTable2` or `GetIfTable2Ex`.
    pub unsafe fn from_raw(ptr: *mut MIB_IF_TABLE2) -> Self {
        Self { ptr }
    }

    /// Returns the raw pointer to `MIB_IF_TABLE2`.
    pub fn as_raw(&self) -> *mut MIB_IF_TABLE2 {
        self.ptr
    }

    /// Returns a slice of the `MIB_IF_ROW2` entries contained in the table.
    pub fn as_slice(&self) -> &[MIB_IF_ROW2] {
        if self.ptr.is_null() {
            &[]
        } else {
            unsafe {
                let num = (*self.ptr).NumEntries as usize;
                if num == 0 {
                    &[]
                } else {
                    let first = (*self.ptr).Table.as_ptr();
                    std::slice::from_raw_parts(first, num)
                }
            }
        }
    }

    /// Number of interface entries in the table.
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Returns `true` if the table contains zero entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Converts all table rows into high-level `Interface` objects.
    pub fn to_interfaces(&self) -> Vec<Interface> {
        let rows = self.as_slice();
        if rows.is_empty() {
            return Vec::new();
        }

        // Fetch compartments and IPv4 metrics in two batch table queries rather than O(N) calls.
        let compartments = collect_adapter_compartments();
        let metrics = collect_ipv4_metrics();

        let mut interfaces = Vec::with_capacity(rows.len());
        for row in rows {
            let luid_val = unsafe { row.InterfaceLuid.Value };
            let compartment_id = lookup_sorted(&compartments, luid_val).unwrap_or(1);
            let metric = lookup_sorted(&metrics, luid_val).unwrap_or(0);
            interfaces.push(Interface::from_row_with_meta(row, compartment_id, metric));
        }
        interfaces
    }
}

impl Deref for IfTable2 {
    type Target = [MIB_IF_ROW2];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl Drop for IfTable2 {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            free_mib_table(self.ptr as *const std::ffi::c_void);
            self.ptr = std::ptr::null_mut();
        }
    }
}

/// A safe wrapper around the raw Win32 `MIB_IF_ROW2` struct.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct MibIfRow2(pub MIB_IF_ROW2);

impl MibIfRow2 {
    /// Creates a new `MibIfRow2` initialized with the given LUID.
    pub fn new(luid: Luid) -> Self {
        let mut row = unsafe { std::mem::zeroed::<MIB_IF_ROW2>() };
        row.InterfaceLuid = luid.0;
        Self(row)
    }

    /// Creates a new `MibIfRow2` initialized with the given interface index.
    pub fn from_index(index: u32) -> Self {
        let mut row = unsafe { std::mem::zeroed::<MIB_IF_ROW2>() };
        row.InterfaceIndex = index;
        Self(row)
    }

    /// Retrieves information for the specified interface from the system.
    pub fn get(&mut self) -> Result<()> {
        get_if_entry2(&mut self.0)
    }

    /// Returns the LUID of the interface.
    pub fn luid(&self) -> Luid {
        Luid(self.0.InterfaceLuid)
    }

    /// Returns the local interface index.
    pub fn index(&self) -> u32 {
        self.0.InterfaceIndex
    }

    /// Returns the interface GUID.
    pub fn guid(&self) -> Guid {
        Guid(self.0.InterfaceGuid)
    }

    /// Returns the alias (friendly name) of the interface.
    pub fn alias(&self) -> String {
        decode_utf16_null_terminated(&self.0.Alias)
    }

    /// Returns the description of the interface.
    pub fn description(&self) -> String {
        decode_utf16_null_terminated(&self.0.Description)
    }

    /// Returns the current hardware physical address.
    pub fn physical_address(&self) -> &[u8] {
        let len = (self.0.PhysicalAddressLength as usize).min(self.0.PhysicalAddress.len());
        &self.0.PhysicalAddress[..len]
    }

    /// Returns the permanent hardware physical address.
    pub fn permanent_physical_address(&self) -> &[u8] {
        let len = (self.0.PhysicalAddressLength as usize).min(self.0.PermanentPhysicalAddress.len());
        &self.0.PermanentPhysicalAddress[..len]
    }

    /// Returns the MTU of the interface.
    pub fn mtu(&self) -> u32 {
        self.0.Mtu
    }

    /// Returns the operational status.
    pub fn oper_status(&self) -> OperStatus {
        OperStatus::from_raw(self.0.OperStatus)
    }

    /// Returns the administrative status.
    pub fn admin_status(&self) -> AdminStatus {
        AdminStatus::from_raw(self.0.AdminStatus)
    }

    /// Returns the interface type.
    pub fn if_type(&self) -> u32 {
        self.0.Type
    }

    /// Returns the media type.
    pub fn media_type(&self) -> u32 {
        self.0.MediaType as u32
    }

    /// Returns the transmit link speed in bits per second.
    pub fn transmit_link_speed(&self) -> u64 {
        self.0.TransmitLinkSpeed
    }

    /// Returns the receive link speed in bits per second.
    pub fn receive_link_speed(&self) -> u64 {
        self.0.ReceiveLinkSpeed
    }
}

/// High-level network interface representation with full property access.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    pub luid: Luid,
    pub index: u32,
    pub guid: Guid,
    pub alias: String,
    pub description: String,
    pub physical_address: Vec<u8>,
    pub permanent_physical_address: Vec<u8>,
    pub mtu: u32,
    pub if_type: u32,
    pub oper_status: OperStatus,
    pub admin_status: AdminStatus,
    pub media_type: u32,
    pub transmit_link_speed: u64,
    pub receive_link_speed: u64,
    pub compartment_id: u32,
    pub metric: u32,
}

impl Interface {
    /// Constructs an `Interface` from a Win32 `MIB_IF_ROW2` entry.
    pub fn from_row(row: &MIB_IF_ROW2) -> Self {
        let luid = Luid(row.InterfaceLuid);
        let compartment_id = get_interface_compartment_id(luid).unwrap_or(1);
        let metric = luid.metric(AddressFamily::Ipv4).unwrap_or(0);
        Self::from_row_with_meta(row, compartment_id, metric)
    }

    fn from_row_with_meta(row: &MIB_IF_ROW2, compartment_id: u32, metric: u32) -> Self {
        let luid = Luid(row.InterfaceLuid);
        let phys_len = (row.PhysicalAddressLength as usize).min(row.PhysicalAddress.len());
        let perm_len = (row.PhysicalAddressLength as usize).min(row.PermanentPhysicalAddress.len());

        Self {
            luid,
            index: row.InterfaceIndex,
            guid: Guid(row.InterfaceGuid),
            alias: decode_utf16_null_terminated(&row.Alias),
            description: decode_utf16_null_terminated(&row.Description),
            physical_address: row.PhysicalAddress[..phys_len].to_vec(),
            permanent_physical_address: row.PermanentPhysicalAddress[..perm_len].to_vec(),
            mtu: row.Mtu,
            if_type: row.Type,
            oper_status: OperStatus::from_raw(row.OperStatus),
            admin_status: AdminStatus::from_raw(row.AdminStatus),
            media_type: row.MediaType as u32,
            transmit_link_speed: row.TransmitLinkSpeed,
            receive_link_speed: row.ReceiveLinkSpeed,
            compartment_id,
            metric,
        }
    }

    /// Retrieves an interface by its LUID.
    pub fn get(luid: Luid) -> Result<Self> {
        let mut row = unsafe { std::mem::zeroed::<MIB_IF_ROW2>() };
        row.InterfaceLuid = luid.0;
        get_if_entry2(&mut row)?;
        Ok(Self::from_row(&row))
    }

    /// Retrieves an interface by its interface index.
    pub fn get_by_index(index: u32) -> Result<Self> {
        let mut row = unsafe { std::mem::zeroed::<MIB_IF_ROW2>() };
        row.InterfaceIndex = index;
        get_if_entry2(&mut row)?;
        Ok(Self::from_row(&row))
    }

    /// Retrieves an interface by its friendly alias (e.g. "Ethernet" or "wg0").
    pub fn get_by_alias(alias: &str) -> Result<Self> {
        let luid = Luid::from_alias(alias)?;
        Self::get(luid)
    }

    /// Retrieves an interface by its device name (e.g. `\DEVICE\TCPIP_{GUID}`).
    pub fn get_by_name(name: &str) -> Result<Self> {
        let luid = Luid::from_name(name)?;
        Self::get(luid)
    }

    /// Retrieves an interface by its GUID.
    pub fn get_by_guid(guid: &Guid) -> Result<Self> {
        let luid = Luid::from_guid(guid)?;
        Self::get(luid)
    }

    /// Retrieves all network interfaces on the local system.
    pub fn get_all() -> Result<Vec<Self>> {
        let table = get_if_table2()?;
        Ok(table.to_interfaces())
    }

    /// Refreshes this interface's properties from the operating system.
    pub fn refresh(&mut self) -> Result<()> {
        let updated = Self::get(self.luid)?;
        *self = updated;
        Ok(())
    }

    /// Returns the MTU of this interface.
    pub fn mtu(&self) -> u32 {
        self.mtu
    }

    /// Sets the MTU of this interface in the operating system and updates this struct.
    pub fn set_mtu(&mut self, mtu: u32) -> Result<()> {
        set_interface_mtu(self.luid, mtu)?;
        self.mtu = mtu;
        Ok(())
    }

    /// Returns the metric of this interface.
    pub fn metric(&self) -> u32 {
        self.metric
    }

    /// Sets the interface metric for the specified address family.
    pub fn set_metric(&mut self, family: AddressFamily, metric: u32) -> Result<()> {
        set_interface_metric(self.luid, family, metric)?;
        self.metric = metric;
        Ok(())
    }

    /// Returns the operational status of this interface.
    pub fn oper_status(&self) -> OperStatus {
        self.oper_status
    }

    /// Returns the administrative status of this interface.
    pub fn admin_status(&self) -> AdminStatus {
        self.admin_status
    }

    /// Sets the administrative status (Up/Down) of this interface.
    pub fn set_admin_status(&mut self, status: AdminStatus) -> Result<()> {
        set_interface_admin_status(self.index, status)?;
        self.admin_status = status;
        Ok(())
    }

    /// Returns the compartment ID of this interface.
    pub fn compartment_id(&self) -> u32 {
        self.compartment_id
    }

    /// Sets the compartment ID of this interface.
    pub fn set_compartment_id(&mut self, compartment_id: u32) -> Result<()> {
        set_interface_compartment_id(self.luid, compartment_id)?;
        self.compartment_id = compartment_id;
        Ok(())
    }
}

#[inline]
fn lookup_sorted(entries: &[(u64, u32)], key: u64) -> Option<u32> {
    entries
        .binary_search_by_key(&key, |&(k, _)| k)
        .ok()
        .map(|idx| entries[idx].1)
}
