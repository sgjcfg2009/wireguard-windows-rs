//! `wireguard-ipcfg-core` provides high-performance, memory-safe, idiomatic Rust wrappers
//! around Windows IP Helper (`iphlpapi.dll`) and NDIS APIs for WireGuard on Windows.
//!
//! Subsystems included:
//! - Locally Unique Identifier (`Luid`) conversions: from/to alias, from/to name, from/to GUID, from/to index.
//! - Globally Unique Identifier (`Guid`) utilities: parsing (braced/unbraced/compact), formatting, byte conversions.
//! - Interface management: query and set MTU, routing metric, operational status, administrative status, compartment ID.
//! - Safe wrappers around Win32 IP Helper functions: `GetIfTable2`, `GetIfTable2Ex`, `GetIfEntry2`, `SetIfEntry`, `SetIfEntry2`, `SetIpInterfaceEntry`.

pub mod error;
pub mod guid;
pub mod interface;
pub mod ip_helper;
pub mod luid;
pub mod types;
mod util;

pub use error::{format_win32_error, IpCfgError, Result};
pub use guid::Guid;
pub use interface::{IfTable2, Interface, MibIfRow2};
pub use ip_helper::{
    configure_ip_interface_family, free_mib_table, get_adapters_addresses, get_if_entry2,
    get_if_table2, get_if_table2_ex, get_interface_compartment_id, get_ip_interface_entry,
    initialize_ip_interface_entry, set_if_entry, set_if_entry2, set_interface_admin_status,
    set_interface_compartment_id, set_interface_metric, set_interface_mtu,
    set_ip_interface_entry, AdapterAddresses,
};
pub use luid::Luid;
pub use types::{AddressFamily, AdminStatus, GaaFlags, OperStatus};

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::str::FromStr;

    #[test]
    fn test_guid_parse_canonical_braced() {
        let raw = "{12345678-abcd-ef01-2345-6789abcdef01}";
        let guid = Guid::from_str(raw).expect("Failed to parse braced GUID");
        assert_eq!(guid.0.data1, 0x12345678);
        assert_eq!(guid.0.data2, 0xabcd);
        assert_eq!(guid.0.data3, 0xef01);
        assert_eq!(guid.0.data4, [0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01]);
        assert_eq!(guid.to_string(), raw);
    }

    #[test]
    fn test_guid_parse_unbraced() {
        let raw = "12345678-ABCD-EF01-2345-6789ABCDEF01";
        let guid = Guid::from_str(raw).expect("Failed to parse uppercase unbraced GUID");
        assert_eq!(guid.0.data1, 0x12345678);
        assert_eq!(guid.0.data2, 0xabcd);
        assert_eq!(guid.0.data3, 0xef01);
        assert_eq!(guid.0.data4, [0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01]);
        assert_eq!(
            guid.to_string_without_braces(),
            "12345678-abcd-ef01-2345-6789abcdef01"
        );
    }

    #[test]
    fn test_guid_parse_compact_hex() {
        let raw = "00112233445566778899aabbccddeeff";
        let guid = Guid::from_str(raw).expect("Failed to parse compact 32-hex GUID");
        assert_eq!(guid.0.data1, 0x00112233);
        assert_eq!(guid.0.data2, 0x4455);
        assert_eq!(guid.0.data3, 0x6677);
        assert_eq!(guid.0.data4, [0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_guid_parse_invalid() {
        assert!(Guid::from_str("not-a-guid").is_err());
        assert!(Guid::from_str("{12345678-1234-1234-1234-1234567890}").is_err()); // too short
        assert!(Guid::from_str("{12345678-1234-1234-1234-12345678901234}").is_err()); // too long
        assert!(Guid::from_str("{12345678-zzzz-1234-1234-123456789012}").is_err()); // invalid hex
    }

    #[test]
    fn test_guid_roundtrip_bytes() {
        let original = Guid::new(0xdeadbeef, 0xcafe, 0xbabe, [1, 2, 3, 4, 5, 6, 7, 8]);
        let le_bytes = original.to_bytes_le();
        let from_le = Guid::from_bytes_le(le_bytes);
        assert_eq!(original, from_le);

        let be_bytes = original.to_bytes_be();
        let from_be = Guid::from_bytes_be(be_bytes);
        assert_eq!(original, from_be);
    }

    #[test]
    fn test_guid_hash_and_ordering() {
        let g1 = Guid::from_str("{00000000-0000-0000-0000-000000000001}").unwrap();
        let g2 = Guid::from_str("{00000000-0000-0000-0000-000000000002}").unwrap();
        let g3 = Guid::from_str("{00000000-0000-0000-0000-000000000001}").unwrap();

        assert_eq!(g1, g3);
        assert_ne!(g1, g2);

        let mut set = HashSet::new();
        set.insert(g1);
        set.insert(g2);
        assert_eq!(set.len(), 2);
        assert!(set.contains(&g3));
    }

    #[test]
    fn test_luid_basics() {
        let luid = Luid::from_u64(0x0123456789abcdef);
        assert_eq!(luid.as_u64(), 0x0123456789abcdef);
        assert_eq!(luid.to_string(), "Luid(0x0123456789abcdef)");

        let luid_copy = luid;
        assert_eq!(luid, luid_copy);

        let mut map = HashSet::new();
        map.insert(luid);
        assert!(map.contains(&Luid::from_u64(0x0123456789abcdef)));
    }

    #[test]
    fn test_live_get_if_table2() {
        let table = get_if_table2().expect("Failed to get interface table from Windows");
        assert!(!table.is_empty(), "Interface table must contain at least one interface");

        let interfaces = table.to_interfaces();
        assert_eq!(table.len(), interfaces.len());

        for iface in &interfaces {
            // Verify LUID <-> index roundtrip
            if iface.index != 0 {
                let from_idx = Luid::from_index(iface.index).expect("Luid::from_index failed");
                assert_eq!(iface.luid, from_idx);

                let back_idx = iface.luid.to_index().expect("luid.to_index failed");
                assert_eq!(iface.index, back_idx);
            }

            // Verify LUID <-> GUID roundtrip
            let guid = iface.luid.to_guid().expect("luid.to_guid failed");
            assert_eq!(guid, iface.guid);

            let back_luid = guid.to_luid().expect("guid.to_luid failed");
            assert_eq!(iface.luid, back_luid);

            // Verify LUID <-> name roundtrip
            if let Ok(name) = iface.luid.to_name() {
                if !name.is_empty() {
                    let from_name = Luid::from_name(&name).expect("Luid::from_name failed");
                    assert_eq!(iface.luid, from_name);
                }
            }

            // Verify LUID <-> alias roundtrip
            if let Ok(alias) = iface.luid.to_alias() {
                if !alias.is_empty() {
                    if let Ok(from_alias) = Luid::from_alias(&alias) {
                        assert_eq!(iface.luid, from_alias);
                    }
                }
            }

            // Verify GetIfEntry2
            let mut row = unsafe { std::mem::zeroed::<windows_sys::Win32::NetworkManagement::IpHelper::MIB_IF_ROW2>() };
            row.InterfaceLuid = iface.luid.0;
            get_if_entry2(&mut row).expect("get_if_entry2 failed for live interface");
            assert_eq!(row.InterfaceIndex, iface.index);
        }
    }
}
