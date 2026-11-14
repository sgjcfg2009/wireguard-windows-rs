// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.

//! WireGuard configuration file parser, serializer, and migration tools for Windows.
//!
//! Re-implementation in 100% Rust of `conf/parser.go`, `conf/writer.go`, `conf/name.go`,
//! and `conf/migration_windows.go`.

pub mod migration;
pub mod name;
pub mod parser;
pub mod path;
pub mod store;
pub mod writer;

pub use migration::{migrate_unencrypted_configs, MigrationError, MigrationRecord};
pub use name::{
    sanitize_tunnel_name, service_name_of_tunnel, tunnel_name_is_less, tunnel_name_is_valid,
    TunnelNameError,
};
pub use parser::{
    from_wg_quick, from_wg_quick_with_unknown_encoding, parse_config, parse_config_bytes,
    parse_config_with_name, parse_endpoint, ParseError,
};
pub use path::{
    config_path, name_from_path, path_is_encrypted, PathError, CONFIG_FILE_SUFFIX,
    CONFIG_FILE_UNENCRYPTED_SUFFIX,
};
pub use store::{list_config_names, load_from_path, StoreError};
pub use writer::{to_wg_conf, to_wg_quick};

// Re-export common types from wireguard-types
pub use wireguard_types::{
    AllowedIp, Endpoint, InterfaceConfig, Key, KeyParseError, PeerConfig, TunnelConfig as Config,
    TunnelConfig,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    const TEST_CONFIG: &str = r#"
[Interface]
Address = 10.192.122.1/24
Address = 10.10.0.1/16
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 51820 # comments don't matter
DNS = 1.1.1.1, 8.8.8.8, corp.internal
MTU = 1420
PreUp = echo 'preup # test'
Table = auto

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 192.95.5.67:1234
AllowedIPs = 10.192.122.3/32, 10.192.124.1/24

[Peer]
PublicKey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=
Endpoint = [2607:5300:60:6b0::c05f:543]:2468
AllowedIPs = 10.192.122.4/32, 192.168.0.0/16
PersistentKeepalive = 100

[Peer]
PublicKey = gN65BkIKy1eCE9pP1wdc8ROUtkHLF2PfAqYdyYBz6EA=
PresharedKey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=
Endpoint = test.wireguard.com:18981
AllowedIPs = 10.10.10.230/32
"#;

    #[test]
    fn test_parse_valid_config() {
        let conf = parse_config(TEST_CONFIG).expect("valid config should parse");

        // Interface checks
        assert_eq!(conf.interface.addresses.len(), 2);
        assert_eq!(
            conf.interface.addresses[0],
            AllowedIp::new(IpAddr::V4(Ipv4Addr::new(10, 192, 122, 1)), 24)
        );
        assert_eq!(
            conf.interface.addresses[1],
            AllowedIp::new(IpAddr::V4(Ipv4Addr::new(10, 10, 0, 1)), 16)
        );
        assert_eq!(
            conf.interface.private_key.unwrap().to_base64(),
            "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
        );
        assert_eq!(conf.interface.listen_port, Some(51820));
        assert_eq!(conf.interface.mtu, Some(1420));
        assert_eq!(conf.interface.dns.len(), 2);
        assert_eq!(conf.interface.dns_search, vec!["corp.internal"]);
        assert_eq!(conf.interface.pre_up.as_deref(), Some("echo 'preup # test'"));
        assert!(!conf.interface.table_off);

        // Peers check
        assert_eq!(conf.peers.len(), 3);

        // Peer 0
        assert_eq!(
            conf.peers[0].public_key.to_base64(),
            "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
        );
        assert_eq!(
            conf.peers[0].endpoint,
            Some(Endpoint::new("192.95.5.67", 1234))
        );
        assert_eq!(conf.peers[0].allowed_ips.len(), 2);

        // Peer 1
        assert_eq!(
            conf.peers[1].public_key.to_base64(),
            "TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0="
        );
        assert_eq!(
            conf.peers[1].endpoint,
            Some(Endpoint::new("2607:5300:60:6b0::c05f:543", 2468))
        );
        assert_eq!(conf.peers[1].persistent_keepalive, Some(100));

        // Peer 2
        assert_eq!(
            conf.peers[2].public_key.to_base64(),
            "gN65BkIKy1eCE9pP1wdc8ROUtkHLF2PfAqYdyYBz6EA="
        );
        assert_eq!(
            conf.peers[2].preshared_key.as_ref().unwrap().to_base64(),
            "TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0="
        );
        assert_eq!(
            conf.peers[2].endpoint,
            Some(Endpoint::new("test.wireguard.com", 18981))
        );
        assert_eq!(conf.peers[2].allowed_ips.len(), 1);
    }

    #[test]
    fn test_roundtrip_serialization() {
        let conf1 = parse_config(TEST_CONFIG).expect("parse original config");
        let serialized = to_wg_conf(&conf1);
        let conf2 = parse_config(&serialized).expect("parse serialized config");

        assert_eq!(conf1.interface.addresses, conf2.interface.addresses);
        assert_eq!(conf1.interface.private_key, conf2.interface.private_key);
        assert_eq!(conf1.interface.listen_port, conf2.interface.listen_port);
        assert_eq!(conf1.interface.mtu, conf2.interface.mtu);
        assert_eq!(conf1.interface.dns, conf2.interface.dns);
        assert_eq!(conf1.interface.dns_search, conf2.interface.dns_search);
        assert_eq!(conf1.interface.pre_up, conf2.interface.pre_up);
        assert_eq!(conf1.interface.table_off, conf2.interface.table_off);

        assert_eq!(conf1.peers.len(), conf2.peers.len());
        for (p1, p2) in conf1.peers.iter().zip(conf2.peers.iter()) {
            assert_eq!(p1.public_key, p2.public_key);
            assert_eq!(p1.preshared_key, p2.preshared_key);
            assert_eq!(p1.endpoint, p2.endpoint);
            assert_eq!(p1.allowed_ips, p2.allowed_ips);
            assert_eq!(p1.persistent_keepalive, p2.persistent_keepalive);
        }

        // Second roundtrip is idempotent
        let serialized2 = to_wg_conf(&conf2);
        assert_eq!(serialized, serialized2);
    }

    #[test]
    fn test_invalid_configs() {
        // Missing section
        assert!(matches!(
            parse_config("PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n"),
            Err(ParseError::NotInSection(_))
        ));

        // Missing equals
        assert!(matches!(
            parse_config("[Interface]\nPrivateKey\n"),
            Err(ParseError::MissingEquals(_))
        ));

        // Missing value
        assert!(matches!(
            parse_config("[Interface]\nPrivateKey =\n"),
            Err(ParseError::MissingValue(_))
        ));

        // Missing private key in interface
        assert_eq!(
            parse_config("[Interface]\nListenPort = 51820\n"),
            Err(ParseError::MissingPrivateKey)
        );

        // Missing public key in peer
        assert_eq!(
            parse_config("[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n[Peer]\nEndpoint = 1.2.3.4:51820\n"),
            Err(ParseError::MissingPublicKey)
        );

        // Invalid key in [Interface]
        assert!(matches!(
            parse_config("[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nUnknownField = 123\n"),
            Err(ParseError::InvalidInterfaceKey(_))
        ));

        // Invalid key in [Peer]
        assert!(matches!(
            parse_config("[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nUnknownPeerField = 123\n"),
            Err(ParseError::InvalidPeerKey(_))
        ));

        // Two commas in a row
        assert!(matches!(
            parse_config("[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.0.0.1/24,,10.0.0.2/24\n"),
            Err(ParseError::DoubleComma(_))
        ));

        // Invalid IP
        assert!(matches!(
            parse_config("[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 999.999.999.999/24\n"),
            Err(ParseError::InvalidIp(_))
        ));

        // Invalid CIDR prefix
        assert!(matches!(
            parse_config("[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.0.0.1/33\n"),
            Err(ParseError::InvalidCidr(_))
        ));

        // Invalid MTU
        assert!(matches!(
            parse_config("[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nMTU = 500\n"),
            Err(ParseError::InvalidMtu(_))
        ));

        // Invalid Port
        assert!(matches!(
            parse_config("[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nListenPort = 70000\n"),
            Err(ParseError::InvalidPort(_))
        ));
    }

    #[test]
    fn test_parse_endpoint_cases() {
        // Valid IPv4
        let ep = parse_endpoint("192.168.42.0:51880").unwrap();
        assert_eq!(ep.host, "192.168.42.0");
        assert_eq!(ep.port, 51880);

        // Valid domain
        let ep = parse_endpoint("test.wireguard.com:18981").unwrap();
        assert_eq!(ep.host, "test.wireguard.com");
        assert_eq!(ep.port, 18981);

        // Valid bracketed IPv6
        let ep = parse_endpoint("[2607:5300:60:6b0::c05f:543]:2468").unwrap();
        assert_eq!(ep.host, "2607:5300:60:6b0::c05f:543");
        assert_eq!(ep.port, 2468);

        // Invalid bracketed IPv4
        assert!(parse_endpoint("[192.168.42.0:]:51880").is_err());

        // Invalid missing bracket
        assert!(parse_endpoint("[::::::invalid:18981").is_err());

        // Bare IPv6 without brackets
        assert!(parse_endpoint("::0").is_err());
    }

    #[test]
    fn test_utf8_bom_and_utf16_parsing() {
        let content = "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n";

        // UTF-8 with BOM
        let mut with_bom = vec![0xEF, 0xBB, 0xBF];
        with_bom.extend_from_slice(content.as_bytes());
        let conf = parse_config_bytes(&with_bom, "wg0").unwrap();
        assert_eq!(conf.name, "wg0");
        assert!(conf.interface.private_key.is_some());

        // UTF-16LE with BOM
        let mut u16_le = vec![0xFF, 0xFE];
        for u in content.encode_utf16() {
            u16_le.extend_from_slice(&u.to_le_bytes());
        }
        let conf_u16_le = parse_config_bytes(&u16_le, "wg0").unwrap();
        assert_eq!(conf_u16_le.interface.private_key, conf.interface.private_key);

        // UTF-16BE with BOM
        let mut u16_be = vec![0xFE, 0xFF];
        for u in content.encode_utf16() {
            u16_be.extend_from_slice(&u.to_be_bytes());
        }
        let conf_u16_be = parse_config_bytes(&u16_be, "wg0").unwrap();
        assert_eq!(conf_u16_be.interface.private_key, conf.interface.private_key);

        // ISO-8859-1 fallback (invalid UTF-8 byte 0xE9 in comment)
        let latin1 = b"[Interface]\n# Caf\xE9\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n";
        let conf_latin1 = parse_config_bytes(latin1, "wg0").unwrap();
        assert_eq!(conf_latin1.interface.private_key, conf.interface.private_key);

        // Invalid tunnel name rejected
        assert!(parse_config_bytes(&with_bom, "bad/name").is_err());
    }
}
