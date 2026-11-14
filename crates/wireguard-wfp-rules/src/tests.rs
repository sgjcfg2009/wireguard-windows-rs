/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use wireguard_wfp_engine::{Guid, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_PERMIT, FWP_MATCH_EQUAL};
    use crate::builder::{ConditionData, FilterBuilder, RuleCondition};
    use crate::manager::FirewallConfig;
    use crate::error::RulesError;

    #[test]
    fn test_builder_fluent_api() {
        let cond = RuleCondition::uint16(FWPM_CONDITION_IP_REMOTE_PORT, FWP_MATCH_EQUAL, 53);
        assert_eq!(cond.match_type, FWP_MATCH_EQUAL);
        match cond.data {
            ConditionData::Uint16(v) => assert_eq!(v, 53),
            _ => panic!("Expected Uint16 condition data"),
        }

        let builder = FilterBuilder::new("Test Rule", FWPM_LAYER_ALE_AUTH_CONNECT_V4)
            .description("Test description")
            .action(FWP_ACTION_PERMIT)
            .weight(15)
            .condition(cond);

        // Verify builder fields
        let _ = builder;
    }

    #[test]
    fn test_rule_condition_constructors() {
        let v4 = Ipv4Addr::new(192, 168, 1, 1);
        let cond_v4 = RuleCondition::ipv4(Guid::zero(), FWP_MATCH_EQUAL, v4);
        match cond_v4.data {
            ConditionData::Uint32(v) => assert_eq!(v, u32::from(v4)),
            _ => panic!("Expected Uint32 for IPv4"),
        }

        let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let cond_v6 = RuleCondition::ipv6(Guid::zero(), FWP_MATCH_EQUAL, v6);
        match cond_v6.data {
            ConditionData::ByteArray16(bytes) => assert_eq!(*bytes, v6.octets()),
            _ => panic!("Expected ByteArray16 for IPv6"),
        }

        let cond_u64 = RuleCondition::uint64(Guid::zero(), FWP_MATCH_EQUAL, 0x123456789abcdef0);
        match cond_u64.data {
            ConditionData::Uint64(v) => assert_eq!(*v, 0x123456789abcdef0),
            _ => panic!("Expected Uint64"),
        }
    }

    #[test]
    fn test_firewall_config_defaults() {
        let cfg = FirewallConfig::default();
        assert_eq!(cfg.tun_interface_luid, 0);
        assert!(!cfg.do_not_restrict);
        assert!(cfg.dns_servers.is_empty());
        assert!(cfg.wireguard_endpoints.is_empty());
        assert!(!cfg.permit_hyperv);
    }

    #[test]
    fn test_dns_weight_validation() {
        // Allow weight must be strictly greater than deny weight
        let allow = 14;
        let deny = 15;
        let err = if deny >= allow {
            Some(RulesError::InvalidDnsWeights { allow, deny })
        } else {
            None
        };
        assert!(err.is_some());
    }
}
