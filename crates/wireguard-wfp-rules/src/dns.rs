/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use std::net::IpAddr;
use tracing::info;
use wireguard_wfp_engine::{
    BaseObjects, Engine, FwpmFilterCondition0, Guid, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT,
    FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
    FWP_MATCH_EQUAL, IPPROTO_TCP, IPPROTO_UDP,
};

use crate::builder::{add_filter_raw, cond_bytes16_ref, cond_ipv4, cond_u16, cond_u8};
use crate::error::RulesError;

/// Configures DNS leak prevention:
/// 1. Blocks all standard DNS traffic (port 53 over UDP and TCP) for IPv4 and IPv6.
/// 2. Whitelists only the specified WireGuard DNS servers with a higher evaluation weight.
///
/// Any DNS queries sent outside the tunnel to external resolvers (e.g. ISP or local router)
/// are dropped by the deny rules, preventing DNS leaks.
pub fn block_dns(
    except_dns_servers: &[IpAddr],
    engine: &Engine,
    base_objects: &BaseObjects,
    weight_allow: u8,
    weight_deny: u8,
) -> Result<Vec<u64>, RulesError> {
    let has_v4 = except_dns_servers.iter().any(|ip| ip.is_ipv4());
    let has_v6 = except_dns_servers.iter().any(|ip| ip.is_ipv6());
    let cap = 4 + usize::from(has_v4) * 2 + usize::from(has_v6) * 2;
    let mut filter_ids = Vec::with_capacity(cap);
    block_dns_into(
        except_dns_servers,
        engine,
        base_objects,
        weight_allow,
        weight_deny,
        &mut filter_ids,
    )?;
    Ok(filter_ids)
}

pub(crate) fn block_dns_into(
    except_dns_servers: &[IpAddr],
    engine: &Engine,
    base_objects: &BaseObjects,
    weight_allow: u8,
    weight_deny: u8,
    out: &mut Vec<u64>,
) -> Result<(), RulesError> {
    if weight_deny >= weight_allow {
        return Err(RulesError::InvalidDnsWeights {
            allow: weight_allow,
            deny: weight_deny,
        });
    }

    info!(
        "Installing DNS leak prevention rules: blocking port 53 (weight={}), permitting {} servers (weight={})",
        weight_deny,
        except_dns_servers.len(),
        weight_allow
    );

    // ========================================================================
    // 1. Universal DNS Block Rules (Port 53, UDP/TCP)
    // ========================================================================
    let deny_conds = [
        cond_u16(FWPM_CONDITION_IP_REMOTE_PORT, FWP_MATCH_EQUAL, 53),
        // Repeating FWPM_CONDITION_IP_PROTOCOL provides logical OR in WFP
        cond_u8(FWPM_CONDITION_IP_PROTOCOL, FWP_MATCH_EQUAL, IPPROTO_UDP),
        cond_u8(FWPM_CONDITION_IP_PROTOCOL, FWP_MATCH_EQUAL, IPPROTO_TCP),
    ];

    let deny_layers = [
        (FWPM_LAYER_ALE_AUTH_CONNECT_V4, "Block DNS outbound (IPv4)"),
        (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, "Block DNS inbound (IPv4)"),
        (FWPM_LAYER_ALE_AUTH_CONNECT_V6, "Block DNS outbound (IPv6)"),
        (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, "Block DNS inbound (IPv6)"),
    ];

    for (layer, name) in deny_layers {
        let id = add_filter_raw(
            engine,
            &base_objects.provider,
            &base_objects.filters,
            name,
            "",
            layer,
            FWP_ACTION_BLOCK,
            weight_deny,
            0,
            &deny_conds,
        )?;
        out.push(id);
    }

    let mut v4_count = 0usize;
    let mut v6_count = 0usize;
    for ip in except_dns_servers {
        match ip {
            IpAddr::V4(_) => v4_count += 1,
            IpAddr::V6(_) => v6_count += 1,
        }
    }

    let install_allow = |layers: [(Guid, &str); 2], conds: &[FwpmFilterCondition0], out: &mut Vec<u64>| -> Result<(), RulesError> {
        for (layer, name) in layers {
            let id = add_filter_raw(
                engine,
                &base_objects.provider,
                &base_objects.filters,
                name,
                "",
                layer,
                FWP_ACTION_PERMIT,
                weight_allow,
                FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
                conds,
            )?;
            out.push(id);
        }
        Ok(())
    };

    // ========================================================================
    // 2. Allow Rules for Whitelisted IPv4 DNS Servers
    // ========================================================================
    if v4_count > 0 {
        let v4_layers = [
            (FWPM_LAYER_ALE_AUTH_CONNECT_V4, "Allow DNS outbound (IPv4)"),
            (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, "Allow DNS inbound (IPv4)"),
        ];

        const STACK_V4_CAP: usize = 5;
        if v4_count <= STACK_V4_CAP {
            let mut conds = [FwpmFilterCondition0::default(); 3 + STACK_V4_CAP];
            conds[0..3].copy_from_slice(&deny_conds);
            let mut idx = 3;
            for ip in except_dns_servers {
                if let IpAddr::V4(v4) = ip {
                    conds[idx] = cond_ipv4(FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_MATCH_EQUAL, *v4);
                    idx += 1;
                }
            }
            install_allow(v4_layers, &conds[..idx], out)?;
        } else {
            let mut conds = Vec::with_capacity(3 + v4_count);
            conds.extend_from_slice(&deny_conds);
            for ip in except_dns_servers {
                if let IpAddr::V4(v4) = ip {
                    conds.push(cond_ipv4(FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_MATCH_EQUAL, *v4));
                }
            }
            install_allow(v4_layers, &conds, out)?;
        }
    }

    // ========================================================================
    // 3. Allow Rules for Whitelisted IPv6 DNS Servers
    // ========================================================================
    if v6_count > 0 {
        let v6_layers = [
            (FWPM_LAYER_ALE_AUTH_CONNECT_V6, "Allow DNS outbound (IPv6)"),
            (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, "Allow DNS inbound (IPv6)"),
        ];

        const STACK_V6_CAP: usize = 5;
        if v6_count <= STACK_V6_CAP {
            let mut v6_octets = [[0u8; 16]; STACK_V6_CAP];
            let mut count = 0usize;
            for ip in except_dns_servers {
                if let IpAddr::V6(v6) = ip {
                    v6_octets[count] = v6.octets();
                    count += 1;
                }
            }

            let mut conds = [FwpmFilterCondition0::default(); 3 + STACK_V6_CAP];
            conds[0..3].copy_from_slice(&deny_conds);
            for (i, octets) in v6_octets[..count].iter().enumerate() {
                conds[3 + i] = cond_bytes16_ref(
                    FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    FWP_MATCH_EQUAL,
                    octets,
                );
            }
            install_allow(v6_layers, &conds[..3 + count], out)?;
        } else {
            let mut v6_octets = Vec::with_capacity(v6_count);
            for ip in except_dns_servers {
                if let IpAddr::V6(v6) = ip {
                    v6_octets.push(v6.octets());
                }
            }
            let mut conds = Vec::with_capacity(3 + v6_octets.len());
            conds.extend_from_slice(&deny_conds);
            for octets in &v6_octets {
                conds.push(cond_bytes16_ref(
                    FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    FWP_MATCH_EQUAL,
                    octets,
                ));
            }
            install_allow(v6_layers, &conds, out)?;
        }
    }

    Ok(())
}
