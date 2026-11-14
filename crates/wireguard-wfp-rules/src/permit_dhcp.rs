/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use tracing::info;
use wireguard_wfp_engine::{
    BaseObjects, Engine, FwpV6AddrAndMask, FWPM_CONDITION_IP_LOCAL_ADDRESS,
    FWPM_CONDITION_IP_LOCAL_PORT, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    FWP_ACTION_PERMIT, FWP_MATCH_EQUAL, IPPROTO_UDP,
};

use crate::builder::{
    add_filter_raw, cond_bytes16_ref, cond_u16, cond_u32, cond_u8, cond_v6_prefix_ref,
};
use crate::error::RulesError;

// Known IPv6 multicast and link-local addresses for DHCPv6
static LINK_LOCAL_PREFIX_MASK: FwpV6AddrAndMask = FwpV6AddrAndMask {
    addr: [
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ],
    prefix_length: 10,
};

static LINK_LOCAL_DHCP_MULTICAST: [u8; 16] = [
    0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02,
];

static SITE_LOCAL_DHCP_MULTICAST: [u8; 16] = [
    0xff, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03,
];

/// Permits IPv4 DHCP discovery, request, and lease renewal traffic.
pub fn permit_dhcp_ipv4(
    engine: &Engine,
    base_objects: &BaseObjects,
    weight: u8,
) -> Result<Vec<u64>, RulesError> {
    let mut filter_ids = Vec::with_capacity(2);
    permit_dhcp_ipv4_into(engine, base_objects, weight, &mut filter_ids)?;
    Ok(filter_ids)
}

pub(crate) fn permit_dhcp_ipv4_into(
    engine: &Engine,
    base_objects: &BaseObjects,
    weight: u8,
    out: &mut Vec<u64>,
) -> Result<(), RulesError> {
    info!("Installing DHCP IPv4 permit rules (weight={})", weight);

    let conds = [
        cond_u8(FWPM_CONDITION_IP_PROTOCOL, FWP_MATCH_EQUAL, IPPROTO_UDP),
        cond_u16(FWPM_CONDITION_IP_LOCAL_PORT, FWP_MATCH_EQUAL, 68),
        cond_u16(FWPM_CONDITION_IP_REMOTE_PORT, FWP_MATCH_EQUAL, 67),
        cond_u32(FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_MATCH_EQUAL, 0xffffffff),
    ];

    // #1 Outbound DHCP request on IPv4: UDP local 68 -> remote 67, remote 255.255.255.255
    let id1 = add_filter_raw(
        engine,
        &base_objects.provider,
        &base_objects.filters,
        "Permit outbound DHCP request (IPv4)",
        "",
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWP_ACTION_PERMIT,
        weight,
        0,
        &conds,
    )?;
    out.push(id1);

    // #2 Inbound DHCP response on IPv4: UDP local 68 <- remote 67
    let id2 = add_filter_raw(
        engine,
        &base_objects.provider,
        &base_objects.filters,
        "Permit inbound DHCP response (IPv4)",
        "",
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        FWP_ACTION_PERMIT,
        weight,
        0,
        &conds[..3],
    )?;
    out.push(id2);

    Ok(())
}

/// Permits IPv6 DHCPv6 discovery, solicitation, and configuration traffic.
pub fn permit_dhcp_ipv6(
    engine: &Engine,
    base_objects: &BaseObjects,
    weight: u8,
) -> Result<Vec<u64>, RulesError> {
    let mut filter_ids = Vec::with_capacity(2);
    permit_dhcp_ipv6_into(engine, base_objects, weight, &mut filter_ids)?;
    Ok(filter_ids)
}

pub(crate) fn permit_dhcp_ipv6_into(
    engine: &Engine,
    base_objects: &BaseObjects,
    weight: u8,
    out: &mut Vec<u64>,
) -> Result<(), RulesError> {
    info!("Installing DHCP IPv6 permit rules (weight={})", weight);

    // #1 Outbound DHCP request on IPv6: UDP local 546 -> remote 547
    // Repeating FWPM_CONDITION_IP_REMOTE_ADDRESS provides logical OR between link-local and site-local multicast.
    let conds_out = [
        cond_u8(FWPM_CONDITION_IP_PROTOCOL, FWP_MATCH_EQUAL, IPPROTO_UDP),
        cond_bytes16_ref(
            FWPM_CONDITION_IP_REMOTE_ADDRESS,
            FWP_MATCH_EQUAL,
            &LINK_LOCAL_DHCP_MULTICAST,
        ),
        cond_bytes16_ref(
            FWPM_CONDITION_IP_REMOTE_ADDRESS,
            FWP_MATCH_EQUAL,
            &SITE_LOCAL_DHCP_MULTICAST,
        ),
        cond_u16(FWPM_CONDITION_IP_REMOTE_PORT, FWP_MATCH_EQUAL, 547),
        cond_v6_prefix_ref(
            FWPM_CONDITION_IP_LOCAL_ADDRESS,
            FWP_MATCH_EQUAL,
            &LINK_LOCAL_PREFIX_MASK,
        ),
        cond_u16(FWPM_CONDITION_IP_LOCAL_PORT, FWP_MATCH_EQUAL, 546),
    ];
    let id1 = add_filter_raw(
        engine,
        &base_objects.provider,
        &base_objects.filters,
        "Permit outbound DHCP request (IPv6)",
        "",
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        FWP_ACTION_PERMIT,
        weight,
        0,
        &conds_out,
    )?;
    out.push(id1);

    // #2 Inbound DHCP response on IPv6: UDP local 546 <- remote 547
    let conds_in = [
        conds_out[0],
        cond_v6_prefix_ref(
            FWPM_CONDITION_IP_REMOTE_ADDRESS,
            FWP_MATCH_EQUAL,
            &LINK_LOCAL_PREFIX_MASK,
        ),
        conds_out[3],
        conds_out[4],
        conds_out[5],
    ];
    let id2 = add_filter_raw(
        engine,
        &base_objects.provider,
        &base_objects.filters,
        "Permit inbound DHCP response (IPv6)",
        "",
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        FWP_ACTION_PERMIT,
        weight,
        0,
        &conds_in,
    )?;
    out.push(id2);

    Ok(())
}
