/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use tracing::info;
use wireguard_wfp_engine::{
    BaseObjects, Engine, FwpV6AddrAndMask, FWPM_CONDITION_ICMP_CODE,
    FWPM_CONDITION_ICMP_TYPE, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWP_ACTION_PERMIT, FWP_MATCH_EQUAL,
    IPPROTO_ICMPV6,
};

use crate::builder::{
    add_filter_raw, cond_bytes16_ref, cond_u16, cond_u8, cond_v6_prefix_ref,
};
use crate::error::RulesError;

static LINK_LOCAL_PREFIX_MASK: FwpV6AddrAndMask = FwpV6AddrAndMask {
    addr: [
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ],
    prefix_length: 10,
};

static LINK_LOCAL_ROUTER_MULTICAST: [u8; 16] = [
    0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
];

/// Permits IPv6 Neighbor Discovery Protocol (NDP) messages:
/// - Router Solicitation (ICMPv6 type 133, code 0)
/// - Router Advertisement (ICMPv6 type 134, code 0)
/// - Neighbor Solicitation (ICMPv6 type 135, code 0)
/// - Neighbor Advertisement (ICMPv6 type 136, code 0)
/// - Redirect Message (ICMPv6 type 137, code 0)
pub fn permit_ndp(
    engine: &Engine,
    base_objects: &BaseObjects,
    weight: u8,
) -> Result<Vec<u64>, RulesError> {
    let mut filter_ids = Vec::with_capacity(7);
    permit_ndp_into(engine, base_objects, weight, &mut filter_ids)?;
    Ok(filter_ids)
}

pub(crate) fn permit_ndp_into(
    engine: &Engine,
    base_objects: &BaseObjects,
    weight: u8,
    out: &mut Vec<u64>,
) -> Result<(), RulesError> {
    info!("Installing NDP permit rules (weight={})", weight);

    let router_multicast = cond_bytes16_ref(
        FWPM_CONDITION_IP_REMOTE_ADDRESS,
        FWP_MATCH_EQUAL,
        &LINK_LOCAL_ROUTER_MULTICAST,
    );
    let link_local = cond_v6_prefix_ref(
        FWPM_CONDITION_IP_REMOTE_ADDRESS,
        FWP_MATCH_EQUAL,
        &LINK_LOCAL_PREFIX_MASK,
    );

    let specs = [
        // 1. Router Solicitation Message: ICMP type 133, code 0. Outgoing.
        ("Permit NDP type 133", FWPM_LAYER_ALE_AUTH_CONNECT_V6, 133u16, Some(router_multicast)),
        // 2. Router Advertisement Message: ICMP type 134, code 0. Incoming.
        ("Permit NDP type 134", FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, 134u16, Some(link_local)),
        // 3. Neighbor Solicitation Message: ICMP type 135, code 0. Outgoing & Incoming.
        ("Permit NDP type 135 (outbound)", FWPM_LAYER_ALE_AUTH_CONNECT_V6, 135u16, None),
        ("Permit NDP type 135 (inbound)", FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, 135u16, None),
        // 4. Neighbor Advertisement Message: ICMP type 136, code 0. Outgoing & Incoming.
        ("Permit NDP type 136 (outbound)", FWPM_LAYER_ALE_AUTH_CONNECT_V6, 136u16, None),
        ("Permit NDP type 136 (inbound)", FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, 136u16, None),
        // 5. Redirect Message: ICMP type 137, code 0. Incoming.
        ("Permit NDP type 137", FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, 137u16, Some(link_local)),
    ];

    let mut conds = [
        cond_u8(FWPM_CONDITION_IP_PROTOCOL, FWP_MATCH_EQUAL, IPPROTO_ICMPV6),
        cond_u16(FWPM_CONDITION_ICMP_TYPE, FWP_MATCH_EQUAL, 0),
        cond_u16(FWPM_CONDITION_ICMP_CODE, FWP_MATCH_EQUAL, 0),
        router_multicast,
    ];

    for (name, layer, icmp_type, extra) in specs {
        conds[1] = cond_u16(FWPM_CONDITION_ICMP_TYPE, FWP_MATCH_EQUAL, icmp_type);
        let cond_slice = match extra {
            Some(c) => {
                conds[3] = c;
                &conds[..4]
            }
            None => &conds[..3],
        };
        let id = add_filter_raw(
            engine,
            &base_objects.provider,
            &base_objects.filters,
            name,
            "",
            layer,
            FWP_ACTION_PERMIT,
            weight,
            0,
            cond_slice,
        )?;
        out.push(id);
    }

    Ok(())
}
