/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use tracing::info;
use wireguard_wfp_engine::{
    BaseObjects, Engine, FWPM_CONDITION_IP_LOCAL_INTERFACE,
    FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWP_ACTION_PERMIT, FWP_MATCH_EQUAL,
};

use crate::builder::{add_filter_raw, cond_u64_ref};
use crate::error::RulesError;

/// Permits all inbound and outbound traffic through the WireGuard TUN/virtual adapter.
///
/// Identified by the adapter's NDIS Interface LUID (`if_luid`).
pub fn permit_tun_interface(
    if_luid: u64,
    engine: &Engine,
    base_objects: &BaseObjects,
    weight: u8,
) -> Result<Vec<u64>, RulesError> {
    let mut filter_ids = Vec::with_capacity(4);
    permit_tun_interface_into(if_luid, engine, base_objects, weight, &mut filter_ids)?;
    Ok(filter_ids)
}

pub(crate) fn permit_tun_interface_into(
    if_luid: u64,
    engine: &Engine,
    base_objects: &BaseObjects,
    weight: u8,
    out: &mut Vec<u64>,
) -> Result<(), RulesError> {
    info!(
        "Installing TUN interface permit rules for LUID 0x{:016x} (weight={})",
        if_luid, weight
    );

    let layers = [
        (
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            "Permit outbound IPv4 traffic on TUN",
        ),
        (
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            "Permit inbound IPv4 traffic on TUN",
        ),
        (
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            "Permit outbound IPv6 traffic on TUN",
        ),
        (
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            "Permit inbound IPv6 traffic on TUN",
        ),
    ];

    let luid_val = if_luid;
    let conds = [cond_u64_ref(
        FWPM_CONDITION_IP_LOCAL_INTERFACE,
        FWP_MATCH_EQUAL,
        &luid_val,
    )];

    for (layer, name) in layers {
        let id = add_filter_raw(
            engine,
            &base_objects.provider,
            &base_objects.filters,
            name,
            "",
            layer,
            FWP_ACTION_PERMIT,
            weight,
            FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
            &conds,
        )?;
        out.push(id);
    }

    Ok(())
}
