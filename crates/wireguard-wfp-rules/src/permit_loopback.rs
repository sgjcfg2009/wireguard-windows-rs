/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use tracing::info;
use wireguard_wfp_engine::{
    BaseObjects, Engine, FWPM_CONDITION_FLAGS, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    FWP_ACTION_PERMIT, FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_MATCH_FLAGS_ALL_SET,
};

use crate::builder::{add_filter_raw, cond_u32};
use crate::error::RulesError;

/// Permits all loopback traffic (IPv4 and IPv6).
///
/// Localhost communication (127.0.0.1 and ::1) must remain open for local IPC,
/// services, and RPC while the killswitch is active.
pub fn permit_loopback(
    engine: &Engine,
    base_objects: &BaseObjects,
    weight: u8,
) -> Result<Vec<u64>, RulesError> {
    let mut filter_ids = Vec::with_capacity(4);
    permit_loopback_into(engine, base_objects, weight, &mut filter_ids)?;
    Ok(filter_ids)
}

pub(crate) fn permit_loopback_into(
    engine: &Engine,
    base_objects: &BaseObjects,
    weight: u8,
    out: &mut Vec<u64>,
) -> Result<(), RulesError> {
    info!("Installing loopback permit rules (weight={})", weight);

    let layers = [
        (
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            "Permit outbound on loopback (IPv4)",
        ),
        (
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            "Permit inbound on loopback (IPv4)",
        ),
        (
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            "Permit outbound on loopback (IPv6)",
        ),
        (
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            "Permit inbound on loopback (IPv6)",
        ),
    ];

    let conds = [cond_u32(
        FWPM_CONDITION_FLAGS,
        FWP_MATCH_FLAGS_ALL_SET,
        FWP_CONDITION_FLAG_IS_LOOPBACK,
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
