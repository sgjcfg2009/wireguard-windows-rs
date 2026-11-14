/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use tracing::info;
use wireguard_wfp_engine::{
    BaseObjects, Engine, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWP_ACTION_BLOCK,
};

use crate::builder::add_filter_raw;
use crate::error::RulesError;

/// Installs the default-deny killswitch filters: blocks all traffic on IPv4 and IPv6
/// except what is explicitly permitted by higher-weight rules in the WireGuard sublayer.
pub fn block_all(
    engine: &Engine,
    base_objects: &BaseObjects,
    weight: u8,
) -> Result<Vec<u64>, RulesError> {
    let mut filter_ids = Vec::with_capacity(4);
    block_all_into(engine, base_objects, weight, &mut filter_ids)?;
    Ok(filter_ids)
}

pub(crate) fn block_all_into(
    engine: &Engine,
    base_objects: &BaseObjects,
    weight: u8,
    out: &mut Vec<u64>,
) -> Result<(), RulesError> {
    info!("Installing default-deny killswitch rules (weight={})", weight);

    let layers = [
        (FWPM_LAYER_ALE_AUTH_CONNECT_V4, "Block all outbound (IPv4)"),
        (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, "Block all inbound (IPv4)"),
        (FWPM_LAYER_ALE_AUTH_CONNECT_V6, "Block all outbound (IPv6)"),
        (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, "Block all inbound (IPv6)"),
    ];

    for (layer, name) in layers {
        let id = add_filter_raw(
            engine,
            &base_objects.provider,
            &base_objects.filters,
            name,
            "",
            layer,
            FWP_ACTION_BLOCK,
            weight,
            0,
            &[],
        )?;
        out.push(id);
    }

    Ok(())
}
