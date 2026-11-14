/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use tracing::info;
use wireguard_wfp_engine::{
    BaseObjects, Engine, FWPM_CONDITION_L2_FLAGS,
    FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE, FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE,
    FWP_ACTION_PERMIT, FWP_CONDITION_L2_IS_VM2VM, FWP_MATCH_EQUAL,
};

use crate::builder::{add_filter_raw, cond_u32};
use crate::error::RulesError;

/// Permits Layer-2 VM-to-VM traffic for Hyper-V environments.
pub fn permit_hyper_v(
    engine: &Engine,
    base_objects: &BaseObjects,
    weight: u8,
) -> Result<Vec<u64>, RulesError> {
    let mut filter_ids = Vec::with_capacity(2);
    permit_hyper_v_into(engine, base_objects, weight, &mut filter_ids)?;
    Ok(filter_ids)
}

pub(crate) fn permit_hyper_v_into(
    engine: &Engine,
    base_objects: &BaseObjects,
    weight: u8,
    out: &mut Vec<u64>,
) -> Result<(), RulesError> {
    info!("Installing Hyper-V permit rules (weight={})", weight);

    let conds = [cond_u32(
        FWPM_CONDITION_L2_FLAGS,
        FWP_MATCH_EQUAL,
        FWP_CONDITION_L2_IS_VM2VM,
    )];

    let layers = [
        (
            FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE,
            "Permit Hyper-V => Hyper-V outbound",
        ),
        (
            FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE,
            "Permit Hyper-V => Hyper-V inbound",
        ),
    ];

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
            0,
            &conds,
        )?;
        out.push(id);
    }

    Ok(())
}
