/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use tracing::{debug, info, warn};
use wireguard_wfp_engine::{
    get_current_process_security_descriptor, AppIdBlob, BaseObjects, Engine,
    FwpByteBlob, FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_ALE_USER_ID,
    FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWP_ACTION_PERMIT, FWP_MATCH_EQUAL,
};

use crate::builder::{add_filter_raw, cond_byte_blob_ref, cond_sd_ref};
use crate::error::RulesError;

/// Permits unrestricted inbound and outbound network traffic for the WireGuard service process.
///
/// Restricts permission by matching the application executable path (`FWPM_CONDITION_ALE_APP_ID`)
/// and the service security descriptor (`FWPM_CONDITION_ALE_USER_ID`), ensuring other processes
/// executing the same binary cannot bypass the tunnel firewall.
pub fn permit_wireguard_service(
    engine: &Engine,
    base_objects: &BaseObjects,
    weight: u8,
) -> Result<Vec<u64>, RulesError> {
    let mut filter_ids = Vec::with_capacity(4);
    permit_wireguard_service_into(engine, base_objects, weight, &mut filter_ids)?;
    Ok(filter_ids)
}

pub(crate) fn permit_wireguard_service_into(
    engine: &Engine,
    base_objects: &BaseObjects,
    weight: u8,
    out: &mut Vec<u64>,
) -> Result<(), RulesError> {
    info!("Installing WireGuard service permit rules (weight={})", weight);

    let app_id = AppIdBlob::current_process()?;

    // SECURITY_DESCRIPTOR of the service SID
    let mut sd_bytes = match get_current_process_security_descriptor() {
        Ok(bytes) => {
            debug!("Obtained service security descriptor ({} bytes)", bytes.len());
            Some(bytes)
        }
        Err(e) => {
            warn!("Could not obtain service security descriptor: {}; using AppID-only restriction", e);
            None
        }
    };

    let sd_blob: FwpByteBlob;
    let mut conds = [cond_byte_blob_ref(
        FWPM_CONDITION_ALE_APP_ID,
        FWP_MATCH_EQUAL,
        app_id.as_blob(),
    ); 2];
    let cond_count = if let Some(ref mut sd) = sd_bytes {
        sd_blob = FwpByteBlob {
            size: sd.len() as u32,
            #[cfg(target_pointer_width = "64")]
            _pad: 0,
            data: sd.as_mut_ptr(),
        };
        conds[1] = cond_sd_ref(FWPM_CONDITION_ALE_USER_ID, FWP_MATCH_EQUAL, &sd_blob);
        2
    } else {
        1
    };
    let cond_slice = &conds[..cond_count];

    let layers = [
        (
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            "Permit unrestricted outbound traffic for WireGuard service (IPv4)",
        ),
        (
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            "Permit unrestricted inbound traffic for WireGuard service (IPv4)",
        ),
        (
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            "Permit unrestricted outbound traffic for WireGuard service (IPv6)",
        ),
        (
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            "Permit unrestricted inbound traffic for WireGuard service (IPv6)",
        ),
    ];

    let start = out.len();
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
            cond_slice,
        )?;
        out.push(id);
    }

    info!("WireGuard service permit rules installed successfully: {:?}", &out[start..]);
    Ok(())
}
