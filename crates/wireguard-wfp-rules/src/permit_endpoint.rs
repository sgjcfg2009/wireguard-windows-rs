/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use std::net::{IpAddr, SocketAddr};
use tracing::info;
use wireguard_wfp_engine::{
    BaseObjects, Engine, FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS,
    FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    FWP_ACTION_PERMIT, FWP_MATCH_EQUAL, IPPROTO_UDP,
};

use crate::builder::{add_filter_raw, cond_bytes16_ref, cond_ipv4, cond_u16, cond_u8};
use crate::error::RulesError;

/// Permits direct UDP communication to specified WireGuard peer endpoints.
///
/// Ensures UDP traffic with the remote WireGuard server/peers on their configured
/// IP and port is explicitly allowed through the firewall killswitch.
pub fn permit_wireguard_endpoints(
    endpoints: &[SocketAddr],
    engine: &Engine,
    base_objects: &BaseObjects,
    weight: u8,
) -> Result<Vec<u64>, RulesError> {
    if endpoints.is_empty() {
        return Ok(Vec::new());
    }

    let mut filter_ids = Vec::with_capacity(endpoints.len() * 2);
    permit_wireguard_endpoints_into(endpoints, engine, base_objects, weight, &mut filter_ids)?;
    Ok(filter_ids)
}

pub(crate) fn permit_wireguard_endpoints_into(
    endpoints: &[SocketAddr],
    engine: &Engine,
    base_objects: &BaseObjects,
    weight: u8,
    out: &mut Vec<u64>,
) -> Result<(), RulesError> {
    if endpoints.is_empty() {
        return Ok(());
    }

    info!(
        "Installing WireGuard peer endpoint permit rules for {} endpoints (weight={})",
        endpoints.len(),
        weight
    );

    for endpoint in endpoints {
        let port = endpoint.port();
        match endpoint.ip() {
            IpAddr::V4(v4) => {
                let conds = [
                    cond_u8(FWPM_CONDITION_IP_PROTOCOL, FWP_MATCH_EQUAL, IPPROTO_UDP),
                    cond_u16(FWPM_CONDITION_IP_REMOTE_PORT, FWP_MATCH_EQUAL, port),
                    cond_ipv4(FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_MATCH_EQUAL, v4),
                ];
                let layers = [
                    (
                        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                        "Permit WireGuard UDP endpoint outbound (IPv4)",
                    ),
                    (
                        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                        "Permit WireGuard UDP endpoint inbound (IPv4)",
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
                        FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
                        &conds,
                    )?;
                    out.push(id);
                }
            }
            IpAddr::V6(v6) => {
                let octets = v6.octets();
                let conds = [
                    cond_u8(FWPM_CONDITION_IP_PROTOCOL, FWP_MATCH_EQUAL, IPPROTO_UDP),
                    cond_u16(FWPM_CONDITION_IP_REMOTE_PORT, FWP_MATCH_EQUAL, port),
                    cond_bytes16_ref(FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_MATCH_EQUAL, &octets),
                ];
                let layers = [
                    (
                        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                        "Permit WireGuard UDP endpoint outbound (IPv6)",
                    ),
                    (
                        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                        "Permit WireGuard UDP endpoint inbound (IPv6)",
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
                        FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
                        &conds,
                    )?;
                    out.push(id);
                }
            }
        }
    }

    Ok(())
}
