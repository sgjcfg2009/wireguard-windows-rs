// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.

use std::fmt::Write;
use wireguard_types::TunnelConfig;

/// Serializes a WireGuard configuration (`TunnelConfig`) into standard WireGuard INI format.
pub fn to_wg_conf(config: &TunnelConfig) -> String {
    let mut out = String::with_capacity(256 + config.peers.len() * 192);
    let mut b64_buf = [0u8; 44];

    out.push_str("[Interface]\n");
    if let Some(ref pk) = config.interface.private_key {
        let _ = writeln!(out, "PrivateKey = {}", pk.encode_base64(&mut b64_buf));
    }
    if let Some(port) = config.interface.listen_port {
        if port > 0 {
            let _ = writeln!(out, "ListenPort = {port}");
        }
    }
    if !config.interface.addresses.is_empty() {
        out.push_str("Address = ");
        for (i, addr) in config.interface.addresses.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            let _ = write!(out, "{addr}");
        }
        out.push('\n');
    }
    if !config.interface.dns.is_empty() || !config.interface.dns_search.is_empty() {
        out.push_str("DNS = ");
        let mut first = true;
        for ip in &config.interface.dns {
            if !first {
                out.push_str(", ");
            }
            first = false;
            let _ = write!(out, "{ip}");
        }
        for domain in &config.interface.dns_search {
            if !first {
                out.push_str(", ");
            }
            first = false;
            out.push_str(domain);
        }
        out.push('\n');
    }
    if let Some(mtu) = config.interface.mtu {
        if mtu > 0 {
            let _ = writeln!(out, "MTU = {mtu}");
        }
    }
    if let Some(ref pre_up) = config.interface.pre_up {
        if !pre_up.is_empty() {
            let _ = writeln!(out, "PreUp = {pre_up}");
        }
    }
    if let Some(ref post_up) = config.interface.post_up {
        if !post_up.is_empty() {
            let _ = writeln!(out, "PostUp = {post_up}");
        }
    }
    if let Some(ref pre_down) = config.interface.pre_down {
        if !pre_down.is_empty() {
            let _ = writeln!(out, "PreDown = {pre_down}");
        }
    }
    if let Some(ref post_down) = config.interface.post_down {
        if !post_down.is_empty() {
            let _ = writeln!(out, "PostDown = {post_down}");
        }
    }
    if config.interface.table_off {
        out.push_str("Table = off\n");
    }

    for peer in &config.peers {
        out.push_str("\n[Peer]\n");
        let _ = writeln!(
            out,
            "PublicKey = {}",
            peer.public_key.encode_base64(&mut b64_buf)
        );
        if let Some(ref psk) = peer.preshared_key {
            if !psk.is_zero() {
                let _ = writeln!(out, "PresharedKey = {}", psk.encode_base64(&mut b64_buf));
            }
        }
        if !peer.allowed_ips.is_empty() {
            out.push_str("AllowedIPs = ");
            for (i, ip) in peer.allowed_ips.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                let _ = write!(out, "{ip}");
            }
            out.push('\n');
        }
        if let Some(ref ep) = peer.endpoint {
            if !ep.host.is_empty() {
                let _ = writeln!(out, "Endpoint = {ep}");
            }
        }
        if let Some(keepalive) = peer.persistent_keepalive {
            if keepalive > 0 {
                let _ = writeln!(out, "PersistentKeepalive = {keepalive}");
            }
        }
    }

    out
}

/// Alias for `to_wg_conf` matching Go method `ToWgQuick`.
pub fn to_wg_quick(config: &TunnelConfig) -> String {
    to_wg_conf(config)
}
