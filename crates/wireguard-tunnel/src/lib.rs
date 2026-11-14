// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.

//! WireGuard Windows Tunnel Service Engine.
//!
//! Orchestrates the complete WireGuard tunnel lifecycle:
//! 1. Parses and decrypts configuration (`wireguard-conf`).
//! 2. Initializes and loads driver adapter (`wireguard-driver`).
//! 3. Configures IP addresses, MTU, routes, and DNS (`wireguard-ipcfg-*`).
//! 4. Establishes Windows Filtering Platform (WFP) kill-switch & DNS leak prevention rules (`wireguard-wfp-*`).
//! 5. Dispatches Windows Service Control Manager status loop (`wireguard-service`).

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use thiserror::Error;
use tracing::{info, warn};

use wireguard_conf::parser::parse_config_bytes;
use wireguard_conf::{name_from_path, parse_config, service_name_of_tunnel, CONFIG_FILE_SUFFIX};
use wireguard_driver::{set_driver_logger, AdapterLogState, AdapterState, WireGuardAdapter};
use wireguard_ipcfg_core::{configure_ip_interface_family, AddressFamily, Luid};
use wireguard_service::dispatcher::{run_service, ServiceControlEvent, ServiceStatusReporter};

#[derive(Debug, Error)]
pub enum TunnelError {
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Driver error: {0}")]
    Driver(#[from] wireguard_driver::DriverError),
    #[error("IP configuration error: {0}")]
    IpCfg(String),
    #[error("Firewall error: {0}")]
    Firewall(#[from] wireguard_wfp_rules::RulesError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Service error: {0}")]
    Service(String),
}

pub static USE_FIXED_GUID_INSTEAD_OF_DETERMINISTIC: AtomicBool = AtomicBool::new(false);

pub fn set_use_fixed_guid_instead_of_deterministic(use_fixed: bool) {
    USE_FIXED_GUID_INSTEAD_OF_DETERMINISTIC.store(use_fixed, Ordering::SeqCst);
}

struct StackLogBuf {
    buf: [u8; 512],
    len: usize,
    truncated: bool,
}

impl StackLogBuf {
    fn new() -> Self {
        Self {
            buf: [0u8; 512],
            len: 0,
            truncated: false,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl std::fmt::Write for StackLogBuf {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        if self.truncated || self.len >= self.buf.len() {
            return Ok(());
        }
        let remaining = self.buf.len() - self.len;
        let bytes = s.as_bytes();
        let copy_len = if bytes.len() <= remaining {
            bytes.len()
        } else {
            self.truncated = true;
            let mut n = remaining;
            while n > 0 && !s.is_char_boundary(n) {
                n -= 1;
            }
            n
        };
        self.buf[self.len..self.len + copy_len].copy_from_slice(&bytes[..copy_len]);
        self.len += copy_len;
        Ok(())
    }
}

macro_rules! ringlog_fmt {
    ($($arg:tt)*) => {
        if let Some(logger) = wireguard_ringlog::global() {
            let mut buf = StackLogBuf::new();
            let _ = std::fmt::Write::write_fmt(&mut buf, format_args!($($arg)*));
            let _ = logger.write_bytes(buf.as_bytes());
        }
    };
}

/// Runs the WireGuard tunnel lifecycle for a given configuration file.
///
/// When invoked by the Windows Service Control Manager (`/tunnelservice <conf>`),
/// dispatches `StartServiceCtrlDispatcherW` and keeps the adapter & firewall alive
/// until `SERVICE_CONTROL_STOP` or `SERVICE_CONTROL_SHUTDOWN` is received.
pub fn run(conf_path: &Path) -> Result<(), TunnelError> {
    let tunnel_name = name_from_path(conf_path).map_err(|e| TunnelError::Config(e.to_string()))?;
    let service_name =
        service_name_of_tunnel(&tunnel_name).map_err(|e| TunnelError::Config(e.to_string()))?;
    let conf_owned = conf_path.to_path_buf();

    match run_service(&service_name, move |ctx| {
        run_tunnel_engine(&conf_owned, Some(&ctx.status), Some(&ctx.control_rx)).map_err(|e| {
            ringlog_fmt!("ERROR: Tunnel service '{}' failed: {}", ctx.service_name, e);
            wireguard_service::error::ServiceError::from_wg_code(
                wireguard_service::error::WireGuardServiceCode::CreateNetworkAdapter,
            )
            .into()
        })
    }) {
        Ok(()) => Ok(()),
        Err(wireguard_service::error::ServiceError::NotRunningAsService) => {
            // Direct invocation outside SCM
            run_tunnel_engine(conf_path, None, None)
        }
        Err(e) => Err(TunnelError::Service(e.to_string())),
    }
}

const FIXED_TUNNEL_GUID: windows_sys::core::GUID = windows_sys::core::GUID {
    data1: 0xdeadbeef,
    data2: 0xbeef,
    data3: 0xbeef,
    data4: [0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef],
};

/// Generates a deterministic UUIDv5-style GUID from the tunnel name so Windows reuses
/// the same NLA profile and adapter device instance across restarts.
fn deterministic_guid_for_tunnel(name: &str) -> windows_sys::core::GUID {
    if USE_FIXED_GUID_INSTEAD_OF_DETERMINISTIC.load(Ordering::Relaxed) {
        return FIXED_TUNNEL_GUID;
    }

    // FNV-1a 128-bit double pass over WireGuard namespace + lowercase UTF-16LE tunnel name
    const OFFSET1: u64 = 0xcbf29ce484222325;
    const OFFSET2: u64 = 0x84222325cbf29ce4;
    const PRIME: u64 = 0x00000100000001b3;

    let mut h1 = OFFSET1;
    let mut h2 = OFFSET2;

    for b in b"WireGuard Tunnel Deterministic GUID v1" {
        h1 ^= *b as u64;
        h1 = h1.wrapping_mul(PRIME);
        h2 = h2.wrapping_add(*b as u64).wrapping_mul(PRIME);
    }

    for ch in name.chars().flat_map(|c| c.to_lowercase()) {
        let mut buf = [0u16; 2];
        for u in ch.encode_utf16(&mut buf) {
            for b in u.to_le_bytes() {
                h1 ^= b as u64;
                h1 = h1.wrapping_mul(PRIME);
                h2 = h2.wrapping_add(b as u64).wrapping_mul(PRIME);
            }
        }
    }

    let b1 = h1.to_le_bytes();
    let b2 = h2.to_le_bytes();
    windows_sys::core::GUID {
        data1: u32::from_le_bytes([b1[0], b1[1], b1[2], b1[3]]),
        data2: u16::from_le_bytes([b1[4], b1[5]]),
        data3: (u16::from_le_bytes([b1[6], b1[7]]) & 0x0fff) | 0x5000,
        data4: [
            (b2[0] & 0x3f) | 0x80,
            b2[1],
            b2[2],
            b2[3],
            b2[4],
            b2[5],
            b2[6],
            b2[7],
        ],
    }
}

fn run_tunnel_engine(
    conf_path: &Path,
    status_reporter: Option<&ServiceStatusReporter>,
    control_rx: Option<&std::sync::mpsc::Receiver<ServiceControlEvent>>,
) -> Result<(), TunnelError> {
    let tunnel_name = name_from_path(conf_path).map_err(|e| TunnelError::Config(e.to_string()))?;
    info!("Starting WireGuard tunnel service for '{}'", tunnel_name);

    // Log to Data/log.bin if available
    let log_bin = Path::new(r"C:\Program Files\WireGuard\Data\log.bin");
    let _ = wireguard_ringlog::init_global_logger(log_bin, "TUN");
    ringlog_fmt!("[{}] Starting WireGuard tunnel service", tunnel_name);

    // Forward wireguard.dll / kernel driver log events directly to log.bin
    let tn_for_log = tunnel_name.clone();
    let _ = set_driver_logger(Some(move |_level, _ts, msg: &str| {
        let trimmed = msg.trim();
        if !trimmed.is_empty() {
            ringlog_fmt!("[{}] {}", tn_for_log, trimmed);
        }
    }));

    // Read and parse configuration (supports both `.conf.dpapi` and `.conf`)
    let path_str = conf_path.to_string_lossy();
    let config = if path_str.ends_with(CONFIG_FILE_SUFFIX) {
        let decrypt_and_parse = |p: &Path, name: &str| -> Result<wireguard_conf::TunnelConfig, String> {
            let enc = std::fs::read(p).map_err(|e| e.to_string())?;
            let mut dec = wireguard_dpapi::decrypt_with_expected_description(&enc, name)
                .or_else(|_| wireguard_dpapi::decrypt(&enc))
                .map_err(|e| e.to_string())?;
            let parsed = parse_config_bytes(&dec, name).map_err(|e| e.to_string());
            wireguard_dpapi::secure_zero(&mut dec);
            parsed
        };

        // When running as a Windows Service, the process already executes as LocalSystem.
        // Try direct DPAPI decryption first before falling back to do_as_system.
        match decrypt_and_parse(conf_path, &tunnel_name) {
            Ok(cfg) => cfg,
            Err(_) => {
                let p = conf_path.to_path_buf();
                let name_clone = tunnel_name.clone();
                wireguard_elevate::do_as_system(move || {
                    decrypt_and_parse(&p, &name_clone)
                        .map_err(wireguard_elevate::ElevateError::ProcessNotFound)
                })
                .map_err(|e| TunnelError::Config(e.to_string()))?
            }
        }
    } else {
        let mut content = std::fs::read_to_string(conf_path)?;
        let parsed = parse_config(&content).map_err(|e| TunnelError::Config(e.to_string()));
        // SAFETY: zeroing the UTF-8 buffer with 0x00 leaves valid NUL UTF-8 bytes before drop.
        unsafe {
            wireguard_dpapi::secure_zero(content.as_bytes_mut());
        }
        parsed?
    };

    // Create or open the WireGuard adapter with a deterministic GUID
    let requested_guid = deterministic_guid_for_tunnel(&tunnel_name);
    let adapter = WireGuardAdapter::create(&tunnel_name, "WireGuard", Some(&requested_guid))?;
    let _ = adapter.set_logging(AdapterLogState::On);

    let luid_val = adapter.luid()?;
    info!("WireGuard adapter created with LUID: {}", luid_val);
    ringlog_fmt!("[{}] Created WireGuard adapter (LUID: {})", tunnel_name, luid_val);

    // Apply cryptographic configuration (keys, peers, allowed IPs) and bring adapter Up
    adapter.set_configuration(&config.interface, &config.peers)?;
    adapter.set_adapter_state(AdapterState::Up)?;

    let luid = Luid::from_u64(luid_val);

    // Determine effective MTU (defaults to 1420 when omitted, matching official WireGuard for Windows)
    let mtu = match config.interface.mtu {
        Some(m) if m > 0 => m as u32,
        _ => 1420,
    };

    let mut found_default4 = false;
    let mut found_default6 = false;
    if !config.interface.table_off {
        for peer in &config.peers {
            for allowed_ip in &peer.allowed_ips {
                if allowed_ip.cidr == 0 {
                    if allowed_ip.addr.is_ipv4() {
                        found_default4 = true;
                    } else {
                        found_default6 = true;
                    }
                }
            }
        }
    }

    // Configure WFP Firewall (Kill-switch and DNS leak protection) BEFORE adding routes/addresses
    // matching official WireGuard for Windows (`enableFirewall` in `addressconfig.go`).
    let restrict_all = config.peers.len() == 1
        && !config.interface.table_off
        && (found_default4 || found_default6);
    let do_not_restrict = !restrict_all && config.interface.dns.is_empty();

    let peer_endpoints: Vec<std::net::SocketAddr> = config
        .peers
        .iter()
        .filter_map(|p| p.endpoint.as_ref())
        .filter_map(|ep| ep.resolve().ok())
        .flatten()
        .collect();

    let fw_config = wireguard_wfp_rules::FirewallConfig {
        tun_interface_luid: luid.as_u64(),
        do_not_restrict,
        dns_servers: config.interface.dns.clone(),
        wireguard_endpoints: peer_endpoints,
        permit_hyperv: false,
    };

    let _firewall = match wireguard_wfp_rules::Firewall::enable(fw_config) {
        Ok(fw) => {
            ringlog_fmt!("[{}] Firewall rules enabled", tunnel_name);
            Some(fw)
        }
        Err(e) => {
            warn!("Failed to enable WFP firewall: {}", e);
            ringlog_fmt!("[{}] Warning: Failed to enable WFP firewall: {}", tunnel_name, e);
            None
        }
    };

    // Clean up duplicate tunnel IP addresses from any other disconnected interfaces
    let iface_ips: Vec<std::net::IpAddr> =
        config.interface.addresses.iter().map(|a| a.addr).collect();
    wireguard_ipcfg_routes::cleanup_addresses_on_disconnected_interfaces(luid, &iface_ips);

    // Configure IPv4 and IPv6 MIB_IPINTERFACE_ROW (DadTransmits = 0, NlMtu = 1420, Metric = 0)
    if let Err(e) = configure_ip_interface_family(luid, AddressFamily::Ipv4, mtu, found_default4) {
        warn!("Failed to configure IPv4 interface entry: {}", e);
    }
    if let Err(e) = configure_ip_interface_family(luid, AddressFamily::Ipv6, mtu, found_default6) {
        warn!("Failed to configure IPv6 interface entry: {}", e);
    }

    // Configure interface IP addresses
    for addr in &config.interface.addresses {
        if let Err(e) = wireguard_ipcfg_routes::add_unicast_address(luid, addr.addr, addr.cidr) {
            warn!("Failed to add interface address {}/{}: {}", addr.addr, addr.cidr, e);
        }
    }

    // Configure AllowedIP routes (deduplicated) if Table != off
    if !config.interface.table_off {
        let mut added_routes =
            std::collections::HashSet::with_capacity(config.peers.len() * 2);
        for peer in &config.peers {
            for allowed_ip in &peer.allowed_ips {
                if added_routes.insert((allowed_ip.addr, allowed_ip.cidr)) {
                    if let Err(e) = wireguard_ipcfg_routes::add_route(
                        luid,
                        allowed_ip.addr,
                        allowed_ip.cidr,
                        None,
                        0,
                    ) {
                        warn!(
                            "Failed to add route {}/{}: {}",
                            allowed_ip.addr, allowed_ip.cidr, e
                        );
                    }
                }
            }
        }
    }

    // Configure DNS servers and search domains
    if let Err(e) = wireguard_ipcfg_dns::set_dns(
        luid,
        &config.interface.dns,
        &config.interface.dns_search,
    ) {
        warn!("Failed to set DNS servers: {}", e);
        ringlog_fmt!("[{}] Warning: Failed to set DNS servers: {}", tunnel_name, e);
    } else {
        ringlog_fmt!("[{}] Configured DNS servers: {:?}", tunnel_name, config.interface.dns);
    }

    // Drop privileges while retaining driver privileges if required
    let _ = wireguard_elevate::drop_all_privileges(true);

    if let Some(reporter) = status_reporter {
        use windows_sys::Win32::System::Services::{
            SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
        };
        let _ = reporter.set_running(SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
    }

    info!("Tunnel '{}' is now RUNNING", tunnel_name);
    ringlog_fmt!("[{}] Startup complete; tunnel is RUNNING", tunnel_name);

    if let Some(rx) = control_rx {
        while let Ok(evt) = rx.recv() {
            if matches!(evt, ServiceControlEvent::Stop | ServiceControlEvent::Shutdown) {
                break;
            }
        }
    }

    ringlog_fmt!("[{}] Shutting down tunnel service", tunnel_name);
    drop(adapter);
    let _ = set_driver_logger(
        None::<fn(wireguard_driver::LogLevel, std::time::SystemTime, &str)>,
    );

    Ok(())
}
