/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use tracing::info;

use wireguard_wfp_engine::{BaseObjects, Engine};

use crate::dns::block_dns_into;
use crate::error::RulesError;
use crate::killswitch::block_all_into;
use crate::permit_dhcp::{permit_dhcp_ipv4_into, permit_dhcp_ipv6_into};
use crate::permit_endpoint::permit_wireguard_endpoints_into;
use crate::permit_hyperv::permit_hyper_v_into;
use crate::permit_loopback::permit_loopback_into;
use crate::permit_ndp::permit_ndp_into;
use crate::permit_service::permit_wireguard_service_into;
use crate::permit_tun::permit_tun_interface_into;

/// Configuration options for enabling the WireGuard WFP firewall killswitch.
#[derive(Clone, Debug, Default)]
pub struct FirewallConfig {
    /// NDIS Interface LUID of the WireGuard TUN adapter.
    pub tun_interface_luid: u64,
    /// If true, only permits the WireGuard service process without installing the default block-all killswitch.
    pub do_not_restrict: bool,
    /// Specific DNS servers to whitelist (port 53). All other DNS traffic will be blocked.
    pub dns_servers: Vec<IpAddr>,
    /// Remote WireGuard peer endpoints (IP:port) to explicitly permit outside the tunnel.
    pub wireguard_endpoints: Vec<SocketAddr>,
    /// If true, permits Layer-2 VM-to-VM traffic for Hyper-V environments.
    pub permit_hyperv: bool,
}

/// Active WireGuard firewall instance managing WFP rules.
///
/// Implements RAII: when `Firewall` is dropped or `disable()` is called,
/// the dynamic WFP session is closed, causing the Windows Filtering Platform
/// to immediately purge all sublayers, provider registrations, and filter rules.
pub struct Firewall {
    engine: Engine,
    base_objects: BaseObjects,
    filter_ids: Vec<u64>,
    active: bool,
}

impl Firewall {
    /// Enables the WireGuard firewall and applies killswitch and permit rules atomically.
    pub fn enable(config: FirewallConfig) -> Result<Self, RulesError> {
        info!("Enabling WireGuard WFP firewall (tun_luid=0x{:016x}, do_not_restrict={})",
            config.tun_interface_luid, config.do_not_restrict
        );

        // Open dynamic WFP engine session
        let engine = Engine::open("WireGuard", "WireGuard dynamic session", true)?;

        let expected_filters = if config.do_not_restrict {
            4
        } else {
            let has_v4_dns = config.dns_servers.iter().any(|ip| ip.is_ipv4());
            let has_v6_dns = config.dns_servers.iter().any(|ip| ip.is_ipv6());
            let dns_filters = if config.dns_servers.is_empty() {
                0
            } else {
                4 + usize::from(has_v4_dns) * 2 + usize::from(has_v6_dns) * 2
            };
            // service(4) + loopback(4) + tun(4) + dhcp4(2) + dhcp6(2) + ndp(7) + block_all(4)
            27 + dns_filters
                + config.wireguard_endpoints.len() * 2
                + usize::from(config.permit_hyperv) * 2
        };
        let mut all_filter_ids = Vec::with_capacity(expected_filters);

        let base_objects: BaseObjects = engine.run_transaction(|txn| -> Result<BaseObjects, RulesError> {
            let eng = txn.engine();
            // Register provider and sublayer
            let base = eng.register_base_objects("WireGuard", "WireGuard filters")?;

            // 1. Unconditionally permit WireGuard service process traffic (weight 15)
            permit_wireguard_service_into(eng, &base, 15, &mut all_filter_ids)?;

            if !config.do_not_restrict {
                // 2. DNS Leak Prevention: Whitelist WireGuard DNS servers (weight 15), block others (weight 14)
                if !config.dns_servers.is_empty() {
                    block_dns_into(&config.dns_servers, eng, &base, 15, 14, &mut all_filter_ids)?;
                }

                // 3. Permit direct UDP traffic to remote peer endpoints outside tunnel (weight 15)
                if !config.wireguard_endpoints.is_empty() {
                    permit_wireguard_endpoints_into(
                        &config.wireguard_endpoints,
                        eng,
                        &base,
                        15,
                        &mut all_filter_ids,
                    )?;
                }

                // 4. Permit loopback traffic (weight 13)
                permit_loopback_into(eng, &base, 13, &mut all_filter_ids)?;

                // 5. Permit all traffic on the WireGuard TUN adapter (weight 12)
                permit_tun_interface_into(config.tun_interface_luid, eng, &base, 12, &mut all_filter_ids)?;

                // 6. Permit DHCP IPv4 (weight 12)
                permit_dhcp_ipv4_into(eng, &base, 12, &mut all_filter_ids)?;

                // 7. Permit DHCP IPv6 (weight 12)
                permit_dhcp_ipv6_into(eng, &base, 12, &mut all_filter_ids)?;

                // 8. Permit NDP neighbor discovery (weight 12)
                permit_ndp_into(eng, &base, 12, &mut all_filter_ids)?;

                // 9. Permit Hyper-V VM-to-VM traffic if requested (weight 12)
                if config.permit_hyperv {
                    permit_hyper_v_into(eng, &base, 12, &mut all_filter_ids)?;
                }

                // 10. Default-deny killswitch: block everything else (weight 0)
                block_all_into(eng, &base, 0, &mut all_filter_ids)?;
            }

            Ok(base)
        })?;

        info!("WireGuard WFP firewall enabled successfully with {} installed filters", all_filter_ids.len());

        Ok(Self {
            engine,
            base_objects,
            filter_ids: all_filter_ids,
            active: true,
        })
    }

    /// Disables the firewall and releases all dynamic WFP rules and sublayers.
    pub fn disable(&mut self) -> Result<(), RulesError> {
        if !self.active {
            return Ok(());
        }

        info!("Disabling WireGuard WFP firewall and tearing down dynamic session");
        self.active = false;
        self.filter_ids.clear();
        self.engine.close()?;
        Ok(())
    }

    /// Returns the registered BaseObjects (provider and filters sublayer GUIDs).
    pub fn base_objects(&self) -> &BaseObjects {
        &self.base_objects
    }

    /// Returns the installed filter rule IDs.
    pub fn filter_ids(&self) -> &[u64] {
        &self.filter_ids
    }

    /// Returns true if the firewall is currently active.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

impl Drop for Firewall {
    fn drop(&mut self) {
        if self.active {
            let _ = self.disable();
        }
    }
}

// ============================================================================
// Global Singleton API Matching wireguard-windows Go Architecture
// ============================================================================

static GLOBAL_FIREWALL: Mutex<Option<Firewall>> = Mutex::new(None);

/// Enables the global WireGuard firewall instance.
pub fn enable_firewall(
    tun_luid: u64,
    do_not_restrict: bool,
    restrict_to_dns_servers: Vec<IpAddr>,
) -> Result<(), RulesError> {
    let mut lock = GLOBAL_FIREWALL.lock().unwrap_or_else(|e| e.into_inner());
    if lock.is_some() {
        return Err(RulesError::AlreadyEnabled);
    }

    let config = FirewallConfig {
        tun_interface_luid: tun_luid,
        do_not_restrict,
        dns_servers: restrict_to_dns_servers,
        wireguard_endpoints: Vec::new(),
        permit_hyperv: false,
    };

    let firewall = Firewall::enable(config)?;
    *lock = Some(firewall);
    Ok(())
}

/// Disables the global WireGuard firewall instance.
pub fn disable_firewall() {
    let mut lock = GLOBAL_FIREWALL.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(mut fw) = lock.take() {
        let _ = fw.disable();
    }
}
