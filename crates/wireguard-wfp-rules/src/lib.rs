/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

//! Windows Filtering Platform (WFP) firewall rules for WireGuard.
//!
//! Provides killswitch default-deny blocking, WireGuard service and endpoint permits,
//! DNS leak prevention, loopback, DHCP, and NDP neighbor discovery rules.

pub mod error;
pub mod builder;
pub mod permit_service;
pub mod permit_endpoint;
pub mod permit_loopback;
pub mod permit_tun;
pub mod permit_dhcp;
pub mod permit_ndp;
pub mod permit_hyperv;
pub mod dns;
pub mod killswitch;
pub mod manager;
mod tests;

pub use error::RulesError;
pub use builder::{ConditionData, FilterBuilder, RuleCondition};
pub use permit_service::permit_wireguard_service;
pub use permit_endpoint::permit_wireguard_endpoints;
pub use permit_loopback::permit_loopback;
pub use permit_tun::permit_tun_interface;
pub use permit_dhcp::{permit_dhcp_ipv4, permit_dhcp_ipv6};
pub use permit_ndp::permit_ndp;
pub use permit_hyperv::permit_hyper_v;
pub use dns::block_dns;
pub use killswitch::block_all;
pub use manager::{disable_firewall, enable_firewall, Firewall, FirewallConfig};
