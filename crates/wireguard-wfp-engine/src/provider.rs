/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use std::ptr;
use tracing::{debug, error, info};

use crate::error::WfpError;
use crate::ffi::*;
use crate::guid::Guid;
use crate::session::{with_display_data, Engine};

/// Fundamental WireGuard-specific WFP objects.
///
/// Contains the GUIDs of the registered WireGuard provider and the
/// high-weight sublayer where WireGuard permissive and blocking filter
/// rules are placed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BaseObjects {
    /// GUID of the registered WireGuard WFP provider.
    pub provider: Guid,
    /// GUID of the registered WireGuard WFP sublayer.
    pub filters: Guid,
}

impl Engine {
    /// Registers a new dynamic WFP provider and filters sublayer with randomly generated GUIDs.
    ///
    /// # Arguments
    /// * `provider_name` - Name for the WFP provider (e.g. "WireGuard").
    /// * `sublayer_name` - Name for the WFP sublayer (e.g. "WireGuard filters").
    pub fn register_base_objects(
        &self,
        provider_name: &str,
        sublayer_name: &str,
    ) -> Result<BaseObjects, WfpError> {
        let provider_guid = Guid::random()?;
        let filters_guid = Guid::random()?;
        self.register_base_objects_with_guids(provider_name, sublayer_name, provider_guid, filters_guid)
    }

    /// Registers a WFP provider and filters sublayer using explicitly provided GUIDs.
    pub fn register_base_objects_with_guids(
        &self,
        provider_name: &str,
        sublayer_name: &str,
        provider_guid: Guid,
        filters_guid: Guid,
    ) -> Result<BaseObjects, WfpError> {
        if !self.is_valid() {
            return Err(WfpError::EngineClosed);
        }

        // 1. Register WFP Provider
        {
            debug!("Adding WFP provider '{}' ({})", provider_name, provider_guid);
            let status = with_display_data(provider_name, "WireGuard provider", |display_data| {
                let mut provider = FwpmProvider0::default();
                provider.provider_key = provider_guid;
                provider.display_data = display_data;
                unsafe { FwpmProviderAdd0(self.handle(), &provider, ptr::null()) }
            });
            if status != 0 {
                error!("FwpmProviderAdd0 failed: 0x{:08x}", status);
                return Err(WfpError::Win32(status));
            }
        }

        // 2. Register WFP Filters Sublayer
        {
            debug!("Adding WFP sublayer '{}' ({})", sublayer_name, filters_guid);
            let status = with_display_data(
                sublayer_name,
                "Permissive and blocking filters",
                |display_data| {
                    let mut sublayer = FwpmSublayer0::default();
                    sublayer.sub_layer_key = filters_guid;
                    sublayer.display_data = display_data;
                    sublayer.provider_key = &provider_guid;
                    sublayer.weight = 0xFFFF; // Maximum priority weight
                    unsafe { FwpmSubLayerAdd0(self.handle(), &sublayer, ptr::null()) }
                },
            );
            if status != 0 {
                error!("FwpmSubLayerAdd0 failed: 0x{:08x}", status);
                // Attempt cleanup of the provider registered above
                let _ = unsafe { FwpmProviderDeleteByKey0(self.handle(), &provider_guid) };
                return Err(WfpError::Win32(status));
            }
        }

        info!(
            "Registered base WFP objects: provider={}, sublayer={}",
            provider_guid, filters_guid
        );

        Ok(BaseObjects {
            provider: provider_guid,
            filters: filters_guid,
        })
    }
}
