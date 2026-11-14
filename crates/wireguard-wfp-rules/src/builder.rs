/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr;
use tracing::{debug, error};

use wireguard_wfp_engine::{
    with_display_data, Engine, FwpByteBlob, FwpConditionValue0, FwpV4AddrAndMask,
    FwpV6AddrAndMask, FwpValue0, FwpmAction0, FwpmFilter0, FwpmFilterAdd0,
    FwpmFilterCondition0, Guid, WfpError, FWP_ACTION_PERMIT, FWP_BYTE_ARRAY16_TYPE,
    FWP_BYTE_BLOB_TYPE, FWP_SECURITY_DESCRIPTOR_TYPE, FWP_UINT16, FWP_UINT32,
    FWP_UINT64, FWP_UINT8, FWP_V4_ADDR_MASK, FWP_V6_ADDR_MASK,
};

use crate::error::RulesError;

/// Storage for condition data that must remain pinned in memory during `FwpmFilterAdd0`.
pub enum ConditionData {
    Uint8(u8),
    Uint16(u16),
    Uint32(u32),
    Uint64(Box<u64>),
    ByteArray16(Box<[u8; 16]>),
    V4AddrMask(Box<FwpV4AddrAndMask>),
    V6AddrMask(Box<FwpV6AddrAndMask>),
    ByteBlob(Box<FwpByteBlob>),
    SecurityDescriptor(Box<FwpByteBlob>),
}

/// A single filter match condition.
pub struct RuleCondition {
    pub field_key: Guid,
    pub match_type: u32,
    pub data: ConditionData,
}

impl RuleCondition {
    /// Creates a condition matching a u8 value.
    pub fn uint8(field_key: Guid, match_type: u32, val: u8) -> Self {
        Self {
            field_key,
            match_type,
            data: ConditionData::Uint8(val),
        }
    }

    /// Creates a condition matching a u16 value (e.g. port or ICMP code).
    pub fn uint16(field_key: Guid, match_type: u32, val: u16) -> Self {
        Self {
            field_key,
            match_type,
            data: ConditionData::Uint16(val),
        }
    }

    /// Creates a condition matching a u32 value (e.g. IPv4 addr in host byte order or flags).
    pub fn uint32(field_key: Guid, match_type: u32, val: u32) -> Self {
        Self {
            field_key,
            match_type,
            data: ConditionData::Uint32(val),
        }
    }

    /// Creates a condition matching a u64 value (e.g. Interface LUID).
    pub fn uint64(field_key: Guid, match_type: u32, val: u64) -> Self {
        Self {
            field_key,
            match_type,
            data: ConditionData::Uint64(Box::new(val)),
        }
    }

    /// Creates a condition matching an exact IPv4 address.
    pub fn ipv4(field_key: Guid, match_type: u32, ip: Ipv4Addr) -> Self {
        Self::uint32(field_key, match_type, u32::from(ip))
    }

    /// Creates a condition matching an exact IPv6 address (16 bytes).
    pub fn ipv6(field_key: Guid, match_type: u32, ip: Ipv6Addr) -> Self {
        Self {
            field_key,
            match_type,
            data: ConditionData::ByteArray16(Box::new(ip.octets())),
        }
    }

    /// Creates a condition matching a raw 16-byte array.
    pub fn byte_array16(field_key: Guid, match_type: u32, bytes: [u8; 16]) -> Self {
        Self {
            field_key,
            match_type,
            data: ConditionData::ByteArray16(Box::new(bytes)),
        }
    }

    /// Creates a condition matching an IPv6 address with a prefix mask (CIDR).
    pub fn ipv6_prefix(field_key: Guid, match_type: u32, ip: [u8; 16], prefix_length: u8) -> Self {
        Self {
            field_key,
            match_type,
            data: ConditionData::V6AddrMask(Box::new(FwpV6AddrAndMask {
                addr: ip,
                prefix_length,
            })),
        }
    }

    /// Creates a condition matching an application binary ID blob.
    pub fn app_id(field_key: Guid, match_type: u32, blob: FwpByteBlob) -> Self {
        Self {
            field_key,
            match_type,
            data: ConditionData::ByteBlob(Box::new(blob)),
        }
    }

    /// Creates a condition matching a Security Descriptor blob.
    pub fn security_descriptor(field_key: Guid, match_type: u32, blob: FwpByteBlob) -> Self {
        Self {
            field_key,
            match_type,
            data: ConditionData::SecurityDescriptor(Box::new(blob)),
        }
    }
}

#[inline]
pub(crate) fn raw_cond(
    field_key: Guid,
    match_type: u32,
    value_type: u32,
    value: usize,
) -> FwpmFilterCondition0 {
    FwpmFilterCondition0 {
        field_key,
        match_type,
        #[cfg(target_pointer_width = "64")]
        _pad: 0,
        condition_value: FwpConditionValue0 {
            value_type,
            #[cfg(target_pointer_width = "64")]
            _pad: 0,
            value,
        },
    }
}

#[inline]
pub(crate) fn cond_u8(field_key: Guid, match_type: u32, val: u8) -> FwpmFilterCondition0 {
    raw_cond(field_key, match_type, FWP_UINT8, val as usize)
}

#[inline]
pub(crate) fn cond_u16(field_key: Guid, match_type: u32, val: u16) -> FwpmFilterCondition0 {
    raw_cond(field_key, match_type, FWP_UINT16, val as usize)
}

#[inline]
pub(crate) fn cond_u32(field_key: Guid, match_type: u32, val: u32) -> FwpmFilterCondition0 {
    raw_cond(field_key, match_type, FWP_UINT32, val as usize)
}

#[inline]
pub(crate) fn cond_ipv4(field_key: Guid, match_type: u32, ip: Ipv4Addr) -> FwpmFilterCondition0 {
    cond_u32(field_key, match_type, u32::from(ip))
}

#[inline]
pub(crate) fn cond_u64_ref(field_key: Guid, match_type: u32, val: &u64) -> FwpmFilterCondition0 {
    raw_cond(
        field_key,
        match_type,
        FWP_UINT64,
        val as *const u64 as usize,
    )
}

#[inline]
pub(crate) fn cond_bytes16_ref(
    field_key: Guid,
    match_type: u32,
    bytes: &[u8; 16],
) -> FwpmFilterCondition0 {
    raw_cond(
        field_key,
        match_type,
        FWP_BYTE_ARRAY16_TYPE,
        bytes as *const [u8; 16] as usize,
    )
}

#[inline]
pub(crate) fn cond_v6_prefix_ref(
    field_key: Guid,
    match_type: u32,
    addr_mask: &FwpV6AddrAndMask,
) -> FwpmFilterCondition0 {
    raw_cond(
        field_key,
        match_type,
        FWP_V6_ADDR_MASK,
        addr_mask as *const FwpV6AddrAndMask as usize,
    )
}

#[inline]
pub(crate) fn cond_byte_blob_ref(
    field_key: Guid,
    match_type: u32,
    blob: &FwpByteBlob,
) -> FwpmFilterCondition0 {
    raw_cond(
        field_key,
        match_type,
        FWP_BYTE_BLOB_TYPE,
        blob as *const FwpByteBlob as usize,
    )
}

#[inline]
pub(crate) fn cond_sd_ref(
    field_key: Guid,
    match_type: u32,
    blob: &FwpByteBlob,
) -> FwpmFilterCondition0 {
    raw_cond(
        field_key,
        match_type,
        FWP_SECURITY_DESCRIPTOR_TYPE,
        blob as *const FwpByteBlob as usize,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_filter_raw(
    engine: &Engine,
    provider_key: &Guid,
    sublayer_key: &Guid,
    name: &str,
    description: &str,
    layer_key: Guid,
    action_type: u32,
    weight: u8,
    flags: u32,
    conditions: &[FwpmFilterCondition0],
) -> Result<u64, RulesError> {
    if !engine.is_valid() {
        return Err(RulesError::Engine(WfpError::EngineClosed));
    }

    let mut filter_id = 0u64;
    debug!(
        "Adding WFP filter '{}' on layer {} (weight={}, action=0x{:08x})",
        name, layer_key, weight, action_type
    );

    let status = with_display_data(name, description, |display_data| {
        let mut filter = FwpmFilter0::default();
        filter.display_data = display_data;
        filter.provider_key = provider_key;
        filter.sub_layer_key = *sublayer_key;
        filter.layer_key = layer_key;
        filter.weight = FwpValue0 {
            value_type: FWP_UINT8,
            #[cfg(target_pointer_width = "64")]
            _pad: 0,
            value: weight as usize,
        };
        filter.flags = flags;
        filter.action = FwpmAction0 {
            action_type,
            filter_type: Guid::zero(),
        };

        if !conditions.is_empty() {
            filter.num_filter_conditions = conditions.len() as u32;
            filter.filter_condition = conditions.as_ptr();
        }

        unsafe { FwpmFilterAdd0(engine.handle(), &filter, ptr::null(), &mut filter_id) }
    });

    if status != 0 {
        error!(
            "FwpmFilterAdd0 failed for '{}' on layer {}: 0x{:08x}",
            name, layer_key, status
        );
        return Err(RulesError::Engine(WfpError::Win32(status)));
    }

    debug!("Filter '{}' installed with ID {}", name, filter_id);
    Ok(filter_id)
}

#[inline]
fn condition_to_raw(cond: &RuleCondition) -> FwpmFilterCondition0 {
    let (value_type, value) = match &cond.data {
        ConditionData::Uint8(v) => (FWP_UINT8, *v as usize),
        ConditionData::Uint16(v) => (FWP_UINT16, *v as usize),
        ConditionData::Uint32(v) => (FWP_UINT32, *v as usize),
        ConditionData::Uint64(v) => (FWP_UINT64, v.as_ref() as *const u64 as usize),
        ConditionData::ByteArray16(v) => (FWP_BYTE_ARRAY16_TYPE, v.as_ref() as *const [u8; 16] as usize),
        ConditionData::V4AddrMask(v) => (FWP_V4_ADDR_MASK, v.as_ref() as *const FwpV4AddrAndMask as usize),
        ConditionData::V6AddrMask(v) => (FWP_V6_ADDR_MASK, v.as_ref() as *const FwpV6AddrAndMask as usize),
        ConditionData::ByteBlob(v) => (FWP_BYTE_BLOB_TYPE, v.as_ref() as *const FwpByteBlob as usize),
        ConditionData::SecurityDescriptor(v) => (
            FWP_SECURITY_DESCRIPTOR_TYPE,
            v.as_ref() as *const FwpByteBlob as usize,
        ),
    };
    raw_cond(cond.field_key, cond.match_type, value_type, value)
}

/// Fluent builder for constructing and installing a WFP filter rule.
pub struct FilterBuilder<'a> {
    name: &'a str,
    description: &'a str,
    layer_key: Guid,
    action_type: u32,
    weight: u8,
    flags: u32,
    conditions: Vec<RuleCondition>,
}

impl<'a> FilterBuilder<'a> {
    /// Starts constructing a new filter for the given WFP layer.
    pub fn new(name: &'a str, layer_key: Guid) -> Self {
        Self {
            name,
            description: "",
            layer_key,
            action_type: FWP_ACTION_PERMIT,
            weight: 0,
            flags: 0,
            conditions: Vec::new(),
        }
    }

    /// Sets the description string.
    pub fn description(mut self, desc: &'a str) -> Self {
        self.description = desc;
        self
    }

    /// Sets the filter action (e.g. `FWP_ACTION_PERMIT` or `FWP_ACTION_BLOCK`).
    pub fn action(mut self, action_type: u32) -> Self {
        self.action_type = action_type;
        self
    }

    /// Sets the rule evaluation weight within its sublayer.
    pub fn weight(mut self, weight: u8) -> Self {
        self.weight = weight;
        self
    }

    /// Sets filter flags (e.g. `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`).
    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Adds a single condition to the filter.
    pub fn condition(mut self, condition: RuleCondition) -> Self {
        self.conditions.push(condition);
        self
    }

    /// Adds multiple conditions to the filter.
    pub fn conditions(mut self, conditions: impl IntoIterator<Item = RuleCondition>) -> Self {
        self.conditions.extend(conditions);
        self
    }

    /// Installs this filter rule into the WFP engine.
    pub fn add(
        self,
        engine: &Engine,
        provider_key: &Guid,
        sublayer_key: &Guid,
    ) -> Result<u64, RulesError> {
        const STACK_COND_CAP: usize = 8;
        if self.conditions.len() <= STACK_COND_CAP {
            let mut stack_raw = [FwpmFilterCondition0::default(); STACK_COND_CAP];
            for (dst, cond) in stack_raw.iter_mut().zip(self.conditions.iter()) {
                *dst = condition_to_raw(cond);
            }
            add_filter_raw(
                engine,
                provider_key,
                sublayer_key,
                self.name,
                self.description,
                self.layer_key,
                self.action_type,
                self.weight,
                self.flags,
                &stack_raw[..self.conditions.len()],
            )
        } else {
            let mut heap_raw = Vec::with_capacity(self.conditions.len());
            for cond in &self.conditions {
                heap_raw.push(condition_to_raw(cond));
            }
            add_filter_raw(
                engine,
                provider_key,
                sublayer_key,
                self.name,
                self.description,
                self.layer_key,
                self.action_type,
                self.weight,
                self.flags,
                &heap_raw,
            )
        }
    }
}
