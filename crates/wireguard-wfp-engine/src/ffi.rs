/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

#![allow(non_snake_case, non_camel_case_types)]

use std::ffi::c_void;
use crate::guid::Guid;

// ============================================================================
// WFP Constants
// ============================================================================

pub const FWP_ACTION_FLAG_TERMINATING: u32 = 0x00001000;
pub const FWP_ACTION_FLAG_NON_TERMINATING: u32 = 0x00002000;
pub const FWP_ACTION_FLAG_CALLOUT: u32 = 0x00004000;

pub const FWP_ACTION_BLOCK: u32 = 0x00000001 | FWP_ACTION_FLAG_TERMINATING;
pub const FWP_ACTION_PERMIT: u32 = 0x00000002 | FWP_ACTION_FLAG_TERMINATING;
pub const FWP_ACTION_CALLOUT_TERMINATING: u32 = 0x00000003 | FWP_ACTION_FLAG_CALLOUT | FWP_ACTION_FLAG_TERMINATING;
pub const FWP_ACTION_CALLOUT_INSPECTION: u32 = 0x00000004 | FWP_ACTION_FLAG_CALLOUT | FWP_ACTION_FLAG_NON_TERMINATING;
pub const FWP_ACTION_CALLOUT_UNKNOWN: u32 = 0x00000005 | FWP_ACTION_FLAG_CALLOUT;
pub const FWP_ACTION_CONTINUE: u32 = 0x00000006 | FWP_ACTION_FLAG_NON_TERMINATING;
pub const FWP_ACTION_NONE: u32 = 0x00000007;
pub const FWP_ACTION_NONE_NO_MATCH: u32 = 0x00000008;
pub const FWP_ACTION_BITMAP_INDEX_SET: u32 = 0x00000009;

pub const FWP_MATCH_EQUAL: u32 = 0;
pub const FWP_MATCH_GREATER: u32 = 1;
pub const FWP_MATCH_LESS: u32 = 2;
pub const FWP_MATCH_GREATER_OR_EQUAL: u32 = 3;
pub const FWP_MATCH_LESS_OR_EQUAL: u32 = 4;
pub const FWP_MATCH_RANGE: u32 = 5;
pub const FWP_MATCH_FLAGS_ALL_SET: u32 = 6;
pub const FWP_MATCH_FLAGS_ANY_SET: u32 = 7;
pub const FWP_MATCH_FLAGS_NONE_SET: u32 = 8;
pub const FWP_MATCH_EQUAL_CASE_INSENSITIVE: u32 = 9;
pub const FWP_MATCH_NOT_EQUAL: u32 = 10;
pub const FWP_MATCH_PREFIX: u32 = 11;
pub const FWP_MATCH_NOT_PREFIX: u32 = 12;

pub const FWP_EMPTY: u32 = 0;
pub const FWP_UINT8: u32 = 1;
pub const FWP_UINT16: u32 = 2;
pub const FWP_UINT32: u32 = 3;
pub const FWP_UINT64: u32 = 4;
pub const FWP_INT8: u32 = 5;
pub const FWP_INT16: u32 = 6;
pub const FWP_INT32: u32 = 7;
pub const FWP_INT64: u32 = 8;
pub const FWP_FLOAT: u32 = 9;
pub const FWP_DOUBLE: u32 = 10;
pub const FWP_BYTE_ARRAY16_TYPE: u32 = 11;
pub const FWP_BYTE_BLOB_TYPE: u32 = 12;
pub const FWP_SID: u32 = 13;
pub const FWP_SECURITY_DESCRIPTOR_TYPE: u32 = 14;
pub const FWP_TOKEN_INFORMATION_TYPE: u32 = 15;
pub const FWP_TOKEN_ACCESS_INFORMATION_TYPE: u32 = 16;
pub const FWP_UNICODE_STRING_TYPE: u32 = 17;
pub const FWP_BYTE_ARRAY6_TYPE: u32 = 18;
pub const FWP_BITMAP_INDEX_TYPE: u32 = 19;
pub const FWP_BITMAP_ARRAY64_TYPE: u32 = 20;
pub const FWP_SINGLE_DATA_TYPE_MAX: u32 = 0xff;
pub const FWP_V4_ADDR_MASK: u32 = FWP_SINGLE_DATA_TYPE_MAX + 1; // 256
pub const FWP_V6_ADDR_MASK: u32 = FWP_V4_ADDR_MASK + 1;         // 257
pub const FWP_RANGE_TYPE: u32 = FWP_V6_ADDR_MASK + 1;           // 258

pub const FWP_CONDITION_FLAG_IS_LOOPBACK: u32 = 0x00000001;
pub const FWP_CONDITION_L2_IS_VM2VM: u32 = 0x00000010;

pub const FWPM_SESSION_FLAG_DYNAMIC: u32 = 0x00000001;
pub const FWPM_SUBLAYER_FLAG_PERSISTENT: u32 = 0x00000001;

pub const FWPM_FILTER_FLAG_NONE: u32 = 0x00000000;
pub const FWPM_FILTER_FLAG_PERSISTENT: u32 = 0x00000001;
pub const FWPM_FILTER_FLAG_BOOTTIME: u32 = 0x00000002;
pub const FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT: u32 = 0x00000004;
pub const FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT: u32 = 0x00000008;
pub const FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED: u32 = 0x00000010;
pub const FWPM_FILTER_FLAG_DISABLED: u32 = 0x00000020;
pub const FWPM_FILTER_FLAG_INDEXED: u32 = 0x00000040;
pub const FWPM_FILTER_FLAG_HAS_SECURITY_REALM_PROVIDER_CONTEXT: u32 = 0x00000080;
pub const FWPM_FILTER_FLAG_SYSTEMOS_ONLY: u32 = 0x00000100;
pub const FWPM_FILTER_FLAG_GAMEOS_ONLY: u32 = 0x00000200;
pub const FWPM_FILTER_FLAG_SILENT_MODE: u32 = 0x00000400;
pub const FWPM_FILTER_FLAG_IPSEC_NO_ACQUIRE_INITIATE: u32 = 0x00000800;

pub const RPC_C_AUTHN_NONE: u32 = 0;
pub const RPC_C_AUTHN_WINNT: u32 = 10;
pub const RPC_C_AUTHN_DEFAULT: u32 = 0xFFFFFFFF;

pub const FWP_ACTRL_MATCH_FILTER: u32 = 1;

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;

pub const INFINITE_TIMEOUT: u32 = 0xFFFFFFFF;

// ============================================================================
// WFP Struct Definitions Matching C ABI
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FwpByteBlob {
    pub size: u32,
    #[cfg(target_pointer_width = "64")]
    pub _pad: u32,
    pub data: *mut u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FwpmDisplayData0 {
    pub name: *const u16,
    pub description: *const u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FwpValue0 {
    pub value_type: u32,
    #[cfg(target_pointer_width = "64")]
    pub _pad: u32,
    pub value: usize,
}

pub type FwpConditionValue0 = FwpValue0;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FwpmAction0 {
    pub action_type: u32,
    pub filter_type: Guid,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FwpmFilterCondition0 {
    pub field_key: Guid,
    pub match_type: u32,
    #[cfg(target_pointer_width = "64")]
    pub _pad: u32,
    pub condition_value: FwpConditionValue0,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FwpV4AddrAndMask {
    pub addr: u32,
    pub mask: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FwpV6AddrAndMask {
    pub addr: [u8; 16],
    pub prefix_length: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FwpByteArray16 {
    pub bytes: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FwpByteArray6 {
    pub bytes: [u8; 6],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FwpBitmapArray64 {
    pub bytes: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FwpmFilter0 {
    pub filter_key: Guid,
    pub display_data: FwpmDisplayData0,
    pub flags: u32,
    #[cfg(target_pointer_width = "64")]
    pub _pad0: u32,
    pub provider_key: *const Guid,
    pub provider_data: FwpByteBlob,
    pub layer_key: Guid,
    pub sub_layer_key: Guid,
    pub weight: FwpValue0,
    pub num_filter_conditions: u32,
    #[cfg(target_pointer_width = "64")]
    pub _pad1: u32,
    pub filter_condition: *const FwpmFilterCondition0,
    pub action: FwpmAction0,
    pub _offset1: [u8; 4],
    pub provider_context_key: Guid,
    pub reserved: *const Guid,
    #[cfg(target_pointer_width = "32")]
    pub _offset2: [u8; 4],
    pub filter_id: u64,
    pub effective_weight: FwpValue0,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FwpmProvider0 {
    pub provider_key: Guid,
    pub display_data: FwpmDisplayData0,
    pub flags: u32,
    #[cfg(target_pointer_width = "64")]
    pub _pad0: u32,
    pub provider_data: FwpByteBlob,
    pub service_name: *const u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FwpmSession0 {
    pub session_key: Guid,
    pub display_data: FwpmDisplayData0,
    pub flags: u32,
    pub txn_wait_timeout_in_msec: u32,
    pub process_id: u32,
    #[cfg(target_pointer_width = "64")]
    pub _pad0: u32,
    pub sid: *mut c_void,
    pub username: *const u16,
    pub kernel_mode: u32,
    #[cfg(target_pointer_width = "64")]
    pub _pad1: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FwpmSublayer0 {
    pub sub_layer_key: Guid,
    pub display_data: FwpmDisplayData0,
    pub flags: u32,
    #[cfg(target_pointer_width = "64")]
    pub _pad0: u32,
    pub provider_key: *const Guid,
    pub provider_data: FwpByteBlob,
    pub weight: u16,
    #[cfg(target_pointer_width = "64")]
    pub _pad1: [u8; 6],
    #[cfg(target_pointer_width = "32")]
    pub _pad1: [u8; 2],
}

// ============================================================================
// Windows Filtering Platform Function Bindings (fwpuclnt.dll)
// ============================================================================

#[link(name = "fwpuclnt")]
extern "system" {
    pub fn FwpmEngineOpen0(
        server_name: *const u16,
        authn_service: u32,
        auth_identity: *const c_void,
        session: *const FwpmSession0,
        engine_handle: *mut *mut c_void,
    ) -> u32;

    pub fn FwpmEngineClose0(engine_handle: *mut c_void) -> u32;

    pub fn FwpmTransactionBegin0(engine_handle: *mut c_void, flags: u32) -> u32;

    pub fn FwpmTransactionCommit0(engine_handle: *mut c_void) -> u32;

    pub fn FwpmTransactionAbort0(engine_handle: *mut c_void) -> u32;

    pub fn FwpmProviderAdd0(
        engine_handle: *mut c_void,
        provider: *const FwpmProvider0,
        security_descriptor: *const c_void,
    ) -> u32;

    pub fn FwpmProviderDeleteByKey0(
        engine_handle: *mut c_void,
        key: *const Guid,
    ) -> u32;

    pub fn FwpmSubLayerAdd0(
        engine_handle: *mut c_void,
        sub_layer: *const FwpmSublayer0,
        security_descriptor: *const c_void,
    ) -> u32;

    pub fn FwpmSubLayerDeleteByKey0(
        engine_handle: *mut c_void,
        key: *const Guid,
    ) -> u32;

    pub fn FwpmFilterAdd0(
        engine_handle: *mut c_void,
        filter: *const FwpmFilter0,
        security_descriptor: *const c_void,
        id: *mut u64,
    ) -> u32;

    pub fn FwpmFilterDeleteById0(
        engine_handle: *mut c_void,
        id: u64,
    ) -> u32;

    pub fn FwpmFilterDeleteByKey0(
        engine_handle: *mut c_void,
        key: *const Guid,
    ) -> u32;

    pub fn FwpmGetAppIdFromFileName0(
        file_name: *const u16,
        app_id: *mut *mut FwpByteBlob,
    ) -> u32;

    pub fn FwpmFreeMemory0(p: *mut *mut c_void);
}
