/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use std::fmt;
use std::str::FromStr;
use crate::error::WfpError;

/// Win32 GUID structure matching the C ABI.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

#[link(name = "ole32")]
extern "system" {
    fn CoCreateGuid(pguid: *mut Guid) -> i32;
}

impl Guid {
    /// Creates a new GUID from raw fields.
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self {
            data1,
            data2,
            data3,
            data4,
        }
    }

    /// Creates a GUID with all zero fields.
    pub const fn zero() -> Self {
        Self {
            data1: 0,
            data2: 0,
            data3: 0,
            data4: [0; 8],
        }
    }

    /// Generates a new random GUID using Windows `CoCreateGuid`.
    pub fn random() -> Result<Self, WfpError> {
        let mut guid = Self::zero();
        let hr = unsafe { CoCreateGuid(&mut guid) };
        if hr != 0 {
            return Err(WfpError::Hresult(hr));
        }
        Ok(guid)
    }

    /// Creates a GUID from 16 bytes in big-endian network byte order.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self {
            data1: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            data2: u16::from_be_bytes([bytes[4], bytes[5]]),
            data3: u16::from_be_bytes([bytes[6], bytes[7]]),
            data4: [
                bytes[8], bytes[9], bytes[10], bytes[11],
                bytes[12], bytes[13], bytes[14], bytes[15],
            ],
        }
    }

    /// Converts the GUID to 16 bytes in big-endian network byte order.
    pub const fn to_bytes(&self) -> [u8; 16] {
        let d1 = self.data1.to_be_bytes();
        let d2 = self.data2.to_be_bytes();
        let d3 = self.data3.to_be_bytes();
        [
            d1[0], d1[1], d1[2], d1[3],
            d2[0], d2[1],
            d3[0], d3[1],
            self.data4[0], self.data4[1], self.data4[2], self.data4[3],
            self.data4[4], self.data4[5], self.data4[6], self.data4[7],
        ]
    }

    /// Creates a GUID from a u128 integer.
    pub const fn from_u128(v: u128) -> Self {
        Self::from_bytes(v.to_be_bytes())
    }

    /// Converts the GUID to a u128 integer.
    pub const fn to_u128(&self) -> u128 {
        u128::from_be_bytes(self.to_bytes())
    }
}

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

#[inline]
fn write_hex_byte(dst: &mut [u8], pos: usize, byte: u8) {
    dst[pos] = HEX_LOWER[(byte >> 4) as usize];
    dst[pos + 1] = HEX_LOWER[(byte & 0x0F) as usize];
}

#[inline]
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[inline]
fn hex_byte(b: &[u8], i: usize) -> Option<u8> {
    Some((hex_nibble(b[i])? << 4) | hex_nibble(b[i + 1])?)
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0u8; 36];
        let d1 = self.data1.to_be_bytes();
        let d2 = self.data2.to_be_bytes();
        let d3 = self.data3.to_be_bytes();

        write_hex_byte(&mut buf, 0, d1[0]);
        write_hex_byte(&mut buf, 2, d1[1]);
        write_hex_byte(&mut buf, 4, d1[2]);
        write_hex_byte(&mut buf, 6, d1[3]);
        buf[8] = b'-';
        write_hex_byte(&mut buf, 9, d2[0]);
        write_hex_byte(&mut buf, 11, d2[1]);
        buf[13] = b'-';
        write_hex_byte(&mut buf, 14, d3[0]);
        write_hex_byte(&mut buf, 16, d3[1]);
        buf[18] = b'-';
        write_hex_byte(&mut buf, 19, self.data4[0]);
        write_hex_byte(&mut buf, 21, self.data4[1]);
        buf[23] = b'-';
        write_hex_byte(&mut buf, 24, self.data4[2]);
        write_hex_byte(&mut buf, 26, self.data4[3]);
        write_hex_byte(&mut buf, 28, self.data4[4]);
        write_hex_byte(&mut buf, 30, self.data4[5]);
        write_hex_byte(&mut buf, 32, self.data4[6]);
        write_hex_byte(&mut buf, 34, self.data4[7]);

        // SAFETY: all 36 bytes in `buf` are ASCII hex digits or '-'.
        let s = unsafe { std::str::from_utf8_unchecked(&buf) };
        f.write_str(s)
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl FromStr for Guid {
    type Err = WfpError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut b = s.as_bytes();
        while let Some(&c) = b.first() {
            if c == b'{' || c == b'}' {
                b = &b[1..];
            } else {
                break;
            }
        }
        while let Some(&c) = b.last() {
            if c == b'{' || c == b'}' {
                b = &b[..b.len() - 1];
            } else {
                break;
            }
        }

        if b.len() != 36 || b[8] != b'-' || b[13] != b'-' || b[18] != b'-' || b[23] != b'-' {
            return Err(WfpError::InvalidGuid(s.to_string()));
        }

        let parse = || -> Option<Self> {
            let d1 = u32::from_be_bytes([
                hex_byte(b, 0)?,
                hex_byte(b, 2)?,
                hex_byte(b, 4)?,
                hex_byte(b, 6)?,
            ]);
            let d2 = u16::from_be_bytes([hex_byte(b, 9)?, hex_byte(b, 11)?]);
            let d3 = u16::from_be_bytes([hex_byte(b, 14)?, hex_byte(b, 16)?]);
            let data4 = [
                hex_byte(b, 19)?,
                hex_byte(b, 21)?,
                hex_byte(b, 24)?,
                hex_byte(b, 26)?,
                hex_byte(b, 28)?,
                hex_byte(b, 30)?,
                hex_byte(b, 32)?,
                hex_byte(b, 34)?,
            ];
            Some(Guid::new(d1, d2, d3, data4))
        };

        parse().ok_or_else(|| WfpError::InvalidGuid(s.to_string()))
    }
}

// ============================================================================
// Standard WFP Well-Known Layer GUIDs
// ============================================================================

/// FWPM_LAYER_ALE_AUTH_CONNECT_V4: c38d57d1-05a7-4c33-904f-7fbceee60e82
pub const FWPM_LAYER_ALE_AUTH_CONNECT_V4: Guid = Guid::new(
    0xc38d57d1,
    0x05a7,
    0x4c33,
    [0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82],
);

/// FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4: e1cd9fe7-f4b5-4273-96c0-592e487b8650
pub const FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4: Guid = Guid::new(
    0xe1cd9fe7,
    0xf4b5,
    0x4273,
    [0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50],
);

/// FWPM_LAYER_ALE_AUTH_CONNECT_V6: 4a72393b-319f-44bc-84c3-ba54dcb3b6b4
pub const FWPM_LAYER_ALE_AUTH_CONNECT_V6: Guid = Guid::new(
    0x4a72393b,
    0x319f,
    0x44bc,
    [0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4],
);

/// FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6: a3b42c97-9f04-4672-b87e-cee9c483257f
pub const FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6: Guid = Guid::new(
    0xa3b42c97,
    0x9f04,
    0x4672,
    [0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f],
);

/// FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE: 94c44912-9d6f-4ebf-b995-05ab8a088d1b
pub const FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE: Guid = Guid::new(
    0x94c44912,
    0x9d6f,
    0x4ebf,
    [0xb9, 0x95, 0x05, 0xab, 0x8a, 0x08, 0x8d, 0x1b],
);

/// FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE: d4220bd3-62ce-4f08-ae88-b56e8526df50
pub const FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE: Guid = Guid::new(
    0xd4220bd3,
    0x62ce,
    0x4f08,
    [0xae, 0x88, 0xb5, 0x6e, 0x85, 0x26, 0xdf, 0x50],
);

// ============================================================================
// Standard WFP Condition Field GUIDs
// ============================================================================

/// FWPM_CONDITION_IP_LOCAL_INTERFACE: 4cd62a49-59c3-4969-b7f3-bda5d32890a4
pub const FWPM_CONDITION_IP_LOCAL_INTERFACE: Guid = Guid::new(
    0x4cd62a49,
    0x59c3,
    0x4969,
    [0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4],
);

/// FWPM_CONDITION_IP_REMOTE_ADDRESS: b235ae9a-1d64-49b8-a44c-5ff3d9095045
pub const FWPM_CONDITION_IP_REMOTE_ADDRESS: Guid = Guid::new(
    0xb235ae9a,
    0x1d64,
    0x49b8,
    [0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45],
);

/// FWPM_CONDITION_IP_PROTOCOL: 3971ef2b-623e-4f9a-8cb1-6e79b806b9a7
pub const FWPM_CONDITION_IP_PROTOCOL: Guid = Guid::new(
    0x3971ef2b,
    0x623e,
    0x4f9a,
    [0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7],
);

/// FWPM_CONDITION_IP_LOCAL_PORT: 0c1ba1af-5765-453f-af22-a8f791ac775b
pub const FWPM_CONDITION_IP_LOCAL_PORT: Guid = Guid::new(
    0x0c1ba1af,
    0x5765,
    0x453f,
    [0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b],
);

/// FWPM_CONDITION_IP_REMOTE_PORT: c35a604d-d22b-4e1a-91b4-68f674ee674b
pub const FWPM_CONDITION_IP_REMOTE_PORT: Guid = Guid::new(
    0xc35a604d,
    0xd22b,
    0x4e1a,
    [0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b],
);

/// FWPM_CONDITION_ALE_APP_ID: d78e1e87-8644-4ea5-9437-d809ecefc971
pub const FWPM_CONDITION_ALE_APP_ID: Guid = Guid::new(
    0xd78e1e87,
    0x8644,
    0x4ea5,
    [0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71],
);

/// FWPM_CONDITION_ALE_USER_ID: af043a0a-b34d-4f86-979c-c90371af6e66
pub const FWPM_CONDITION_ALE_USER_ID: Guid = Guid::new(
    0xaf043a0a,
    0xb34d,
    0x4f86,
    [0x97, 0x9c, 0xc9, 0x03, 0x71, 0xaf, 0x6e, 0x66],
);

/// FWPM_CONDITION_IP_LOCAL_ADDRESS: d9ee00de-c1ef-4617-bfe3-ffd8f5a08957
pub const FWPM_CONDITION_IP_LOCAL_ADDRESS: Guid = Guid::new(
    0xd9ee00de,
    0xc1ef,
    0x4617,
    [0xbf, 0xe3, 0xff, 0xd8, 0xf5, 0xa0, 0x89, 0x57],
);

/// FWPM_CONDITION_ICMP_TYPE: identical to FWPM_CONDITION_IP_LOCAL_PORT
pub const FWPM_CONDITION_ICMP_TYPE: Guid = FWPM_CONDITION_IP_LOCAL_PORT;

/// FWPM_CONDITION_ICMP_CODE: identical to FWPM_CONDITION_IP_REMOTE_PORT
pub const FWPM_CONDITION_ICMP_CODE: Guid = FWPM_CONDITION_IP_REMOTE_PORT;

/// FWPM_CONDITION_FLAGS: 632ce23b-5167-435c-86d7-e903684aa80c
pub const FWPM_CONDITION_FLAGS: Guid = Guid::new(
    0x632ce23b,
    0x5167,
    0x435c,
    [0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c],
);

/// FWPM_CONDITION_L2_FLAGS: 7bc43cbf-37ba-45f1-b74a-82ff518eeb10
pub const FWPM_CONDITION_L2_FLAGS: Guid = Guid::new(
    0x7bc43cbf,
    0x37ba,
    0x45f1,
    [0xb7, 0x4a, 0x82, 0xff, 0x51, 0x8e, 0xeb, 0x10],
);
