use std::fmt;
use std::str::FromStr;
use windows_sys::core::GUID;

use crate::error::{IpCfgError, Result};
use crate::luid::Luid;

/// A type-safe wrapper around the Windows `GUID` structure.
#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct Guid(pub GUID);

impl Default for Guid {
    fn default() -> Self {
        Self::ZERO
    }
}

impl Guid {
    /// The zero / null GUID (`{00000000-0000-0000-0000-000000000000}`).
    pub const ZERO: Self = Self(GUID {
        data1: 0,
        data2: 0,
        data3: 0,
        data4: [0; 8],
    });

    /// Creates a new `Guid` from individual components.
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self(GUID {
            data1,
            data2,
            data3,
            data4,
        })
    }

    /// Converts the GUID to a 16-byte array in Windows little-endian format.
    pub fn to_bytes_le(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&self.0.data1.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.0.data2.to_le_bytes());
        bytes[6..8].copy_from_slice(&self.0.data3.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.0.data4);
        bytes
    }

    /// Creates a GUID from a 16-byte array in Windows little-endian format.
    pub fn from_bytes_le(bytes: [u8; 16]) -> Self {
        let data1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let data2 = u16::from_le_bytes([bytes[4], bytes[5]]);
        let data3 = u16::from_le_bytes([bytes[6], bytes[7]]);
        let mut data4 = [0u8; 8];
        data4.copy_from_slice(&bytes[8..16]);
        Self(GUID {
            data1,
            data2,
            data3,
            data4,
        })
    }

    /// Converts the GUID to an RFC 4122 big-endian 16-byte array.
    pub fn to_bytes_be(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&self.0.data1.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.0.data2.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.0.data3.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.0.data4);
        bytes
    }

    /// Creates a GUID from an RFC 4122 big-endian 16-byte array.
    pub fn from_bytes_be(bytes: [u8; 16]) -> Self {
        let data1 = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let data2 = u16::from_be_bytes([bytes[4], bytes[5]]);
        let data3 = u16::from_be_bytes([bytes[6], bytes[7]]);
        let mut data4 = [0u8; 8];
        data4.copy_from_slice(&bytes[8..16]);
        Self(GUID {
            data1,
            data2,
            data3,
            data4,
        })
    }

    /// Converts the GUID to a network interface LUID using Win32 `ConvertInterfaceGuidToLuid`.
    pub fn to_luid(&self) -> Result<Luid> {
        Luid::from_guid(self)
    }

    /// Formats the GUID into a stack buffer with or without enclosing curly braces.
    #[inline]
    fn format_to_stack<'a>(&self, braced: bool, buf: &'a mut [u8; 38]) -> &'a str {
        const HEX: &[u8; 16] = b"0123456789abcdef";

        #[inline]
        fn write_byte(dst: &mut [u8], pos: &mut usize, b: u8) {
            dst[*pos] = HEX[(b >> 4) as usize];
            dst[*pos + 1] = HEX[(b & 0x0f) as usize];
            *pos += 2;
        }

        let mut pos = 0usize;
        if braced {
            buf[pos] = b'{';
            pos += 1;
        }

        for b in self.0.data1.to_be_bytes() {
            write_byte(buf, &mut pos, b);
        }
        buf[pos] = b'-';
        pos += 1;

        for b in self.0.data2.to_be_bytes() {
            write_byte(buf, &mut pos, b);
        }
        buf[pos] = b'-';
        pos += 1;

        for b in self.0.data3.to_be_bytes() {
            write_byte(buf, &mut pos, b);
        }
        buf[pos] = b'-';
        pos += 1;

        write_byte(buf, &mut pos, self.0.data4[0]);
        write_byte(buf, &mut pos, self.0.data4[1]);
        buf[pos] = b'-';
        pos += 1;

        for &b in &self.0.data4[2..8] {
            write_byte(buf, &mut pos, b);
        }

        if braced {
            buf[pos] = b'}';
            pos += 1;
        }

        // Safety: `buf[..pos]` contains only ASCII hex digits, hyphens, and optional braces.
        unsafe { std::str::from_utf8_unchecked(&buf[..pos]) }
    }

    /// Formats the GUID with standard enclosing curly braces:
    /// `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`
    pub fn to_string_with_braces(&self) -> String {
        let mut buf = [0u8; 38];
        self.format_to_stack(true, &mut buf).to_owned()
    }

    /// Formats the GUID without curly braces:
    /// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
    pub fn to_string_without_braces(&self) -> String {
        let mut buf = [0u8; 38];
        self.format_to_stack(false, &mut buf).to_owned()
    }
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
fn parse_hex_byte(bytes: &[u8]) -> Option<u8> {
    Some((hex_nibble(bytes[0])? << 4) | hex_nibble(bytes[1])?)
}

fn parse_guid_bytes(cleaned: &[u8]) -> Option<GUID> {
    if cleaned.len() == 36
        && cleaned[8] == b'-'
        && cleaned[13] == b'-'
        && cleaned[18] == b'-'
        && cleaned[23] == b'-'
    {
        let data1 = u32::from_be_bytes([
            parse_hex_byte(&cleaned[0..2])?,
            parse_hex_byte(&cleaned[2..4])?,
            parse_hex_byte(&cleaned[4..6])?,
            parse_hex_byte(&cleaned[6..8])?,
        ]);
        let data2 = u16::from_be_bytes([
            parse_hex_byte(&cleaned[9..11])?,
            parse_hex_byte(&cleaned[11..13])?,
        ]);
        let data3 = u16::from_be_bytes([
            parse_hex_byte(&cleaned[14..16])?,
            parse_hex_byte(&cleaned[16..18])?,
        ]);
        let data4 = [
            parse_hex_byte(&cleaned[19..21])?,
            parse_hex_byte(&cleaned[21..23])?,
            parse_hex_byte(&cleaned[24..26])?,
            parse_hex_byte(&cleaned[26..28])?,
            parse_hex_byte(&cleaned[28..30])?,
            parse_hex_byte(&cleaned[30..32])?,
            parse_hex_byte(&cleaned[32..34])?,
            parse_hex_byte(&cleaned[34..36])?,
        ];
        Some(GUID {
            data1,
            data2,
            data3,
            data4,
        })
    } else if cleaned.len() == 32 {
        let data1 = u32::from_be_bytes([
            parse_hex_byte(&cleaned[0..2])?,
            parse_hex_byte(&cleaned[2..4])?,
            parse_hex_byte(&cleaned[4..6])?,
            parse_hex_byte(&cleaned[6..8])?,
        ]);
        let data2 = u16::from_be_bytes([
            parse_hex_byte(&cleaned[8..10])?,
            parse_hex_byte(&cleaned[10..12])?,
        ]);
        let data3 = u16::from_be_bytes([
            parse_hex_byte(&cleaned[12..14])?,
            parse_hex_byte(&cleaned[14..16])?,
        ]);
        let data4 = [
            parse_hex_byte(&cleaned[16..18])?,
            parse_hex_byte(&cleaned[18..20])?,
            parse_hex_byte(&cleaned[20..22])?,
            parse_hex_byte(&cleaned[22..24])?,
            parse_hex_byte(&cleaned[24..26])?,
            parse_hex_byte(&cleaned[26..28])?,
            parse_hex_byte(&cleaned[28..30])?,
            parse_hex_byte(&cleaned[30..32])?,
        ];
        Some(GUID {
            data1,
            data2,
            data3,
            data4,
        })
    } else {
        None
    }
}

impl FromStr for Guid {
    type Err = IpCfgError;

    /// Parses a GUID string in any of the following standard representations:
    /// - `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`
    /// - `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
    /// - `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` (32 hex chars)
    fn from_str(s: &str) -> Result<Self> {
        let trimmed = s.trim().as_bytes();
        let cleaned = match trimmed {
            [b'{', inner @ .., b'}'] | [b'(', inner @ .., b')'] => inner,
            _ => trimmed,
        };

        parse_guid_bytes(cleaned)
            .map(Self)
            .ok_or_else(|| IpCfgError::InvalidGuid(s.to_string()))
    }
}

impl PartialEq for Guid {
    fn eq(&self, other: &Self) -> bool {
        self.0.data1 == other.0.data1
            && self.0.data2 == other.0.data2
            && self.0.data3 == other.0.data3
            && self.0.data4 == other.0.data4
    }
}

impl Eq for Guid {}

impl PartialOrd for Guid {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Guid {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_bytes_le().cmp(&other.to_bytes_le())
    }
}

impl std::hash::Hash for Guid {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.data1.hash(state);
        self.0.data2.hash(state);
        self.0.data3.hash(state);
        self.0.data4.hash(state);
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0u8; 38];
        f.write_str(self.format_to_stack(true, &mut buf))
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0u8; 38];
        f.write_str("Guid(")?;
        f.write_str(self.format_to_stack(true, &mut buf))?;
        f.write_str(")")
    }
}

impl From<GUID> for Guid {
    fn from(guid: GUID) -> Self {
        Self(guid)
    }
}

impl From<Guid> for GUID {
    fn from(guid: Guid) -> Self {
        guid.0
    }
}

impl AsRef<GUID> for Guid {
    fn as_ref(&self) -> &GUID {
        &self.0
    }
}

impl AsMut<GUID> for Guid {
    fn as_mut(&mut self) -> &mut GUID {
        &mut self.0
    }
}
