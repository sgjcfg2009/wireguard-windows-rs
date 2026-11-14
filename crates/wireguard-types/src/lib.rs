use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use serde::{Deserialize, Serialize};

pub const KEY_LEN: usize = 32;

/// Secure random bytes generation using Windows CSPRNG (`RtlGenRandom` / `SystemFunction036`),
/// with a fallback to `/dev/urandom` on Unix for cross-platform support.
#[cfg(windows)]
fn fill_random_bytes(dest: &mut [u8]) -> Result<(), std::io::Error> {
    #[link(name = "advapi32")]
    extern "system" {
        #[link_name = "SystemFunction036"]
        fn RtlGenRandom(buffer: *mut u8, length: u32) -> u8;
    }
    let ret = unsafe { RtlGenRandom(dest.as_mut_ptr(), dest.len() as u32) };
    if ret != 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(windows))]
fn fill_random_bytes(dest: &mut [u8]) -> Result<(), std::io::Error> {
    use std::fs::File;
    use std::io::Read;
    let mut file = File::open("/dev/urandom")?;
    file.read_exact(dest)?;
    Ok(())
}

/// A 32-byte WireGuard Curve25519 key (private, public, or preshared).
///
/// Implements automatic memory zeroization on drop to securely wipe sensitive
/// key material from memory.
#[derive(Clone, Default)]
pub struct Key(pub [u8; KEY_LEN]);

/// Sensitive key alias.
pub type SensitiveKey = Key;

impl Key {
    /// Creates a new key wrapping the provided 32 bytes.
    pub const fn new(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Creates an all-zero key.
    pub const fn zero() -> Self {
        Self([0u8; KEY_LEN])
    }

    /// Creates a new key from a byte array.
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Attempts to create a key from a slice of bytes (must be exactly 32 bytes).
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, KeyParseError> {
        if slice.len() != KEY_LEN {
            return Err(KeyParseError::InvalidLength(slice.len()));
        }
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(slice);
        Ok(Self(key))
    }

    /// Returns a reference to the underlying 32-byte array.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Returns a slice over the key bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the key and returns the raw 32-byte array.
    pub fn into_bytes(self) -> [u8; KEY_LEN] {
        self.0
    }

    /// Generates a new 32-byte cryptographically secure random preshared key.
    pub fn generate_preshared() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        fill_random_bytes(&mut bytes).expect("CSPRNG failed to generate random bytes");
        Self(bytes)
    }

    /// Generates a new 32-byte Curve25519 private key, clamped according to RFC 7748.
    pub fn generate_private() -> Self {
        let mut key = Self::generate_preshared();
        key.clamp_curve25519();
        key
    }

    /// Go-compatible alias for preshared key generation.
    pub fn new_preshared_key() -> Self {
        Self::generate_preshared()
    }

    /// Go-compatible alias for private key generation.
    pub fn new_private_key() -> Self {
        Self::generate_private()
    }

    /// Clamps the key for Curve25519 scalar multiplication (RFC 7748):
    /// key[0] &= 248; key[31] = (key[31] & 127) | 64;
    pub fn clamp_curve25519(&mut self) {
        self.0[0] &= 248;
        self.0[31] = (self.0[31] & 127) | 64;
    }

    /// Derives the Curve25519 public key corresponding to this private key.
    pub fn public_key(&self) -> Self {
        let mut clamped = Key(self.0);
        clamped.clamp_curve25519();
        let pub_bytes = x25519_dalek::x25519(clamped.0, x25519_dalek::X25519_BASEPOINT_BYTES);
        Self(pub_bytes)
    }

    /// Go-compatible alias for `public_key()`.
    pub fn public(&self) -> Self {
        self.public_key()
    }

    /// Encodes the key as standard Base64 into a 44-byte stack buffer, returning a `&str`.
    #[inline]
    pub fn encode_base64<'a>(&self, buf: &'a mut [u8; 44]) -> &'a str {
        use base64::Engine;
        let len = base64::engine::general_purpose::STANDARD
            .encode_slice(self.0, buf)
            .expect("44-byte buffer always fits 32-byte base64 key");
        // SAFETY: base64 output is strictly ASCII
        unsafe { core::str::from_utf8_unchecked(&buf[..len]) }
    }

    /// Formats the key as standard Base64 string.
    pub fn to_base64(&self) -> String {
        let mut buf = [0u8; 44];
        self.encode_base64(&mut buf).to_owned()
    }

    /// Parses a key from standard Base64 string without allocating on valid keys.
    pub fn from_base64(s: &str) -> Result<Self, KeyParseError> {
        use base64::Engine;
        let s = s.trim();
        if s.len() <= 64 {
            let mut decoded = [0u8; 48];
            let res = base64::engine::general_purpose::STANDARD
                .decode_slice(s.as_bytes(), &mut decoded)
                .map_err(|e| match e {
                    base64::DecodeSliceError::DecodeError(de) => {
                        KeyParseError::InvalidBase64(de.to_string())
                    }
                    base64::DecodeSliceError::OutputSliceTooSmall => {
                        KeyParseError::InvalidLength(49)
                    }
                })
                .and_then(|n| {
                    if n != KEY_LEN {
                        return Err(KeyParseError::InvalidLength(n));
                    }
                    let mut key = [0u8; KEY_LEN];
                    key.copy_from_slice(&decoded[..KEY_LEN]);
                    Ok(Self(key))
                });
            zeroize_bytes(&mut decoded);
            return res;
        }

        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|e| KeyParseError::InvalidBase64(e.to_string()))?;
        let len = bytes.len();
        zeroize_bytes(&mut bytes);
        Err(KeyParseError::InvalidLength(len))
    }

    /// Formats the key as lowercase hexadecimal string without intermediate formatting calls.
    pub fn to_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = [0u8; KEY_LEN * 2];
        for (i, &b) in self.0.iter().enumerate() {
            out[i * 2] = HEX[(b >> 4) as usize];
            out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
        }
        // SAFETY: `HEX` contains strictly ASCII digits/letters
        unsafe { String::from_utf8_unchecked(out.to_vec()) }
    }

    /// Parses a key from hexadecimal string (must be 64 hex characters).
    pub fn from_hex(s: &str) -> Result<Self, KeyParseError> {
        let s = s.trim();
        let bytes = s.as_bytes();
        if bytes.len() != KEY_LEN * 2 {
            return Err(KeyParseError::InvalidHex(format!(
                "expected {} hex characters, got {}",
                KEY_LEN * 2,
                bytes.len()
            )));
        }
        let mut key = [0u8; KEY_LEN];
        for (i, pair) in bytes.chunks_exact(2).enumerate() {
            let Some(hi) = hex_nibble(pair[0]) else {
                zeroize_bytes(&mut key);
                return Err(KeyParseError::InvalidHex(format!(
                    "invalid hex byte at index {}",
                    i * 2
                )));
            };
            let Some(lo) = hex_nibble(pair[1]) else {
                zeroize_bytes(&mut key);
                return Err(KeyParseError::InvalidHex(format!(
                    "invalid hex byte at index {}",
                    i * 2 + 1
                )));
            };
            key[i] = (hi << 4) | lo;
        }
        Ok(Self(key))
    }

    /// Constant-time check if the key is all zeros.
    pub fn is_zero(&self) -> bool {
        use subtle::ConstantTimeEq;
        [0u8; KEY_LEN].ct_eq(&self.0).into()
    }

    /// Wipes the key bytes in place using volatile writes and memory fences.
    pub fn zeroize(&mut self) {
        zeroize_bytes(&mut self.0);
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
fn zeroize_bytes(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        unsafe {
            core::ptr::write_volatile(b, 0);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

impl Drop for Key {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl subtle::ConstantTimeEq for Key {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.ct_eq(other).into()
    }
}

impl Eq for Key {}

impl std::hash::Hash for Key {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl PartialOrd for Key {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Key {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl AsRef<[u8; KEY_LEN]> for Key {
    fn as_ref(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::Deref for Key {
    type Target = [u8; KEY_LEN];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<[u8; KEY_LEN]> for Key {
    fn from(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }
}

impl TryFrom<&[u8]> for Key {
    type Error = KeyParseError;
    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from_slice(slice)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyParseError {
    #[error("invalid base64 encoding: {0}")]
    InvalidBase64(String),
    #[error("invalid hex encoding: {0}")]
    InvalidHex(String),
    #[error("invalid key length: expected 32 bytes, got {0}")]
    InvalidLength(usize),
}

impl FromStr for Key {
    type Err = KeyParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_base64(s)
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0u8; 44];
        write!(f, "Key({})", self.encode_base64(&mut buf))
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0u8; 44];
        f.write_str(self.encode_base64(&mut buf))
    }
}

impl Serialize for Key {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut buf = [0u8; 44];
        serializer.serialize_str(self.encode_base64(&mut buf))
    }
}

impl<'de> Deserialize<'de> for Key {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct KeyVisitor;

        impl<'de> serde::de::Visitor<'de> for KeyVisitor {
            type Value = Key;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a base64-encoded 32-byte WireGuard key")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Key::from_base64(v).map_err(E::custom)
            }

            fn visit_string<E>(self, mut v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let res = Key::from_base64(&v).map_err(E::custom);
                // SAFETY: overwriting with ASCII NUL bytes preserves valid UTF-8.
                unsafe { zeroize_bytes(v.as_bytes_mut()) };
                res
            }
        }

        deserializer.deserialize_str(KeyVisitor)
    }
}

/// An endpoint address (host/IP and UDP port).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    /// Creates a new endpoint with the specified host and UDP port.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    /// Returns `true` if the endpoint host is empty.
    pub fn is_empty(&self) -> bool {
        self.host.is_empty()
    }

    /// Resolves the endpoint to standard socket addresses using DNS / OS resolver.
    pub fn resolve(&self) -> std::io::Result<Vec<std::net::SocketAddr>> {
        use std::net::ToSocketAddrs;
        if self.is_empty() {
            return Ok(Vec::new());
        }
        (self.host.as_str(), self.port).to_socket_addrs().map(|iter| iter.collect())
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') && !self.host.starts_with('[') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EndpointParseError {
    #[error("missing port in endpoint: {0}")]
    MissingPort(String),
    #[error("invalid port in endpoint: {0}")]
    InvalidPort(String),
    #[error("invalid host in endpoint: {0}")]
    InvalidHost(String),
    #[error("brackets must contain an IPv6 address: {0}")]
    InvalidIpv6Bracket(String),
}

impl FromStr for Endpoint {
    type Err = EndpointParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let (host_str, port_str) = match s.rfind(':') {
            Some(idx) => (&s[..idx], &s[idx + 1..]),
            None => return Err(EndpointParseError::MissingPort(s.to_string())),
        };
        if host_str.is_empty() {
            return Err(EndpointParseError::InvalidHost(host_str.to_string()));
        }
        let port: u16 = port_str
            .parse()
            .map_err(|_| EndpointParseError::InvalidPort(port_str.to_string()))?;

        let host = if host_str.starts_with('[') && host_str.ends_with(']') {
            let inner = &host_str[1..host_str.len() - 1];
            let check_ip = if let Some(pct) = inner.rfind('%') {
                &inner[..pct]
            } else {
                inner
            };
            if let Ok(ip) = check_ip.parse::<IpAddr>() {
                if !ip.is_ipv6() {
                    return Err(EndpointParseError::InvalidIpv6Bracket(host_str.to_string()));
                }
            } else {
                return Err(EndpointParseError::InvalidIpv6Bracket(host_str.to_string()));
            }
            inner.to_string()
        } else if host_str.contains(':') {
            return Err(EndpointParseError::InvalidIpv6Bracket(host_str.to_string()));
        } else {
            host_str.to_string()
        };

        Ok(Self { host, port })
    }
}

/// An IP network prefix / CIDR (e.g. 10.0.0.1/32, 192.168.1.0/24, 2001:db8::/32).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AllowedIp {
    pub addr: IpAddr,
    pub cidr: u8,
}

impl AllowedIp {
    /// Creates a new AllowedIp network prefix.
    pub const fn new(addr: IpAddr, cidr: u8) -> Self {
        Self { addr, cidr }
    }

    /// Returns the maximum CIDR prefix length for this address family (32 for IPv4, 128 for IPv6).
    pub const fn max_cidr(&self) -> u8 {
        if self.addr.is_ipv4() {
            32
        } else {
            128
        }
    }

    /// Returns `true` if the CIDR prefix length is valid for its address family.
    pub const fn is_valid(&self) -> bool {
        self.cidr <= self.max_cidr()
    }

    /// Returns the network prefix with host bits zeroed out according to the CIDR mask.
    pub fn masked(&self) -> Self {
        match self.addr {
            IpAddr::V4(ipv4) => {
                let ip_u32 = u32::from(ipv4);
                let mask = if self.cidr == 0 {
                    0
                } else if self.cidr >= 32 {
                    !0u32
                } else {
                    !0u32 << (32 - self.cidr)
                };
                let masked_ip = std::net::Ipv4Addr::from(ip_u32 & mask);
                Self {
                    addr: IpAddr::V4(masked_ip),
                    cidr: self.cidr,
                }
            }
            IpAddr::V6(ipv6) => {
                let ip_u128 = u128::from(ipv6);
                let mask = if self.cidr == 0 {
                    0
                } else if self.cidr >= 128 {
                    !0u128
                } else {
                    !0u128 << (128 - self.cidr)
                };
                let masked_ip = std::net::Ipv6Addr::from(ip_u128 & mask);
                Self {
                    addr: IpAddr::V6(masked_ip),
                    cidr: self.cidr,
                }
            }
        }
    }

    /// Checks if a given IP address matches this subnet prefix.
    pub fn contains_addr(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(target)) => {
                let net_u32 = u32::from(net);
                let target_u32 = u32::from(target);
                let mask = if self.cidr == 0 {
                    0
                } else if self.cidr >= 32 {
                    !0u32
                } else {
                    !0u32 << (32 - self.cidr)
                };
                (net_u32 & mask) == (target_u32 & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(target)) => {
                let net_u128 = u128::from(net);
                let target_u128 = u128::from(target);
                let mask = if self.cidr == 0 {
                    0
                } else if self.cidr >= 128 {
                    !0u128
                } else {
                    !0u128 << (128 - self.cidr)
                };
                (net_u128 & mask) == (target_u128 & mask)
            }
            _ => false,
        }
    }
}

impl fmt::Display for AllowedIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.cidr)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AllowedIpParseError {
    #[error("invalid IP address: {0}")]
    InvalidIp(String),
    #[error("invalid CIDR prefix: {0}")]
    InvalidCidr(String),
    #[error("CIDR prefix {prefix} exceeds max {max} for {addr}")]
    CidrOverflow { prefix: u8, max: u8, addr: String },
}

impl FromStr for AllowedIp {
    type Err = AllowedIpParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if let Some((addr_str, cidr_str)) = s.split_once('/') {
            let addr: IpAddr = addr_str
                .parse()
                .map_err(|_| AllowedIpParseError::InvalidIp(addr_str.to_string()))?;
            let cidr: u8 = cidr_str
                .parse()
                .map_err(|_| AllowedIpParseError::InvalidCidr(cidr_str.to_string()))?;
            let max = if addr.is_ipv4() { 32 } else { 128 };
            if cidr > max {
                return Err(AllowedIpParseError::CidrOverflow {
                    prefix: cidr,
                    max,
                    addr: addr_str.to_string(),
                });
            }
            Ok(Self { addr, cidr })
        } else {
            let addr: IpAddr = s
                .parse()
                .map_err(|_| AllowedIpParseError::InvalidIp(s.to_string()))?;
            let cidr = if addr.is_ipv4() { 32 } else { 128 };
            Ok(Self { addr, cidr })
        }
    }
}

/// Interface configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<Key>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<AllowedIp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", alias = "dns_servers")]
    pub dns: Vec<IpAddr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_search: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_up: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_up: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_down: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_down: Option<String>,
    #[serde(default)]
    pub table_off: bool,
}

impl InterfaceConfig {
    /// Returns a slice of DNS servers.
    pub fn dns_servers(&self) -> &[IpAddr] {
        &self.dns
    }
}

/// Peer configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerConfig {
    pub public_key: Key,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<Key>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_ips: Vec<AllowedIp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<Endpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive: Option<u16>,
    #[serde(default)]
    pub rx_bytes: u64,
    #[serde(default)]
    pub tx_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_handshake_time: Option<Duration>,
}

impl PeerConfig {
    /// Creates a new peer with the given public key.
    pub fn new(public_key: Key) -> Self {
        Self {
            public_key,
            preshared_key: None,
            allowed_ips: Vec::new(),
            endpoint: None,
            persistent_keepalive: None,
            rx_bytes: 0,
            tx_bytes: 0,
            last_handshake_time: None,
        }
    }
}

/// Full configuration for a WireGuard tunnel.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelConfig {
    pub name: String,
    pub interface: InterfaceConfig,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
}

/// Alias for `TunnelConfig`.
pub type Config = TunnelConfig;

impl TunnelConfig {
    /// Creates a new configuration with the given tunnel name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            interface: InterfaceConfig::default(),
            peers: Vec::new(),
        }
    }

    /// Redacts secret keys from the configuration (for non-elevated callers).
    pub fn redact(&mut self) {
        self.interface.private_key = None;
        self.interface.pre_up = None;
        self.interface.post_up = None;
        self.interface.pre_down = None;
        self.interface.post_down = None;
        for (i, peer) in self.peers.iter_mut().enumerate() {
            let mut redacted_pub = [0u8; KEY_LEN];
            redacted_pub[..8].copy_from_slice(&(i as u64).to_le_bytes());
            peer.public_key = Key(redacted_pub);
            peer.preshared_key = None;
        }
    }

    /// Deduplicates network address entries and DNS servers.
    pub fn deduplicate_network_entries(&mut self) {
        let mut seen_addr = std::collections::HashSet::new();
        self.interface.addresses.retain(|a| seen_addr.insert(*a));

        let mut seen_dns = std::collections::HashSet::new();
        self.interface.dns.retain(|d| seen_dns.insert(*d));

        for peer in &mut self.peers {
            let mut seen_peer_addr = std::collections::HashSet::new();
            peer.allowed_ips.retain(|a| seen_peer_addr.insert(*a));
        }
    }

    /// Checks if routes or addresses intersect with another configuration.
    pub fn intersects_with(&self, other: &TunnelConfig) -> bool {
        let mut cap = self.interface.addresses.len() * 2;
        for peer in &self.peers {
            cap += peer.allowed_ips.len();
        }
        let mut all_routes = std::collections::HashSet::with_capacity(cap);
        for a in &self.interface.addresses {
            all_routes.insert(*a);
            all_routes.insert(a.masked());
        }
        for peer in &self.peers {
            for a in &peer.allowed_ips {
                all_routes.insert(a.masked());
            }
        }
        for a in &other.interface.addresses {
            if all_routes.contains(a) || all_routes.contains(&a.masked()) {
                return true;
            }
        }
        for peer in &other.peers {
            for a in &peer.allowed_ips {
                if all_routes.contains(&a.masked()) {
                    return true;
                }
            }
        }
        false
    }
}

/// Operational state of a tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[repr(i32)]
pub enum TunnelState {
    #[default]
    Unknown = 0,
    Started = 1,
    Stopped = 2,
    Starting = 3,
    Stopping = 4,
}

impl fmt::Display for TunnelState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(f, "Unknown"),
            Self::Started => write!(f, "Started"),
            Self::Stopped => write!(f, "Stopped"),
            Self::Starting => write!(f, "Starting"),
            Self::Stopping => write!(f, "Stopping"),
        }
    }
}

/// Software update availability state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[repr(u32)]
pub enum UpdateState {
    #[default]
    Unknown = 0,
    FoundUpdate = 1,
    UpdatesDisabledUnofficialBuild = 2,
}

/// Download progress for updater.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DownloadProgress {
    pub activity: String,
    pub bytes_downloaded: u64,
    pub bytes_total: u64,
    pub error: Option<String>,
    pub complete: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_key_base64_and_hex() {
        let priv_key = Key::generate_private();
        assert!(!priv_key.is_zero());
        assert_eq!(priv_key.0[0] & 248, priv_key.0[0]);
        assert_eq!(priv_key.0[31] & 127 | 64, priv_key.0[31]);

        let b64 = priv_key.to_base64();
        let parsed_b64 = Key::from_base64(&b64).expect("valid base64");
        assert_eq!(priv_key, parsed_b64);

        let hex = priv_key.to_hex();
        let parsed_hex = Key::from_hex(&hex).expect("valid hex");
        assert_eq!(priv_key, parsed_hex);
    }

    #[test]
    fn test_public_key_derivation_rfc7748() {
        let alice_priv_hex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
        let alice_priv = Key::from_hex(alice_priv_hex).expect("valid hex");
        let alice_pub = alice_priv.public_key();
        assert_eq!(
            alice_pub.to_hex(),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
    }

    #[test]
    fn test_key_zeroize_on_drop() {
        let mut key = Key::generate_preshared();
        assert!(!key.is_zero());
        key.zeroize();
        assert!(key.is_zero());
    }

    #[test]
    fn test_preshared_key_generation() {
        let psk1 = Key::generate_preshared();
        let psk2 = Key::generate_preshared();
        assert_ne!(psk1, psk2);
        assert!(!psk1.is_zero());
        assert!(!psk2.is_zero());
    }

    #[test]
    fn test_allowed_ip_parsing_and_masking() {
        let a1: AllowedIp = "192.168.1.100/24".parse().expect("valid cidr");
        assert_eq!(a1.addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(a1.cidr, 24);
        assert_eq!(a1.to_string(), "192.168.1.100/24");

        let masked = a1.masked();
        assert_eq!(masked.addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)));
        assert_eq!(masked.cidr, 24);

        assert!(a1.contains_addr(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))));
        assert!(!a1.contains_addr(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))));

        // Plain IP defaults to /32
        let a2: AllowedIp = "10.0.0.1".parse().expect("plain ip");
        assert_eq!(a2.cidr, 32);

        // IPv6
        let v6: AllowedIp = "2001:db8::1/64".parse().expect("valid ipv6 cidr");
        assert_eq!(v6.cidr, 64);
        let masked_v6 = v6.masked();
        assert_eq!(
            masked_v6.addr,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0))
        );

        // Overflow
        assert!("10.0.0.1/33".parse::<AllowedIp>().is_err());
        assert!("::1/129".parse::<AllowedIp>().is_err());
    }

    #[test]
    fn test_endpoint_parsing_and_formatting() {
        let ep1: Endpoint = "192.168.1.1:51820".parse().expect("valid endpoint");
        assert_eq!(ep1.host, "192.168.1.1");
        assert_eq!(ep1.port, 51820);
        assert_eq!(ep1.to_string(), "192.168.1.1:51820");

        let ep2: Endpoint = "[2001:db8::1]:51820".parse().expect("valid ipv6 endpoint");
        assert_eq!(ep2.host, "2001:db8::1");
        assert_eq!(ep2.port, 51820);
        assert_eq!(ep2.to_string(), "[2001:db8::1]:51820");

        let ep3: Endpoint = "vpn.example.com:443".parse().expect("valid dns endpoint");
        assert_eq!(ep3.host, "vpn.example.com");
        assert_eq!(ep3.port, 443);
        assert_eq!(ep3.to_string(), "vpn.example.com:443");

        assert!("invalid_endpoint".parse::<Endpoint>().is_err());
        assert!("[1.2.3.4]:51820".parse::<Endpoint>().is_err());
    }

    #[test]
    fn test_serialization_json() {
        let mut config = Config::new("wg0");
        let priv_key = Key::generate_private();
        let pub_key = priv_key.public_key();

        config.interface.private_key = Some(priv_key);
        config.interface.listen_port = Some(51820);
        config.interface.addresses.push("10.0.0.1/24".parse().unwrap());
        config.interface.dns.push("1.1.1.1".parse().unwrap());

        let mut peer = PeerConfig::new(pub_key.clone());
        peer.endpoint = Some("198.51.100.1:51820".parse().unwrap());
        peer.allowed_ips.push("0.0.0.0/0".parse().unwrap());
        peer.persistent_keepalive = Some(25);
        config.peers.push(peer);

        let json = serde_json::to_string_pretty(&config).expect("serialize json");
        let deserialized: Config = serde_json::from_str(&json).expect("deserialize json");
        assert_eq!(config, deserialized);

        // Test redact
        let mut redacted = config.clone();
        redacted.redact();
        assert!(redacted.interface.private_key.is_none());
        assert_ne!(redacted.peers[0].public_key, pub_key);
    }

    #[test]
    fn test_deduplicate_network_entries() {
        let mut config = Config::new("wg0");
        config.interface.addresses.push("10.0.0.1/24".parse().unwrap());
        config.interface.addresses.push("10.0.0.1/24".parse().unwrap());
        config.interface.dns.push("1.1.1.1".parse().unwrap());
        config.interface.dns.push("1.1.1.1".parse().unwrap());

        let mut peer = PeerConfig::new(Key::generate_private().public_key());
        peer.allowed_ips.push("10.0.0.2/32".parse().unwrap());
        peer.allowed_ips.push("10.0.0.2/32".parse().unwrap());
        config.peers.push(peer);

        config.deduplicate_network_entries();
        assert_eq!(config.interface.addresses.len(), 1);
        assert_eq!(config.interface.dns.len(), 1);
        assert_eq!(config.peers[0].allowed_ips.len(), 1);
    }

    #[test]
    fn test_intersects_with() {
        let mut c1 = Config::new("wg0");
        c1.interface.addresses.push("10.0.0.1/24".parse().unwrap());

        let mut c2 = Config::new("wg1");
        c2.interface.addresses.push("10.0.0.5/24".parse().unwrap());

        let mut c3 = Config::new("wg2");
        c3.interface.addresses.push("192.168.1.1/24".parse().unwrap());

        assert!(c1.intersects_with(&c2));
        assert!(!c1.intersects_with(&c3));
    }

    #[test]
    fn test_invalid_keys() {
        assert!(Key::from_base64("too_short").is_err());
        assert!(Key::from_base64("!!!notbase64@@@").is_err());
        assert!(Key::from_hex("1234abcd").is_err());
        assert!(Key::from_hex("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());
        // 64-byte UTF-8 input with multi-byte character across odd/even pair boundary must not panic
        let non_ascii_64 = format!("a{}b", "é".repeat(31));
        assert_eq!(non_ascii_64.len(), 64);
        assert!(Key::from_hex(&non_ascii_64).is_err());
    }

    #[test]
    fn test_endpoint_resolve() {
        let ep = Endpoint::new("127.0.0.1", 51820);
        let addrs = ep.resolve().expect("resolve loopback");
        assert!(!addrs.is_empty());
        assert_eq!(addrs[0].port(), 51820);

        let empty = Endpoint::new("", 51820);
        assert!(empty.is_empty());
        assert!(empty.resolve().unwrap().is_empty());
    }
}
