use std::mem::{size_of, MaybeUninit};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::ptr;
use std::time::Duration;
use wireguard_types::{AllowedIp, Endpoint, InterfaceConfig, Key, PeerConfig};
use crate::error::{DriverError, Result};

pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 23;

pub mod interface_flags {
    pub const HAS_PUBLIC_KEY: u32 = 1 << 0;
    pub const HAS_PRIVATE_KEY: u32 = 1 << 1;
    pub const HAS_LISTEN_PORT: u32 = 1 << 2;
    pub const REPLACE_PEERS: u32 = 1 << 3;
}

pub mod peer_flags {
    pub const HAS_PUBLIC_KEY: u32 = 1 << 0;
    pub const HAS_PRESHARED_KEY: u32 = 1 << 1;
    pub const HAS_PERSISTENT_KEEPALIVE: u32 = 1 << 2;
    pub const HAS_ENDPOINT: u32 = 1 << 3;
    pub const REPLACE_ALLOWED_IPS: u32 = 1 << 5;
    pub const REMOVE: u32 = 1 << 6;
    pub const UPDATE_ONLY: u32 = 1 << 7;
}

pub mod allowed_ip_flags {
    pub const REMOVE: u32 = 1 << 0;
}

/// Windows SOCKADDR_INET binary representation (28 bytes).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RawSockaddrInet {
    pub family: u16,
    pub data: [u8; 26],
}

impl Default for RawSockaddrInet {
    fn default() -> Self {
        Self {
            family: 0,
            data: [0u8; 26],
        }
    }
}

impl RawSockaddrInet {
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        let mut raw = Self::default();
        match addr {
            SocketAddr::V4(v4) => {
                raw.family = AF_INET;
                let port_bytes = v4.port().to_be_bytes();
                raw.data[0..2].copy_from_slice(&port_bytes);
                raw.data[2..6].copy_from_slice(&v4.ip().octets());
            }
            SocketAddr::V6(v6) => {
                raw.family = AF_INET6;
                let port_bytes = v6.port().to_be_bytes();
                raw.data[0..2].copy_from_slice(&port_bytes);
                let flow_bytes = v6.flowinfo().to_be_bytes();
                raw.data[2..6].copy_from_slice(&flow_bytes);
                raw.data[6..22].copy_from_slice(&v6.ip().octets());
                let scope_bytes = v6.scope_id().to_le_bytes();
                raw.data[22..26].copy_from_slice(&scope_bytes);
            }
        }
        raw
    }

    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        match self.family {
            AF_INET => {
                let port = u16::from_be_bytes([self.data[0], self.data[1]]);
                let ip = Ipv4Addr::new(self.data[2], self.data[3], self.data[4], self.data[5]);
                Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
            }
            AF_INET6 => {
                let port = u16::from_be_bytes([self.data[0], self.data[1]]);
                let flowinfo = u32::from_be_bytes([self.data[2], self.data[3], self.data[4], self.data[5]]);
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&self.data[6..22]);
                let ip = Ipv6Addr::from(octets);
                let scope_id = u32::from_le_bytes([self.data[22], self.data[23], self.data[24], self.data[25]]);
                Some(SocketAddr::V6(SocketAddrV6::new(ip, port, flowinfo, scope_id)))
            }
            _ => None,
        }
    }
}

/// Interface structure matching WireGuardNT ABI (80 bytes).
///
/// C layout (`_WIREGUARD_INTERFACE` in `wireguard.h`):
/// - `Flags`: 0..4 (`u32`)
/// - `ListenPort`: 4..6 (`u16`)
/// - `PrivateKey`: 6..38 (`[u8; 32]`, align 1 — NO padding before `PrivateKey`!)
/// - `PublicKey`: 38..70 (`[u8; 32]`, align 1)
/// - `_pad`: 70..72 (`[u8; 2]` alignment padding before `PeersCount`)
/// - `PeersCount`: 72..76 (`u32`)
/// - `_pad2`: 76..80 (`[u8; 4]` tail padding for `align(8)`)
#[repr(C, align(8))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WgIoctlInterface {
    pub flags: u32,
    pub listen_port: u16,
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
    pub _pad: [u8; 2],
    pub peers_count: u32,
    pub _pad2: [u8; 4],
}

/// Peer structure matching WireGuardNT ABI (136 bytes).
#[repr(C, align(8))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WgIoctlPeer {
    pub flags: u32,
    pub _reserved: u32,
    pub public_key: [u8; 32],
    pub preshared_key: [u8; 32],
    pub persistent_keepalive: u16,
    pub _pad: u16,
    pub endpoint: RawSockaddrInet,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub last_handshake: u64,
    pub allowed_ips_count: u32,
    pub _pad2: [u8; 4],
}

/// Allowed IP structure matching WireGuardNT ABI (24 bytes).
#[repr(C, align(4))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WgIoctlAllowedIp {
    pub address: [u8; 16],
    pub address_family: u16,
    pub cidr: u8,
    pub _pad: u8,
    pub flags: u32,
}

/// Log line entry structure for WG_IOCTL_READ_LOG_LINE (520 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WgIoctlLogEntry {
    pub timestamp: u64,
    pub msg: [u8; 512],
}

// Compile-time assertions verifying exact C ABI byte layouts, offsets, and sizes.
const _: () = {
    assert!(size_of::<RawSockaddrInet>() == 28);
    assert!(size_of::<WgIoctlInterface>() == 80);
    assert!(std::mem::offset_of!(WgIoctlInterface, flags) == 0);
    assert!(std::mem::offset_of!(WgIoctlInterface, listen_port) == 4);
    assert!(std::mem::offset_of!(WgIoctlInterface, private_key) == 6);
    assert!(std::mem::offset_of!(WgIoctlInterface, public_key) == 38);
    assert!(std::mem::offset_of!(WgIoctlInterface, peers_count) == 72);
    assert!(size_of::<WgIoctlPeer>() == 136);
    assert!(std::mem::offset_of!(WgIoctlPeer, public_key) == 8);
    assert!(std::mem::offset_of!(WgIoctlPeer, preshared_key) == 40);
    assert!(std::mem::offset_of!(WgIoctlPeer, persistent_keepalive) == 72);
    assert!(std::mem::offset_of!(WgIoctlPeer, endpoint) == 76);
    assert!(std::mem::offset_of!(WgIoctlPeer, tx_bytes) == 104);
    assert!(std::mem::offset_of!(WgIoctlPeer, rx_bytes) == 112);
    assert!(std::mem::offset_of!(WgIoctlPeer, last_handshake) == 120);
    assert!(std::mem::offset_of!(WgIoctlPeer, allowed_ips_count) == 128);
    assert!(size_of::<WgIoctlAllowedIp>() == 24);
    assert!(size_of::<WgIoctlLogEntry>() == 520);
};

/// 8-byte aligned heap buffer for WireGuardNT ABI structures that zeroes its memory on drop.
pub(crate) struct AlignedZeroedBuffer {
    words: Vec<u64>,
    byte_len: usize,
}

impl AlignedZeroedBuffer {
    pub(crate) fn with_byte_capacity(byte_capacity: usize) -> Self {
        Self {
            words: Vec::with_capacity(byte_capacity.div_ceil(8)),
            byte_len: 0,
        }
    }

    pub(crate) fn with_zeroed_bytes(byte_len: usize) -> Self {
        Self {
            words: vec![0u64; byte_len.div_ceil(8)],
            byte_len,
        }
    }

    pub(crate) fn resize_bytes(&mut self, new_byte_len: usize) {
        self.words.resize(new_byte_len.div_ceil(8), 0);
        self.byte_len = new_byte_len;
    }

    #[inline]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.words.as_ptr() as *const u8, self.byte_len) }
    }

    #[inline]
    pub(crate) fn as_mut_ptr(&mut self) -> *mut u8 {
        self.words.as_mut_ptr() as *mut u8
    }

    #[inline]
    pub(crate) fn byte_len(&self) -> usize {
        self.byte_len
    }

    fn extend_from_slice(&mut self, bytes: &[u8]) {
        let new_byte_len = self.byte_len + bytes.len();
        let needed_words = new_byte_len.div_ceil(8);
        if self.words.len() < needed_words {
            self.words.resize(needed_words, 0);
        }
        unsafe {
            ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                (self.words.as_mut_ptr() as *mut u8).add(self.byte_len),
                bytes.len(),
            );
        }
        self.byte_len = new_byte_len;
    }
}

impl Drop for AlignedZeroedBuffer {
    fn drop(&mut self) {
        for word in &mut self.words {
            unsafe {
                ptr::write_volatile(word, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

trait AbiSink {
    fn append_bytes(&mut self, bytes: &[u8]);
}

impl AbiSink for Vec<u8> {
    #[inline]
    fn append_bytes(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

impl AbiSink for AlignedZeroedBuffer {
    #[inline]
    fn append_bytes(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

#[inline]
fn append_raw<T: Copy>(sink: &mut impl AbiSink, val: &T) {
    let bytes = unsafe {
        std::slice::from_raw_parts((val as *const T) as *const u8, size_of::<T>())
    };
    sink.append_bytes(bytes);
}

/// Helper to serialize high-level WireGuard configurations to contiguous ABI buffers.
pub struct ConfigBuilder {
    buffer: Vec<u8>,
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigBuilder {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
        }
    }

    fn exact_capacity(interface: &InterfaceConfig, peers: &[PeerConfig]) -> usize {
        let _ = interface;
        let total_allowed_ips: usize = peers.iter().map(|p| p.allowed_ips.len()).sum();
        size_of::<WgIoctlInterface>()
            + peers.len() * size_of::<WgIoctlPeer>()
            + total_allowed_ips * size_of::<WgIoctlAllowedIp>()
    }

    /// Serializes an interface configuration and slice of peers into a single pre-allocated WireGuardNT ABI buffer.
    pub fn build(interface: &InterfaceConfig, peers: &[PeerConfig]) -> Result<Vec<u8>> {
        let mut builder = Self::with_capacity(Self::exact_capacity(interface, peers));
        Self::write_into(interface, peers, &mut builder.buffer)?;
        Ok(builder.buffer)
    }

    /// Serializes configuration into an 8-byte aligned buffer that zeroes keys on drop.
    pub(crate) fn build_aligned(
        interface: &InterfaceConfig,
        peers: &[PeerConfig],
    ) -> Result<AlignedZeroedBuffer> {
        let mut buf = AlignedZeroedBuffer::with_byte_capacity(Self::exact_capacity(interface, peers));
        Self::write_into(interface, peers, &mut buf)?;
        Ok(buf)
    }

    fn write_into(
        interface: &InterfaceConfig,
        peers: &[PeerConfig],
        sink: &mut impl AbiSink,
    ) -> Result<()> {
        let mut iface = WgIoctlInterface {
            flags: 0,
            listen_port: 0,
            _pad: [0; 2],
            private_key: [0; 32],
            public_key: [0; 32],
            peers_count: peers.len() as u32,
            _pad2: [0; 4],
        };

        if let Some(port) = interface.listen_port {
            iface.listen_port = port;
            iface.flags |= interface_flags::HAS_LISTEN_PORT;
        }

        if let Some(ref priv_key) = interface.private_key {
            iface.private_key.copy_from_slice(priv_key.as_bytes());
            iface.flags |= interface_flags::HAS_PRIVATE_KEY;
        }

        iface.flags |= interface_flags::REPLACE_PEERS;

        append_raw(sink, &iface);

        for peer in peers {
            let mut ioctl_peer = WgIoctlPeer {
                flags: peer_flags::HAS_PUBLIC_KEY | peer_flags::REPLACE_ALLOWED_IPS,
                _reserved: 0,
                public_key: *peer.public_key.as_bytes(),
                preshared_key: [0; 32],
                persistent_keepalive: 0,
                _pad: 0,
                endpoint: RawSockaddrInet::default(),
                tx_bytes: peer.tx_bytes,
                rx_bytes: peer.rx_bytes,
                last_handshake: 0,
                allowed_ips_count: peer.allowed_ips.len() as u32,
                _pad2: [0; 4],
            };

            if let Some(ref psk) = peer.preshared_key {
                ioctl_peer.preshared_key.copy_from_slice(psk.as_bytes());
                ioctl_peer.flags |= peer_flags::HAS_PRESHARED_KEY;
            }

            if let Some(ka) = peer.persistent_keepalive {
                ioctl_peer.persistent_keepalive = ka;
                ioctl_peer.flags |= peer_flags::HAS_PERSISTENT_KEEPALIVE;
            }

            if let Some(ref ep) = peer.endpoint {
                if let Ok(ip) = ep.host.parse::<IpAddr>() {
                    let sock_addr = SocketAddr::new(ip, ep.port);
                    ioctl_peer.endpoint = RawSockaddrInet::from_socket_addr(sock_addr);
                    ioctl_peer.flags |= peer_flags::HAS_ENDPOINT;
                } else if let Ok(mut addrs) = (ep.host.as_str(), ep.port).to_socket_addrs() {
                    if let Some(first) = addrs.next() {
                        ioctl_peer.endpoint = RawSockaddrInet::from_socket_addr(first);
                        ioctl_peer.flags |= peer_flags::HAS_ENDPOINT;
                    }
                }
            }

            append_raw(sink, &ioctl_peer);
            unsafe {
                ptr::write_volatile(&mut ioctl_peer.preshared_key, [0u8; 32]);
            }

            for allowed_ip in &peer.allowed_ips {
                let mut ioctl_ip = WgIoctlAllowedIp {
                    address: [0; 16],
                    address_family: if allowed_ip.addr.is_ipv4() { AF_INET } else { AF_INET6 },
                    cidr: allowed_ip.cidr,
                    _pad: 0,
                    flags: 0,
                };

                match allowed_ip.addr {
                    IpAddr::V4(v4) => {
                        ioctl_ip.address[0..4].copy_from_slice(&v4.octets());
                    }
                    IpAddr::V6(v6) => {
                        ioctl_ip.address.copy_from_slice(&v6.octets());
                    }
                }

                append_raw(sink, &ioctl_ip);
            }
        }

        // Wipe local stack structs containing sensitive keys
        unsafe {
            ptr::write_volatile(&mut iface.private_key, [0u8; 32]);
        }
        Ok(())
    }
}

/// Helper to parse a contiguous WireGuardNT ABI buffer into high-level configurations.
pub struct ConfigParser;

impl ConfigParser {
    pub fn parse(buffer: &[u8]) -> Result<(InterfaceConfig, Vec<PeerConfig>)> {
        if buffer.len() < size_of::<WgIoctlInterface>() {
            return Err(DriverError::InvalidConfig(format!(
                "buffer length {} is smaller than WgIoctlInterface {}",
                buffer.len(),
                size_of::<WgIoctlInterface>()
            )));
        }

        let mut offset = 0;
        let mut iface_raw = MaybeUninit::<WgIoctlInterface>::uninit();
        unsafe {
            ptr::copy_nonoverlapping(
                buffer.as_ptr().add(offset),
                iface_raw.as_mut_ptr() as *mut u8,
                size_of::<WgIoctlInterface>(),
            );
        }
        let iface_raw = unsafe { iface_raw.assume_init() };
        offset += size_of::<WgIoctlInterface>();

        let mut iface = InterfaceConfig::default();
        if (iface_raw.flags & interface_flags::HAS_LISTEN_PORT) != 0 {
            iface.listen_port = Some(iface_raw.listen_port);
        }
        if (iface_raw.flags & interface_flags::HAS_PRIVATE_KEY) != 0 {
            iface.private_key = Some(Key::new(iface_raw.private_key));
        }

        let max_peers = (buffer.len() - offset) / size_of::<WgIoctlPeer>();
        let mut peers = Vec::with_capacity((iface_raw.peers_count as usize).min(max_peers));

        for _ in 0..iface_raw.peers_count {
            if offset + size_of::<WgIoctlPeer>() > buffer.len() {
                return Err(DriverError::InvalidConfig(
                    "unexpected buffer truncation while reading peer".into(),
                ));
            }

            let mut peer_raw = MaybeUninit::<WgIoctlPeer>::uninit();
            unsafe {
                ptr::copy_nonoverlapping(
                    buffer.as_ptr().add(offset),
                    peer_raw.as_mut_ptr() as *mut u8,
                    size_of::<WgIoctlPeer>(),
                );
            }
            let peer_raw = unsafe { peer_raw.assume_init() };
            offset += size_of::<WgIoctlPeer>();

            let pub_key = Key::new(peer_raw.public_key);
            let mut peer = PeerConfig::new(pub_key);

            if (peer_raw.flags & peer_flags::HAS_PRESHARED_KEY) != 0 {
                peer.preshared_key = Some(Key::new(peer_raw.preshared_key));
            }
            if (peer_raw.flags & peer_flags::HAS_PERSISTENT_KEEPALIVE) != 0 {
                peer.persistent_keepalive = Some(peer_raw.persistent_keepalive);
            }
            if (peer_raw.flags & peer_flags::HAS_ENDPOINT) != 0 {
                if let Some(sock_addr) = peer_raw.endpoint.to_socket_addr() {
                    peer.endpoint = Some(Endpoint::new(sock_addr.ip().to_string(), sock_addr.port()));
                }
            }

            peer.tx_bytes = peer_raw.tx_bytes;
            peer.rx_bytes = peer_raw.rx_bytes;

            // Windows FILETIME to Duration conversion (100-nanosecond intervals since Jan 1 1601)
            const FILETIME_TO_UNIX_OFFSET: u64 = 116444736000000000;
            if peer_raw.last_handshake > FILETIME_TO_UNIX_OFFSET {
                let nanos = (peer_raw.last_handshake - FILETIME_TO_UNIX_OFFSET).saturating_mul(100);
                peer.last_handshake_time = Some(Duration::from_nanos(nanos));
            }

            let max_ips = (buffer.len() - offset) / size_of::<WgIoctlAllowedIp>();
            let mut allowed_ips =
                Vec::with_capacity((peer_raw.allowed_ips_count as usize).min(max_ips));
            for _ in 0..peer_raw.allowed_ips_count {
                if offset + size_of::<WgIoctlAllowedIp>() > buffer.len() {
                    return Err(DriverError::InvalidConfig(
                        "unexpected buffer truncation while reading allowed IP".into(),
                    ));
                }

                let mut ip_raw = MaybeUninit::<WgIoctlAllowedIp>::uninit();
                unsafe {
                    ptr::copy_nonoverlapping(
                        buffer.as_ptr().add(offset),
                        ip_raw.as_mut_ptr() as *mut u8,
                        size_of::<WgIoctlAllowedIp>(),
                    );
                }
                let ip_raw = unsafe { ip_raw.assume_init() };
                offset += size_of::<WgIoctlAllowedIp>();

                let ip_addr = match ip_raw.address_family {
                    AF_INET => {
                        let octets = [
                            ip_raw.address[0],
                            ip_raw.address[1],
                            ip_raw.address[2],
                            ip_raw.address[3],
                        ];
                        IpAddr::V4(Ipv4Addr::from(octets))
                    }
                    AF_INET6 => {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&ip_raw.address);
                        IpAddr::V6(Ipv6Addr::from(octets))
                    }
                    _ => {
                        continue;
                    }
                };

                allowed_ips.push(AllowedIp::new(ip_addr, ip_raw.cidr));
            }

            peer.allowed_ips = allowed_ips;
            peers.push(peer);
        }

        Ok((iface, peers))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_struct_sizes() {
        assert_eq!(size_of::<RawSockaddrInet>(), 28);
        assert_eq!(size_of::<WgIoctlInterface>(), 80);
        assert_eq!(size_of::<WgIoctlPeer>(), 136);
        assert_eq!(size_of::<WgIoctlAllowedIp>(), 24);
        assert_eq!(size_of::<WgIoctlLogEntry>(), 520);
    }

    #[test]
    fn test_sockaddr_inet_v4() {
        let addr = "192.168.1.50:51820".parse::<SocketAddr>().unwrap();
        let raw = RawSockaddrInet::from_socket_addr(addr);
        assert_eq!(raw.family, AF_INET);
        let back = raw.to_socket_addr().unwrap();
        assert_eq!(addr, back);
    }

    #[test]
    fn test_sockaddr_inet_v6() {
        let addr = "[2001:db8::1]:51820".parse::<SocketAddr>().unwrap();
        let raw = RawSockaddrInet::from_socket_addr(addr);
        assert_eq!(raw.family, AF_INET6);
        let back = raw.to_socket_addr().unwrap();
        assert_eq!(addr, back);
    }

    #[test]
    fn test_config_builder_and_parser_roundtrip() {
        let mut iface = InterfaceConfig::default();
        iface.listen_port = Some(51820);
        let priv_key = Key::new([1u8; 32]);
        iface.private_key = Some(priv_key.clone());

        let pub_key = Key::new([2u8; 32]);
        let mut peer = PeerConfig::new(pub_key.clone());
        peer.endpoint = Some(Endpoint::new("10.0.0.1", 51820));
        peer.persistent_keepalive = Some(25);
        peer.allowed_ips = vec![
            AllowedIp::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 32),
            AllowedIp::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
        ];

        let peers = vec![peer];
        let bytes = ConfigBuilder::build(&iface, &peers).unwrap();

        assert!(bytes.len() >= size_of::<WgIoctlInterface>() + size_of::<WgIoctlPeer>());

        let (parsed_iface, parsed_peers) = ConfigParser::parse(&bytes).unwrap();
        assert_eq!(parsed_iface.listen_port, Some(51820));
        assert_eq!(parsed_iface.private_key, Some(priv_key));
        assert_eq!(parsed_peers.len(), 1);
        assert_eq!(parsed_peers[0].public_key, pub_key);
        assert_eq!(parsed_peers[0].persistent_keepalive, Some(25));
        assert_eq!(parsed_peers[0].allowed_ips.len(), 2);
    }
}
