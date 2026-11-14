// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.

use crate::name::tunnel_name_is_valid;
use std::net::IpAddr;
use thiserror::Error;
use wireguard_types::{AllowedIp, AllowedIpParseError, Endpoint, Key, PeerConfig, TunnelConfig};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("line must occur in a section: {0}")]
    NotInSection(String),
    #[error("config key is missing an equals separator: {0}")]
    MissingEquals(String),
    #[error("key must have a value: {0}")]
    MissingValue(String),
    #[error("invalid key for [Interface] section: {0}")]
    InvalidInterfaceKey(String),
    #[error("invalid key for [Peer] section: {0}")]
    InvalidPeerKey(String),
    #[error("two commas in a row: {0}")]
    DoubleComma(String),
    #[error("invalid IP address: {0}")]
    InvalidIp(String),
    #[error("invalid CIDR prefix: {0}")]
    InvalidCidr(String),
    #[error("missing port from endpoint: {0}")]
    MissingPort(String),
    #[error("invalid endpoint host: {0}")]
    InvalidEndpointHost(String),
    #[error("brackets must contain an IPv6 address: {0}")]
    InvalidEndpointBracket(String),
    #[error("invalid port: {0}")]
    InvalidPort(String),
    #[error("invalid MTU: {0}")]
    InvalidMtu(String),
    #[error("invalid persistent keepalive: {0}")]
    InvalidPersistentKeepalive(String),
    #[error("invalid table: {0}")]
    InvalidTable(String),
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("an interface must have a private key")]
    MissingPrivateKey,
    #[error("all peers must have public keys")]
    MissingPublicKey,
    #[error("tunnel name is not valid: {0}")]
    InvalidTunnelName(String),
    #[error("invalid encoding: {0}")]
    InvalidEncoding(String),
}

fn for_each_comma_item<F>(s: &str, mut f: F) -> Result<(), ParseError>
where
    F: FnMut(&str) -> Result<(), ParseError>,
{
    for item in s.split(',') {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            return Err(ParseError::DoubleComma(s.to_string()));
        }
        f(trimmed)?;
    }
    Ok(())
}

fn parse_ip_cidr(s: &str) -> Result<AllowedIp, ParseError> {
    let s = s.trim();
    s.parse::<AllowedIp>().map_err(|e| match e {
        AllowedIpParseError::InvalidIp(_) => ParseError::InvalidIp(s.to_string()),
        AllowedIpParseError::InvalidCidr(_) | AllowedIpParseError::CidrOverflow { .. } => {
            ParseError::InvalidCidr(s.to_string())
        }
    })
}

pub fn parse_endpoint(s: &str) -> Result<Endpoint, ParseError> {
    let s = s.trim();
    let (host, port_str) = s
        .rfind(':')
        .map(|idx| (&s[..idx], &s[idx + 1..]))
        .ok_or_else(|| ParseError::MissingPort(s.to_string()))?;

    if host.is_empty() {
        return Err(ParseError::InvalidEndpointHost(host.to_string()));
    }

    let port = parse_port(port_str)?;

    let mut clean_host = host;
    let host_has_colon = host.contains(':');
    let starts_bracket = host.starts_with('[');
    let ends_bracket = host.ends_with(']');

    if starts_bracket || ends_bracket || host_has_colon {
        if host.len() > 3 && starts_bracket && ends_bracket && host_has_colon {
            let inner = &host[1..host.len() - 1];
            let ip_part = match inner.rfind('%') {
                Some(zone_idx) if zone_idx > 0 => &inner[..zone_idx],
                _ => inner,
            };
            match ip_part.parse::<IpAddr>() {
                Ok(IpAddr::V6(_)) => {
                    clean_host = inner;
                }
                _ => return Err(ParseError::InvalidEndpointBracket(host.to_string())),
            }
        } else {
            return Err(ParseError::InvalidEndpointBracket(host.to_string()));
        }
    }

    Ok(Endpoint::new(clean_host, port))
}

fn parse_port(s: &str) -> Result<u16, ParseError> {
    let s = s.trim();
    s.parse::<u16>()
        .map_err(|_| ParseError::InvalidPort(s.to_string()))
}

fn parse_mtu(s: &str) -> Result<u16, ParseError> {
    let s = s.trim();
    let m = s
        .parse::<u32>()
        .map_err(|_| ParseError::InvalidMtu(s.to_string()))?;
    if !(576..=65535).contains(&m) {
        return Err(ParseError::InvalidMtu(s.to_string()));
    }
    Ok(m as u16)
}

fn parse_persistent_keepalive(s: &str) -> Result<Option<u16>, ParseError> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("off") {
        return Ok(None);
    }
    let k = s
        .parse::<u32>()
        .map_err(|_| ParseError::InvalidPersistentKeepalive(s.to_string()))?;
    if k > 65535 {
        return Err(ParseError::InvalidPersistentKeepalive(s.to_string()));
    }
    if k == 0 {
        Ok(None)
    } else {
        Ok(Some(k as u16))
    }
}

fn parse_table(s: &str) -> Result<bool, ParseError> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("off") {
        return Ok(true);
    }
    if s.eq_ignore_ascii_case("auto") || s.eq_ignore_ascii_case("main") {
        return Ok(false);
    }
    if s.parse::<u32>().is_ok() {
        return Ok(false);
    }
    Err(ParseError::InvalidTable(s.to_string()))
}

fn parse_key_base64(s: &str) -> Result<Key, ParseError> {
    Key::from_base64(s).map_err(|e| ParseError::InvalidKey(format!("{e}: {s}")))
}

#[derive(PartialEq)]
enum ParserState {
    NotInASection,
    InInterfaceSection,
    InPeerSection,
}

struct ConfigParserState {
    config: TunnelConfig,
    state: ParserState,
    current_peer: Option<PeerConfig>,
    saw_private_key: bool,
}

impl ConfigParserState {
    fn new(name: &str) -> Result<Self, ParseError> {
        if !name.is_empty() && !tunnel_name_is_valid(name) {
            return Err(ParseError::InvalidTunnelName(name.to_string()));
        }
        Ok(Self {
            config: TunnelConfig::new(name),
            state: ParserState::NotInASection,
            current_peer: None,
            saw_private_key: false,
        })
    }

    fn feed_line(&mut self, line: &str) -> Result<(), ParseError> {
        // Strip comments, unless preup/postup/predown/postdown
        let code = match line.split_once('#') {
            Some((c, _)) => c,
            None => line,
        };
        let stripped = code.trim();
        if stripped.is_empty() {
            return Ok(());
        }

        let (key, mut val, has_value) = match stripped.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim(), true),
            None => (stripped, "", false),
        };

        if !has_value && key.eq_ignore_ascii_case("[interface]") {
            if let Some(peer) = self.current_peer.take() {
                self.config.peers.push(peer);
            }
            self.state = ParserState::InInterfaceSection;
            return Ok(());
        }

        if !has_value && key.eq_ignore_ascii_case("[peer]") {
            if let Some(peer) = self.current_peer.take() {
                self.config.peers.push(peer);
            }
            self.current_peer = Some(PeerConfig::new(Key::default()));
            self.state = ParserState::InPeerSection;
            return Ok(());
        }

        if self.state == ParserState::NotInASection {
            return Err(ParseError::NotInSection(stripped.to_string()));
        }

        if !has_value {
            return Err(ParseError::MissingEquals(stripped.to_string()));
        }

        // For shell hook commands, preserve '#' in the value
        if key.eq_ignore_ascii_case("preup")
            || key.eq_ignore_ascii_case("postup")
            || key.eq_ignore_ascii_case("predown")
            || key.eq_ignore_ascii_case("postdown")
        {
            if let Some((_, full_v)) = line.split_once('=') {
                val = full_v.trim();
            }
        }

        if val.is_empty() {
            return Err(ParseError::MissingValue(stripped.to_string()));
        }

        match self.state {
            ParserState::InInterfaceSection => {
                if key.eq_ignore_ascii_case("privatekey") {
                    let k = parse_key_base64(val)?;
                    self.config.interface.private_key = Some(k);
                    self.saw_private_key = true;
                } else if key.eq_ignore_ascii_case("listenport") {
                    let port = parse_port(val)?;
                    self.config.interface.listen_port = Some(port);
                } else if key.eq_ignore_ascii_case("mtu") {
                    let mtu = parse_mtu(val)?;
                    self.config.interface.mtu = Some(mtu);
                } else if key.eq_ignore_ascii_case("address") {
                    for_each_comma_item(val, |addr| {
                        let allowed_ip = parse_ip_cidr(addr)?;
                        self.config.interface.addresses.push(allowed_ip);
                        Ok(())
                    })?;
                } else if key.eq_ignore_ascii_case("dns") {
                    for_each_comma_item(val, |item| {
                        if let Ok(ip) = item.parse::<IpAddr>() {
                            self.config.interface.dns.push(ip);
                        } else {
                            self.config.interface.dns_search.push(item.to_string());
                        }
                        Ok(())
                    })?;
                } else if key.eq_ignore_ascii_case("preup") {
                    self.config.interface.pre_up = Some(val.to_string());
                } else if key.eq_ignore_ascii_case("postup") {
                    self.config.interface.post_up = Some(val.to_string());
                } else if key.eq_ignore_ascii_case("predown") {
                    self.config.interface.pre_down = Some(val.to_string());
                } else if key.eq_ignore_ascii_case("postdown") {
                    self.config.interface.post_down = Some(val.to_string());
                } else if key.eq_ignore_ascii_case("table") {
                    let table_off = parse_table(val)?;
                    self.config.interface.table_off = table_off;
                } else {
                    return Err(ParseError::InvalidInterfaceKey(key.to_lowercase()));
                }
            }
            ParserState::InPeerSection => {
                let peer = self
                    .current_peer
                    .as_mut()
                    .ok_or_else(|| ParseError::NotInSection(stripped.to_string()))?;
                if key.eq_ignore_ascii_case("publickey") {
                    let k = parse_key_base64(val)?;
                    peer.public_key = k;
                } else if key.eq_ignore_ascii_case("presharedkey") {
                    let k = parse_key_base64(val)?;
                    peer.preshared_key = Some(k);
                } else if key.eq_ignore_ascii_case("allowedips") {
                    for_each_comma_item(val, |ip| {
                        let allowed_ip = parse_ip_cidr(ip)?;
                        peer.allowed_ips.push(allowed_ip);
                        Ok(())
                    })?;
                } else if key.eq_ignore_ascii_case("endpoint") {
                    let ep = parse_endpoint(val)?;
                    peer.endpoint = Some(ep);
                } else if key.eq_ignore_ascii_case("persistentkeepalive") {
                    peer.persistent_keepalive = parse_persistent_keepalive(val)?;
                } else {
                    return Err(ParseError::InvalidPeerKey(key.to_lowercase()));
                }
            }
            ParserState::NotInASection => unreachable!(),
        }

        Ok(())
    }

    fn finish(mut self) -> Result<TunnelConfig, ParseError> {
        if let Some(peer) = self.current_peer.take() {
            self.config.peers.push(peer);
        }

        if !self.saw_private_key {
            return Err(ParseError::MissingPrivateKey);
        }

        for peer in &self.config.peers {
            if peer.public_key.is_zero() {
                return Err(ParseError::MissingPublicKey);
            }
        }

        Ok(self.config)
    }
}

#[inline]
fn zeroize_string(s: &mut String) {
    // SAFETY: writing ASCII NUL bytes preserves valid UTF-8.
    let bytes = unsafe { s.as_bytes_mut() };
    for b in bytes {
        unsafe {
            core::ptr::write_volatile(b, 0);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    s.clear();
}

/// Streams UTF-16LE/BE payload bytes line-by-line into `ConfigParserState` without
/// allocating an intermediate `Vec<u16>` or whole-file `String`.
/// Returns `None` if an unpaired UTF-16 surrogate is encountered.
fn parse_utf16_bytes(
    bytes: &[u8],
    big_endian: bool,
    name: &str,
) -> Option<Result<TunnelConfig, ParseError>> {
    let mut parser = match ConfigParserState::new(name) {
        Ok(p) => p,
        Err(e) => return Some(Err(e)),
    };
    let mut line_buf = String::with_capacity(128);

    let iter = bytes.chunks_exact(2).map(|c| {
        if big_endian {
            u16::from_be_bytes([c[0], c[1]])
        } else {
            u16::from_le_bytes([c[0], c[1]])
        }
    });

    for decoded in char::decode_utf16(iter) {
        let Ok(c) = decoded else {
            zeroize_string(&mut line_buf);
            return None;
        };
        if c == '\n' {
            if line_buf.ends_with('\r') {
                line_buf.pop();
            }
            if let Err(e) = parser.feed_line(&line_buf) {
                zeroize_string(&mut line_buf);
                return Some(Err(e));
            }
            zeroize_string(&mut line_buf);
        } else {
            line_buf.push(c);
        }
    }

    if !line_buf.is_empty() {
        if let Err(e) = parser.feed_line(&line_buf) {
            zeroize_string(&mut line_buf);
            return Some(Err(e));
        }
    }
    zeroize_string(&mut line_buf);

    Some(parser.finish())
}

/// Parses a WireGuard configuration from text string.
///
/// If `name` is non-empty, validates that the tunnel name complies with naming rules.
pub fn parse_config_with_name(text: &str, name: &str) -> Result<TunnelConfig, ParseError> {
    let mut parser = ConfigParserState::new(name)?;
    for line in text.lines() {
        parser.feed_line(line)?;
    }
    parser.finish()
}

/// Parses a WireGuard configuration from text string without name constraint.
pub fn parse_config(text: &str) -> Result<TunnelConfig, ParseError> {
    parse_config_with_name(text, "")
}

/// Parses a WireGuard wg-quick configuration with tunnel name validation (matches Go `FromWgQuick`).
pub fn from_wg_quick(text: &str, name: &str) -> Result<TunnelConfig, ParseError> {
    if !tunnel_name_is_valid(name) {
        return Err(ParseError::InvalidTunnelName(name.to_string()));
    }
    parse_config_with_name(text, name)
}

/// Parses configuration bytes with automatic detection of UTF-8, UTF-8 BOM, UTF-16LE, and UTF-16BE.
pub fn parse_config_bytes(bytes: &[u8], name: &str) -> Result<TunnelConfig, ParseError> {
    // 1. Strip UTF-8 BOM if present
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        if let Ok(s) = std::str::from_utf8(&bytes[3..]) {
            return parse_config_with_name(s, name);
        }
    }

    // 2. UTF-16LE BOM (streamed line-by-line)
    if bytes.starts_with(&[0xFF, 0xFE]) && bytes.len() % 2 == 0 {
        if let Some(res) = parse_utf16_bytes(&bytes[2..], false, name) {
            return res;
        }
    }

    // 3. UTF-16BE BOM (streamed line-by-line)
    if bytes.starts_with(&[0xFE, 0xFF]) && bytes.len() % 2 == 0 {
        if let Some(res) = parse_utf16_bytes(&bytes[2..], true, name) {
            return res;
        }
    }

    // 4. Try standard UTF-8
    if let Ok(s) = std::str::from_utf8(bytes) {
        return parse_config_with_name(s, name);
    }

    // 5. Try ISO-8859-1 / Windows-1252 fallback (streamed line-by-line)
    let mut parser = ConfigParserState::new(name)?;
    let mut line_buf = String::with_capacity(128);
    for mut line_bytes in bytes.split(|&b| b == b'\n') {
        if line_bytes.ends_with(b"\r") {
            line_bytes = &line_bytes[..line_bytes.len() - 1];
        }
        if line_bytes.is_ascii() {
            // SAFETY: ASCII bytes are always valid UTF-8.
            let line = unsafe { std::str::from_utf8_unchecked(line_bytes) };
            parser.feed_line(line)?;
        } else {
            line_buf.clear();
            line_buf.extend(line_bytes.iter().map(|&b| b as char));
            if let Err(e) = parser.feed_line(&line_buf) {
                zeroize_string(&mut line_buf);
                return Err(e);
            }
            zeroize_string(&mut line_buf);
        }
    }
    parser.finish()
}

/// Matches Go `FromWgQuickWithUnknownEncoding`
pub fn from_wg_quick_with_unknown_encoding(
    bytes: &[u8],
    name: &str,
) -> Result<TunnelConfig, ParseError> {
    if !tunnel_name_is_valid(name) {
        return Err(ParseError::InvalidTunnelName(name.to_string()));
    }
    parse_config_bytes(bytes, name)
}
