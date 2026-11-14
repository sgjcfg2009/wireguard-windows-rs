// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.

use thiserror::Error;

const RESERVED_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TunnelNameError {
    #[error("tunnel name is not valid: {0}")]
    InvalidName(String),
}

fn is_reserved(name: &str) -> bool {
    let base = match name.split_once('.') {
        Some((b, _)) => b,
        None => name,
    };
    for &res in RESERVED_NAMES {
        if base.eq_ignore_ascii_case(res) {
            return true;
        }
    }
    false
}

/// Validates whether a tunnel name adheres to WireGuard and Windows naming restrictions.
///
/// Restrictions:
/// - Must be 1 to 32 characters in length.
/// - Allowed characters: `a-z`, `A-Z`, `0-9`, `_`, `=`, `+`, `.`, `-`.
/// - Must not start or end with `.`.
/// - Must not be a reserved Windows device name (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`).
pub fn tunnel_name_is_valid(name: &str) -> bool {
    if name.is_empty() || name.len() > 32 {
        return false;
    }
    if name.starts_with('.') || name.ends_with('.') {
        return false;
    }
    if is_reserved(name) {
        return false;
    }
    name.bytes().all(|b| {
        matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'=' | b'+' | b'.' | b'-')
    })
}

/// Generates the Windows Service Control Manager service name for a given tunnel.
///
/// Format: `WireGuardTunnel$<tunnelName>`
pub fn service_name_of_tunnel(tunnel_name: &str) -> Result<String, TunnelNameError> {
    if !tunnel_name_is_valid(tunnel_name) {
        return Err(TunnelNameError::InvalidName(tunnel_name.to_string()));
    }
    let mut out = String::with_capacity(16 + tunnel_name.len());
    out.push_str("WireGuardTunnel$");
    out.push_str(tunnel_name);
    Ok(out)
}

/// Iterates over whitespace-normalized characters (`trim()` + collapse whitespace runs to `' '`).
struct NormalizedChars<'a> {
    rest: &'a str,
}

impl<'a> NormalizedChars<'a> {
    #[inline]
    fn new(s: &'a str) -> Self {
        Self { rest: s.trim() }
    }

    #[inline]
    fn next_char(&mut self) -> Option<char> {
        let c = self.rest.chars().next()?;
        self.rest = &self.rest[c.len_utf8()..];
        if c.is_whitespace() {
            self.rest = self.rest.trim_start();
            Some(' ')
        } else {
            Some(c)
        }
    }

    /// Consumes a contiguous ASCII digit run (starting with `first_digit`) and returns
    /// `(parsed_u64_if_fits, digit_byte_slice_len_note)` by returning `Ok(u64)` on valid parse
    /// or `Err(())` on `u64` overflow, advancing `self.rest` to the end of the digit run.
    #[inline]
    fn consume_digit_run(&mut self, first_digit: char) -> Result<(u64, &'a str), &'a str> {
        // Reconstruct slice starting from `first_digit`
        // SAFETY: `self.rest` immediately follows `first_digit` (1 ASCII byte) in original `&str`
        let digit_start_ptr = unsafe { self.rest.as_ptr().sub(1) };
        let mut digit_bytes = 1usize;
        for b in self.rest.bytes() {
            if b.is_ascii_digit() {
                digit_bytes += 1;
            } else {
                break;
            }
        }
        self.rest = &self.rest[digit_bytes - 1..];
        let slice = unsafe {
            core::str::from_utf8_unchecked(core::slice::from_raw_parts(digit_start_ptr, digit_bytes))
        };
        let mut acc: u64 = (first_digit as u8 - b'0') as u64;
        for &b in &slice.as_bytes()[1..] {
            let Some(next) = acc.checked_mul(10).and_then(|v| v.checked_add((b - b'0') as u64)) else {
                return Err(slice);
            };
            acc = next;
        }
        Ok((acc, slice))
    }
}

/// Zero-allocation natural sort comparison for tunnel names matching wireguard-windows.
pub fn tunnel_name_is_less(a: &str, b: &str) -> bool {
    if a == b {
        return false;
    }

    let mut ia = NormalizedChars::new(a);
    let mut ib = NormalizedChars::new(b);

    loop {
        match (ia.next_char(), ib.next_char()) {
            (None, None) | (Some(_), None) => return false,
            (None, Some(_)) => return true,
            (Some(ca), Some(cb)) => {
                match (ca.is_ascii_digit(), cb.is_ascii_digit()) {
                    (true, true) => {
                        let ord = match (ia.consume_digit_run(ca), ib.consume_digit_run(cb)) {
                            (Ok((na, _)), Ok((nb, _))) => na.cmp(&nb),
                            (Ok(_), Err(_)) => std::cmp::Ordering::Less,
                            (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
                            (Err(sa), Err(sb)) => sa.cmp(sb),
                        };
                        if ord != std::cmp::Ordering::Equal {
                            return ord == std::cmp::Ordering::Less;
                        }
                    }
                    // Digits always sort before non-digits (regardless of preceding text token)
                    (true, false) => return true,
                    (false, true) => return false,
                    (false, false) => {
                        if ca != cb {
                            let ord = ca.to_lowercase().cmp(cb.to_lowercase());
                            if ord != std::cmp::Ordering::Equal {
                                return ord == std::cmp::Ordering::Less;
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Sanitizes an arbitrary string into a valid WireGuard tunnel name.
///
/// Replaces illegal characters with `_`, trims dots, handles reserved names,
/// and truncates to 32 characters.
pub fn sanitize_tunnel_name(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(32));
    let mut seen_non_dot = false;

    for c in raw.chars() {
        let mapped = if matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '=' | '+' | '.' | '-')
        {
            c
        } else {
            '_'
        };
        if mapped == '.' && !seen_non_dot {
            continue;
        }
        seen_non_dot = true;
        if out.len() < 32 {
            out.push(mapped);
        } else {
            break;
        }
    }

    while out.ends_with('.') {
        out.pop();
    }

    if out.is_empty() {
        return "wg0".to_string();
    }

    if is_reserved(&out) {
        if out.len() + 3 <= 32 {
            out.insert_str(0, "wg_");
        } else {
            out.clear();
            out.push_str("wg0");
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_tunnel_names() {
        assert!(tunnel_name_is_valid("wg0"));
        assert!(tunnel_name_is_valid("office-vpn"));
        assert!(tunnel_name_is_valid("server_1+2=3"));
        assert!(tunnel_name_is_valid("a.b.c"));
        assert!(tunnel_name_is_valid("12345678901234567890123456789012")); // 32 chars
    }

    #[test]
    fn test_invalid_tunnel_names() {
        assert!(!tunnel_name_is_valid("")); // empty
        assert!(!tunnel_name_is_valid(".starts_with_dot"));
        assert!(!tunnel_name_is_valid("ends_with_dot."));
        assert!(!tunnel_name_is_valid("CON"));
        assert!(!tunnel_name_is_valid("con.txt"));
        assert!(!tunnel_name_is_valid("aux"));
        assert!(!tunnel_name_is_valid("NUL"));
        assert!(!tunnel_name_is_valid("COM1"));
        assert!(!tunnel_name_is_valid("lpt5"));
        assert!(!tunnel_name_is_valid("has space"));
        assert!(!tunnel_name_is_valid("has$dollar"));
        assert!(!tunnel_name_is_valid("has/slash"));
        assert!(!tunnel_name_is_valid("has\\backslash"));
        assert!(!tunnel_name_is_valid("123456789012345678901234567890123")); // 33 chars
    }

    #[test]
    fn test_service_name_of_tunnel() {
        assert_eq!(
            service_name_of_tunnel("wg0").unwrap(),
            "WireGuardTunnel$wg0"
        );
        assert!(service_name_of_tunnel("invalid name with spaces").is_err());
    }

    #[test]
    fn test_tunnel_name_natural_sort() {
        assert!(tunnel_name_is_less("wg1", "wg2"));
        assert!(tunnel_name_is_less("wg2", "wg10"));
        assert!(!tunnel_name_is_less("wg10", "wg2"));
        assert!(tunnel_name_is_less("tunnel01", "tunnel2"));
        assert!(!tunnel_name_is_less("wg0", "wg0"));
    }

    #[test]
    fn test_sanitize_tunnel_name() {
        assert_eq!(sanitize_tunnel_name("My Tunnel (Home)"), "My_Tunnel__Home_");
        assert!(tunnel_name_is_valid(&sanitize_tunnel_name("My Tunnel (Home)")));
        assert_eq!(sanitize_tunnel_name("CON"), "wg_CON");
        assert!(tunnel_name_is_valid(&sanitize_tunnel_name("CON")));
        assert_eq!(sanitize_tunnel_name("..."), "wg0");
        assert!(tunnel_name_is_valid(&sanitize_tunnel_name("...")));
    }
}
