use std::fmt;

/// Operational status of an interface.
/// Corresponds to `IF_OPER_STATUS` (RFC 2863).
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(i32)]
pub enum OperStatus {
    Up = 1,
    Down = 2,
    Testing = 3,
    Unknown = 4,
    Dormant = 5,
    NotPresent = 6,
    LowerLayerDown = 7,
}

impl OperStatus {
    pub fn from_raw(val: i32) -> Self {
        match val {
            1 => Self::Up,
            2 => Self::Down,
            3 => Self::Testing,
            4 => Self::Unknown,
            5 => Self::Dormant,
            6 => Self::NotPresent,
            7 => Self::LowerLayerDown,
            _ => Self::Unknown,
        }
    }

    pub fn to_raw(self) -> i32 {
        self as i32
    }

    pub fn is_up(self) -> bool {
        matches!(self, Self::Up)
    }
}

impl fmt::Display for OperStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Up => write!(f, "Up"),
            Self::Down => write!(f, "Down"),
            Self::Testing => write!(f, "Testing"),
            Self::Unknown => write!(f, "Unknown"),
            Self::Dormant => write!(f, "Dormant"),
            Self::NotPresent => write!(f, "NotPresent"),
            Self::LowerLayerDown => write!(f, "LowerLayerDown"),
        }
    }
}

/// Administrative status of an interface.
/// Corresponds to `NET_IF_ADMIN_STATUS` (RFC 2863).
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(i32)]
pub enum AdminStatus {
    Up = 1,
    Down = 2,
    Testing = 3,
}

impl AdminStatus {
    pub fn from_raw(val: i32) -> Self {
        match val {
            1 => Self::Up,
            2 => Self::Down,
            3 => Self::Testing,
            _ => Self::Down,
        }
    }

    pub fn to_raw(self) -> i32 {
        self as i32
    }

    pub fn is_up(self) -> bool {
        matches!(self, Self::Up)
    }
}

impl fmt::Display for AdminStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Up => write!(f, "Up"),
            Self::Down => write!(f, "Down"),
            Self::Testing => write!(f, "Testing"),
        }
    }
}

/// Protocol address family.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum AddressFamily {
    Unspecified = 0,
    Ipv4 = 2,
    Ipv6 = 23,
}

impl AddressFamily {
    pub fn from_raw(val: u16) -> Self {
        match val {
            2 => Self::Ipv4,
            23 => Self::Ipv6,
            _ => Self::Unspecified,
        }
    }

    pub fn to_raw(self) -> u16 {
        self as u16
    }
}

impl fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unspecified => write!(f, "AF_UNSPEC"),
            Self::Ipv4 => write!(f, "AF_INET"),
            Self::Ipv6 => write!(f, "AF_INET6"),
        }
    }
}

/// Flags for GetAdaptersAddresses (`GAA_FLAG_*`).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct GaaFlags(pub u32);

impl GaaFlags {
    pub const SKIP_UNICAST: u32 = 0x0001;
    pub const SKIP_ANYCAST: u32 = 0x0002;
    pub const SKIP_MULTICAST: u32 = 0x0004;
    pub const SKIP_DNS_SERVER: u32 = 0x0008;
    pub const INCLUDE_PREFIX: u32 = 0x0010;
    pub const SKIP_FRIENDLY_NAME: u32 = 0x0020;
    pub const INCLUDE_WINS_INFO: u32 = 0x0040;
    pub const INCLUDE_GATEWAYS: u32 = 0x0080;
    pub const INCLUDE_ALL_INTERFACES: u32 = 0x0100;
    pub const INCLUDE_ALL_COMPARTMENTS: u32 = 0x0200;
    pub const INCLUDE_TUNNEL_BINDING_ORDER: u32 = 0x0400;
    pub const SKIP_DNS_INFO: u32 = 0x0800;

    pub const DEFAULT: Self = Self(0);
    pub const SKIP_ALL: Self = Self(
        Self::SKIP_UNICAST
            | Self::SKIP_ANYCAST
            | Self::SKIP_MULTICAST
            | Self::SKIP_DNS_SERVER
            | Self::SKIP_FRIENDLY_NAME
            | Self::SKIP_DNS_INFO,
    );
    pub const INCLUDE_ALL: Self = Self(
        Self::INCLUDE_PREFIX
            | Self::INCLUDE_WINS_INFO
            | Self::INCLUDE_GATEWAYS
            | Self::INCLUDE_ALL_INTERFACES
            | Self::INCLUDE_ALL_COMPARTMENTS
            | Self::INCLUDE_TUNNEL_BINDING_ORDER,
    );
}

impl std::ops::BitOr for GaaFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOr<u32> for GaaFlags {
    type Output = Self;
    fn bitor(self, rhs: u32) -> Self::Output {
        Self(self.0 | rhs)
    }
}
