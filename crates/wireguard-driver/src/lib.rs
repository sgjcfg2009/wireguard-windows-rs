//! # wireguard-driver
//!
//! Production-grade 100% Rust implementation for managing WireGuardNT kernel miniport
//! and Wintun fallback network adapters on Microsoft Windows.
//!
//! ## Capabilities
//! - WireGuardNT IOCTL control codes (`WG_IOCTL_GET_ADAPTER`, `WG_IOCTL_SET_ADAPTER`,
//!   `WG_IOCTL_SET_ADAPTER_STATE`, `WG_IOCTL_READ_LOG`).
//! - Complete WireGuard adapter lifecycle: creation, opening, deletion, status, LUID query,
//!   driver version detection, and atomic configuration transfer matching the WireGuardNT C ABI.
//! - Safe abstractions over Win32 `DeviceIoControl` with compile-time checked C ABI struct alignment.
//! - Fallback support for Wintun layer-3 TUN adapters and packet ring session management.
//! - Driver diagnostic ring log streaming and synchronous/asynchronous polling.

pub mod abi;
pub mod adapter;
pub mod dll;
pub mod error;
pub mod ioctl;
pub mod logging;
pub mod wintun;

pub use abi::{
    allowed_ip_flags, interface_flags, peer_flags, ConfigBuilder, ConfigParser,
    RawSockaddrInet, WgIoctlAllowedIp, WgIoctlInterface, WgIoctlLogEntry, WgIoctlPeer,
};
pub use adapter::{AdapterLogState, AdapterState, WireGuardAdapter};
pub use dll::{WireGuardAdapterHandle, WireGuardDll};
pub use error::{DriverError, Result};
pub use ioctl::{
    ctl_code, dev_ioctl, FILE_ANY_ACCESS, FILE_READ_ACCESS, FILE_READ_WRITE_ACCESS,
    FILE_WRITE_ACCESS, METHOD_BUFFERED, METHOD_IN_DIRECT, METHOD_NEITHER, METHOD_OUT_DIRECT,
    WG_DEVICE_TYPE, WG_IOCTL_GET, WG_IOCTL_GET_ADAPTER, WG_IOCTL_READ_LOG,
    WG_IOCTL_READ_LOG_LINE, WG_IOCTL_SET, WG_IOCTL_SET_ADAPTER, WG_IOCTL_SET_ADAPTER_STATE,
};
pub use logging::{
    filetime_to_system_time, set_driver_logger, DriverLogEntry, DriverLogPollingHandle,
    DriverLogReader, LogLevel,
};
pub use wintun::{
    WintunAdapter, WintunAdapterHandle, WintunDll, WintunSession, WintunSessionHandle,
    WINTUN_MAX_RING_CAPACITY, WINTUN_MIN_RING_CAPACITY,
};
