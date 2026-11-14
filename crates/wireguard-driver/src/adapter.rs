use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
use wireguard_types::{InterfaceConfig, PeerConfig};
use crate::abi::{AlignedZeroedBuffer, ConfigBuilder, ConfigParser};
use crate::dll::{with_wide_null, WireGuardAdapterHandle, WireGuardDll};
use crate::error::{DriverError, Result};

/// WireGuard adapter operational state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u32)]
pub enum AdapterState {
    #[default]
    Down = 0,
    Up = 1,
}

impl From<u32> for AdapterState {
    fn from(val: u32) -> Self {
        match val {
            1 => AdapterState::Up,
            _ => AdapterState::Down,
        }
    }
}

/// WireGuard adapter logging mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u32)]
pub enum AdapterLogState {
    #[default]
    Off = 0,
    On = 1,
    OnWithPrefix = 2,
}

/// Managed handle representing an active WireGuard network adapter.
pub struct WireGuardAdapter {
    handle: WireGuardAdapterHandle,
    last_guess_size: AtomicUsize,
}

unsafe impl Send for WireGuardAdapter {}
unsafe impl Sync for WireGuardAdapter {}

impl WireGuardAdapter {
    /// Creates a new WireGuard adapter.
    ///
    /// `name`: The cosmetic name of the adapter.
    /// `tunnel_type`: Adapter type string, typically `"WireGuard"`.
    /// `requested_guid`: Optional deterministic adapter GUID (influences NLA generation).
    pub fn create(
        name: &str,
        tunnel_type: &str,
        requested_guid: Option<&windows_sys::core::GUID>,
    ) -> Result<Self> {
        let dll = WireGuardDll::load()?;
        let guid_ptr = match requested_guid {
            Some(g) => g as *const _ as *const c_void,
            None => ptr::null(),
        };

        let handle = with_wide_null(name, |name_w| {
            with_wide_null(tunnel_type, |type_w| unsafe {
                (dll.create_adapter)(name_w, type_w, guid_ptr)
            })
        });
        if handle.is_null() {
            return Err(DriverError::last_win32_error("WireGuardCreateAdapter"));
        }

        tracing::info!(name, "created WireGuard adapter");
        Ok(Self {
            handle,
            last_guess_size: AtomicUsize::new(1024),
        })
    }

    /// Opens an existing WireGuard adapter by name.
    pub fn open(name: &str) -> Result<Self> {
        let dll = WireGuardDll::load()?;
        let handle = with_wide_null(name, |name_w| unsafe { (dll.open_adapter)(name_w) });
        if handle.is_null() {
            return Err(DriverError::last_win32_error("WireGuardOpenAdapter"));
        }

        tracing::info!(name, "opened existing WireGuard adapter");
        Ok(Self {
            handle,
            last_guess_size: AtomicUsize::new(1024),
        })
    }

    /// Returns the raw adapter handle.
    pub fn raw_handle(&self) -> WireGuardAdapterHandle {
        self.handle
    }

    /// Retrieves the Locally Unique Identifier (LUID) of the adapter.
    pub fn luid(&self) -> Result<u64> {
        let dll = WireGuardDll::load()?;
        let mut luid: u64 = 0;
        unsafe {
            (dll.get_adapter_luid)(self.handle, &mut luid);
        }
        Ok(luid)
    }

    /// Returns the current running WireGuardNT kernel driver version.
    pub fn running_driver_version() -> Result<u32> {
        let dll = WireGuardDll::load()?;
        let version = unsafe { (dll.get_running_driver_version)() };
        if version == 0 {
            return Err(DriverError::last_win32_error("WireGuardGetRunningDriverVersion"));
        }
        Ok(version)
    }

    /// Uninstalls / deletes the driver service from the system if no adapters are currently active.
    pub fn delete_driver() -> Result<()> {
        let dll = WireGuardDll::load()?;
        let ok = unsafe { (dll.delete_driver)() };
        if ok == 0 {
            return Err(DriverError::last_win32_error("WireGuardDeleteDriver"));
        }
        tracing::info!("WireGuard driver uninstalled successfully");
        Ok(())
    }

    /// Configures logging state on this adapter.
    pub fn set_logging(&self, state: AdapterLogState) -> Result<()> {
        let dll = WireGuardDll::load()?;
        let ok = unsafe { (dll.set_adapter_logging)(self.handle, state as u32) };
        if ok == 0 {
            return Err(DriverError::last_win32_error("WireGuardSetAdapterLogging"));
        }
        Ok(())
    }

    /// Retrieves the operational state of the adapter (Up or Down).
    pub fn adapter_state(&self) -> Result<AdapterState> {
        let dll = WireGuardDll::load()?;
        let mut state: u32 = 0;
        let ok = unsafe { (dll.get_adapter_state)(self.handle, &mut state) };
        if ok == 0 {
            return Err(DriverError::last_win32_error("WireGuardGetAdapterState"));
        }
        Ok(AdapterState::from(state))
    }

    /// Sets the operational state of the adapter (Up or Down).
    pub fn set_adapter_state(&self, state: AdapterState) -> Result<()> {
        let dll = WireGuardDll::load()?;
        let ok = unsafe { (dll.set_adapter_state)(self.handle, state as u32) };
        if ok == 0 {
            return Err(DriverError::last_win32_error("WireGuardSetAdapterState"));
        }
        tracing::debug!(?state, "set WireGuard adapter state");
        Ok(())
    }

    /// Applies configuration (keys, listen port, peers, endpoints, allowed IPs) to the adapter.
    pub fn set_configuration(
        &self,
        interface: &InterfaceConfig,
        peers: &[PeerConfig],
    ) -> Result<()> {
        let dll = WireGuardDll::load()?;
        let buffer = ConfigBuilder::build_aligned(interface, peers)?;

        let ok = unsafe {
            (dll.set_configuration)(
                self.handle,
                buffer.as_bytes().as_ptr(),
                buffer.byte_len() as u32,
            )
        };
        if ok == 0 {
            return Err(DriverError::last_win32_error("WireGuardSetConfiguration"));
        }
        tracing::debug!(peers_count = peers.len(), "applied configuration to WireGuard adapter");
        Ok(())
    }

    /// Retrieves the active configuration and statistics from the adapter.
    pub fn get_configuration(&self) -> Result<(InterfaceConfig, Vec<PeerConfig>)> {
        let dll = WireGuardDll::load()?;
        let mut size = self.last_guess_size.load(Ordering::Relaxed).max(1024) as u32;

        let mut buf = AlignedZeroedBuffer::with_zeroed_bytes(size as usize);
        loop {
            let ok = unsafe {
                (dll.get_configuration)(self.handle, buf.as_mut_ptr(), &mut size)
            };

            if ok != 0 {
                self.last_guess_size.store(size as usize, Ordering::Relaxed);
                return ConfigParser::parse(&buf.as_bytes()[..size as usize]);
            }

            let last_err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            if last_err != ERROR_MORE_DATA {
                return Err(DriverError::from_win32_error("WireGuardGetConfiguration", last_err));
            }
            // `size` has been updated by the driver with the required buffer size; resize in place and retry.
            buf.resize_bytes(size as usize);
        }
    }
}

impl Drop for WireGuardAdapter {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            if let Ok(dll) = WireGuardDll::load() {
                unsafe {
                    (dll.close_adapter)(self.handle);
                }
            }
        }
    }
}
