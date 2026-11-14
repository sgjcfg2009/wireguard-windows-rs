use std::ffi::c_void;
use std::ptr;
use std::sync::{Mutex, OnceLock};
use windows_sys::Win32::Foundation::{BOOL, FreeLibrary, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW,
    LOAD_LIBRARY_SEARCH_APPLICATION_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use crate::dll::with_wide_null;
use crate::error::{DriverError, Result};

pub type WintunAdapterHandle = *mut c_void;
pub type WintunSessionHandle = *mut c_void;

/// Minimum and maximum ring buffer capacities for Wintun sessions (in bytes, powers of 2).
pub const WINTUN_MIN_RING_CAPACITY: u32 = 0x20000;    // 128 KiB
pub const WINTUN_MAX_RING_CAPACITY: u32 = 0x4000000;  // 64 MiB

pub type WintunCreateAdapterFn = unsafe extern "system" fn(
    name: *const u16,
    tunnel_type: *const u16,
    requested_guid: *const c_void,
) -> WintunAdapterHandle;

pub type WintunOpenAdapterFn = unsafe extern "system" fn(name: *const u16) -> WintunAdapterHandle;

pub type WintunCloseAdapterFn = unsafe extern "system" fn(adapter: WintunAdapterHandle);

pub type WintunDeleteDriverFn = unsafe extern "system" fn() -> BOOL;

pub type WintunGetAdapterLuidFn = unsafe extern "system" fn(adapter: WintunAdapterHandle, luid: *mut u64);

pub type WintunGetRunningDriverVersionFn = unsafe extern "system" fn() -> u32;

pub type WintunStartSessionFn = unsafe extern "system" fn(
    adapter: WintunAdapterHandle,
    capacity: u32,
) -> WintunSessionHandle;

pub type WintunEndSessionFn = unsafe extern "system" fn(session: WintunSessionHandle);

pub type WintunGetReadWaitEventFn = unsafe extern "system" fn(session: WintunSessionHandle) -> HANDLE;

pub type WintunReceivePacketFn = unsafe extern "system" fn(
    session: WintunSessionHandle,
    packet_size: *mut u32,
) -> *mut u8;

pub type WintunReleaseReceivePacketFn = unsafe extern "system" fn(
    session: WintunSessionHandle,
    packet: *const u8,
);

pub type WintunAllocateSendPacketFn = unsafe extern "system" fn(
    session: WintunSessionHandle,
    packet_size: u32,
) -> *mut u8;

pub type WintunSendPacketFn = unsafe extern "system" fn(
    session: WintunSessionHandle,
    packet: *const u8,
);

/// Dynamic bindings to `wintun.dll`.
pub struct WintunDll {
    _module: HANDLE,
    pub create_adapter: WintunCreateAdapterFn,
    pub open_adapter: WintunOpenAdapterFn,
    pub close_adapter: WintunCloseAdapterFn,
    pub delete_driver: WintunDeleteDriverFn,
    pub get_adapter_luid: WintunGetAdapterLuidFn,
    pub get_running_driver_version: WintunGetRunningDriverVersionFn,
    pub start_session: WintunStartSessionFn,
    pub end_session: WintunEndSessionFn,
    pub get_read_wait_event: WintunGetReadWaitEventFn,
    pub receive_packet: WintunReceivePacketFn,
    pub release_receive_packet: WintunReleaseReceivePacketFn,
    pub allocate_send_packet: WintunAllocateSendPacketFn,
    pub send_packet: WintunSendPacketFn,
}

unsafe impl Send for WintunDll {}
unsafe impl Sync for WintunDll {}

struct WintunLibGuard(HANDLE);

impl Drop for WintunLibGuard {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                FreeLibrary(self.0);
            }
            self.0 = ptr::null_mut();
        }
    }
}

impl WintunDll {
    pub fn load() -> Result<&'static Self> {
        static INSTANCE: OnceLock<WintunDll> = OnceLock::new();
        static INIT_LOCK: Mutex<()> = Mutex::new(());

        if let Some(dll) = INSTANCE.get() {
            return Ok(dll);
        }

        let _init_guard = INIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(dll) = INSTANCE.get() {
            return Ok(dll);
        }

        let dll = Self::load_from_name("wintun.dll")?;
        let _ = INSTANCE.set(dll);
        Ok(INSTANCE.get().unwrap())
    }

    pub fn load_from_name(name: &str) -> Result<Self> {
        let module = with_wide_null(name, |name_ptr| unsafe {
            LoadLibraryExW(
                name_ptr,
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        });

        if module.is_null() || module == INVALID_HANDLE_VALUE {
            return Err(DriverError::last_win32_error("LoadLibraryExW(wintun.dll)"));
        }

        let mut guard = WintunLibGuard(module);

        unsafe fn get_sym<T>(module: HANDLE, name: &'static [u8]) -> Result<T> {
            let proc = GetProcAddress(module, name.as_ptr() as *const _);
            if proc.is_none() {
                return Err(DriverError::ProcNotFound {
                    symbol: std::str::from_utf8(&name[..name.len().saturating_sub(1)])
                        .unwrap_or("unknown"),
                });
            }
            Ok(std::mem::transmute_copy(&proc))
        }

        unsafe {
            let create_adapter = get_sym(module, b"WintunCreateAdapter\0")?;
            let open_adapter = get_sym(module, b"WintunOpenAdapter\0")?;
            let close_adapter = get_sym(module, b"WintunCloseAdapter\0")?;
            let delete_driver = get_sym(module, b"WintunDeleteDriver\0")?;
            let get_adapter_luid = get_sym(module, b"WintunGetAdapterLUID\0")?;
            let get_running_driver_version = get_sym(module, b"WintunGetRunningDriverVersion\0")?;
            let start_session = get_sym(module, b"WintunStartSession\0")?;
            let end_session = get_sym(module, b"WintunEndSession\0")?;
            let get_read_wait_event = get_sym(module, b"WintunGetReadWaitEvent\0")?;
            let receive_packet = get_sym(module, b"WintunReceivePacket\0")?;
            let release_receive_packet = get_sym(module, b"WintunReleaseReceivePacket\0")?;
            let allocate_send_packet = get_sym(module, b"WintunAllocateSendPacket\0")?;
            let send_packet = get_sym(module, b"WintunSendPacket\0")?;

            guard.0 = ptr::null_mut();
            Ok(Self {
                _module: module,
                create_adapter,
                open_adapter,
                close_adapter,
                delete_driver,
                get_adapter_luid,
                get_running_driver_version,
                start_session,
                end_session,
                get_read_wait_event,
                receive_packet,
                release_receive_packet,
                allocate_send_packet,
                send_packet,
            })
        }
    }
}

impl Drop for WintunDll {
    fn drop(&mut self) {
        if !self._module.is_null() && self._module != INVALID_HANDLE_VALUE {
            unsafe {
                FreeLibrary(self._module);
            }
        }
    }
}

/// Fallback adapter for Wintun driver layer.
pub struct WintunAdapter {
    handle: WintunAdapterHandle,
}

unsafe impl Send for WintunAdapter {}
unsafe impl Sync for WintunAdapter {}

impl WintunAdapter {
    pub fn create(
        name: &str,
        tunnel_type: &str,
        requested_guid: Option<&windows_sys::core::GUID>,
    ) -> Result<Self> {
        let dll = WintunDll::load()?;
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
            return Err(DriverError::last_win32_error("WintunCreateAdapter"));
        }

        tracing::info!(name, "created Wintun fallback adapter");
        Ok(Self { handle })
    }

    pub fn open(name: &str) -> Result<Self> {
        let dll = WintunDll::load()?;
        let handle = with_wide_null(name, |name_w| unsafe { (dll.open_adapter)(name_w) });
        if handle.is_null() {
            return Err(DriverError::last_win32_error("WintunOpenAdapter"));
        }

        tracing::info!(name, "opened existing Wintun fallback adapter");
        Ok(Self { handle })
    }

    pub fn luid(&self) -> Result<u64> {
        let dll = WintunDll::load()?;
        let mut luid: u64 = 0;
        unsafe {
            (dll.get_adapter_luid)(self.handle, &mut luid);
        }
        Ok(luid)
    }

    pub fn running_driver_version() -> Result<u32> {
        let dll = WintunDll::load()?;
        let ver = unsafe { (dll.get_running_driver_version)() };
        if ver == 0 {
            return Err(DriverError::last_win32_error("WintunGetRunningDriverVersion"));
        }
        Ok(ver)
    }

    pub fn delete_driver() -> Result<()> {
        let dll = WintunDll::load()?;
        let ok = unsafe { (dll.delete_driver)() };
        if ok == 0 {
            return Err(DriverError::last_win32_error("WintunDeleteDriver"));
        }
        tracing::info!("Wintun driver uninstalled successfully");
        Ok(())
    }

    pub fn start_session(&self, ring_capacity: u32) -> Result<WintunSession> {
        let dll = WintunDll::load()?;
        let session = unsafe { (dll.start_session)(self.handle, ring_capacity) };
        if session.is_null() {
            return Err(DriverError::last_win32_error("WintunStartSession"));
        }
        Ok(WintunSession { handle: session })
    }
}

impl Drop for WintunAdapter {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            if let Ok(dll) = WintunDll::load() {
                unsafe {
                    (dll.close_adapter)(self.handle);
                }
            }
        }
    }
}

/// Active packet transmission session with Wintun driver.
pub struct WintunSession {
    handle: WintunSessionHandle,
}

unsafe impl Send for WintunSession {}
unsafe impl Sync for WintunSession {}

impl WintunSession {
    /// Returns the Win32 event signaled when new packets are available to receive.
    pub fn read_wait_event(&self) -> Result<HANDLE> {
        let dll = WintunDll::load()?;
        let event = unsafe { (dll.get_read_wait_event)(self.handle) };
        if event.is_null() || event == INVALID_HANDLE_VALUE {
            return Err(DriverError::last_win32_error("WintunGetReadWaitEvent"));
        }
        Ok(event)
    }

    /// Attempts to receive a packet from the ring buffer.
    ///
    /// If no packet is available, returns `Ok(None)`.
    pub unsafe fn receive_packet(&self) -> Result<Option<(*const u8, u32)>> {
        let dll = WintunDll::load()?;
        let mut packet_size: u32 = 0;
        let ptr = (dll.receive_packet)(self.handle, &mut packet_size);
        if ptr.is_null() {
            let err = windows_sys::Win32::Foundation::GetLastError();
            if err == windows_sys::Win32::Foundation::ERROR_NO_MORE_ITEMS {
                return Ok(None);
            }
            return Err(DriverError::from_win32_error("WintunReceivePacket", err));
        }
        Ok(Some((ptr, packet_size)))
    }

    /// Releases a previously received packet buffer.
    pub unsafe fn release_receive_packet(&self, packet: *const u8) -> Result<()> {
        let dll = WintunDll::load()?;
        (dll.release_receive_packet)(self.handle, packet);
        Ok(())
    }

    /// Allocates an outbound packet buffer in the transmit ring.
    pub unsafe fn allocate_send_packet(&self, size: u32) -> Result<*mut u8> {
        let dll = WintunDll::load()?;
        let ptr = (dll.allocate_send_packet)(self.handle, size);
        if ptr.is_null() {
            return Err(DriverError::last_win32_error("WintunAllocateSendPacket"));
        }
        Ok(ptr)
    }

    /// Queues the allocated packet for transmission.
    pub unsafe fn send_packet(&self, packet: *const u8) -> Result<()> {
        let dll = WintunDll::load()?;
        (dll.send_packet)(self.handle, packet);
        Ok(())
    }
}

impl Drop for WintunSession {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            if let Ok(dll) = WintunDll::load() {
                unsafe {
                    (dll.end_session)(self.handle);
                }
            }
        }
    }
}
