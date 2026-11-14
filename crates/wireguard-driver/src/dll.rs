use std::ffi::c_void;
use std::sync::{Mutex, OnceLock};
use windows_sys::Win32::Foundation::{BOOL, FreeLibrary, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::LibraryLoader::{
    FindResourceW, GetProcAddress, LoadLibraryExW, LoadResource, LockResource, SizeofResource,
    LOAD_LIBRARY_AS_DATAFILE, LOAD_LIBRARY_SEARCH_APPLICATION_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use wireguard_memmod::MemoryModule;
use crate::error::{DriverError, Result};

pub type WireGuardAdapterHandle = *mut c_void;

/// C ABI function prototypes from `wireguard.h`.
pub type WireGuardCreateAdapterFn = unsafe extern "system" fn(
    name: *const u16,
    tunnel_type: *const u16,
    requested_guid: *const c_void,
) -> WireGuardAdapterHandle;

pub type WireGuardOpenAdapterFn = unsafe extern "system" fn(name: *const u16) -> WireGuardAdapterHandle;

pub type WireGuardCloseAdapterFn = unsafe extern "system" fn(adapter: WireGuardAdapterHandle);

pub type WireGuardDeleteDriverFn = unsafe extern "system" fn() -> BOOL;

pub type WireGuardGetAdapterLuidFn = unsafe extern "system" fn(adapter: WireGuardAdapterHandle, luid: *mut u64);

pub type WireGuardGetRunningDriverVersionFn = unsafe extern "system" fn() -> u32;

pub type WireGuardSetAdapterLoggingFn = unsafe extern "system" fn(adapter: WireGuardAdapterHandle, log_state: u32) -> BOOL;

pub type WireGuardSetAdapterStateFn = unsafe extern "system" fn(adapter: WireGuardAdapterHandle, state: u32) -> BOOL;

pub type WireGuardGetAdapterStateFn = unsafe extern "system" fn(adapter: WireGuardAdapterHandle, state: *mut u32) -> BOOL;

pub type WireGuardSetConfigurationFn = unsafe extern "system" fn(
    adapter: WireGuardAdapterHandle,
    config: *const u8,
    size: u32,
) -> BOOL;

pub type WireGuardGetConfigurationFn = unsafe extern "system" fn(
    adapter: WireGuardAdapterHandle,
    config: *mut u8,
    size: *mut u32,
) -> BOOL;

pub type WireGuardLoggerCallback = unsafe extern "system" fn(level: u32, timestamp: u64, msg: *const u16);

pub type WireGuardSetLoggerFn = unsafe extern "system" fn(callback: Option<WireGuardLoggerCallback>);

/// Dynamic bindings to `wireguard.dll`.
pub struct WireGuardDll {
    _module: HANDLE,
    _memmod: Option<MemoryModule>,
    pub create_adapter: WireGuardCreateAdapterFn,
    pub open_adapter: WireGuardOpenAdapterFn,
    pub close_adapter: WireGuardCloseAdapterFn,
    pub delete_driver: WireGuardDeleteDriverFn,
    pub get_adapter_luid: WireGuardGetAdapterLuidFn,
    pub get_running_driver_version: WireGuardGetRunningDriverVersionFn,
    pub set_adapter_logging: WireGuardSetAdapterLoggingFn,
    pub set_adapter_state: WireGuardSetAdapterStateFn,
    pub get_adapter_state: WireGuardGetAdapterStateFn,
    pub set_configuration: WireGuardSetConfigurationFn,
    pub get_configuration: WireGuardGetConfigurationFn,
    pub set_logger: Option<WireGuardSetLoggerFn>,
}

unsafe impl Send for WireGuardDll {}
unsafe impl Sync for WireGuardDll {}

static WIREGUARD_DLL_INSTANCE: OnceLock<WireGuardDll> = OnceLock::new();
static WIREGUARD_DLL_INIT_LOCK: Mutex<()> = Mutex::new(());

struct FreeLibGuard(HANDLE);

impl Drop for FreeLibGuard {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                FreeLibrary(self.0);
            }
            self.0 = std::ptr::null_mut();
        }
    }
}

trait SymResolver {
    unsafe fn resolve<T: Copy>(&self, sym_nul: &'static [u8]) -> Result<T>;
}

impl SymResolver for MemoryModule {
    unsafe fn resolve<T: Copy>(&self, sym_nul: &'static [u8]) -> Result<T> {
        let name = std::str::from_utf8(&sym_nul[..sym_nul.len().saturating_sub(1)]).unwrap_or("unknown");
        self.get_proc(name).map_err(|_| DriverError::ProcNotFound { symbol: name })
    }
}

struct ModuleSyms(HANDLE);

impl SymResolver for ModuleSyms {
    unsafe fn resolve<T: Copy>(&self, sym_nul: &'static [u8]) -> Result<T> {
        let proc = GetProcAddress(self.0, sym_nul.as_ptr());
        if proc.is_none() {
            let name = std::str::from_utf8(&sym_nul[..sym_nul.len().saturating_sub(1)]).unwrap_or("unknown");
            return Err(DriverError::ProcNotFound { symbol: name });
        }
        Ok(std::mem::transmute_copy(&proc))
    }
}

impl WireGuardDll {
    /// Returns the already-loaded `WireGuardDll` instance without loading it.
    pub(crate) fn get_loaded() -> Option<&'static Self> {
        WIREGUARD_DLL_INSTANCE.get()
    }

    /// Loads `wireguard.dll` from the system, application directory, or `RT_RCDATA` embedded resource.
    pub fn load() -> Result<&'static Self> {
        if let Some(dll) = WIREGUARD_DLL_INSTANCE.get() {
            return Ok(dll);
        }

        let _init_guard = WIREGUARD_DLL_INIT_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(dll) = WIREGUARD_DLL_INSTANCE.get() {
            return Ok(dll);
        }

        let dll = Self::load_from_name("wireguard.dll")
            .or_else(|_| Self::load_from_host_wireguard_resource())?;
        let _ = WIREGUARD_DLL_INSTANCE.set(dll);
        Ok(WIREGUARD_DLL_INSTANCE.get().unwrap())
    }

    unsafe fn from_resolver(
        module: HANDLE,
        resolver: &impl SymResolver,
    ) -> Result<Self> {
        Ok(Self {
            _module: module,
            _memmod: None,
            create_adapter: resolver.resolve(b"WireGuardCreateAdapter\0")?,
            open_adapter: resolver.resolve(b"WireGuardOpenAdapter\0")?,
            close_adapter: resolver.resolve(b"WireGuardCloseAdapter\0")?,
            delete_driver: resolver.resolve(b"WireGuardDeleteDriver\0")?,
            get_adapter_luid: resolver.resolve(b"WireGuardGetAdapterLUID\0")?,
            get_running_driver_version: resolver.resolve(b"WireGuardGetRunningDriverVersion\0")?,
            set_adapter_logging: resolver.resolve(b"WireGuardSetAdapterLogging\0")?,
            set_adapter_state: resolver.resolve(b"WireGuardSetAdapterState\0")?,
            get_adapter_state: resolver.resolve(b"WireGuardGetAdapterState\0")?,
            set_configuration: resolver.resolve(b"WireGuardSetConfiguration\0")?,
            get_configuration: resolver.resolve(b"WireGuardGetConfiguration\0")?,
            set_logger: resolver.resolve(b"WireGuardSetLogger\0").ok(),
        })
    }

    /// Loads the WHQL-signed `wireguard.dll` embedded in the current executable (`NULL`)
    /// or `C:\Program Files\WireGuard\wireguard.exe` (`RT_RCDATA` resource `"wireguard.dll"`)
    /// using `MemoryModule`.
    pub fn load_from_host_wireguard_resource() -> Result<Self> {
        const RT_RCDATA_ID: *const u16 = 10usize as *const u16;

        with_wide_null("wireguard.dll", |res_name_ptr| unsafe {
            // 1. First try the currently running executable image (hModule = NULL)
            let mut h_mod: HANDLE = std::ptr::null_mut();
            let mut free_guard = FreeLibGuard(std::ptr::null_mut());
            let mut h_res = FindResourceW(h_mod, res_name_ptr, RT_RCDATA_ID);

            // 2. Fallback to C:\Program Files\WireGuard\wireguard.exe if running from another binary
            if h_res.is_null() {
                h_mod = with_wide_null(r"C:\Program Files\WireGuard\wireguard.exe", |host_exe| {
                    LoadLibraryExW(host_exe, std::ptr::null_mut(), LOAD_LIBRARY_AS_DATAFILE)
                });
                if h_mod.is_null() || h_mod == INVALID_HANDLE_VALUE {
                    return Err(DriverError::last_win32_error(
                        "LoadLibraryExW(C:\\Program Files\\WireGuard\\wireguard.exe)",
                    ));
                }
                free_guard.0 = h_mod;
                h_res = FindResourceW(h_mod, res_name_ptr, RT_RCDATA_ID);
                if h_res.is_null() {
                    return Err(DriverError::last_win32_error("FindResourceW(wireguard.dll)"));
                }
            }

            let size = SizeofResource(h_mod, h_res) as usize;
            let h_glob = LoadResource(h_mod, h_res);
            if h_glob.is_null() || size == 0 {
                return Err(DriverError::last_win32_error("LoadResource(wireguard.dll)"));
            }

            let ptr = LockResource(h_glob) as *const u8;
            if ptr.is_null() {
                return Err(DriverError::last_win32_error("LockResource(wireguard.dll)"));
            }

            // Load directly from the locked resource view; `free_guard` drops after `MemoryModule::load`.
            let slice = std::slice::from_raw_parts(ptr, size);
            let memmod = MemoryModule::load(slice).map_err(|_| DriverError::ProcNotFound {
                symbol: "MemoryModule::load(wireguard.dll)",
            })?;
            drop(free_guard);

            let mut dll = Self::from_resolver(std::ptr::null_mut(), &memmod)?;
            dll._memmod = Some(memmod);
            Ok(dll)
        })
    }

    /// Loads the DLL with a specified name or path.
    pub fn load_from_name(name: &str) -> Result<Self> {
        let module = with_wide_null(name, |name_ptr| unsafe {
            LoadLibraryExW(
                name_ptr,
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        });

        if module.is_null() || module == INVALID_HANDLE_VALUE {
            return Err(DriverError::last_win32_error("LoadLibraryExW(wireguard.dll)"));
        }

        let mut guard = FreeLibGuard(module);
        let dll = unsafe { Self::from_resolver(module, &ModuleSyms(module))? };
        guard.0 = std::ptr::null_mut();
        Ok(dll)
    }
}

impl Drop for WireGuardDll {
    fn drop(&mut self) {
        if !self._module.is_null() && self._module != INVALID_HANDLE_VALUE {
            unsafe {
                FreeLibrary(self._module);
            }
        }
    }
}

/// Converts a UTF-8 string into a null-terminated UTF-16 pointer without heap allocation
/// when the string fits in a 128-unit stack buffer.
#[inline]
pub(crate) fn with_wide_null<R>(s: &str, f: impl FnOnce(*const u16) -> R) -> R {
    let mut stack = [0u16; 128];
    let heap: Vec<u16>;
    let ptr = if s.len() < stack.len() {
        let mut idx = 0;
        for u in s.encode_utf16() {
            if idx + 1 >= stack.len() {
                idx = usize::MAX;
                break;
            }
            stack[idx] = u;
            idx += 1;
        }
        if idx != usize::MAX {
            stack[idx] = 0;
            stack.as_ptr()
        } else {
            heap = s.encode_utf16().chain(std::iter::once(0)).collect();
            heap.as_ptr()
        }
    } else {
        heap = s.encode_utf16().chain(std::iter::once(0)).collect();
        heap.as_ptr()
    };
    f(ptr)
}
