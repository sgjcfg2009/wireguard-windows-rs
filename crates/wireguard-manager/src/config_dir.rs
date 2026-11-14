// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.

//! Configuration directory manager.
//!
//! Manages DPAPI-encrypted WireGuard configurations in `C:\Program Files\WireGuard\Data`
//! with strict security permissions (`O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`).

use std::fs;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::thread;
use std::time::Duration;
use tracing::{debug, error, info, warn};

use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    SetKernelObjectSecurity, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, FindCloseChangeNotification, FindFirstChangeNotificationW,
    FindNextChangeNotification, FlushFileBuffers, GetFileInformationByHandle,
    GetFinalPathNameByHandleW, WriteFile, BY_HANDLE_FILE_INFORMATION,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_WRITE,
    FILE_NOTIFY_CHANGE_ATTRIBUTES, FILE_NOTIFY_CHANGE_CREATION, FILE_NOTIFY_CHANGE_DIR_NAME,
    FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_ACCESS, FILE_NOTIFY_CHANGE_LAST_WRITE,
    FILE_NOTIFY_CHANGE_SECURITY, FILE_NOTIFY_CHANGE_SIZE, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_ALWAYS, OPEN_EXISTING, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, SetEvent, WaitForMultipleObjects, WaitForSingleObject, INFINITE,
};

use wireguard_conf::{
    name_from_path, tunnel_name_is_valid, CONFIG_FILE_SUFFIX,
    CONFIG_FILE_UNENCRYPTED_SUFFIX,
};
use wireguard_types::TunnelConfig;

use crate::error::ManagerError;
use crate::wide::{with_path_wide_null, with_wide_null};

/// Strict SDDL for the WireGuard Data directory.
/// SYSTEM (SY) and Built-in Administrators (BA) receive Full Access (FA)
/// with Object Inherit (OI) and Container Inherit (CI). DACL is Protected (PAI).
pub const DATA_DIR_SDDL: &str = "O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// Strict SDDL for individual encrypted configuration files.
/// SYSTEM receives Full Access (FA), Administrators receive Standard Delete (SD).
pub const ENCRYPTED_FILE_SDDL: &str = "O:SYG:SYD:PAI(A;;FA;;;SY)(A;;SD;;;BA)";

static CUSTOM_ROOT_DIR: OnceLock<RwLock<Option<PathBuf>>> = OnceLock::new();

fn get_root_lock() -> &'static RwLock<Option<PathBuf>> {
    CUSTOM_ROOT_DIR.get_or_init(|| RwLock::new(None))
}

/// Allows overriding the root directory (useful for testing or non-standard deployments).
pub fn set_custom_root_dir(path: PathBuf) {
    let mut lock = get_root_lock().write().unwrap();
    *lock = Some(path);
}

/// Safe RAII wrapper around a Win32 Security Descriptor created from SDDL.
pub struct SecurityDescriptorWrapper(PSECURITY_DESCRIPTOR);

unsafe impl Send for SecurityDescriptorWrapper {}
unsafe impl Sync for SecurityDescriptorWrapper {}

impl SecurityDescriptorWrapper {
    pub fn from_sddl(sddl: &str) -> Result<Self, ManagerError> {
        let mut p_sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let ok = with_wide_null(sddl, |wide| unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide,
                SDDL_REVISION_1,
                &mut p_sd,
                ptr::null_mut(),
            )
        });
        if ok == 0 || p_sd.is_null() {
            return Err(ManagerError::last_win32("ConvertStringSecurityDescriptorToSecurityDescriptorW"));
        }
        Ok(Self(p_sd))
    }

    pub fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0
    }

    pub fn to_security_attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }
}

impl Drop for SecurityDescriptorWrapper {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0 as _);
            }
            self.0 = ptr::null_mut();
        }
    }
}

struct StopEvent(HANDLE);

unsafe impl Send for StopEvent {}
unsafe impl Sync for StopEvent {}

impl StopEvent {
    fn new() -> Result<Self, ManagerError> {
        let handle = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if handle.is_null() {
            return Err(ManagerError::last_win32("CreateEventW"));
        }
        Ok(Self(handle))
    }

    fn signal(&self) {
        unsafe {
            SetEvent(self.0);
        }
    }

    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for StopEvent {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
            self.0 = ptr::null_mut();
        }
    }
}

/// RAII guard for the background configuration directory change watcher thread.
///
/// Signals cancellation via a manual-reset Win32 event and joins the watcher
/// thread on [`stop`](Self::stop) or [`Drop`].
pub struct ConfigDirWatcher {
    stop_event: Arc<StopEvent>,
    thread: Option<thread::JoinHandle<()>>,
}

impl ConfigDirWatcher {
    /// Signals the watcher thread to stop without waiting for it to exit.
    pub fn signal_stop(&self) {
        self.stop_event.signal();
    }

    /// Signals cancellation and waits cleanly for the watcher thread to finish.
    pub fn stop(mut self) {
        self.stop_inner();
    }

    fn stop_inner(&mut self) {
        self.stop_event.signal();
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for ConfigDirWatcher {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

/// Manages WireGuard configuration storage on Windows.
#[derive(Clone)]
pub struct ConfigDirManager {
    data_dir: PathBuf,
    configurations_dir: PathBuf,
    change_callbacks: Arc<Mutex<Vec<Box<dyn Fn() + Send + Sync + 'static>>>>,
    active_stop_event: Arc<Mutex<Option<Arc<StopEvent>>>>,
}

pub type ConfigDir = ConfigDirManager;

impl ConfigDirManager {
    /// Opens the default WireGuard data directory.
    pub fn open_default() -> Result<Self, ManagerError> {
        Self::new()
    }

    /// Creates or resolves the WireGuard data directory structure with strict Win32 security permissions.
    pub fn new() -> Result<Self, ManagerError> {
        let root = Self::resolve_data_directory(true)?;
        let configurations_dir = root.join("Configurations");

        if !configurations_dir.exists() {
            fs::create_dir_all(&configurations_dir)?;
        }

        Ok(Self {
            data_dir: root,
            configurations_dir,
            change_callbacks: Arc::new(Mutex::new(Vec::new())),
            active_stop_event: Arc::new(Mutex::new(None)),
        })
    }

    /// Resolves the canonical `C:\Program Files\WireGuard\Data` path.
    pub fn resolve_data_directory(create: bool) -> Result<PathBuf, ManagerError> {
        if let Some(custom) = get_root_lock().read().unwrap().as_ref() {
            if create && !custom.exists() {
                fs::create_dir_all(custom)?;
            }
            return Ok(custom.clone());
        }

        let program_files = std::env::var("ProgramFiles")
            .unwrap_or_else(|_| r"C:\Program Files".to_string());
        let wireguard_dir = Path::new(&program_files).join("WireGuard");
        let data_dir = wireguard_dir.join("Data");

        if !create {
            return Ok(data_dir);
        }

        // Create WireGuard parent dir (inherits ACL from Program Files)
        with_path_wide_null(&wireguard_dir, |wg_wide| unsafe {
            CreateDirectoryW(wg_wide, ptr::null());
        });

        // Prepare strict security attributes for Data directory
        let sd = SecurityDescriptorWrapper::from_sddl(DATA_DIR_SDDL)?;
        let mut sa = sd.to_security_attributes();

        // Create directory with security attributes
        let data_handle: HANDLE = with_path_wide_null(&data_dir, |data_wide| {
            let mut handle: HANDLE = INVALID_HANDLE_VALUE;
            for _ in 0..10 {
                unsafe {
                    CreateDirectoryW(data_wide, &mut sa);
                }

                handle = unsafe {
                    CreateFileW(
                        data_wide,
                        READ_CONTROL | WRITE_OWNER | WRITE_DAC,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        ptr::null(),
                        OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                        ptr::null_mut(),
                    )
                };

                if handle != INVALID_HANDLE_VALUE {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
            handle
        });

        if data_handle == INVALID_HANDLE_VALUE {
            return Err(ManagerError::last_win32("CreateFileW(DataDir)"));
        }

        // Verify directory properties (prevent reparse point / junction hijacking)
        let mut file_info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        let ok = unsafe { GetFileInformationByHandle(data_handle, &mut file_info) };
        if ok == 0 {
            unsafe { CloseHandle(data_handle) };
            return Err(ManagerError::last_win32("GetFileInformationByHandle"));
        }

        if file_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            unsafe { CloseHandle(data_handle) };
            return Err(ManagerError::DataDirectory("Data path is not a directory".into()));
        }

        if file_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            unsafe { CloseHandle(data_handle) };
            return Err(ManagerError::DataDirectory("Data directory is a reparse point/junction".into()));
        }

        // Verify path canonical location (stack-buffered with heap fallback for very long paths)
        let mut stack_path = [0u16; 512];
        let mut len = unsafe {
            GetFinalPathNameByHandleW(
                data_handle,
                stack_path.as_mut_ptr(),
                stack_path.len() as u32,
                0,
            )
        };
        let mut heap_path: Vec<u16> = Vec::new();
        let final_slice: Option<&[u16]> = if len > 0 && (len as usize) < stack_path.len() {
            Some(&stack_path[..len as usize])
        } else if (len as usize) >= stack_path.len() {
            heap_path.resize(len as usize, 0);
            len = unsafe {
                GetFinalPathNameByHandleW(
                    data_handle,
                    heap_path.as_mut_ptr(),
                    heap_path.len() as u32,
                    0,
                )
            };
            if len > 0 && (len as usize) < heap_path.len() {
                Some(&heap_path[..len as usize])
            } else {
                None
            }
        } else {
            None
        };

        if let Some(slice) = final_slice {
            let final_str = String::from_utf16_lossy(slice);
            let canonical = final_str.strip_prefix(r"\\?\").unwrap_or(&final_str);
            let expected = data_dir.to_string_lossy();
            if !canonical.eq_ignore_ascii_case(expected.as_ref()) {
                warn!(
                    "Data directory final path '{}' differs from expected '\\\\?\\{}'",
                    final_str, expected
                );
            }
        }

        // Apply strict kernel object security
        let sec_ok = unsafe {
            SetKernelObjectSecurity(
                data_handle,
                DACL_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION
                    | OWNER_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                sd.as_ptr(),
            )
        };

        unsafe { CloseHandle(data_handle) };

        if sec_ok == 0 {
            return Err(ManagerError::last_win32("SetKernelObjectSecurity(DataDir)"));
        }

        Ok(data_dir)
    }

    /// Returns the data directory path.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Returns the configurations directory (`Data/Configurations`).
    pub fn configurations_dir(&self) -> &Path {
        &self.configurations_dir
    }

    /// Returns the path to the binary ringlog file (`Data/log.bin`).
    pub fn log_file_path(&self) -> PathBuf {
        self.data_dir.join("log.bin")
    }

    /// Returns the expected encrypted file path for a tunnel (`Configurations/<name>.conf.dpapi`).
    pub fn config_path(&self, tunnel_name: &str) -> Result<PathBuf, ManagerError> {
        if !tunnel_name_is_valid(tunnel_name) {
            return Err(ManagerError::InvalidTunnelName(tunnel_name.to_string()));
        }
        Ok(self.configurations_dir.join(format!("{tunnel_name}{CONFIG_FILE_SUFFIX}")))
    }

    /// Lists all available tunnel names in the configurations directory.
    pub fn list_tunnel_names(&self) -> Result<Vec<String>, ManagerError> {
        let mut names = Vec::new();
        if !self.configurations_dir.exists() {
            return Ok(names);
        }

        for entry in fs::read_dir(&self.configurations_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !entry.file_type()?.is_file() {
                continue;
            }

            if let Ok(name) = name_from_path(&path) {
                if tunnel_name_is_valid(&name) && !names.contains(&name) {
                    names.push(name);
                }
            }
        }

        names.sort();
        Ok(names)
    }

    /// Writes an encrypted configuration file atomically with strict security descriptors.
    pub fn save_config(
        &self,
        config: &TunnelConfig,
        overwrite: bool,
    ) -> Result<PathBuf, ManagerError> {
        if !tunnel_name_is_valid(&config.name) {
            return Err(ManagerError::InvalidTunnelName(config.name.clone()));
        }

        let destination = self.config_path(&config.name)?;
        if destination.exists() && !overwrite {
            return Err(ManagerError::DataDirectory(format!(
                "Configuration '{}' already exists",
                config.name
            )));
        }

        // Serialize to wg-quick format
        let conf_text = wireguard_conf::to_wg_quick(config);
        let conf_bytes = conf_text.as_bytes();

        // Encrypt using DPAPI with tunnel name as description
        let encrypted_bytes = wireguard_dpapi::encrypt(conf_bytes, Some(&config.name))?;

        // Write locked-down atomic file
        Self::write_locked_down_file(&destination, overwrite, &encrypted_bytes)?;

        info!("Saved encrypted configuration for tunnel '{}' to {:?}", config.name, destination);
        Ok(destination)
    }

    /// Loads and decrypts a tunnel configuration from disk.
    pub fn load_config(&self, tunnel_name: &str) -> Result<TunnelConfig, ManagerError> {
        if !tunnel_name_is_valid(tunnel_name) {
            return Err(ManagerError::InvalidTunnelName(tunnel_name.to_string()));
        }

        let encrypted_path = self.config_path(tunnel_name)?;
        let unencrypted_path = self.configurations_dir.join(format!("{tunnel_name}{CONFIG_FILE_UNENCRYPTED_SUFFIX}"));

        let (bytes, is_encrypted) = if encrypted_path.exists() {
            (fs::read(&encrypted_path)?, true)
        } else if unencrypted_path.exists() {
            (fs::read(&unencrypted_path)?, false)
        } else {
            return Err(ManagerError::DataDirectory(format!(
                "Configuration file for '{}' not found",
                tunnel_name
            )));
        };

        let decrypted_bytes = if is_encrypted {
            wireguard_dpapi::decrypt_with_expected_description(&bytes, tunnel_name)?
        } else {
            bytes
        };

        let conf = wireguard_conf::parse_config_bytes(&decrypted_bytes, tunnel_name)
            .map_err(|e| ManagerError::ConfigParse(e.to_string()))?;

        Ok(conf)
    }

    /// Deletes a configuration file from disk.
    pub fn delete_config(&self, tunnel_name: &str) -> Result<(), ManagerError> {
        if !tunnel_name_is_valid(tunnel_name) {
            return Err(ManagerError::InvalidTunnelName(tunnel_name.to_string()));
        }

        let encrypted_path = self.config_path(tunnel_name)?;
        let unencrypted_path = self.configurations_dir.join(format!("{tunnel_name}{CONFIG_FILE_UNENCRYPTED_SUFFIX}"));

        let mut deleted = false;
        if encrypted_path.exists() {
            fs::remove_file(&encrypted_path)?;
            deleted = true;
        }
        if unencrypted_path.exists() {
            fs::remove_file(&unencrypted_path)?;
            deleted = true;
        }

        if !deleted {
            return Err(ManagerError::DataDirectory(format!(
                "Configuration for '{}' does not exist",
                tunnel_name
            )));
        }

        info!("Deleted configuration for tunnel '{}'", tunnel_name);
        Ok(())
    }

    /// Migrates any legacy unencrypted `.conf` files to `.conf.dpapi`.
    pub fn migrate_unencrypted<F>(&self, on_migrated: F) -> Result<(), ManagerError>
    where
        F: Fn(&str, &Path, &Path),
    {
        if !self.configurations_dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(&self.configurations_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !entry.file_type()?.is_file() {
                continue;
            }

            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();
            if !name_str.ends_with(CONFIG_FILE_UNENCRYPTED_SUFFIX) || name_str.ends_with(CONFIG_FILE_SUFFIX) {
                continue;
            }

            let tunnel_name = &name_str[..name_str.len() - CONFIG_FILE_UNENCRYPTED_SUFFIX.len()];
            if !tunnel_name_is_valid(tunnel_name) {
                continue;
            }

            match fs::read(&path) {
                Ok(bytes) => match wireguard_conf::parse_config_bytes(&bytes, tunnel_name) {
                    Ok(config) => {
                        match self.save_config(&config, false) {
                            Ok(new_path) => {
                                let _ = fs::remove_file(&path);
                                info!("Migrated unencrypted config '{tunnel_name}' to {:?}", new_path);
                                on_migrated(tunnel_name, &path, &new_path);
                            }
                            Err(e) => {
                                warn!("Failed to save migrated config '{tunnel_name}': {e}");
                            }
                        }
                    }
                    Err(e) => warn!("Failed to parse unencrypted config '{tunnel_name}' for migration: {e}"),
                },
                Err(e) => warn!("Failed to read unencrypted config '{tunnel_name}': {e}"),
            }
        }

        Ok(())
    }

    /// Writes a file securely with restricted permissions (`ENCRYPTED_FILE_SDDL`)
    /// by creating a temporary file and atomically renaming it.
    fn write_locked_down_file(
        destination: &Path,
        overwrite: bool,
        contents: &[u8],
    ) -> Result<(), ManagerError> {
        let parent = destination
            .parent()
            .ok_or_else(|| ManagerError::DataDirectory("Destination has no parent dir".into()))?;

        // Generate temporary file name on the stack (32 hex chars + ".tmp")
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let rand_bytes: [u8; 16] = rand_compat();
        let mut tmp_name_bytes = [0u8; 36];
        for (i, &b) in rand_bytes.iter().enumerate() {
            tmp_name_bytes[i * 2] = HEX[(b >> 4) as usize];
            tmp_name_bytes[i * 2 + 1] = HEX[(b & 0x0f) as usize];
        }
        tmp_name_bytes[32..36].copy_from_slice(b".tmp");
        let tmp_name = std::str::from_utf8(&tmp_name_bytes).expect("ASCII hex filename");
        let tmp_path = parent.join(tmp_name);

        let sd = SecurityDescriptorWrapper::from_sddl(ENCRYPTED_FILE_SDDL)?;
        let mut sa = sd.to_security_attributes();

        let handle = with_path_wide_null(&tmp_path, |tmp_wide| unsafe {
            CreateFileW(
                tmp_wide,
                FILE_GENERIC_WRITE,
                FILE_SHARE_READ,
                &mut sa,
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        });

        if handle == INVALID_HANDLE_VALUE {
            return Err(ManagerError::last_win32("CreateFileW(temp)"));
        }

        let mut bytes_written: u32 = 0;
        let write_ok = unsafe {
            WriteFile(
                handle,
                contents.as_ptr(),
                contents.len() as u32,
                &mut bytes_written,
                ptr::null_mut(),
            )
        };

        if write_ok == 0 || (bytes_written as usize) != contents.len() {
            unsafe { CloseHandle(handle) };
            let _ = fs::remove_file(&tmp_path);
            return Err(ManagerError::last_win32("WriteFile(temp)"));
        }

        let flush_ok = unsafe { FlushFileBuffers(handle) };
        unsafe { CloseHandle(handle) };

        if flush_ok == 0 {
            let _ = fs::remove_file(&tmp_path);
            return Err(ManagerError::last_win32("FlushFileBuffers(temp)"));
        }

        // Rename atomically using std::fs::rename or copy
        if overwrite && destination.exists() {
            let _ = fs::remove_file(destination);
        }

        if let Err(e) = fs::rename(&tmp_path, destination) {
            let _ = fs::remove_file(&tmp_path);
            return Err(ManagerError::Io(e));
        }

        Ok(())
    }

    /// Registers a change callback to be triggered when the configurations directory changes.
    pub fn register_change_callback<F>(&self, cb: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        self.change_callbacks.lock().unwrap().push(Box::new(cb));
    }

    /// Signals any active watcher started by this manager to stop.
    pub fn stop_watcher(&self) {
        if let Some(ev) = self.active_stop_event.lock().unwrap().as_ref() {
            ev.signal();
        }
    }

    /// Starts a cleanly stoppable background watcher thread for configuration directory changes.
    ///
    /// Uses a manual-reset Win32 event with `WaitForMultipleObjects` and bounded
    /// exponential backoff on transient failures, replacing unbounded polling sleeps.
    pub fn start_watcher(&self) -> Result<ConfigDirWatcher, ManagerError> {
        const INITIAL_BACKOFF_MS: u32 = 250;
        const MAX_BACKOFF_MS: u32 = 5_000;

        let stop = Arc::new(StopEvent::new()?);
        if let Some(prev) = self.active_stop_event.lock().unwrap().replace(Arc::clone(&stop)) {
            prev.signal();
        }

        let dir = self.configurations_dir.clone();
        let callbacks = Arc::clone(&self.change_callbacks);
        let thread_stop = Arc::clone(&stop);

        let thread = thread::Builder::new()
            .name("config-dir-watcher".to_string())
            .spawn(move || {
                let mut backoff_ms = INITIAL_BACKOFF_MS;

                loop {
                    if unsafe { WaitForSingleObject(thread_stop.raw(), 0) } == WAIT_OBJECT_0 {
                        break;
                    }

                    let handle = with_path_wide_null(&dir, |wide| unsafe {
                        FindFirstChangeNotificationW(
                            wide,
                            0, // do not watch subtree
                            FILE_NOTIFY_CHANGE_FILE_NAME
                                | FILE_NOTIFY_CHANGE_DIR_NAME
                                | FILE_NOTIFY_CHANGE_ATTRIBUTES
                                | FILE_NOTIFY_CHANGE_SIZE
                                | FILE_NOTIFY_CHANGE_LAST_WRITE
                                | FILE_NOTIFY_CHANGE_LAST_ACCESS
                                | FILE_NOTIFY_CHANGE_CREATION
                                | FILE_NOTIFY_CHANGE_SECURITY,
                        )
                    });

                    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
                        error!(
                            "FindFirstChangeNotificationW failed for {:?} (retry in {} ms)",
                            dir, backoff_ms
                        );
                        if unsafe { WaitForSingleObject(thread_stop.raw(), backoff_ms) }
                            == WAIT_OBJECT_0
                        {
                            break;
                        }
                        backoff_ms = (backoff_ms.saturating_mul(2)).min(MAX_BACKOFF_MS);
                        continue;
                    }

                    let handles = [thread_stop.raw(), handle];
                    let mut saw_change = false;

                    loop {
                        let wait = unsafe {
                            WaitForMultipleObjects(
                                handles.len() as u32,
                                handles.as_ptr(),
                                0,
                                INFINITE,
                            )
                        };

                        if wait == WAIT_OBJECT_0 {
                            unsafe { FindCloseChangeNotification(handle) };
                            return;
                        }

                        if wait == WAIT_OBJECT_0 + 1 {
                            saw_change = true;
                            backoff_ms = INITIAL_BACKOFF_MS;
                            debug!("Configuration directory change detected in {:?}", dir);
                            let cbs = callbacks.lock().unwrap();
                            for cb in cbs.iter() {
                                cb();
                            }
                            drop(cbs);

                            let next_ok = unsafe { FindNextChangeNotification(handle) };
                            if next_ok == 0 {
                                break;
                            }
                        } else {
                            if wait == WAIT_FAILED {
                                warn!("WaitForMultipleObjects failed in config watcher for {:?}", dir);
                            }
                            break;
                        }
                    }

                    unsafe { FindCloseChangeNotification(handle) };

                    if !saw_change {
                        if unsafe { WaitForSingleObject(thread_stop.raw(), backoff_ms) }
                            == WAIT_OBJECT_0
                        {
                            break;
                        }
                        backoff_ms = (backoff_ms.saturating_mul(2)).min(MAX_BACKOFF_MS);
                    } else {
                        backoff_ms = INITIAL_BACKOFF_MS;
                    }
                }
            })?;

        Ok(ConfigDirWatcher {
            stop_event: stop,
            thread: Some(thread),
        })
    }
}

/// Fallback pseudorandom byte generator using atomic sequence + stack entropy + timestamp.
fn rand_compat() -> [u8; 16] {
    static COUNTER: AtomicU64 = AtomicU64::new(1);

    let mut buf = [0u8; 16];
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed) as u128;
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let ptr_val = &buf as *const _ as usize;
    let seed = time ^ (ptr_val as u128) ^ (seq << 64) ^ seq.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let bytes = seed.to_le_bytes();
    buf.copy_from_slice(&bytes);
    buf
}
