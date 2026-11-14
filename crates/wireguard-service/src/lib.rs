// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.

//! Windows Service Control Manager (SCM) service lifecycle dispatcher, manager,
//! and security descriptor manipulation for WireGuard.

pub mod dispatcher;
pub mod error;
pub mod notify;
pub mod security;
mod wide;

pub use notify::{
    wait_scm_change, wait_service_status_change, watch_services, ScmServiceChange,
    ScmWaitOutcome, ScmWatchCancel, ServiceNotifyEvent, SERVICE_NOTIFY_ALL_STATES,
};

use std::ptr;
use thiserror::Error;
use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_SERVICE_DOES_NOT_EXIST,
};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfigW, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
    OpenSCManagerW, OpenServiceW, QueryServiceConfigW, QueryServiceStatus, StartServiceW,
    QUERY_SERVICE_CONFIGW, SC_HANDLE, SC_MANAGER_ALL_ACCESS, SERVICE_AUTO_START,
    SERVICE_CONTROL_STOP, SERVICE_QUERY_STATUS, SERVICE_STATUS,
};

use crate::wide::{with_opt_wide_null, with_wide_null};

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("failed to connect to Service Control Manager (Win32 error: {0})")]
    ConnectManager(u32),
    #[error("failed to open service '{name}' (Win32 error: {code})")]
    OpenService { name: String, code: u32 },
    #[error("failed to create service '{name}' (Win32 error: {code})")]
    CreateService { name: String, code: u32 },
    #[error("failed to start service '{name}' (Win32 error: {code})")]
    StartService { name: String, code: u32 },
    #[error("failed to stop service '{name}' (Win32 error: {code})")]
    StopService { name: String, code: u32 },
    #[error("failed to delete service '{name}' (Win32 error: {code})")]
    DeleteService { name: String, code: u32 },
    #[error("failed to query service '{name}' (Win32 error: {code})")]
    QueryService { name: String, code: u32 },
    #[error("failed to configure service '{name}' (Win32 error: {code})")]
    ConfigureService { name: String, code: u32 },
    #[error("service '{0}' already running")]
    AlreadyRunning(String),
    #[error("service '{0}' does not exist")]
    DoesNotExist(String),
    #[error("failed during SCM notification watch '{operation}' (Win32 error: {code})")]
    Notify { operation: &'static str, code: u32 },
}

/// RAII wrapper for an SCM handle (`SC_HANDLE`).
#[derive(Debug)]
pub struct ScmHandle(SC_HANDLE);

unsafe impl Send for ScmHandle {}
unsafe impl Sync for ScmHandle {}

impl ScmHandle {
    /// Opens the local Service Control Manager with the requested access rights.
    pub fn open(desired_access: u32) -> Result<Self, ServiceError> {
        let handle = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), desired_access) };
        if handle.is_null() {
            let code = unsafe { GetLastError() };
            return Err(ServiceError::ConnectManager(code));
        }
        Ok(Self(handle))
    }

    /// Opens the Service Control Manager on the specified host/database.
    pub fn open_sc_manager(
        machine_name: Option<&str>,
        database_name: Option<&str>,
        desired_access: u32,
    ) -> Result<Self, ServiceError> {
        let handle = with_opt_wide_null(machine_name, |machine_w| {
            with_opt_wide_null(database_name, |db_w| unsafe {
                OpenSCManagerW(machine_w, db_w, desired_access)
            })
        });
        if handle.is_null() {
            let code = unsafe { GetLastError() };
            return Err(ServiceError::ConnectManager(code));
        }
        Ok(Self(handle))
    }

    /// Opens the SCM with full management access (`SC_MANAGER_ALL_ACCESS`).
    pub fn open_all_access() -> Result<Self, ServiceError> {
        Self::open(SC_MANAGER_ALL_ACCESS)
    }

    /// Returns the raw `SC_HANDLE`.
    pub fn as_raw(&self) -> SC_HANDLE {
        self.0
    }

    /// Creates a new service in the SCM database.
    pub fn create_service(
        &self,
        service_name: &str,
        display_name: &str,
        desired_access: u32,
        service_type: u32,
        start_type: u32,
        error_control: u32,
        binary_path: &str,
        load_order_group: Option<&str>,
        dependencies: Option<&[&str]>,
        service_start_name: Option<&str>,
        password: Option<&str>,
    ) -> Result<ServiceHandle, ServiceError> {
        let deps_w = dependencies.map(|deps| {
            let total_units: usize =
                deps.iter().map(|d| d.encode_utf16().count() + 1).sum::<usize>() + 1;
            let mut v = Vec::with_capacity(total_units);
            for d in deps {
                v.extend(d.encode_utf16());
                v.push(0);
            }
            v.push(0);
            v
        });
        let deps_ptr = deps_w.as_ref().map(|v| v.as_ptr()).unwrap_or(ptr::null());

        let handle = with_wide_null(service_name, |svc_name_w| {
            with_wide_null(display_name, |disp_name_w| {
                with_wide_null(binary_path, |bin_path_w| {
                    with_opt_wide_null(load_order_group, |load_order_w| {
                        with_opt_wide_null(service_start_name, |start_name_w| {
                            with_opt_wide_null(password, |pw_w| unsafe {
                                CreateServiceW(
                                    self.0,
                                    svc_name_w,
                                    disp_name_w,
                                    desired_access,
                                    service_type,
                                    start_type,
                                    error_control,
                                    bin_path_w,
                                    load_order_w,
                                    ptr::null_mut(),
                                    deps_ptr,
                                    start_name_w,
                                    pw_w,
                                )
                            })
                        })
                    })
                })
            })
        });

        if handle.is_null() {
            let code = unsafe { GetLastError() };
            return Err(ServiceError::CreateService {
                name: service_name.to_string(),
                code,
            });
        }

        Ok(ServiceHandle {
            handle,
            name: service_name.to_string(),
        })
    }

    /// Opens an existing service.
    pub fn open_service(&self, name: &str, desired_access: u32) -> Result<ServiceHandle, ServiceError> {
        let handle = with_wide_null(name, |name_w| unsafe {
            OpenServiceW(self.0, name_w, desired_access)
        });
        if handle.is_null() {
            let code = unsafe { GetLastError() };
            return Err(ServiceError::OpenService {
                name: name.to_string(),
                code,
            });
        }
        Ok(ServiceHandle {
            handle,
            name: name.to_string(),
        })
    }

    /// Checks if a service exists.
    pub fn service_exists(&self, name: &str) -> bool {
        let handle = with_wide_null(name, |name_w| unsafe {
            OpenServiceW(self.0, name_w, SERVICE_QUERY_STATUS)
        });
        if !handle.is_null() {
            unsafe {
                CloseServiceHandle(handle);
            }
            return true;
        }
        unsafe { GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST }
    }
}

impl Drop for ScmHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseServiceHandle(self.0);
            }
            self.0 = ptr::null_mut();
        }
    }
}

/// RAII wrapper for an individual service handle (`SC_HANDLE`).
#[derive(Debug)]
pub struct ServiceHandle {
    handle: SC_HANDLE,
    name: String,
}

unsafe impl Send for ServiceHandle {}
unsafe impl Sync for ServiceHandle {}

impl ServiceHandle {
    /// Returns the raw `SC_HANDLE`.
    pub fn as_raw(&self) -> SC_HANDLE {
        self.handle
    }

    /// Returns the service name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Queries the current status of the service.
    pub fn query_status(&self) -> Result<SERVICE_STATUS, ServiceError> {
        let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
        let ok = unsafe { QueryServiceStatus(self.handle, &mut status) };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            return Err(ServiceError::QueryService {
                name: self.name.clone(),
                code,
            });
        }
        Ok(status)
    }

    /// Starts the service.
    pub fn start(&self) -> Result<(), ServiceError> {
        let ok = unsafe { StartServiceW(self.handle, 0, ptr::null()) };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            return Err(ServiceError::StartService {
                name: self.name.clone(),
                code,
            });
        }
        Ok(())
    }

    /// Starts the service with arguments (alias for `start`).
    pub fn start_service(&self, _args: &[&str]) -> Result<(), ServiceError> {
        self.start()
    }

    /// Sends a stop control signal to the service.
    pub fn stop(&self) -> Result<SERVICE_STATUS, ServiceError> {
        let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
        let ok = unsafe { ControlService(self.handle, SERVICE_CONTROL_STOP, &mut status) };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            return Err(ServiceError::StopService {
                name: self.name.clone(),
                code,
            });
        }
        Ok(status)
    }

    /// Stops the service (alias for `stop`).
    pub fn stop_service(&self) -> Result<SERVICE_STATUS, ServiceError> {
        self.stop()
    }

    /// Deletes the service from the SCM database.
    pub fn delete(&self) -> Result<(), ServiceError> {
        let ok = unsafe { DeleteService(self.handle) };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            return Err(ServiceError::DeleteService {
                name: self.name.clone(),
                code,
            });
        }
        Ok(())
    }

    /// Deletes the service (alias for `delete`).
    pub fn delete_service(&self) -> Result<(), ServiceError> {
        self.delete()
    }

    /// Updates the service's start type, binary path, and display name in-place without deleting it.
    pub fn update_config(
        &self,
        start_type: u32,
        binary_path: Option<&str>,
        display_name: Option<&str>,
    ) -> Result<(), ServiceError> {
        let ok = with_opt_wide_null(binary_path, |bin_w| {
            with_opt_wide_null(display_name, |disp_w| unsafe {
                ChangeServiceConfigW(
                    self.handle,
                    windows_sys::Win32::System::Services::SERVICE_NO_CHANGE,
                    start_type,
                    windows_sys::Win32::System::Services::SERVICE_NO_CHANGE,
                    bin_w,
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    disp_w,
                )
            })
        });
        if ok == 0 {
            let code = unsafe { GetLastError() };
            return Err(ServiceError::ConfigureService {
                name: self.name.clone(),
                code,
            });
        }
        Ok(())
    }

    /// Sets the start type (e.g. `SERVICE_AUTO_START`, `SERVICE_DEMAND_START`, `SERVICE_DISABLED`).
    pub fn set_start_type(&self, start_type: u32) -> Result<(), ServiceError> {
        self.update_config(start_type, None, None)
    }

    /// Queries whether the service is configured to start automatically.
    pub fn is_auto_start(&self) -> Result<bool, ServiceError> {
        let mut stack_buf = [0u64; 64]; // 512 bytes, 8-byte aligned for QUERY_SERVICE_CONFIGW
        let mut bytes_needed = 0u32;
        let ok = unsafe {
            QueryServiceConfigW(
                self.handle,
                stack_buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW,
                core::mem::size_of_val(&stack_buf) as u32,
                &mut bytes_needed,
            )
        };
        if ok != 0 {
            let config = unsafe { &*(stack_buf.as_ptr() as *const QUERY_SERVICE_CONFIGW) };
            return Ok(config.dwStartType == SERVICE_AUTO_START);
        }

        let code = unsafe { GetLastError() };
        if code != ERROR_INSUFFICIENT_BUFFER {
            return Err(ServiceError::QueryService {
                name: self.name.clone(),
                code,
            });
        }

        let needed_u64 = (bytes_needed as usize)
            .div_ceil(core::mem::size_of::<u64>())
            .max(1);
        let mut heap_buf = vec![0u64; needed_u64];
        let p_config = heap_buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
        let ok = unsafe {
            QueryServiceConfigW(
                self.handle,
                p_config,
                (heap_buf.len() * core::mem::size_of::<u64>()) as u32,
                &mut bytes_needed,
            )
        };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            return Err(ServiceError::QueryService {
                name: self.name.clone(),
                code,
            });
        }
        let config = unsafe { &*p_config };
        Ok(config.dwStartType == SERVICE_AUTO_START)
    }
}

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                CloseServiceHandle(self.handle);
            }
            self.handle = ptr::null_mut();
        }
    }
}
