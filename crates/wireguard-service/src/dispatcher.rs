use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex, OnceLock};

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Services::*;

use crate::error::{determine_error_code, ServiceError};
use crate::wide::{from_wide_ptr, with_wide_null, with_wide_null_checked_mut};

/// Represents an incoming control request from the Service Control Manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceControlEvent {
    Stop,
    Shutdown,
    Pause,
    Continue,
    Interrogate,
    SessionChange { event_type: u32, session_id: u32 },
    ParamChange,
    NetBindAdd,
    NetBindRemove,
    NetBindEnable,
    NetBindDisable,
    Custom(u32),
}

/// Thread-safe status reporter to publish service status changes to SCM.
#[derive(Clone)]
pub struct ServiceStatusReporter {
    handle: SERVICE_STATUS_HANDLE,
    state: Arc<AtomicU32>,
    controls_accepted: Arc<AtomicU32>,
    checkpoint: Arc<AtomicU32>,
}

unsafe impl Send for ServiceStatusReporter {}
unsafe impl Sync for ServiceStatusReporter {}

impl ServiceStatusReporter {
    /// Creates a new reporter for an active SCM status handle.
    pub fn new(handle: SERVICE_STATUS_HANDLE) -> Self {
        Self {
            handle,
            state: Arc::new(AtomicU32::new(SERVICE_START_PENDING)),
            controls_accepted: Arc::new(AtomicU32::new(0)),
            checkpoint: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Sets raw service status via `SetServiceStatus`.
    pub fn set_status(&self, status: &SERVICE_STATUS) -> Result<(), ServiceError> {
        let ok = unsafe { SetServiceStatus(self.handle, status) };
        if ok == 0 {
            return Err(ServiceError::last_win32_error());
        }
        self.state.store(status.dwCurrentState, Ordering::SeqCst);
        self.controls_accepted.store(status.dwControlsAccepted, Ordering::SeqCst);
        Ok(())
    }

    /// Reports that the service is running and ready to accept the specified control codes.
    pub fn set_running(&self, accepts: u32) -> Result<(), ServiceError> {
        self.controls_accepted.store(accepts, Ordering::SeqCst);
        self.checkpoint.store(0, Ordering::SeqCst);
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: SERVICE_RUNNING,
            dwControlsAccepted: accepts,
            dwWin32ExitCode: NO_ERROR,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: 0,
        };
        self.set_status(&status)
    }

    /// Reports that the service is in the process of starting.
    pub fn set_start_pending(&self, wait_hint_ms: u32) -> Result<(), ServiceError> {
        let cp = self.checkpoint.fetch_add(1, Ordering::SeqCst) + 1;
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: SERVICE_START_PENDING,
            dwControlsAccepted: 0,
            dwWin32ExitCode: NO_ERROR,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: cp,
            dwWaitHint: wait_hint_ms,
        };
        self.set_status(&status)
    }

    /// Reports that the service is stopping.
    pub fn set_stop_pending(&self, wait_hint_ms: u32) -> Result<(), ServiceError> {
        let cp = self.checkpoint.fetch_add(1, Ordering::SeqCst) + 1;
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: SERVICE_STOP_PENDING,
            dwControlsAccepted: 0,
            dwWin32ExitCode: NO_ERROR,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: cp,
            dwWaitHint: wait_hint_ms,
        };
        self.set_status(&status)
    }

    /// Reports that the service has completely stopped.
    pub fn set_stopped(&self, win32_exit_code: u32, service_specific_code: u32) -> Result<(), ServiceError> {
        self.checkpoint.store(0, Ordering::SeqCst);
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: SERVICE_STOPPED,
            dwControlsAccepted: 0,
            dwWin32ExitCode: win32_exit_code,
            dwServiceSpecificExitCode: service_specific_code,
            dwCheckPoint: 0,
            dwWaitHint: 0,
        };
        self.set_status(&status)
    }

    /// Re-reports the current status (used when responding to `SERVICE_CONTROL_INTERROGATE`).
    pub fn re_report_status(&self) -> Result<(), ServiceError> {
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: self.state.load(Ordering::SeqCst),
            dwControlsAccepted: self.controls_accepted.load(Ordering::SeqCst),
            dwWin32ExitCode: NO_ERROR,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: self.checkpoint.load(Ordering::SeqCst),
            dwWaitHint: 0,
        };
        let ok = unsafe { SetServiceStatus(self.handle, &status) };
        if ok == 0 {
            return Err(ServiceError::last_win32_error());
        }
        Ok(())
    }

    /// Returns the current known service state.
    pub fn current_state(&self) -> u32 {
        self.state.load(Ordering::SeqCst)
    }
}

/// Execution context passed into the service main closure.
pub struct ServiceContext {
    pub service_name: String,
    pub args: Vec<String>,
    pub status: ServiceStatusReporter,
    pub control_rx: Receiver<ServiceControlEvent>,
}

type ServiceHandlerFn = Box<dyn FnOnce(ServiceContext) -> Result<(), ServiceError> + Send + 'static>;

struct RegisteredService {
    handler: Mutex<Option<ServiceHandlerFn>>,
    control_tx: Sender<ServiceControlEvent>,
    control_rx: Mutex<Option<Receiver<ServiceControlEvent>>>,
    service_result_tx: Sender<Result<(), ServiceError>>,
}

static REGISTRY: OnceLock<Mutex<HashMap<String, Arc<RegisteredService>>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<String, Arc<RegisteredService>>> {
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Runs a Windows service by connecting to the Service Control Manager dispatcher.
///
/// This function blocks until the service has exited.
pub fn run_service<F>(service_name: &str, handler: F) -> Result<(), ServiceError>
where
    F: FnOnce(ServiceContext) -> Result<(), ServiceError> + Send + 'static,
{
    let norm_name = service_name.to_lowercase();
    let (control_tx, control_rx) = channel();
    let (res_tx, res_rx) = channel();

    let entry = Arc::new(RegisteredService {
        handler: Mutex::new(Some(Box::new(handler))),
        control_tx,
        control_rx: Mutex::new(Some(control_rx)),
        service_result_tx: res_tx,
    });

    {
        let mut reg = registry().lock().unwrap();
        reg.insert(norm_name.clone(), Arc::clone(&entry));
    }

    let dispatch_res = with_wide_null_checked_mut(service_name, |wide_name| {
        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: wide_name,
                lpServiceProc: Some(service_main_entry),
            },
            SERVICE_TABLE_ENTRYW {
                lpServiceName: core::ptr::null_mut(),
                lpServiceProc: None,
            },
        ];

        unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) }
    });

    // Clean up registry entry even if service_name contained an interior NUL.
    {
        let mut reg = registry().lock().unwrap();
        reg.remove(&norm_name);
    }

    let ok = dispatch_res?;

    if ok == 0 {
        let err = unsafe { GetLastError() };
        if err == 1063 {
            // ERROR_FAILED_SERVICE_CONTROLLER_CONNECT
            return Err(ServiceError::NotRunningAsService);
        }
        return Err(ServiceError::DispatchFailed(err));
    }

    // Return the result from the service handler if available
    match res_rx.recv() {
        Ok(res) => res,
        Err(_) => Ok(()),
    }
}

/// Win32 ServiceMain callback entry point.
unsafe extern "system" fn service_main_entry(argc: u32, argv: *mut *mut u16) {
    if argv.is_null() || argc == 0 {
        return;
    }

    let service_name = from_wide_ptr(*argv);
    let norm_name = service_name.to_lowercase();

    let entry = {
        let reg = registry().lock().unwrap();
        match reg.get(&norm_name) {
            Some(e) => Arc::clone(e),
            None => return,
        }
    };

    let mut args = Vec::with_capacity(argc as usize);
    for i in 0..argc {
        let arg_ptr = *argv.add(i as usize);
        args.push(from_wide_ptr(arg_ptr));
    }

    if service_name.contains('\0') {
        return;
    }

    // Prepare context for the control handler callback
    let ctrl_ctx = Box::new(ControlContext {
        control_tx: entry.control_tx.clone(),
        status_reporter: Mutex::new(None),
    });
    let ctrl_ctx_ptr = Box::into_raw(ctrl_ctx);

    let status_handle = with_wide_null(&service_name, |wide_name| unsafe {
        RegisterServiceCtrlHandlerExW(
            wide_name,
            Some(service_ctrl_handler_entry),
            ctrl_ctx_ptr as *const core::ffi::c_void,
        )
    });

    if status_handle.is_null() {
        let _ = Box::from_raw(ctrl_ctx_ptr);
        let err = ServiceError::last_win32_error();
        let _ = entry.service_result_tx.send(Err(err));
        return;
    }

    let reporter = ServiceStatusReporter::new(status_handle);
    {
        let mut rep_guard = (*ctrl_ctx_ptr).status_reporter.lock().unwrap();
        *rep_guard = Some(reporter.clone());
    }

    // Immediately inform SCM that we are starting
    let _ = reporter.set_start_pending(5000);

    let handler_opt = {
        let mut guard = entry.handler.lock().unwrap();
        guard.take()
    };

    let control_rx_opt = {
        let mut guard = entry.control_rx.lock().unwrap();
        guard.take()
    };

    let result = if let (Some(handler), Some(control_rx)) = (handler_opt, control_rx_opt) {
        let ctx = ServiceContext {
            service_name,
            args,
            status: reporter.clone(),
            control_rx,
        };

        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(ctx))) {
            Ok(h_res) => h_res,
            Err(p) => {
                let msg = if let Some(s) = p.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = p.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "Unknown panic".to_string()
                };
                Err(ServiceError::HandlerPanic(msg))
            }
        }
    } else {
        Err(ServiceError::DispatchFailed(0))
    };

    // Report stopped to SCM
    let (is_specific, exit_code) = determine_error_code(&result);
    let (win32_code, spec_code) = if is_specific {
        (ERROR_SERVICE_SPECIFIC_ERROR, exit_code)
    } else {
        (exit_code, 0)
    };

    let _ = reporter.set_stopped(win32_code, spec_code);

    let _ = entry.service_result_tx.send(result);

    // Free the control callback context
    let _ = Box::from_raw(ctrl_ctx_ptr);
}

struct ControlContext {
    control_tx: Sender<ServiceControlEvent>,
    status_reporter: Mutex<Option<ServiceStatusReporter>>,
}

/// Win32 HandlerEx callback entry point.
unsafe extern "system" fn service_ctrl_handler_entry(
    control: u32,
    event_type: u32,
    event_data: *mut core::ffi::c_void,
    context: *mut core::ffi::c_void,
) -> u32 {
    if context.is_null() {
        return ERROR_CALL_NOT_IMPLEMENTED;
    }

    let ctrl_ctx = &*(context as *const ControlContext);

    match control {
        SERVICE_CONTROL_STOP => {
            if let Ok(guard) = ctrl_ctx.status_reporter.lock() {
                if let Some(ref reporter) = *guard {
                    let _ = reporter.set_stop_pending(10_000);
                }
            }
            let _ = ctrl_ctx.control_tx.send(ServiceControlEvent::Stop);
            NO_ERROR
        }
        SERVICE_CONTROL_SHUTDOWN => {
            if let Ok(guard) = ctrl_ctx.status_reporter.lock() {
                if let Some(ref reporter) = *guard {
                    let _ = reporter.set_stop_pending(10_000);
                }
            }
            let _ = ctrl_ctx.control_tx.send(ServiceControlEvent::Shutdown);
            NO_ERROR
        }
        SERVICE_CONTROL_PAUSE => {
            let _ = ctrl_ctx.control_tx.send(ServiceControlEvent::Pause);
            NO_ERROR
        }
        SERVICE_CONTROL_CONTINUE => {
            let _ = ctrl_ctx.control_tx.send(ServiceControlEvent::Continue);
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => {
            if let Ok(guard) = ctrl_ctx.status_reporter.lock() {
                if let Some(ref reporter) = *guard {
                    let _ = reporter.re_report_status();
                }
            }
            let _ = ctrl_ctx.control_tx.send(ServiceControlEvent::Interrogate);
            NO_ERROR
        }
        SERVICE_CONTROL_SESSIONCHANGE => {
            // event_data points to WTSSESSION_NOTIFICATION
            let session_id = if !event_data.is_null() {
                #[repr(C)]
                struct WtsSessionNotification {
                    cb_size: u32,
                    session_id: u32,
                }
                let notif = &*(event_data as *const WtsSessionNotification);
                notif.session_id
            } else {
                0
            };
            let _ = ctrl_ctx
                .control_tx
                .send(ServiceControlEvent::SessionChange {
                    event_type,
                    session_id,
                });
            NO_ERROR
        }
        SERVICE_CONTROL_PARAMCHANGE => {
            let _ = ctrl_ctx.control_tx.send(ServiceControlEvent::ParamChange);
            NO_ERROR
        }
        SERVICE_CONTROL_NETBINDADD => {
            let _ = ctrl_ctx.control_tx.send(ServiceControlEvent::NetBindAdd);
            NO_ERROR
        }
        SERVICE_CONTROL_NETBINDREMOVE => {
            let _ = ctrl_ctx.control_tx.send(ServiceControlEvent::NetBindRemove);
            NO_ERROR
        }
        SERVICE_CONTROL_NETBINDENABLE => {
            let _ = ctrl_ctx.control_tx.send(ServiceControlEvent::NetBindEnable);
            NO_ERROR
        }
        SERVICE_CONTROL_NETBINDDISABLE => {
            let _ = ctrl_ctx.control_tx.send(ServiceControlEvent::NetBindDisable);
            NO_ERROR
        }
        _ => {
            let _ = ctrl_ctx.control_tx.send(ServiceControlEvent::Custom(control));
            NO_ERROR
        }
    }
}
