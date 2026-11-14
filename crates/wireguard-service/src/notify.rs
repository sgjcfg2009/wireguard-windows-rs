//! Event-driven Service Control Manager (SCM) change notification watchers.
//!
//! Wraps Win32 `NotifyServiceStatusChangeW` (`SERVICE_NOTIFY_2W`), alertable waits
//! (`WaitForSingleObjectEx` / `SleepEx`), and a manual-reset `CreateEventW`
//! cancellation handle so callers can react to service creations, deletions,
//! and status transitions without polling loops.

use core::ffi::c_void;
use core::marker::PhantomData;
use core::ptr;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ACCESS_DENIED, ERROR_MORE_DATA,
    ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_MARKED_FOR_DELETE,
    ERROR_SERVICE_NOTIFY_CLIENT_LAGGING, ERROR_SUCCESS, HANDLE, WAIT_FAILED, WAIT_IO_COMPLETION,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Services::{
    EnumServicesStatusExW, NotifyServiceStatusChangeW, ENUM_SERVICE_STATUS_PROCESSW,
    SC_ENUM_PROCESS_INFO, SC_HANDLE, SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE,
    SERVICE_CONTINUE_PENDING, SERVICE_NOTIFY_2W, SERVICE_NOTIFY_CONTINUE_PENDING,
    SERVICE_NOTIFY_CREATED, SERVICE_NOTIFY_DELETED, SERVICE_NOTIFY_DELETE_PENDING,
    SERVICE_NOTIFY_PAUSED, SERVICE_NOTIFY_PAUSE_PENDING, SERVICE_NOTIFY_RUNNING,
    SERVICE_NOTIFY_START_PENDING, SERVICE_NOTIFY_STATUS_CHANGE, SERVICE_NOTIFY_STOPPED,
    SERVICE_NOTIFY_STOP_PENDING, SERVICE_PAUSED, SERVICE_PAUSE_PENDING, SERVICE_QUERY_STATUS,
    SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATE_ALL, SERVICE_STOPPED,
    SERVICE_STOP_PENDING, SERVICE_WIN32,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, SetEvent, SleepEx, WaitForSingleObjectEx, INFINITE,
};

use crate::wide::from_wide_ptr;
use crate::{ScmHandle, ServiceError, ServiceHandle};

/// Bitmask covering every service runtime state transition plus `SERVICE_NOTIFY_DELETE_PENDING`.
///
/// Valid for per-service notifications via `NotifyServiceStatusChangeW` (such as
/// [`wait_service_status_change`]). Note that `SERVICE_NOTIFY_CREATED` and
/// `SERVICE_NOTIFY_DELETED` are only valid when watching an SCM database handle.
pub const SERVICE_NOTIFY_ALL_STATES: u32 = SERVICE_NOTIFY_STOPPED
    | SERVICE_NOTIFY_START_PENDING
    | SERVICE_NOTIFY_STOP_PENDING
    | SERVICE_NOTIFY_RUNNING
    | SERVICE_NOTIFY_CONTINUE_PENDING
    | SERVICE_NOTIFY_PAUSE_PENDING
    | SERVICE_NOTIFY_PAUSED
    | SERVICE_NOTIFY_DELETE_PENDING;

struct CancelInner {
    event: HANDLE,
    cancelled: AtomicBool,
}

unsafe impl Send for CancelInner {}
unsafe impl Sync for CancelInner {}

impl Drop for CancelInner {
    fn drop(&mut self) {
        if !self.event.is_null() {
            unsafe {
                CloseHandle(self.event);
            }
            self.event = ptr::null_mut();
        }
    }
}

/// Thread-safe manual-reset Win32 cancellation token for SCM alertable watchers.
#[derive(Clone)]
pub struct ScmWatchCancel(Arc<CancelInner>);

impl core::fmt::Debug for ScmWatchCancel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ScmWatchCancel")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

impl ScmWatchCancel {
    /// Creates an unsignaled manual-reset Win32 event object usable across threads.
    pub fn new() -> Result<Self, ServiceError> {
        let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if event.is_null() {
            let code = unsafe { GetLastError() };
            return Err(ServiceError::Notify {
                operation: "CreateEventW",
                code,
            });
        }
        Ok(Self(Arc::new(CancelInner {
            event,
            cancelled: AtomicBool::new(false),
        })))
    }

    /// Signals cancellation, immediately waking any alertable wait using this token.
    pub fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::Release);
        unsafe {
            SetEvent(self.0.event);
        }
    }

    /// Returns `true` if [`cancel`](Self::cancel) has already been called.
    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::Acquire)
    }

    fn raw_handle(&self) -> HANDLE {
        self.0.event
    }
}

/// Raw snapshot delivered by a Win32 `SERVICE_NOTIFY_2W` callback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceNotifyEvent {
    pub notification_status: u32,
    pub notification_triggered: u32,
    pub current_state: u32,
    pub service_type: u32,
    pub win32_exit_code: u32,
    pub service_specific_exit_code: u32,
    pub process_id: u32,
    pub service_names: Vec<String>,
}

impl ServiceNotifyEvent {
    fn empty() -> Self {
        Self {
            notification_status: 0,
            notification_triggered: 0,
            current_state: 0,
            service_type: 0,
            win32_exit_code: 0,
            service_specific_exit_code: 0,
            process_id: 0,
            service_names: Vec::new(),
        }
    }
}

/// Result of a one-shot SCM or service status alertable wait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScmWaitOutcome<T> {
    Changed(T),
    Cancelled,
    TimedOut,
}

/// High-level change event delivered by [`watch_services`] or [`wait_scm_change`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScmServiceChange {
    Created(String),
    Deleted(String),
    StateChanged {
        service_name: String,
        current_state: u32,
        process_id: u32,
    },
    DeletePending(String),
    ResyncRequired,
}

enum WatchHandle {
    Scm(ScmHandle),
    Service(ServiceHandle),
}

impl WatchHandle {
    fn raw_handle(&self) -> SC_HANDLE {
        match self {
            WatchHandle::Scm(h) => h.as_raw(),
            WatchHandle::Service(h) => h.as_raw(),
        }
    }
}

struct ApcState {
    fired: bool,
    event: ServiceNotifyEvent,
}

/// Owns a `NotifyServiceStatusChangeW` registration on the current thread.
///
/// The handle MUST be closed *before* draining queued APCs with `SleepEx(0, 1)`
/// and freeing the boxed `SERVICE_NOTIFY_2W` / `ApcState` allocations so no
/// already-queued APC ever dereferences freed memory.
struct NotifyRegistration {
    handle: Option<WatchHandle>,
    notify: *mut SERVICE_NOTIFY_2W,
    state: *mut ApcState,
    _not_send: PhantomData<*const ()>,
}

impl Drop for NotifyRegistration {
    fn drop(&mut self) {
        // Close the SCM/service handle first so SCM cancels pending notifications.
        let _ = self.handle.take();
        unsafe {
            // Drain any APC already queued to this thread prior to CloseServiceHandle.
            while SleepEx(0, 1) == WAIT_IO_COMPLETION {}
            if !self.notify.is_null() {
                let notify = Box::from_raw(self.notify);
                if !notify.pszServiceNames.is_null() {
                    LocalFree(notify.pszServiceNames as _);
                }
                self.notify = ptr::null_mut();
            }
            if !self.state.is_null() {
                let _ = Box::from_raw(self.state);
                self.state = ptr::null_mut();
            }
        }
    }
}

unsafe extern "system" fn scm_notify_callback(parameter: *const c_void) {
    if parameter.is_null() {
        return;
    }
    let notify = &mut *(parameter as *mut SERVICE_NOTIFY_2W);
    let mut service_names = Vec::new();
    if !notify.pszServiceNames.is_null() {
        service_names = parse_multi_sz(notify.pszServiceNames);
        LocalFree(notify.pszServiceNames as _);
        notify.pszServiceNames = ptr::null_mut();
    }
    if notify.pContext.is_null() {
        return;
    }
    let state = &mut *(notify.pContext as *mut ApcState);
    state.event = ServiceNotifyEvent {
        notification_status: notify.dwNotificationStatus,
        notification_triggered: notify.dwNotificationTriggered,
        current_state: notify.ServiceStatus.dwCurrentState,
        service_type: notify.ServiceStatus.dwServiceType,
        win32_exit_code: notify.ServiceStatus.dwWin32ExitCode,
        service_specific_exit_code: notify.ServiceStatus.dwServiceSpecificExitCode,
        process_id: notify.ServiceStatus.dwProcessId,
        service_names,
    };
    state.fired = true;
}

impl NotifyRegistration {
    fn register(handle: WatchHandle, notify_mask: u32) -> Result<Self, ServiceError> {
        let state_ptr = Box::into_raw(Box::new(ApcState {
            fired: false,
            event: ServiceNotifyEvent::empty(),
        }));
        let mut notify_val: SERVICE_NOTIFY_2W = unsafe { core::mem::zeroed() };
        notify_val.dwVersion = SERVICE_NOTIFY_STATUS_CHANGE;
        notify_val.pfnNotifyCallback = Some(scm_notify_callback);
        notify_val.pContext = state_ptr as *mut c_void;
        let notify_ptr = Box::into_raw(Box::new(notify_val));

        let mut reg = Self {
            handle: Some(handle),
            notify: notify_ptr,
            state: state_ptr,
            _not_send: PhantomData,
        };

        reg.rearm(notify_mask)?;
        Ok(reg)
    }

    fn rearm(&mut self, notify_mask: u32) -> Result<(), ServiceError> {
        let raw = match self.handle.as_ref() {
            Some(h) => h.raw_handle(),
            None => {
                return Err(ServiceError::Notify {
                    operation: "NotifyServiceStatusChangeW",
                    code: ERROR_SERVICE_MARKED_FOR_DELETE,
                });
            }
        };

        unsafe {
            (*self.state).fired = false;
            (*self.notify).dwNotificationStatus = 0;
            (*self.notify).dwNotificationTriggered = 0;
            if !(*self.notify).pszServiceNames.is_null() {
                LocalFree((*self.notify).pszServiceNames as _);
                (*self.notify).pszServiceNames = ptr::null_mut();
            }
        }

        let code = unsafe { NotifyServiceStatusChangeW(raw, notify_mask, self.notify) };
        if code != ERROR_SUCCESS {
            return Err(ServiceError::Notify {
                operation: "NotifyServiceStatusChangeW",
                code,
            });
        }
        Ok(())
    }

    fn is_fired(&self) -> bool {
        unsafe { (*self.state).fired }
    }

    fn take_fired(&mut self) -> Option<ServiceNotifyEvent> {
        unsafe {
            if (*self.state).fired {
                (*self.state).fired = false;
                Some(core::mem::replace(
                    &mut (*self.state).event,
                    ServiceNotifyEvent::empty(),
                ))
            } else {
                None
            }
        }
    }
}

/// Reads a Win32 double-null-terminated `MULTI_SZ` UTF-16 buffer into a `Vec<String>`.
///
/// # Safety
/// If non-null, `ptr` must point to a valid double-null-terminated UTF-16 buffer.
unsafe fn parse_multi_sz(mut ptr: *const u16) -> Vec<String> {
    let mut out = Vec::new();
    if ptr.is_null() {
        return out;
    }
    loop {
        if *ptr == 0 {
            break;
        }
        let mut len = 0usize;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = core::slice::from_raw_parts(ptr, len);
        out.push(String::from_utf16_lossy(slice));
        ptr = ptr.add(len + 1);
    }
    out
}

pub(crate) fn starts_with_ignore_ascii_case(haystack: &str, prefix: &str) -> bool {
    haystack
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

/// Builds a `SERVICE_NOTIFY_*` status mask matching all states except `current_state`.
pub(crate) fn status_notify_mask_excluding(current_state: u32) -> u32 {
    let exclude = match current_state {
        SERVICE_STOPPED => SERVICE_NOTIFY_STOPPED,
        SERVICE_START_PENDING => SERVICE_NOTIFY_START_PENDING,
        SERVICE_STOP_PENDING => SERVICE_NOTIFY_STOP_PENDING,
        SERVICE_RUNNING => SERVICE_NOTIFY_RUNNING,
        SERVICE_CONTINUE_PENDING => SERVICE_NOTIFY_CONTINUE_PENDING,
        SERVICE_PAUSE_PENDING => SERVICE_NOTIFY_PAUSE_PENDING,
        SERVICE_PAUSED => SERVICE_NOTIFY_PAUSED,
        _ => 0,
    };
    SERVICE_NOTIFY_ALL_STATES & !exclude
}

/// Parses `SERVICE_NOTIFY_2W.pszServiceNames` entries into typed create/delete events.
///
/// Per Win32 SCM documentation, created service names are prefixed with `'/'`,
/// while deleted service names carry no prefix.
pub(crate) fn parse_notify_service_names(
    names: &[String],
    prefix: Option<&str>,
) -> Vec<ScmServiceChange> {
    let mut changes = Vec::new();
    for entry in names {
        if entry.is_empty() {
            continue;
        }
        let (is_created, service_name) = match entry.strip_prefix('/') {
            Some(stripped) => (true, stripped),
            None => (false, entry.as_str()),
        };
        if service_name.is_empty() {
            continue;
        }
        if let Some(p) = prefix {
            if !starts_with_ignore_ascii_case(service_name, p) {
                continue;
            }
        }
        if is_created {
            changes.push(ScmServiceChange::Created(service_name.to_owned()));
        } else {
            changes.push(ScmServiceChange::Deleted(service_name.to_owned()));
        }
    }
    changes
}

enum AlertableStep {
    ApcRan,
    Cancelled,
    TimedOut,
}

fn wait_alertable_once(
    cancel: Option<&ScmWatchCancel>,
    wait_ms: u32,
) -> Result<AlertableStep, ServiceError> {
    if cancel.is_some_and(|c| c.is_cancelled()) {
        return Ok(AlertableStep::Cancelled);
    }

    if let Some(c) = cancel {
        let res = unsafe { WaitForSingleObjectEx(c.raw_handle(), wait_ms, 1) };
        match res {
            WAIT_OBJECT_0 => Ok(AlertableStep::Cancelled),
            WAIT_IO_COMPLETION => Ok(AlertableStep::ApcRan),
            WAIT_TIMEOUT => Ok(AlertableStep::TimedOut),
            WAIT_FAILED => {
                let code = unsafe { GetLastError() };
                Err(ServiceError::Notify {
                    operation: "WaitForSingleObjectEx",
                    code,
                })
            }
            other => Err(ServiceError::Notify {
                operation: "WaitForSingleObjectEx",
                code: other,
            }),
        }
    } else {
        let res = unsafe { SleepEx(wait_ms, 1) };
        if res == WAIT_IO_COMPLETION {
            Ok(AlertableStep::ApcRan)
        } else {
            Ok(AlertableStep::TimedOut)
        }
    }
}

fn remaining_wait_ms(deadline: Option<Instant>) -> Result<u32, ()> {
    match deadline {
        None => Ok(INFINITE),
        Some(dl) => {
            let now = Instant::now();
            if now >= dl {
                Err(())
            } else {
                let ms = dl.saturating_duration_since(now).as_millis();
                Ok(ms.min((INFINITE - 1) as u128) as u32)
            }
        }
    }
}

fn wait_until_registration_fires(
    reg: &mut NotifyRegistration,
    cancel: Option<&ScmWatchCancel>,
    deadline: Option<Instant>,
) -> Result<ScmWaitOutcome<ServiceNotifyEvent>, ServiceError> {
    // Drain any APC that may already be pending on this thread before sleeping.
    unsafe {
        while SleepEx(0, 1) == WAIT_IO_COMPLETION {}
    }

    loop {
        if cancel.is_some_and(|c| c.is_cancelled()) {
            return Ok(ScmWaitOutcome::Cancelled);
        }
        if let Some(ev) = reg.take_fired() {
            return Ok(ScmWaitOutcome::Changed(ev));
        }

        let wait_ms = match remaining_wait_ms(deadline) {
            Ok(ms) => ms,
            Err(()) => return Ok(ScmWaitOutcome::TimedOut),
        };

        match wait_alertable_once(cancel, wait_ms)? {
            AlertableStep::ApcRan => {
                unsafe {
                    while SleepEx(0, 1) == WAIT_IO_COMPLETION {}
                }
            }
            AlertableStep::Cancelled => return Ok(ScmWaitOutcome::Cancelled),
            AlertableStep::TimedOut => return Ok(ScmWaitOutcome::TimedOut),
        }
    }
}

/// Blocks the calling thread in an alertable wait until the SCM database emits a
/// create/delete change notification matching `service_name_prefix`, `cancel`
/// is signaled, or `timeout_ms` elapses.
pub fn wait_scm_change(
    service_name_prefix: Option<&str>,
    notify_mask: u32,
    cancel: Option<&ScmWatchCancel>,
    timeout_ms: Option<u32>,
) -> Result<ScmWaitOutcome<Vec<ScmServiceChange>>, ServiceError> {
    if cancel.is_some_and(|c| c.is_cancelled()) {
        return Ok(ScmWaitOutcome::Cancelled);
    }

    let deadline = timeout_ms.map(|ms| Instant::now() + Duration::from_millis(ms as u64));
    let scm = ScmHandle::open(SC_MANAGER_CONNECT)?;
    let mut reg = NotifyRegistration::register(WatchHandle::Scm(scm), notify_mask)?;

    loop {
        match wait_until_registration_fires(&mut reg, cancel, deadline)? {
            ScmWaitOutcome::Cancelled => return Ok(ScmWaitOutcome::Cancelled),
            ScmWaitOutcome::TimedOut => return Ok(ScmWaitOutcome::TimedOut),
            ScmWaitOutcome::Changed(ev) => {
                if ev.notification_status == ERROR_SERVICE_NOTIFY_CLIENT_LAGGING {
                    return Ok(ScmWaitOutcome::Changed(vec![
                        ScmServiceChange::ResyncRequired,
                    ]));
                }
                if ev.notification_status != ERROR_SUCCESS {
                    return Err(ServiceError::Notify {
                        operation: "NotifyServiceStatusChangeW",
                        code: ev.notification_status,
                    });
                }

                let changes = parse_notify_service_names(&ev.service_names, service_name_prefix);
                if !changes.is_empty() {
                    return Ok(ScmWaitOutcome::Changed(changes));
                }

                // Event only named unrelated services outside `service_name_prefix`; re-arm and wait.
                if let Err(err) = reg.rearm(notify_mask) {
                    if let ServiceError::Notify { code, .. } = &err {
                        if *code == ERROR_SERVICE_NOTIFY_CLIENT_LAGGING {
                            return Ok(ScmWaitOutcome::Changed(vec![
                                ScmServiceChange::ResyncRequired,
                            ]));
                        }
                    }
                    return Err(err);
                }
            }
        }
    }
}

/// Blocks the calling thread in an alertable wait until `service_name` emits a
/// notification matching `notify_mask`, `cancel` is signaled, or `timeout_ms` elapses.
pub fn wait_service_status_change(
    service_name: &str,
    notify_mask: u32,
    cancel: Option<&ScmWatchCancel>,
    timeout_ms: Option<u32>,
) -> Result<ScmWaitOutcome<ServiceNotifyEvent>, ServiceError> {
    if cancel.is_some_and(|c| c.is_cancelled()) {
        return Ok(ScmWaitOutcome::Cancelled);
    }

    let deadline = timeout_ms.map(|ms| Instant::now() + Duration::from_millis(ms as u64));
    let scm = ScmHandle::open(SC_MANAGER_CONNECT)?;
    let service = scm.open_service(service_name, SERVICE_QUERY_STATUS)?;
    let mut reg = NotifyRegistration::register(WatchHandle::Service(service), notify_mask)?;

    let outcome = wait_until_registration_fires(&mut reg, cancel, deadline);
    // `reg` drops here before returning, closing the service handle and draining APCs.
    outcome
}

struct EnumeratedService {
    name: String,
    current_state: u32,
}

fn enum_matching_services(
    scm: &ScmHandle,
    prefix: Option<&str>,
) -> Result<Vec<EnumeratedService>, ServiceError> {
    let mut stack_buf = [0u64; 1024]; // 8 KiB, 8-byte aligned for ENUM_SERVICE_STATUS_PROCESSW
    let mut heap_buf: Vec<u64> = Vec::new();
    let mut resume_handle = 0u32;
    let mut out = Vec::new();

    loop {
        let (buf_ptr, buf_bytes) = if heap_buf.is_empty() {
            (
                stack_buf.as_mut_ptr() as *mut u8,
                core::mem::size_of_val(&stack_buf) as u32,
            )
        } else {
            (
                heap_buf.as_mut_ptr() as *mut u8,
                (heap_buf.len() * core::mem::size_of::<u64>()) as u32,
            )
        };

        let mut bytes_needed = 0u32;
        let mut services_returned = 0u32;
        let ok = unsafe {
            EnumServicesStatusExW(
                scm.as_raw(),
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                buf_ptr,
                buf_bytes,
                &mut bytes_needed,
                &mut services_returned,
                &mut resume_handle,
                ptr::null(),
            )
        };

        if services_returned > 0 {
            let entries = unsafe {
                core::slice::from_raw_parts(
                    buf_ptr as *const ENUM_SERVICE_STATUS_PROCESSW,
                    services_returned as usize,
                )
            };
            for entry in entries {
                if entry.lpServiceName.is_null() {
                    continue;
                }
                let name = unsafe { from_wide_ptr(entry.lpServiceName) };
                let matches = match prefix {
                    Some(p) => starts_with_ignore_ascii_case(&name, p),
                    None => true,
                };
                if matches {
                    out.push(EnumeratedService {
                        name,
                        current_state: entry.ServiceStatusProcess.dwCurrentState,
                    });
                }
            }
        }

        if ok != 0 {
            break;
        }

        let err = unsafe { GetLastError() };
        if err == ERROR_MORE_DATA {
            if services_returned == 0 {
                let needed_u64 = (bytes_needed as usize)
                    .div_ceil(core::mem::size_of::<u64>())
                    .max(1);
                heap_buf.resize(needed_u64, 0);
            }
            continue;
        }

        return Err(ServiceError::Notify {
            operation: "EnumServicesStatusExW",
            code: err,
        });
    }

    Ok(out)
}

struct ServiceWatch {
    name: String,
    reg: NotifyRegistration,
}

fn open_service_watch(
    scm: &ScmHandle,
    service_name: &str,
    known_state: Option<u32>,
) -> Result<Option<(ServiceWatch, Option<ScmServiceChange>)>, ServiceError> {
    let svc = match scm.open_service(service_name, SERVICE_QUERY_STATUS) {
        Ok(h) => h,
        Err(ServiceError::OpenService { code, .. })
            if code == ERROR_SERVICE_DOES_NOT_EXIST
                || code == ERROR_SERVICE_MARKED_FOR_DELETE
                || code == ERROR_ACCESS_DENIED =>
        {
            return Ok(None);
        }
        Err(err) => return Err(err),
    };

    let (current_state, emit_initial) = match known_state {
        Some(st) => (st, None),
        None => {
            let status = match svc.query_status() {
                Ok(s) => s,
                Err(ServiceError::QueryService { code, .. })
                    if code == ERROR_SERVICE_DOES_NOT_EXIST
                        || code == ERROR_SERVICE_MARKED_FOR_DELETE =>
                {
                    return Ok(None);
                }
                Err(err) => return Err(err),
            };
            let change = if status.dwCurrentState != SERVICE_STOPPED {
                Some(ScmServiceChange::StateChanged {
                    service_name: service_name.to_owned(),
                    current_state: status.dwCurrentState,
                    process_id: 0,
                })
            } else {
                None
            };
            (status.dwCurrentState, change)
        }
    };

    let mask = status_notify_mask_excluding(current_state);
    match NotifyRegistration::register(WatchHandle::Service(svc), mask) {
        Ok(reg) => Ok(Some((
            ServiceWatch {
                name: service_name.to_owned(),
                reg,
            },
            emit_initial,
        ))),
        Err(ServiceError::Notify { code, .. })
            if code == ERROR_SERVICE_DOES_NOT_EXIST || code == ERROR_SERVICE_MARKED_FOR_DELETE =>
        {
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

fn setup_scm_watch_state(
    prefix: Option<&str>,
) -> Result<(ScmHandle, NotifyRegistration, HashMap<String, ServiceWatch>), ServiceError> {
    let scm_db = ScmHandle::open(SC_MANAGER_CONNECT)?;
    // Arm SCM database create/delete notifications *before* enumerating existing
    // services so services created concurrently with startup are never missed.
    let scm_reg = NotifyRegistration::register(
        WatchHandle::Scm(scm_db),
        SERVICE_NOTIFY_CREATED | SERVICE_NOTIFY_DELETED,
    )?;

    let query_scm = ScmHandle::open(SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE)?;
    let services = enum_matching_services(&query_scm, prefix)?;
    let mut watches = HashMap::with_capacity(services.len());
    for svc in services {
        if let Some((watch, _)) = open_service_watch(&query_scm, &svc.name, Some(svc.current_state))?
        {
            watches.insert(svc.name.to_ascii_lowercase(), watch);
        }
    }

    Ok((query_scm, scm_reg, watches))
}

fn is_lagging_error(err: &ServiceError) -> bool {
    matches!(
        err,
        ServiceError::Notify { code, .. } if *code == ERROR_SERVICE_NOTIFY_CLIENT_LAGGING
    )
}

/// Continuously monitors SCM service creations/deletions and per-service status
/// transitions matching `service_name_prefix`, delivering event batches to
/// `on_changes` without polling until `cancel` is signaled or `on_changes`
/// returns `false`.
pub fn watch_services<F>(
    service_name_prefix: Option<&str>,
    cancel: &ScmWatchCancel,
    mut on_changes: F,
) -> Result<(), ServiceError>
where
    F: FnMut(&[ScmServiceChange]) -> bool,
{
    if cancel.is_cancelled() {
        return Ok(());
    }

    let (mut query_scm, mut scm_reg, mut service_watches) =
        setup_scm_watch_state(service_name_prefix)?;

    loop {
        if cancel.is_cancelled() {
            return Ok(());
        }

        // Flush any APCs already queued before deciding whether to block.
        unsafe {
            while SleepEx(0, 1) == WAIT_IO_COMPLETION {}
        }

        let any_fired =
            scm_reg.is_fired() || service_watches.values().any(|w| w.reg.is_fired());
        if !any_fired {
            match wait_alertable_once(Some(cancel), INFINITE)? {
                AlertableStep::Cancelled => return Ok(()),
                AlertableStep::ApcRan => {
                    unsafe {
                        while SleepEx(0, 1) == WAIT_IO_COMPLETION {}
                    }
                }
                AlertableStep::TimedOut => {}
            }
        }

        if cancel.is_cancelled() {
            return Ok(());
        }

        let mut changes = Vec::new();
        let mut needs_resync = false;

        if let Some(ev) = scm_reg.take_fired() {
            if ev.notification_status == ERROR_SERVICE_NOTIFY_CLIENT_LAGGING
                || ev.notification_status != ERROR_SUCCESS
            {
                needs_resync = true;
            } else {
                let db_changes =
                    parse_notify_service_names(&ev.service_names, service_name_prefix);
                for change in db_changes {
                    match &change {
                        ScmServiceChange::Created(name) => {
                            let key = name.to_ascii_lowercase();
                            changes.push(ScmServiceChange::Created(name.clone()));
                            if !service_watches.contains_key(&key) {
                                if let Some((watch, initial_change)) =
                                    open_service_watch(&query_scm, name, None)?
                                {
                                    service_watches.insert(key, watch);
                                    if let Some(extra) = initial_change {
                                        changes.push(extra);
                                    }
                                }
                            }
                        }
                        ScmServiceChange::Deleted(name) => {
                            let key = name.to_ascii_lowercase();
                            // Close open service handle immediately on deletion notification.
                            service_watches.remove(&key);
                            changes.push(ScmServiceChange::Deleted(name.clone()));
                        }
                        _ => {}
                    }
                }

                if let Err(err) = scm_reg.rearm(SERVICE_NOTIFY_CREATED | SERVICE_NOTIFY_DELETED) {
                    if is_lagging_error(&err) {
                        needs_resync = true;
                    } else {
                        return Err(err);
                    }
                }
            }
        }

        if !needs_resync {
            let mut to_remove = Vec::new();
            let keys: Vec<String> = service_watches.keys().cloned().collect();
            for key in keys {
                let Some(watch) = service_watches.get_mut(&key) else {
                    continue;
                };
                let Some(ev) = watch.reg.take_fired() else {
                    continue;
                };

                if ev.notification_status == ERROR_SERVICE_NOTIFY_CLIENT_LAGGING {
                    needs_resync = true;
                    break;
                }

                if ev.notification_status == ERROR_SERVICE_MARKED_FOR_DELETE
                    || (ev.notification_triggered & SERVICE_NOTIFY_DELETE_PENDING) != 0
                {
                    changes.push(ScmServiceChange::DeletePending(watch.name.clone()));
                    // Drop the ServiceHandle promptly so SCM can finish deleting the service.
                    to_remove.push(key);
                    continue;
                }

                if ev.notification_status != ERROR_SUCCESS {
                    needs_resync = true;
                    break;
                }

                changes.push(ScmServiceChange::StateChanged {
                    service_name: watch.name.clone(),
                    current_state: ev.current_state,
                    process_id: ev.process_id,
                });

                let next_mask = status_notify_mask_excluding(ev.current_state);
                match watch.reg.rearm(next_mask) {
                    Ok(()) => {}
                    Err(ServiceError::Notify { code, .. })
                        if code == ERROR_SERVICE_MARKED_FOR_DELETE
                            || code == ERROR_SERVICE_DOES_NOT_EXIST =>
                    {
                        to_remove.push(key);
                    }
                    Err(err) if is_lagging_error(&err) => {
                        needs_resync = true;
                        break;
                    }
                    Err(_) => {
                        needs_resync = true;
                        break;
                    }
                }
            }

            for key in to_remove {
                service_watches.remove(&key);
            }
        }

        if needs_resync {
            // Tear down existing handles before opening a fresh SCM watch baseline.
            service_watches.clear();
            drop(scm_reg);
            let (new_query_scm, new_scm_reg, new_watches) =
                setup_scm_watch_state(service_name_prefix)?;
            query_scm = new_query_scm;
            scm_reg = new_scm_reg;
            service_watches = new_watches;
            if !on_changes(&[ScmServiceChange::ResyncRequired]) {
                return Ok(());
            }
            continue;
        }

        if !changes.is_empty() && !on_changes(&changes) {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_created_and_deleted_service_names_with_prefix_filter() {
        let raw = vec![
            "/WireGuardTunnel$wg0".to_owned(),
            "/OtherService".to_owned(),
            "wireguardtunnel$wg1".to_owned(),
            "Spooler".to_owned(),
            "/".to_owned(),
            "".to_owned(),
        ];
        let parsed = parse_notify_service_names(&raw, Some("WireGuardTunnel$"));
        assert_eq!(
            parsed,
            vec![
                ScmServiceChange::Created("WireGuardTunnel$wg0".to_owned()),
                ScmServiceChange::Deleted("wireguardtunnel$wg1".to_owned()),
            ]
        );
    }

    #[test]
    fn excludes_only_matching_current_state_bit() {
        let running_mask = status_notify_mask_excluding(SERVICE_RUNNING);
        assert_eq!(running_mask & SERVICE_NOTIFY_RUNNING, 0);
        assert_ne!(running_mask & SERVICE_NOTIFY_STOPPED, 0);
        assert_ne!(running_mask & SERVICE_NOTIFY_STOP_PENDING, 0);
        assert_ne!(running_mask & SERVICE_NOTIFY_DELETE_PENDING, 0);

        let unknown_mask = status_notify_mask_excluding(0);
        assert_eq!(unknown_mask, SERVICE_NOTIFY_ALL_STATES);
    }

    #[test]
    fn parses_multi_sz_utf16_buffer() {
        let buf: Vec<u16> = "/wg0\0wg1\0\0".encode_utf16().collect();
        let parsed = unsafe { parse_multi_sz(buf.as_ptr()) };
        assert_eq!(parsed, vec!["/wg0", "wg1"]);

        let empty: [u16; 1] = [0];
        let parsed_empty = unsafe { parse_multi_sz(empty.as_ptr()) };
        assert!(parsed_empty.is_empty());
    }
}
