use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_NO_MORE_ITEMS, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent, WaitForSingleObject};
use crate::abi::WgIoctlLogEntry;
use crate::dll::WireGuardDll;
use crate::error::{DriverError, Result};
use crate::ioctl::{dev_ioctl, WG_IOCTL_READ_LOG_LINE};

/// Driver logging severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogLevel {
    Info = 0,
    Warn = 1,
    Error = 2,
}

impl From<u32> for LogLevel {
    fn from(val: u32) -> Self {
        match val {
            0 => LogLevel::Info,
            1 => LogLevel::Warn,
            _ => LogLevel::Error,
        }
    }
}

/// A parsed log entry originating from the WireGuard driver ring log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverLogEntry {
    pub level: LogLevel,
    pub timestamp: SystemTime,
    pub message: String,
}

const FILETIME_TO_UNIX_OFFSET: u64 = 116444736000000000;

/// Converts a 64-bit Windows FILETIME (100ns increments since 1601-01-01) to `SystemTime`.
pub fn filetime_to_system_time(filetime: u64) -> SystemTime {
    if filetime > FILETIME_TO_UNIX_OFFSET {
        let nanos = (filetime - FILETIME_TO_UNIX_OFFSET).saturating_mul(100);
        UNIX_EPOCH + Duration::from_nanos(nanos)
    } else {
        UNIX_EPOCH
    }
}

type LoggerCallbackFn = Box<dyn Fn(LogLevel, SystemTime, &str) + Send + Sync + 'static>;
static USER_LOGGER: OnceLock<Mutex<Option<LoggerCallbackFn>>> = OnceLock::new();

unsafe extern "system" fn global_wireguard_logger_trampoline(
    level: u32,
    timestamp: u64,
    msg: *const u16,
) {
    if msg.is_null() {
        return;
    }

    let mut len = 0;
    while *msg.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(msg, len);

    let mut stack_utf8 = [0u8; 512];
    let heap_utf8: String;
    let message_str: &str = {
        let mut out_len = 0usize;
        let mut overflow = false;
        for ch_res in std::char::decode_utf16(slice.iter().copied()) {
            let ch = ch_res.unwrap_or(char::REPLACEMENT_CHARACTER);
            let ch_len = ch.len_utf8();
            if out_len + ch_len > stack_utf8.len() {
                overflow = true;
                break;
            }
            ch.encode_utf8(&mut stack_utf8[out_len..]);
            out_len += ch_len;
        }
        if !overflow {
            // SAFETY: `encode_utf8` wrote valid UTF-8 into `stack_utf8[..out_len]`.
            std::str::from_utf8_unchecked(&stack_utf8[..out_len])
        } else {
            heap_utf8 = String::from_utf16_lossy(slice);
            &heap_utf8
        }
    };

    let log_level = LogLevel::from(level);
    let sys_time = filetime_to_system_time(timestamp);

    match log_level {
        LogLevel::Info => tracing::info!(target: "wireguard_driver", "{}", message_str),
        LogLevel::Warn => tracing::warn!(target: "wireguard_driver", "{}", message_str),
        LogLevel::Error => tracing::error!(target: "wireguard_driver", "{}", message_str),
    }

    if let Some(mutex) = USER_LOGGER.get() {
        if let Ok(guard) = mutex.lock() {
            if let Some(ref cb) = *guard {
                cb(log_level, sys_time, message_str);
            }
        }
    }
}

/// Registers a callback to receive log messages streamed from `wireguard.dll`.
pub fn set_driver_logger<F>(callback: Option<F>) -> Result<()>
where
    F: Fn(LogLevel, SystemTime, &str) + Send + Sync + 'static,
{
    let mutex = USER_LOGGER.get_or_init(|| Mutex::new(None));
    let mut guard = mutex.lock().map_err(|_| DriverError::InvalidConfig("mutex poisoned".into()))?;

    if let Some(cb) = callback {
        *guard = Some(Box::new(cb));
        if let Ok(dll) = WireGuardDll::load() {
            if let Some(set_logger_fn) = dll.set_logger {
                unsafe {
                    set_logger_fn(Some(global_wireguard_logger_trampoline));
                }
            }
        }
    } else {
        *guard = None;
        if let Some(dll) = WireGuardDll::get_loaded() {
            if let Some(set_logger_fn) = dll.set_logger {
                unsafe {
                    set_logger_fn(None);
                }
            }
        }
    }

    Ok(())
}

/// Synchronous / asynchronous driver log reader that directly polls the WireGuardNT ring log via IOCTL.
pub struct DriverLogReader {
    device_handle: HANDLE,
    stop_signal: Arc<AtomicBool>,
}

unsafe impl Send for DriverLogReader {}
unsafe impl Sync for DriverLogReader {}

impl DriverLogReader {
    /// Constructs a log reader bound to a WireGuard adapter device handle.
    pub fn new(device_handle: HANDLE) -> Self {
        Self {
            device_handle,
            stop_signal: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Synchronously reads a single line from the driver ring log.
    ///
    /// Returns `Ok(Some(entry))` if a line was read, or `Ok(None)` if no more entries are available.
    pub fn read_log_line(&self) -> Result<Option<DriverLogEntry>> {
        if self.device_handle.is_null() || self.device_handle == INVALID_HANDLE_VALUE {
            return Err(DriverError::InvalidConfig("invalid device handle for log read".into()));
        }

        let mut entry = WgIoctlLogEntry {
            timestamp: 0,
            msg: [0; 512],
        };
        let out_slice = unsafe {
            std::slice::from_raw_parts_mut(
                (&mut entry as *mut WgIoctlLogEntry) as *mut u8,
                std::mem::size_of::<WgIoctlLogEntry>(),
            )
        };

        let result = unsafe {
            dev_ioctl(
                self.device_handle,
                WG_IOCTL_READ_LOG_LINE,
                None,
                Some(out_slice),
            )
        };

        match result {
            Ok(bytes_returned) => {
                if bytes_returned < 8 || entry.timestamp == 0 {
                    return Ok(None);
                }

                let max_msg_bytes = (bytes_returned - 8).min(entry.msg.len());
                let mut msg_len = 0;
                while msg_len < max_msg_bytes && entry.msg[msg_len] != 0 {
                    msg_len += 1;
                }

                let raw_msg = &entry.msg[..msg_len];
                let (level, msg_slice) = if !raw_msg.is_empty() && (raw_msg[0] >= b'1' && raw_msg[0] <= b'3') {
                    let lvl = match raw_msg[0] {
                        b'1' => LogLevel::Error,
                        b'2' => LogLevel::Warn,
                        _ => LogLevel::Info,
                    };
                    (lvl, &raw_msg[1..])
                } else {
                    (LogLevel::Info, raw_msg)
                };

                let message = String::from_utf8_lossy(msg_slice).to_string();
                let timestamp = filetime_to_system_time(entry.timestamp);

                Ok(Some(DriverLogEntry {
                    level,
                    timestamp,
                    message,
                }))
            }
            Err(DriverError::IoctlFailed { win32_code, .. }) if win32_code == ERROR_NO_MORE_ITEMS => {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Spawns a background thread that reads the driver ring log and waits on a cancelable
    /// Win32 manual-reset event between empty reads so `stop()` wakes immediately.
    pub fn start_polling_thread<F>(
        &self,
        poll_interval: Duration,
        on_log: F,
    ) -> DriverLogPollingHandle
    where
        F: Fn(DriverLogEntry) + Send + 'static,
    {
        let handle_val = self.device_handle as usize;
        let stop_signal = Arc::clone(&self.stop_signal);
        stop_signal.store(false, Ordering::SeqCst);

        let event_raw = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        let stop_event = if !event_raw.is_null() && event_raw != INVALID_HANDLE_VALUE {
            Some(Arc::new(EventHandle(event_raw)))
        } else {
            None
        };

        let thread_stop = Arc::clone(&stop_signal);
        let thread_event = stop_event.clone();
        let wait_ms = poll_interval.as_millis().min((u32::MAX - 1) as u128) as u32;

        let join_handle = std::thread::spawn(move || {
            let handle = handle_val as HANDLE;
            let reader = DriverLogReader::new(handle);
            while !thread_stop.load(Ordering::Acquire) {
                match reader.read_log_line() {
                    Ok(Some(entry)) => {
                        on_log(entry);
                        continue;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::debug!(error = ?e, "error reading driver log line");
                    }
                }

                if thread_stop.load(Ordering::Acquire) {
                    break;
                }
                if let Some(ref ev) = thread_event {
                    let wait = unsafe { WaitForSingleObject(ev.0, wait_ms) };
                    if wait == WAIT_OBJECT_0 {
                        break;
                    }
                } else {
                    std::thread::sleep(poll_interval);
                }
            }
        });

        DriverLogPollingHandle {
            stop_signal,
            stop_event,
            thread_handle: Some(join_handle),
        }
    }
}

struct EventHandle(HANDLE);

unsafe impl Send for EventHandle {}
unsafe impl Sync for EventHandle {}

impl Drop for EventHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
            self.0 = std::ptr::null_mut();
        }
    }
}

/// Control handle for a background driver log reader polling thread.
pub struct DriverLogPollingHandle {
    stop_signal: Arc<AtomicBool>,
    stop_event: Option<Arc<EventHandle>>,
    thread_handle: Option<std::thread::JoinHandle<()>>,
}

impl DriverLogPollingHandle {
    /// Signals the background thread to stop immediately and waits for termination.
    pub fn stop(&mut self) {
        self.stop_signal.store(true, Ordering::SeqCst);
        if let Some(ref ev) = self.stop_event {
            unsafe {
                SetEvent(ev.0);
            }
        }
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for DriverLogPollingHandle {
    fn drop(&mut self) {
        self.stop();
    }
}
