use std::ptr;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, ERROR_SEM_TIMEOUT,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, WaitNamedPipeW,
    PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

use crate::error::{with_wide_null, IpcError};
use crate::handle::PipeHandle;
use crate::security::{SecurityDescriptor, STRICT_PIPE_SDDL};

const PIPE_PREFIX: &str = r"\\.\pipe\";

const PIPE_PREFIX_W: [u16; 9] = [
    b'\\' as u16,
    b'\\' as u16,
    b'.' as u16,
    b'\\' as u16,
    b'p' as u16,
    b'i' as u16,
    b'p' as u16,
    b'e' as u16,
    b'\\' as u16,
];

/// Win32 Pipe open mode constants
pub const PIPE_ACCESS_DUPLEX: u32 = 0x00000003;
pub const GENERIC_READ: u32 = 0x80000000;
pub const GENERIC_WRITE: u32 = 0x40000000;

/// Default buffer size for named pipe communication (64 KiB).
pub const DEFAULT_PIPE_BUFFER_SIZE: u32 = 64 * 1024;

/// Default timeout for waiting on pipe connections (5 seconds).
pub const DEFAULT_PIPE_TIMEOUT_MS: u32 = 5000;

/// Formats a pipe name to ensure it starts with the Win32 named pipe path `\\.\pipe\`.
pub fn normalize_pipe_name(name: &str) -> String {
    if name.starts_with(PIPE_PREFIX) {
        name.to_string()
    } else {
        let stripped = name.trim_start_matches('\\');
        let mut out = String::with_capacity(PIPE_PREFIX.len() + stripped.len());
        out.push_str(PIPE_PREFIX);
        out.push_str(stripped);
        out
    }
}

fn with_normalized_pipe_name_wide<R>(name: &str, f: impl FnOnce(*const u16) -> R) -> R {
    if name.starts_with(PIPE_PREFIX) {
        return with_wide_null(name, f);
    }
    const STACK_CAP: usize = 256;
    let stripped = name.trim_start_matches('\\');
    let mut stack = [0u16; STACK_CAP];
    stack[..PIPE_PREFIX_W.len()].copy_from_slice(&PIPE_PREFIX_W);
    let mut len = PIPE_PREFIX_W.len();
    let mut iter = stripped.encode_utf16();
    while let Some(u) = iter.next() {
        if len + 1 >= STACK_CAP {
            let mut heap = Vec::with_capacity(len + 1 + iter.size_hint().0 + 1);
            heap.extend_from_slice(&stack[..len]);
            heap.push(u);
            heap.extend(iter);
            heap.push(0);
            return f(heap.as_ptr());
        }
        stack[len] = u;
        len += 1;
    }
    stack[len] = 0;
    f(stack.as_ptr())
}

/// Server instance of a Win32 Named Pipe.
pub struct NamedPipeServer {
    handle: PipeHandle,
    name: String,
}

impl NamedPipeServer {
    /// Creates a new named pipe server with the default strict security descriptor:
    /// `O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)`.
    pub fn create(name: &str) -> Result<Self, IpcError> {
        Self::create_with_sddl(name, STRICT_PIPE_SDDL, false)
    }

    /// Creates a new named pipe server with a custom SDDL security descriptor.
    ///
    /// If `first_instance` is true, pipe creation will fail if an instance already exists.
    pub fn create_with_sddl(name: &str, sddl: &str, first_instance: bool) -> Result<Self, IpcError> {
        let full_name = normalize_pipe_name(name);

        let sd = SecurityDescriptor::from_sddl(sddl)?;
        let sa = sd.to_security_attributes(false);

        let mut open_mode = PIPE_ACCESS_DUPLEX;
        if first_instance {
            open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }

        let pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT;

        let handle = with_wide_null(&full_name, |wide_name| unsafe {
            CreateNamedPipeW(
                wide_name,
                open_mode,
                pipe_mode,
                PIPE_UNLIMITED_INSTANCES,
                DEFAULT_PIPE_BUFFER_SIZE,
                DEFAULT_PIPE_BUFFER_SIZE,
                DEFAULT_PIPE_TIMEOUT_MS,
                &sa,
            )
        });

        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(IpcError::last_win32_error("CreateNamedPipeW"));
        }

        Ok(Self {
            handle: unsafe { PipeHandle::from_raw(handle) },
            name: full_name,
        })
    }

    /// Waits for a client to connect to this pipe instance.
    pub fn wait_for_connection(&self) -> Result<(), IpcError> {
        let ok = unsafe { ConnectNamedPipe(self.handle.as_raw(), ptr::null_mut()) };
        if ok != 0 {
            return Ok(());
        }

        let err = unsafe { GetLastError() };
        if err == ERROR_PIPE_CONNECTED {
            // Client connected between CreateNamedPipe and ConnectNamedPipe
            Ok(())
        } else {
            Err(IpcError::from_win32("ConnectNamedPipe", err))
        }
    }

    /// Disconnects the connected client from this pipe instance.
    pub fn disconnect(&self) -> Result<(), IpcError> {
        let ok = unsafe { DisconnectNamedPipe(self.handle.as_raw()) };
        if ok == 0 {
            return Err(IpcError::last_win32_error("DisconnectNamedPipe"));
        }
        Ok(())
    }

    /// Consumes the server and returns the underlying connected `PipeHandle`.
    pub fn into_handle(self) -> PipeHandle {
        self.handle
    }

    /// Returns a reference to the underlying `PipeHandle`.
    pub fn handle(&self) -> &PipeHandle {
        &self.handle
    }

    /// Returns the normalized pipe name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Client for connecting to a Win32 Named Pipe.
pub struct NamedPipeClient;

impl NamedPipeClient {
    /// Connects to a named pipe with an optional timeout in milliseconds.
    pub fn connect(name: &str, timeout_ms: Option<u32>) -> Result<PipeHandle, IpcError> {
        let timeout_val = timeout_ms.unwrap_or(DEFAULT_PIPE_TIMEOUT_MS);
        let timeout = Duration::from_millis(timeout_val as u64);
        let start = Instant::now();

        with_normalized_pipe_name_wide(name, |wide_name| loop {
            let handle = unsafe {
                CreateFileW(
                    wide_name,
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    ptr::null(),
                    OPEN_EXISTING,
                    0,
                    ptr::null_mut(),
                )
            };

            if handle != INVALID_HANDLE_VALUE && !handle.is_null() {
                return Ok(unsafe { PipeHandle::from_raw(handle) });
            }

            let err = unsafe { GetLastError() };
            if err == ERROR_PIPE_BUSY {
                let remaining = timeout.saturating_sub(start.elapsed());
                if remaining.is_zero() {
                    return Err(IpcError::Timeout(timeout_val));
                }
                // WaitNamedPipeW treats 0 as NMPWAIT_USE_DEFAULT_WAIT and 0xFFFFFFFF as infinite.
                let wait_ms = remaining.as_millis().clamp(1, (u32::MAX - 1) as u128) as u32;
                let waited = unsafe { WaitNamedPipeW(wide_name, wait_ms) };
                if waited == 0 {
                    let wait_err = unsafe { GetLastError() };
                    if wait_err == ERROR_SEM_TIMEOUT {
                        return Err(IpcError::Timeout(timeout_val));
                    }
                    if wait_err == ERROR_FILE_NOT_FOUND {
                        return Err(IpcError::from_win32(
                            "NamedPipeClient::connect (pipe not found)",
                            wait_err,
                        ));
                    }
                    return Err(IpcError::from_win32("WaitNamedPipeW", wait_err));
                }
                continue;
            } else if err == ERROR_FILE_NOT_FOUND {
                return Err(IpcError::from_win32(
                    "NamedPipeClient::connect (pipe not found)",
                    err,
                ));
            } else {
                return Err(IpcError::from_win32("CreateFileW", err));
            }
        })
    }
}
