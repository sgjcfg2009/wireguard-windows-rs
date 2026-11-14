use std::io::{self, Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, RawHandle};
use std::ptr;
use windows_sys::Win32::Foundation::{
    CloseHandle, DuplicateHandle, GetLastError, DUPLICATE_SAME_ACCESS,
    ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED, HANDLE, HANDLE_FLAG_INHERIT,
    INVALID_HANDLE_VALUE, SetHandleInformation,
};
use windows_sys::Win32::Storage::FileSystem::{FlushFileBuffers, ReadFile, WriteFile};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use crate::error::IpcError;

/// Safe RAII wrapper around a Win32 pipe handle.
#[derive(Debug)]
pub struct PipeHandle(pub(crate) HANDLE);

unsafe impl Send for PipeHandle {}
unsafe impl Sync for PipeHandle {}

impl PipeHandle {
    /// Constructs a `PipeHandle` from a raw Win32 handle.
    ///
    /// # Safety
    /// The caller must ensure that `handle` is a valid open Win32 handle
    /// and that ownership is transferred to this struct.
    pub unsafe fn from_raw(handle: HANDLE) -> Self {
        Self(handle)
    }

    /// Returns the raw Win32 handle without transferring ownership.
    pub fn as_raw(&self) -> HANDLE {
        self.0
    }

    /// Consumes the wrapper, transferring ownership of the raw handle to the caller.
    pub fn into_raw(mut self) -> HANDLE {
        let handle = self.0;
        self.0 = INVALID_HANDLE_VALUE;
        handle
    }

    /// Checks if the handle is invalid or null.
    pub fn is_invalid(&self) -> bool {
        self.0 == INVALID_HANDLE_VALUE || self.0.is_null()
    }

    /// Sets whether this handle is inheritable by child processes.
    pub fn set_inheritable(&self, inheritable: bool) -> Result<(), IpcError> {
        let flags = if inheritable { HANDLE_FLAG_INHERIT } else { 0 };
        let ok = unsafe { SetHandleInformation(self.0, HANDLE_FLAG_INHERIT, flags) };
        if ok == 0 {
            return Err(IpcError::last_win32_error("SetHandleInformation"));
        }
        Ok(())
    }

    /// Duplicates the handle for the current process.
    pub fn try_clone(&self) -> Result<Self, IpcError> {
        let mut new_handle: HANDLE = ptr::null_mut();
        let cur_proc = unsafe { GetCurrentProcess() };
        let ok = unsafe {
            DuplicateHandle(
                cur_proc,
                self.0,
                cur_proc,
                &mut new_handle,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if ok == 0 || new_handle.is_null() || new_handle == INVALID_HANDLE_VALUE {
            return Err(IpcError::last_win32_error("DuplicateHandle"));
        }
        Ok(Self(new_handle))
    }

    /// Blocks the caller until the receiving process has read and consumed all unread bytes
    /// from the pipe buffer (Win32 `FlushFileBuffers`).
    pub fn flush_until_drained(&self) -> Result<(), IpcError> {
        let ok = unsafe { FlushFileBuffers(self.0) };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            if err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED {
                return Ok(());
            }
            return Err(IpcError::from_win32("FlushFileBuffers", err));
        }
        Ok(())
    }
}

impl Drop for PipeHandle {
    fn drop(&mut self) {
        if !self.is_invalid() {
            unsafe {
                CloseHandle(self.0);
            }
            self.0 = INVALID_HANDLE_VALUE;
        }
    }
}

impl Read for PipeHandle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let to_read = buf.len().min(u32::MAX as usize) as u32;
        let mut bytes_read: u32 = 0;

        let ok = unsafe {
            ReadFile(
                self.0,
                buf.as_mut_ptr(),
                to_read,
                &mut bytes_read,
                ptr::null_mut(),
            )
        };

        if ok != 0 {
            return Ok(bytes_read as usize);
        }

        let err = unsafe { GetLastError() };
        match err {
            ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED => {
                // Pipe was closed at the other end: return EOF
                Ok(0)
            }
            other => Err(io::Error::from_raw_os_error(other as i32)),
        }
    }
}

impl Write for PipeHandle {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let to_write = buf.len().min(u32::MAX as usize) as u32;
        let mut bytes_written: u32 = 0;

        let ok = unsafe {
            WriteFile(
                self.0,
                buf.as_ptr(),
                to_write,
                &mut bytes_written,
                ptr::null_mut(),
            )
        };

        if ok != 0 {
            return Ok(bytes_written as usize);
        }

        let err = unsafe { GetLastError() };
        match err {
            ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED => {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "pipe broken"))
            }
            other => Err(io::Error::from_raw_os_error(other as i32)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // On Win32 pipes, FlushFileBuffers blocks until the reader empties the buffer,
        // which causes deadlocks in synchronous request-response pipelines.
        // Data written via WriteFile is already committed to the kernel pipe buffer.
        Ok(())
    }
}

impl AsRawHandle for PipeHandle {
    fn as_raw_handle(&self) -> RawHandle {
        self.0 as RawHandle
    }
}

impl IntoRawHandle for PipeHandle {
    fn into_raw_handle(self) -> RawHandle {
        self.into_raw() as RawHandle
    }
}

impl FromRawHandle for PipeHandle {
    unsafe fn from_raw_handle(handle: RawHandle) -> Self {
        Self::from_raw(handle as HANDLE)
    }
}
