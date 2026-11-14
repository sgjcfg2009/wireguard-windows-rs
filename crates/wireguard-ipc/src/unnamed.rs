use std::os::windows::io::RawHandle;
use std::ptr;
use windows_sys::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::Pipes::CreatePipe;

use crate::error::IpcError;
use crate::handle::PipeHandle;

/// Default buffer size for anonymous pipes (64 KiB).
pub const DEFAULT_ANONYMOUS_PIPE_SIZE: u32 = 64 * 1024;

/// Utility for creating Win32 anonymous pipe pairs with precise inheritance control.
pub struct AnonymousPipe;

impl AnonymousPipe {
    /// Creates a pair of connected anonymous pipe handles: `(read_handle, write_handle)`.
    ///
    /// The `read_inheritable` and `write_inheritable` flags determine whether each respective
    /// handle will be inherited by child processes.
    pub fn create_pair(
        read_inheritable: bool,
        write_inheritable: bool,
        buffer_size: u32,
    ) -> Result<(PipeHandle, PipeHandle), IpcError> {
        let size = if buffer_size == 0 {
            DEFAULT_ANONYMOUS_PIPE_SIZE
        } else {
            buffer_size
        };

        let any_inheritable = read_inheritable || write_inheritable;
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: ptr::null_mut(),
            bInheritHandle: if any_inheritable { 1 } else { 0 },
        };

        let mut read_raw: HANDLE = INVALID_HANDLE_VALUE;
        let mut write_raw: HANDLE = INVALID_HANDLE_VALUE;

        let ok = unsafe { CreatePipe(&mut read_raw, &mut write_raw, &sa, size) };
        if ok == 0 {
            return Err(IpcError::last_win32_error("CreatePipe"));
        }

        let read_handle = unsafe { PipeHandle::from_raw(read_raw) };
        let write_handle = unsafe { PipeHandle::from_raw(write_raw) };

        if any_inheritable {
            if !read_inheritable {
                let ok = unsafe { SetHandleInformation(read_handle.as_raw(), HANDLE_FLAG_INHERIT, 0) };
                if ok == 0 {
                    return Err(IpcError::last_win32_error("SetHandleInformation"));
                }
            }
            if !write_inheritable {
                let ok = unsafe { SetHandleInformation(write_handle.as_raw(), HANDLE_FLAG_INHERIT, 0) };
                if ok == 0 {
                    return Err(IpcError::last_win32_error("SetHandleInformation"));
                }
            }
        }

        Ok((read_handle, write_handle))
    }
}

/// The three IPC pipe pairs used between the elevated Manager Service and the child UI process.
///
/// Matches the original Go architecture:
/// 1. Request pipe: UI writes requests, Manager reads requests.
/// 2. Response pipe: Manager writes responses, UI reads responses.
/// 3. Events pipe: Manager writes notifications, UI reads notifications.
pub struct ManagerUiPipes {
    /// Manager reads UI requests from this pipe.
    pub manager_reader: PipeHandle,
    /// Manager writes UI responses to this pipe.
    pub manager_writer: PipeHandle,
    /// Manager writes UI event notifications to this pipe.
    pub manager_events: PipeHandle,

    /// UI response reader handle (inherited by child UI).
    pub ui_reader: PipeHandle,
    /// UI request writer handle (inherited by child UI).
    pub ui_writer: PipeHandle,
    /// UI events reader handle (inherited by child UI).
    pub ui_events: PipeHandle,
}

/// The set of raw Win32 handles to be passed to the child UI process.
pub struct UiChildHandles {
    pub reader_handle: HANDLE,
    pub writer_handle: HANDLE,
    pub events_handle: HANDLE,
}

impl UiChildHandles {
    /// Returns the handles as an array for `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`.
    pub fn as_handle_slice(&self) -> [HANDLE; 3] {
        [self.reader_handle, self.writer_handle, self.events_handle]
    }

    /// Formats the command line arguments containing the handle numbers (decimal strings).
    pub fn to_cmdline_args(&self) -> [String; 3] {
        [
            (self.reader_handle as usize).to_string(),
            (self.writer_handle as usize).to_string(),
            (self.events_handle as usize).to_string(),
        ]
    }
}

impl ManagerUiPipes {
    /// Creates the complete set of manager-UI IPC pipes.
    ///
    /// The manager-side handles are configured as NOT inheritable.
    /// The UI-side handles are configured as INHERITABLE so they can be passed
    /// to the child process via `CreateProcessAsUser` / `StartupInfoEx`.
    pub fn create() -> Result<Self, IpcError> {
        // UI Request pipe: UI writes (inheritable), Manager reads (non-inheritable)
        let (manager_reader, ui_writer) = AnonymousPipe::create_pair(false, true, 0)?;

        // UI Response pipe: Manager writes (non-inheritable), UI reads (inheritable)
        let (ui_reader, manager_writer) = AnonymousPipe::create_pair(true, false, 0)?;

        // UI Events pipe: Manager writes (non-inheritable), UI reads (inheritable)
        let (ui_events, manager_events) = AnonymousPipe::create_pair(true, false, 0)?;

        Ok(Self {
            manager_reader,
            manager_writer,
            manager_events,
            ui_reader,
            ui_writer,
            ui_events,
        })
    }

    /// Extracts the inheritable UI child handles, closing them in the parent
    /// process after the child process has been spawned.
    pub fn extract_child_handles(&self) -> UiChildHandles {
        UiChildHandles {
            reader_handle: self.ui_reader.as_raw(),
            writer_handle: self.ui_writer.as_raw(),
            events_handle: self.ui_events.as_raw(),
        }
    }

    /// Closes the UI-side handles in the manager process after spawning the child.
    pub fn close_ui_handles(self) -> (PipeHandle, PipeHandle, PipeHandle) {
        drop(self.ui_reader);
        drop(self.ui_writer);
        drop(self.ui_events);
        (self.manager_reader, self.manager_writer, self.manager_events)
    }
}

/// The UI-side client pipes reconstructed from inherited handles.
pub struct UiClientPipes {
    pub reader: PipeHandle,
    pub writer: PipeHandle,
    pub events: PipeHandle,
}

impl UiClientPipes {
    /// Reconstructs the UI client pipes from raw handle values passed on the command line.
    ///
    /// # Safety
    /// The caller must ensure that the handles are valid open handles inherited by this process.
    pub unsafe fn from_raw_handles(
        reader_raw: RawHandle,
        writer_raw: RawHandle,
        events_raw: RawHandle,
    ) -> Self {
        Self {
            reader: PipeHandle::from_raw(reader_raw as HANDLE),
            writer: PipeHandle::from_raw(writer_raw as HANDLE),
            events: PipeHandle::from_raw(events_raw as HANDLE),
        }
    }
}
