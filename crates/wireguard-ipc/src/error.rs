use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Win32 API error: code {0} ({1})")]
    Win32(u32, String),

    #[error("Serialization / JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Security descriptor error: {0}")]
    Security(String),

    #[error("Frame error: {0}")]
    Frame(String),

    #[error("Pipe broken or disconnected")]
    PipeBroken,

    #[error("Timeout waiting for pipe: {0} ms")]
    Timeout(u32),

    #[error("Invalid message received: {0}")]
    InvalidMessage(String),

    #[error("Server returned error: {0}")]
    Server(String),

    #[error("Access denied")]
    AccessDenied,
}

impl IpcError {
    pub(crate) fn from_win32(function_name: &str, code: u32) -> Self {
        let msg = format!("{function_name} failed with Win32 error code {code}");
        IpcError::Win32(code, msg)
    }

    pub fn last_win32_error(function_name: &str) -> Self {
        let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        Self::from_win32(function_name, code)
    }
}

/// Encodes `s` as NUL-terminated UTF-16 onto a stack buffer (falling back to heap if >= 256 units)
/// and passes its pointer to `f`.
pub(crate) fn with_wide_null<R>(s: &str, f: impl FnOnce(*const u16) -> R) -> R {
    const STACK_CAP: usize = 256;
    let mut stack = [0u16; STACK_CAP];
    let mut len = 0usize;
    let mut iter = s.encode_utf16();
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
