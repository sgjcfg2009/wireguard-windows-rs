use thiserror::Error;

/// Result type for wireguard-driver operations.
pub type Result<T, E = DriverError> = std::result::Result<T, E>;

/// Errors encountered during WireGuard driver interactions.
#[derive(Debug, Error)]
pub enum DriverError {
    #[error("Win32 error during {operation}: code {code} ({message})")]
    Win32 {
        code: u32,
        operation: &'static str,
        message: String,
    },

    #[error("failed to load driver library '{path}': code {code}")]
    DllNotFound { path: String, code: u32 },

    #[error("required DLL procedure symbol '{symbol}' was not found")]
    ProcNotFound { symbol: &'static str },

    #[error("invalid WireGuard configuration: {0}")]
    InvalidConfig(String),

    #[error("buffer too small: required {required} bytes, but provided {provided} bytes")]
    BufferTooSmall { required: usize, provided: usize },

    #[error("IOCTL operation 0x{control_code:08X} failed with Win32 code {win32_code}: {message}")]
    IoctlFailed {
        control_code: u32,
        win32_code: u32,
        message: String,
    },

    #[error("failed to convert string to/from UTF-16: {0}")]
    Utf16Conversion(String),

    #[error("adapter '{0}' was not found")]
    AdapterNotFound(String),

    #[error("Wintun session error: {0}")]
    WintunSession(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl DriverError {
    /// Constructs a `Win32` error from an explicit Win32 error code.
    pub(crate) fn from_win32_error(operation: &'static str, code: u32) -> Self {
        let message = std::io::Error::from_raw_os_error(code as i32).to_string();
        Self::Win32 {
            code,
            operation,
            message,
        }
    }

    /// Constructs a `Win32` error from the thread's last Win32 error code.
    pub fn last_win32_error(operation: &'static str) -> Self {
        let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        Self::from_win32_error(operation, code)
    }

    /// Constructs an `IoctlFailed` error from a control code and explicit Win32 error code.
    pub(crate) fn from_ioctl_error(control_code: u32, win32_code: u32) -> Self {
        let message = std::io::Error::from_raw_os_error(win32_code as i32).to_string();
        Self::IoctlFailed {
            control_code,
            win32_code,
            message,
        }
    }

    /// Constructs an `IoctlFailed` error from a control code and last Win32 error.
    pub fn last_ioctl_error(control_code: u32) -> Self {
        let win32_code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        Self::from_ioctl_error(control_code, win32_code)
    }
}
