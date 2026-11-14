/// Result type for wireguard-ipcfg-core operations.
pub type Result<T> = std::result::Result<T, IpCfgError>;

/// Errors that can occur during IP configuration and interface management.
#[derive(Debug, thiserror::Error)]
pub enum IpCfgError {
    #[error("Win32 error {0} (0x{0:08X}): {1}")]
    Win32(u32, String),

    #[error("Invalid GUID string: \"{0}\"")]
    InvalidGuid(String),

    #[error("Network interface not found")]
    NotFound,

    #[error("Buffer too small: required {0} bytes")]
    BufferTooSmall(usize),

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("String conversion error: {0}")]
    StringConversion(String),

    #[error("IP configuration operation failed: {0}")]
    Other(String),
}

impl IpCfgError {
    /// Constructs an `IpCfgError::Win32` with a formatted error message.
    pub fn from_win32(code: u32) -> Self {
        let msg = format_win32_error(code);
        Self::Win32(code, msg)
    }

    /// Returns the underlying Win32 error code, if this is a `Win32` error.
    pub fn win32_code(&self) -> Option<u32> {
        match self {
            Self::Win32(code, _) => Some(*code),
            _ => None,
        }
    }
}

pub fn format_win32_error(code: u32) -> String {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        FormatMessageW, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS,
    };

    let mut buf = [0u16; 512];
    let len = unsafe {
        FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            std::ptr::null(),
            code,
            0,
            buf.as_mut_ptr(),
            buf.len() as u32,
            std::ptr::null_mut(),
        )
    };

    if len > 0 {
        let mut end = (len as usize).min(buf.len());
        while end > 0 {
            match buf[end - 1] {
                0x000D | 0x000A | 0x0020 | 0x002E => end -= 1, // '\r', '\n', ' ', '.'
                _ => break,
            }
        }
        String::from_utf16_lossy(&buf[..end])
    } else {
        format!("System error 0x{:08X}", code)
    }
}
