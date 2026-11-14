use windows_sys::Win32::Foundation::*;

/// Result type for wireguard-ipcfg-routes operations.
pub type Result<T> = std::result::Result<T, RouteError>;

/// Error types for IP address and routing table operations.
#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error("Win32 error {0} (0x{0:08X}): {1}")]
    Win32(u32, String),

    #[error("Route not found")]
    NotFound,

    #[error("Object or IP address already exists")]
    AlreadyExists,

    #[error("Invalid IP prefix or CIDR: {0}")]
    InvalidPrefix(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("String conversion error: {0}")]
    StringConversion(String),

    #[error("Null pointer returned by Win32 IP Helper API")]
    NullPointer,

    #[error("IP routing operation failed: {0}")]
    Other(String),
}

impl RouteError {
    /// Constructs a `RouteError` from a Win32 error code.
    pub fn from_win32(code: u32) -> Self {
        match code {
            ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND => Self::NotFound,
            ERROR_OBJECT_ALREADY_EXISTS => Self::AlreadyExists,
            other => {
                let msg = wireguard_ipcfg_core::format_win32_error(other);
                Self::Win32(other, msg)
            }
        }
    }

    /// Returns the underlying Win32 error code, if this error originated from Win32.
    pub fn win32_code(&self) -> Option<u32> {
        match self {
            Self::Win32(code, _) => Some(*code),
            Self::NotFound => Some(ERROR_NOT_FOUND),
            Self::AlreadyExists => Some(ERROR_OBJECT_ALREADY_EXISTS),
            _ => None,
        }
    }

    /// Returns `true` if the error indicates an entity was not found.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound)
    }

    /// Returns `true` if the error indicates an entity already exists.
    pub fn is_already_exists(&self) -> bool {
        matches!(self, Self::AlreadyExists)
    }
}

impl From<u32> for RouteError {
    fn from(code: u32) -> Self {
        Self::from_win32(code)
    }
}
