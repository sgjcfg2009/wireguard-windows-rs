use wireguard_ipcfg_core::IpCfgError;

/// Result type for wireguard-ipcfg-dns operations.
pub type Result<T> = std::result::Result<T, DnsError>;

/// Errors that can occur during DNS configuration and network change notifications.
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("Win32 error {0} (0x{0:08X}): {1}")]
    Win32(u32, String),

    #[error("IP configuration core error: {0}")]
    IpCfg(#[from] IpCfgError),

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("UTF-16 conversion failed: {0}")]
    Utf16Conversion(String),

    #[error("Registry operation failed: {0}")]
    Registry(String),

    #[error("Service control operation failed: {0}")]
    Service(String),

    #[error("Callback deregistration failed: {0}")]
    CallbackDeregistration(String),

    #[error("DNS configuration error: {0}")]
    Other(String),
}

impl DnsError {
    /// Constructs a `DnsError::Win32` with a formatted Windows system message.
    pub fn from_win32(code: u32) -> Self {
        let msg = wireguard_ipcfg_core::format_win32_error(code);
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
