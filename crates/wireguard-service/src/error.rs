use std::fmt;

/// WireGuard service-specific error codes matching `services.Error` in the Go reference implementation.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WireGuardServiceCode {
    Success = 0,
    RingloggerOpen = 1,
    LoadConfiguration = 2,
    CreateNetworkAdapter = 3,
    DNSLookup = 4,
    Firewall = 5,
    DeviceSetConfig = 6,
    DeviceBringUp = 7,
    BindSocketsToDefaultRoutes = 8,
    MonitorMTUChanges = 9,
    SetNetConfig = 10,
    DetermineExecutablePath = 11,
    TrackTunnels = 12,
    EnumerateSessions = 13,
    DropPrivileges = 14,
    RunScript = 15,
    Win32 = 16,
}

impl WireGuardServiceCode {
    /// Returns the canonical human-readable error description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Success => "No error",
            Self::RingloggerOpen => "Unable to open log file",
            Self::LoadConfiguration => "Unable to load configuration from path",
            Self::CreateNetworkAdapter => "Unable to create network adapter",
            Self::DNSLookup => "Unable to resolve one or more DNS hostname endpoints",
            Self::Firewall => "Unable to enable firewall rules",
            Self::DeviceSetConfig => "Unable to set device configuration",
            Self::DeviceBringUp => "Unable to bring up adapter",
            Self::BindSocketsToDefaultRoutes => "Unable to bind sockets to default route",
            Self::MonitorMTUChanges => "Unable to monitor default route MTU for changes",
            Self::SetNetConfig => "Unable to configure adapter network settings",
            Self::DetermineExecutablePath => "Unable to determine path of running executable",
            Self::TrackTunnels => "Unable to track existing tunnels",
            Self::EnumerateSessions => "Unable to enumerate current sessions",
            Self::DropPrivileges => "Unable to drop privileges",
            Self::RunScript => "An error occurred while running a configuration script command",
            Self::Win32 => "An internal Windows error has occurred",
        }
    }
}

impl fmt::Display for WireGuardServiceCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// Service error types encompassing Win32 errors, WireGuard service errors, SCM errors, and dispatch issues.
#[derive(thiserror::Error, Debug)]
pub enum ServiceError {
    #[error("Win32 error {code} (0x{code:08X}): {message}")]
    Win32 { code: u32, message: String },

    #[error("WireGuard service error {0}: {1}")]
    WireGuard(WireGuardServiceCode, &'static str),

    #[error("Invalid service name: {0}")]
    InvalidName(String),

    #[error("String contains interior null byte")]
    InteriorNull,

    #[error("Service '{0}' already running")]
    AlreadyRunning(String),

    #[error("Service '{0}' is marked for deletion")]
    MarkedForDelete(String),

    #[error("Service '{0}' does not exist")]
    DoesNotExist(String),

    #[error("SCM connection failed: {0}")]
    ScmConnectFailed(#[source] Box<ServiceError>),

    #[error("Service dispatcher failed (0x{0:08X})")]
    DispatchFailed(u32),

    #[error("Failed to connect to service controller: program was not launched as a Windows service")]
    NotRunningAsService,

    #[error("Security descriptor error: {0}")]
    SecurityDescriptor(String),

    #[error("Service handler panicked: {0}")]
    HandlerPanic(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl ServiceError {
    /// Creates a `ServiceError::Win32` with a formatted message for the error code.
    pub fn from_win32(code: u32) -> Self {
        let message = win32_error_message(code);
        Self::Win32 { code, message }
    }

    /// Creates a `ServiceError` representing the last Win32 error from `GetLastError()`.
    pub fn last_win32_error() -> Self {
        let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        Self::from_win32(code)
    }

    /// Creates a `ServiceError::WireGuard` from a `WireGuardServiceCode`.
    pub fn from_wg_code(code: WireGuardServiceCode) -> Self {
        Self::WireGuard(code, code.description())
    }
}

/// Returns the formatted message for a Win32 error code.
pub fn win32_error_message(code: u32) -> String {
    use windows_sys::Win32::System::Diagnostics::Debug::*;

    let mut buf = [0u16; 512];
    let len = unsafe {
        FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            core::ptr::null(),
            code,
            0,
            buf.as_mut_ptr(),
            buf.len() as u32,
            core::ptr::null(),
        )
    };

    if len > 0 {
        let msg = String::from_utf16_lossy(&buf[..len as usize]);
        msg.trim_end_matches(&['\r', '\n', ' '][..]).to_string()
    } else {
        format!("Error code 0x{code:08X} ({code})")
    }
}

/// Translates a result into SCM error exit code pair `(is_service_specific, exit_code)`.
///
/// Corresponds directly to `DetermineErrorCode(err, serviceError)` in Go `services/errors.go`.
pub fn determine_error_code(res: &Result<(), ServiceError>) -> (bool, u32) {
    match res {
        Ok(()) => (false, windows_sys::Win32::Foundation::NO_ERROR),
        Err(ServiceError::Win32 { code, .. }) => (false, *code),
        Err(ServiceError::WireGuard(code, _)) => {
            if *code == WireGuardServiceCode::Success {
                (false, windows_sys::Win32::Foundation::NO_ERROR)
            } else {
                (true, *code as u32)
            }
        }
        Err(_) => (false, 1),
    }
}
