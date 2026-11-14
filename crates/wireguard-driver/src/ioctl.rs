use std::ptr;
use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::IO::DeviceIoControl;
use crate::error::{DriverError, Result};

/// WireGuardNT custom device type identifier.
pub const WG_DEVICE_TYPE: u32 = 45208;

/// Transfer method definitions for Windows IOCTL codes.
pub const METHOD_BUFFERED: u32 = 0;
pub const METHOD_IN_DIRECT: u32 = 1;
pub const METHOD_OUT_DIRECT: u32 = 2;
pub const METHOD_NEITHER: u32 = 3;

/// Access definitions for Windows IOCTL codes.
pub const FILE_ANY_ACCESS: u32 = 0;
pub const FILE_READ_ACCESS: u32 = 0x0001;
pub const FILE_WRITE_ACCESS: u32 = 0x0002;
pub const FILE_READ_WRITE_ACCESS: u32 = FILE_READ_ACCESS | FILE_WRITE_ACCESS;

/// Constructs a 32-bit Win32 Control Code (CTL_CODE).
pub const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

/// Retrieve adapter configuration and statistics (WG_IOCTL_GET).
/// Function 321, METHOD_OUT_DIRECT, Read/Write access.
pub const WG_IOCTL_GET: u32 = ctl_code(WG_DEVICE_TYPE, 321, METHOD_OUT_DIRECT, FILE_READ_WRITE_ACCESS);
pub const WG_IOCTL_GET_ADAPTER: u32 = WG_IOCTL_GET;

/// Set adapter configuration and peers (WG_IOCTL_SET).
/// Function 322, METHOD_IN_DIRECT, Read/Write access.
pub const WG_IOCTL_SET: u32 = ctl_code(WG_DEVICE_TYPE, 322, METHOD_IN_DIRECT, FILE_READ_WRITE_ACCESS);
pub const WG_IOCTL_SET_ADAPTER: u32 = WG_IOCTL_SET;

/// Set or query adapter operational state (WG_IOCTL_SET_ADAPTER_STATE).
/// Function 323, METHOD_BUFFERED, Read/Write access.
pub const WG_IOCTL_SET_ADAPTER_STATE: u32 = ctl_code(WG_DEVICE_TYPE, 323, METHOD_BUFFERED, FILE_READ_WRITE_ACCESS);

/// Read next log line from driver's ring buffer (WG_IOCTL_READ_LOG_LINE).
/// Function 324, METHOD_BUFFERED, Read/Write access.
pub const WG_IOCTL_READ_LOG_LINE: u32 = ctl_code(WG_DEVICE_TYPE, 324, METHOD_BUFFERED, FILE_READ_WRITE_ACCESS);
pub const WG_IOCTL_READ_LOG: u32 = WG_IOCTL_READ_LOG_LINE;

/// Safe wrapper around Win32 `DeviceIoControl`.
///
/// Sends a control code to a device handle with optional input and output buffers.
/// Returns the number of bytes written to `out_buffer` on success.
///
/// If the output buffer is insufficient and the driver signals `ERROR_MORE_DATA`,
/// this returns `Err(DriverError::BufferTooSmall)` indicating retry is necessary.
pub unsafe fn dev_ioctl(
    handle: HANDLE,
    control_code: u32,
    in_buffer: Option<&[u8]>,
    out_buffer: Option<&mut [u8]>,
) -> Result<usize> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(DriverError::InvalidConfig("invalid device handle".into()));
    }

    let (in_ptr, in_size) = in_buffer.map_or((ptr::null(), 0), |b| (b.as_ptr() as *const _, b.len() as u32));
    let (out_ptr, out_size) =
        out_buffer.map_or((ptr::null_mut(), 0), |b| (b.as_mut_ptr() as *mut _, b.len() as u32));

    let mut bytes_returned: u32 = 0;
    let ok = DeviceIoControl(
        handle,
        control_code,
        in_ptr,
        in_size,
        out_ptr,
        out_size,
        &mut bytes_returned,
        ptr::null_mut(),
    );

    if ok == 0 {
        let err = windows_sys::Win32::Foundation::GetLastError();
        if err == ERROR_MORE_DATA {
            return Err(DriverError::BufferTooSmall {
                required: bytes_returned as usize,
                provided: out_size as usize,
            });
        }
        return Err(DriverError::from_ioctl_error(control_code, err));
    }

    Ok(bytes_returned as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioctl_codes() {
        assert_eq!(WG_IOCTL_GET, 0xB098C506);
        assert_eq!(WG_IOCTL_SET, 0xB098C509);
        assert_eq!(WG_IOCTL_SET_ADAPTER_STATE, 0xB098C50C);
        assert_eq!(WG_IOCTL_READ_LOG_LINE, 0xB098C510);
    }
}
