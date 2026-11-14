use crate::error::{IpCfgError, Result};

/// Encodes `s` as null-terminated UTF-16 on the stack when it fits within 259 code units,
/// falling back to a heap `Vec<u16>` only for longer strings.
#[inline]
pub(crate) fn with_wide_null<R>(s: &str, f: impl FnOnce(*const u16) -> R) -> R {
    const STACK_CAP: usize = 260;
    let mut stack = [0u16; STACK_CAP];
    let mut idx = 0usize;

    for unit in s.encode_utf16() {
        if idx + 1 >= STACK_CAP {
            let mut heap = Vec::with_capacity(idx + s.len() + 1);
            heap.extend_from_slice(&stack[..idx]);
            heap.extend(s.encode_utf16().skip(idx));
            heap.push(0);
            return f(heap.as_ptr());
        }
        stack[idx] = unit;
        idx += 1;
    }

    stack[idx] = 0;
    f(stack.as_ptr())
}

/// Decodes a null-terminated UTF-16 slice using lossy replacement for invalid surrogates.
#[inline]
pub(crate) fn decode_utf16_null_terminated(slice: &[u16]) -> String {
    let len = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    String::from_utf16_lossy(&slice[..len])
}

/// Decodes a null-terminated UTF-16 slice strictly, returning `IpCfgError::StringConversion` on invalid UTF-16.
#[inline]
pub(crate) fn decode_utf16_strict(slice: &[u16]) -> Result<String> {
    let len = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    String::from_utf16(&slice[..len]).map_err(|e| IpCfgError::StringConversion(e.to_string()))
}
