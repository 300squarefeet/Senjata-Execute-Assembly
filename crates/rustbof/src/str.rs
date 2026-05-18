use alloc::ffi::CString;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::CStr;

/// Converts a Rust string to a C string, truncating at first interior null.
#[inline]
pub fn to_cstr(s: &str) -> CString {
    let bytes = s.as_bytes();
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    unsafe { CString::from_vec_unchecked(bytes[..len].to_vec()) }
}

/// Converts a null-terminated C string to a Rust string slice.
#[inline]
pub fn from_cstr(data: &[i8]) -> &str {
    let bytes = unsafe { core::slice::from_raw_parts(data.as_ptr() as *const u8, data.len()) };
    CStr::from_bytes_until_nul(bytes)
        .map(|c| c.to_str().unwrap_or(""))
        .unwrap_or("")
}

/// Converts a Rust string to a null-terminated UTF-16 wide string.
#[inline]
pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Converts a UTF-16 wide string slice to a Rust String.
#[inline]
pub fn from_wide(data: &[u16]) -> String {
    let end = data.iter().position(|&c| c == 0).unwrap_or(data.len());
    String::from_utf16_lossy(&data[..end])
}
