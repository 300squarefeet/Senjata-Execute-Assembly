//! **TEMPORARY** file-based diagnostic logger for v0.3.3-diag.
//!
//! All logs append to `C:\Windows\Temp\senjata-runner.log`. Operator
//! reads it via `shell type C:\Windows\Temp\senjata-runner.log` after
//! a failed run.
//!
//! Uses only kernel32 imports (CreateFileA, WriteFile, CloseHandle) —
//! does NOT depend on the named pipe, BeaconAPI smartinject, or any
//! orchestrator initialization. Survives even if everything else is
//! broken. Each log line is best-effort; failures are silent so the
//! diagnostic itself never crashes the sacrificial.
//!
//! Remove or feature-gate before shipping v0.4.

use core::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileA, WriteFile, FILE_APPEND_DATA, FILE_SHARE_READ, OPEN_ALWAYS,
};

const LOG_PATH: &[u8] = b"C:\\Windows\\Temp\\senjata-runner.log\0";

/// Append `msg` then a newline to the log file. Errors silently ignored.
pub fn log(msg: &[u8]) {
    unsafe {
        let h = CreateFileA(
            LOG_PATH.as_ptr(),
            FILE_APPEND_DATA,
            FILE_SHARE_READ,
            ptr::null(),
            OPEN_ALWAYS,
            0,
            ptr::null_mut(),
        );
        if h == INVALID_HANDLE_VALUE {
            return;
        }
        let mut n: u32 = 0;
        let _ = WriteFile(h, msg.as_ptr(), msg.len() as u32, &mut n, ptr::null_mut());
        let _ = WriteFile(h, b"\n".as_ptr(), 1, &mut n, ptr::null_mut());
        let _ = CloseHandle(h);
    }
}

/// Append a single labelled hex value (4 bytes).
pub fn log_hex(label: &[u8], value: u32) {
    unsafe {
        let h = CreateFileA(
            LOG_PATH.as_ptr(),
            FILE_APPEND_DATA,
            FILE_SHARE_READ,
            ptr::null(),
            OPEN_ALWAYS,
            0,
            ptr::null_mut(),
        );
        if h == INVALID_HANDLE_VALUE {
            return;
        }
        let mut buf = [0u8; 80];
        let mut n_out: u32 = 0;
        let written = format_label_hex(&mut buf, label, value);
        let _ = WriteFile(h, buf.as_ptr(), written as u32, &mut n_out, ptr::null_mut());
        let _ = CloseHandle(h);
    }
}

fn format_label_hex(buf: &mut [u8], label: &[u8], value: u32) -> usize {
    let mut i = 0;
    for &b in label {
        if i >= buf.len() { break; }
        buf[i] = b;
        i += 1;
    }
    if i < buf.len() {
        buf[i] = b' '; i += 1;
    }
    if i + 2 < buf.len() {
        buf[i] = b'0'; buf[i+1] = b'x'; i += 2;
    }
    for shift in (0..32).step_by(4).rev() {
        if i >= buf.len() { break; }
        let nibble = ((value >> shift) & 0xF) as u8;
        buf[i] = if nibble < 10 { b'0' + nibble } else { b'a' + (nibble - 10) };
        i += 1;
    }
    if i < buf.len() {
        buf[i] = b'\n'; i += 1;
    }
    i
}

/// Capture GetLastError after a Win32 call and append "<label> last_error=0x..".
pub fn log_last_error(label: &[u8]) {
    unsafe {
        let err = GetLastError();
        log_hex(label, err);
    }
}
