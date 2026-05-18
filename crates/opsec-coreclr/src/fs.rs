//! Thin wrappers over `Bootstrap` NTAPI dispatchers, plus path helpers.
//!
//! All file IO goes through `opsec_bootstrap`'s indirect syscalls — no
//! `CreateFileW` / `WriteFile` from kernel32.

use alloc::vec::Vec;
use core::ffi::c_void;
use opsec_bootstrap::Bootstrap;

#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

#[repr(C)]
pub struct ObjectAttributes {
    pub length: u32,
    pub root_directory: *mut c_void,
    pub object_name: *mut UnicodeString,
    pub attributes: u32,
    pub security_descriptor: *mut c_void,
    pub security_qos: *mut c_void,
}

#[repr(C)]
pub struct IoStatusBlock {
    pub union_status: usize,
    pub information: usize,
}

pub const OBJ_CASE_INSENSITIVE: u32 = 0x40;
pub const FILE_GENERIC_WRITE: u32 = 0x00120116;
pub const DELETE: u32 = 0x00010000;
pub const FILE_SHARE_READ: u32 = 0x01;
pub const FILE_CREATE: u32 = 0x02;
pub const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
pub const FILE_DELETE_ON_CLOSE: u32 = 0x1000;
pub const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
pub const FILE_DIRECTORY_FILE: u32 = 0x01;

/// Build a UNICODE_STRING wrapping a UTF-16 buffer (length excludes NUL).
///
/// # Safety
/// `buf` must outlive the returned struct.
pub unsafe fn make_unicode_string(buf: &mut [u16]) -> UnicodeString {
    let chars = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    UnicodeString {
        length: (chars * 2) as u16,
        maximum_length: (buf.len() * 2) as u16,
        buffer: buf.as_mut_ptr(),
    }
}

/// Open/create a file via NtCreateFile with `FILE_DELETE_ON_CLOSE`.
///
/// # Safety
/// `path_w` must be NT-style: `\??\C:\path\to\file`.
pub unsafe fn create_file_delete_on_close(
    bs: &Bootstrap,
    path_w: &mut [u16],
) -> Option<*mut c_void> {
    unsafe {
        let mut uname = make_unicode_string(path_w);
        let mut attrs = ObjectAttributes {
            length: core::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: core::ptr::null_mut(),
            object_name: &mut uname,
            attributes: OBJ_CASE_INSENSITIVE,
            security_descriptor: core::ptr::null_mut(),
            security_qos: core::ptr::null_mut(),
        };
        let mut iosb = IoStatusBlock { union_status: 0, information: 0 };
        let mut handle: *mut c_void = core::ptr::null_mut();
        let status = bs.nt_create_file(
            &mut handle,
            FILE_GENERIC_WRITE | DELETE,
            &mut attrs as *mut _ as *mut c_void,
            &mut iosb as *mut _ as *mut c_void,
            core::ptr::null_mut(),
            0,
            FILE_SHARE_READ,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE | FILE_SYNCHRONOUS_IO_NONALERT,
            core::ptr::null_mut(),
            0,
        );
        if status < 0 || handle.is_null() {
            None
        } else {
            Some(handle)
        }
    }
}

/// NtCreateFile to create a directory (FILE_DIRECTORY_FILE).
///
/// # Safety
/// `path_w` must be NT-style.
pub unsafe fn create_directory(bs: &Bootstrap, path_w: &mut [u16]) -> bool {
    unsafe {
        let mut uname = make_unicode_string(path_w);
        let mut attrs = ObjectAttributes {
            length: core::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: core::ptr::null_mut(),
            object_name: &mut uname,
            attributes: OBJ_CASE_INSENSITIVE,
            security_descriptor: core::ptr::null_mut(),
            security_qos: core::ptr::null_mut(),
        };
        let mut iosb = IoStatusBlock { union_status: 0, information: 0 };
        let mut handle: *mut c_void = core::ptr::null_mut();
        let status = bs.nt_create_file(
            &mut handle,
            FILE_GENERIC_WRITE,
            &mut attrs as *mut _ as *mut c_void,
            &mut iosb as *mut _ as *mut c_void,
            core::ptr::null_mut(),
            0,
            FILE_SHARE_READ,
            FILE_CREATE,
            FILE_DIRECTORY_FILE,
            core::ptr::null_mut(),
            0,
        );
        let ok = status >= 0 && !handle.is_null();
        if !handle.is_null() {
            bs.nt_close(handle);
        }
        ok
    }
}

/// Write entire buffer via NtWriteFile.
///
/// # Safety
/// `handle` must be a valid open file handle.
pub unsafe fn write_all(bs: &Bootstrap, handle: *mut c_void, bytes: &[u8]) -> bool {
    unsafe {
        let mut iosb = IoStatusBlock { union_status: 0, information: 0 };
        let status = bs.nt_write_file(
            handle,
            core::ptr::null_mut(), core::ptr::null_mut(),
            core::ptr::null_mut(),
            &mut iosb as *mut _ as *mut c_void,
            bytes.as_ptr() as *const c_void,
            bytes.len() as u32,
            core::ptr::null(),
            core::ptr::null(),
        );
        status >= 0
    }
}

/// Convert "C:\path\to\file" UTF-8 → "\\??\\C:\\path\\to\\file" UTF-16 + NUL.
pub fn to_nt_path(dos: &str) -> Vec<u16> {
    let mut out: Vec<u16> = Vec::with_capacity(dos.len() + 8);
    out.extend("\\??\\".encode_utf16());
    out.extend(dos.encode_utf16());
    out.push(0);
    out
}
