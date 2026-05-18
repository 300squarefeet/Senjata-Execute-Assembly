//! Read REG_SZ values from HKEY_LOCAL_MACHINE via NtOpenKey + NtQueryValueKey.

use alloc::vec::Vec;
use core::ffi::c_void;
use opsec_bootstrap::Bootstrap;

use crate::fs::{ObjectAttributes, OBJ_CASE_INSENSITIVE};

const KEY_READ: u32 = 0x20019;
const KEY_QUERY_VALUE_INFORMATION_CLASS: u32 = 2; // KeyValuePartialInformation

/// Read a REG_SZ value from `HKEY_LOCAL_MACHINE\<subkey>`.
///
/// `subkey_w` is NT-style — must be prefixed with `\Registry\Machine\`.
/// `value_w` is the UTF-16 NUL-terminated value name.
///
/// Returns the string contents (UTF-16 → UTF-8 best effort, NUL stripped)
/// or None on any error.
///
/// # Safety
/// Both buffers must remain valid for the call duration.
pub unsafe fn read_reg_sz_machine(
    bs: &Bootstrap,
    subkey_w: &mut [u16],
    value_w: &mut [u16],
) -> Option<alloc::string::String> {
    unsafe {
        let mut sub_name = crate::fs::make_unicode_string(subkey_w);
        let mut attrs = ObjectAttributes {
            length: core::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: core::ptr::null_mut(),
            object_name: &mut sub_name,
            attributes: OBJ_CASE_INSENSITIVE,
            security_descriptor: core::ptr::null_mut(),
            security_qos: core::ptr::null_mut(),
        };
        let mut key_handle: *mut c_void = core::ptr::null_mut();
        let status = bs.nt_open_key(
            &mut key_handle, KEY_READ,
            &mut attrs as *mut _ as *mut c_void);
        if status < 0 || key_handle.is_null() {
            return None;
        }

        let mut value_name = crate::fs::make_unicode_string(value_w);
        let mut buffer = [0u8; 1024];
        let mut result_len: u32 = 0;
        let status = bs.nt_query_value_key(
            key_handle,
            &mut value_name as *mut _ as *mut c_void,
            KEY_QUERY_VALUE_INFORMATION_CLASS,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u32,
            &mut result_len);
        bs.nt_close(key_handle);
        if status < 0 || result_len < 12 {
            return None;
        }

        let info = &buffer[0..12];
        let data_type = u32::from_le_bytes([info[4], info[5], info[6], info[7]]);
        let data_length = u32::from_le_bytes([info[8], info[9], info[10], info[11]]) as usize;
        if data_type != 1 && data_type != 2 {  // REG_SZ=1, REG_EXPAND_SZ=2
            return None;
        }
        let data_start: usize = 12;
        let data_end = data_start.saturating_add(data_length).min(buffer.len());
        if data_end <= data_start { return None; }
        let raw = &buffer[data_start..data_end];

        let u16s: Vec<u16> = raw
            .chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .take_while(|&c| c != 0)
            .collect();
        let s = alloc::string::String::from_utf16(&u16s).ok()?;
        Some(s)
    }
}
