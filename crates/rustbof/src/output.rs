//! Output handling for sending data back to the operator.

use alloc::vec::Vec;
use core::fmt::Write;
use core::ptr::addr_of_mut;

use crate::beacon_api;

/// Callback type for standard output.
pub const CALLBACK_OUTPUT: i32 = 0x00;
/// Callback type for OEM codepage output.
pub const CALLBACK_OUTPUT_OEM: i32 = 0x1E;
/// Callback type for UTF-8 output.
pub const CALLBACK_OUTPUT_UTF8: i32 = 0x20;
/// Callback type for error output.
pub const CALLBACK_ERROR: i32 = 0x0D;
/// Custom callback range start.
pub const CALLBACK_CUSTOM: i32 = 0x1000;
/// Custom callback range end.
pub const CALLBACK_CUSTOM_LAST: i32 = 0x13FF;
/// Global output buffer.
static mut BUFFER: Vec<u8> = Vec::new();

/// Buffered writer implementing `core::fmt::Write`.
pub struct BeaconWriter;

impl Write for BeaconWriter {
    #[inline]
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        unsafe { (*addr_of_mut!(BUFFER)).extend_from_slice(s.as_bytes()) };
        Ok(())
    }
}

/// Flushes the internal buffer with the specified callback type.
#[inline]
pub fn flush(callback: i32) {
    let buf = unsafe { &mut *addr_of_mut!(BUFFER) };
    if !buf.is_empty() {
        unsafe { BeaconOutput(callback, buf.as_ptr(), buf.len() as i32) };
        buf.clear();
    }
}

beacon_api!(BeaconOutput: extern "C" fn(_type: i32, data: *const u8, len: i32));
