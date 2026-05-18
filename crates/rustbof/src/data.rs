//! Argument parsing for BOF entry points.

use crate::beacon_api;

/// Internal Beacon data parser state.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Data {
    original: *mut i8,
    buffer: *mut i8,
    length: i32,
    size: i32,
}

/// Safe wrapper around Beacon's argument parser.
///
/// Tracks position and remaining bytes while extracting typed values
/// from the serialized argument buffer.
///
/// # Examples
///
/// ```ignore
/// use rustbof::data::DataParser;
///
/// fn parse_args(args: *mut u8, len: usize) {
///     let mut parser = DataParser::new(args, len);
///
///     let pid = parser.get_int();
///     let flags = parser.get_short();
///     let path = parser.get_str();
///
///     println!("Remaining bytes: {}", parser.remaining());
/// }
/// ```
#[repr(transparent)]
pub struct DataParser(Data);

impl DataParser {
    /// Creates a new parser from a raw pointer and length.
    #[inline]
    pub fn new(ptr: *mut u8, len: usize) -> Self {
        let mut inner = Data {
            original: ptr.cast(),
            buffer: core::ptr::null_mut(),
            length: 0,
            size: 0,
        };

        unsafe { BeaconDataParse(&mut inner, ptr, len as i32) };

        Self(inner)
    }

    /// Extracts the next 32-bit integer from the buffer.
    #[inline]
    pub fn get_int(&mut self) -> i32 {
        unsafe { BeaconDataInt(&mut self.0) }
    }

    /// Extracts the next 16-bit integer from the buffer.
    #[inline]
    pub fn get_short(&mut self) -> i16 {
        unsafe { BeaconDataShort(&mut self.0) }
    }

    /// Extracts a raw pointer to the current position and advances by `size` bytes.
    #[inline]
    pub fn get_ptr(&mut self, size: usize) -> *mut u8 {
        unsafe { BeaconDataPtr(&mut self.0, size as i32) }
    }

    /// Extracts the next byte slice from the buffer.
    #[inline]
    pub fn get_bytes(&mut self) -> &[u8] {
        let mut size = 0;
        let ptr = unsafe { BeaconDataExtract(&mut self.0, &mut size) };
        unsafe { core::slice::from_raw_parts(ptr, size as usize) }
    }

    /// Extracts the next null-terminated string from the buffer.
    #[inline]
    pub fn get_str(&mut self) -> &str {
        let bytes = self.get_bytes();
        let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        core::str::from_utf8(&bytes[..len]).unwrap_or("")
    }

    /// Returns the number of bytes remaining in the buffer.
    #[inline]
    pub fn remaining(&mut self) -> i32 {
        unsafe { BeaconDataLength(&mut self.0) }
    }
}

beacon_api!(BeaconDataParse: extern "C" fn(parser: *mut Data, buffer: *mut u8, size: i32));
beacon_api!(BeaconDataInt: extern "C" fn(parser: *mut Data) -> i32);
beacon_api!(BeaconDataShort: extern "C" fn(parser: *mut Data) -> i16);
beacon_api!(BeaconDataLength: extern "C" fn(parser: *mut Data) -> i32);
beacon_api!(BeaconDataExtract: extern "C" fn(parser: *mut Data, size: *mut i32) -> *mut u8);
beacon_api!(BeaconDataPtr: extern "C" fn(parser: *mut Data, size: i32) -> *mut u8);
