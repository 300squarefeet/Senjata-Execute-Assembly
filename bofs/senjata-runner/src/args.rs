//! Postex DLL args parser.
//!
//! The .cna packs args via `bof_pack($bid, "ziiiizzzizb", ...)`. CS adds
//! its own 4-byte total-size header before the packed fields; the
//! correct way to read these bytes is via Beacon's `BeaconDataParse` /
//! `BeaconDataInt` / `BeaconDataExtract` APIs (provided to the DLL via
//! smartinject IAT rewrite). The hand-rolled byte reader in v0.3.x got
//! this wrong — it consumed the bof_pack size header as if it were
//! `app_domain`'s length prefix → garbage values → Truncated. Replaced
//! with BeaconAPI calls (same approach as the BOF's `rustbof::data`).

use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;

use crate::beacon_api::{
    beacon_data_extract, beacon_data_int, beacon_data_length, beacon_data_parse, Datap,
};

#[derive(Debug)]
pub struct Args {
    pub app_domain: String,
    pub amsi: bool,
    pub etw: bool,
    pub mailslot: bool,
    pub entry_point: u32,
    pub slot_name: String,
    pub pipe_name: String,
    pub asm_args: String,
    pub mode: u32,
    pub main_name: String,
    pub asm_bytes: Vec<u8>,
}

#[derive(Debug)]
pub enum Error {
    /// Buffer pointer was null or size was zero / negative.
    EmptyBuffer,
    /// All fields extracted but the assembly blob came back empty —
    /// wire-format mismatch between sender and parser.
    Truncated,
}

/// Extract a `z` field (length-prefixed C string including NUL) as an
/// owned `String`. Returns empty if the buffer is dry.
unsafe fn extract_str(parser: &mut Datap) -> String {
    unsafe {
        let mut size: i32 = 0;
        let ptr = beacon_data_extract(parser, &mut size);
        if ptr.is_null() || size <= 0 {
            return String::new();
        }
        let raw_len = size as usize;
        let slice_len = if raw_len > 0 && *ptr.add(raw_len - 1) == 0 {
            raw_len - 1
        } else {
            raw_len
        };
        let slice = core::slice::from_raw_parts(ptr, slice_len);
        String::from_utf8_lossy(slice).into_owned()
    }
}

unsafe fn extract_bytes(parser: &mut Datap) -> Vec<u8> {
    unsafe {
        let mut size: i32 = 0;
        let ptr = beacon_data_extract(parser, &mut size);
        if ptr.is_null() || size <= 0 {
            return Vec::new();
        }
        core::slice::from_raw_parts(ptr, size as usize).to_vec()
    }
}

/// Parse the .cna's `bof_pack("ziiiizzzizb", ...)` payload via Beacon's
/// data parser. `blob` is `lpReserved` from DllEntryPoint(DLL_POSTEX_ATTACH);
/// `len` is `gPostexArgumentsBuffer.UserArgumentBufferSize`.
pub unsafe fn parse(blob: *mut c_void, len: usize) -> Result<Args, Error> {
    unsafe {
        if blob.is_null() || len == 0 {
            return Err(Error::EmptyBuffer);
        }
        let mut parser: Datap = core::mem::zeroed();
        beacon_data_parse(&mut parser, blob as *const u8, len as i32);

        // Field order matches the .cna's bof_pack format
        // "ziiiizzzizb": app_domain, amsi, etw, mailslot, entry_point,
        // slot_name, pipe_name, asm_args, mode, main_name, asm_bytes.
        let app_domain  = extract_str(&mut parser);
        let amsi        = beacon_data_int(&mut parser) != 0;
        let etw         = beacon_data_int(&mut parser) != 0;
        let mailslot    = beacon_data_int(&mut parser) != 0;
        let entry_point = beacon_data_int(&mut parser) as u32;
        let slot_name   = extract_str(&mut parser);
        let pipe_name   = extract_str(&mut parser);
        let asm_args    = extract_str(&mut parser);
        let mode        = beacon_data_int(&mut parser) as u32;
        let main_name   = extract_str(&mut parser);
        let asm_bytes   = extract_bytes(&mut parser);

        if asm_bytes.is_empty() {
            let _remaining = beacon_data_length(&parser);
            return Err(Error::Truncated);
        }

        Ok(Args {
            app_domain,
            amsi,
            etw,
            mailslot,
            entry_point,
            slot_name,
            pipe_name,
            asm_args,
            mode,
            main_name,
            asm_bytes,
        })
    }
}
