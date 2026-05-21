//! Postex DLL args parser. Wire format mirrors
//! `bofs/senjata-execute-assembly/src/args.rs` — the .cna packs both
//! artefacts identically.

use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;

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
    Truncated,
}

/// Read a length-prefixed u32-LE.
unsafe fn read_u32(ptr: *const u8, off: &mut usize, end: usize) -> Result<u32, Error> {
    unsafe {
        if *off + 4 > end {
            return Err(Error::Truncated);
        }
        let v = u32::from_le_bytes([
            *ptr.add(*off),
            *ptr.add(*off + 1),
            *ptr.add(*off + 2),
            *ptr.add(*off + 3),
        ]);
        *off += 4;
        Ok(v)
    }
}

/// Read a `z` (length-prefixed C string).
unsafe fn read_str(ptr: *const u8, off: &mut usize, end: usize) -> Result<String, Error> {
    unsafe {
        let n = read_u32(ptr, off, end)? as usize;
        if *off + n > end {
            return Err(Error::Truncated);
        }
        let slice = core::slice::from_raw_parts(ptr.add(*off), n.saturating_sub(1));
        let s = String::from_utf8_lossy(slice).into_owned();
        *off += n;
        Ok(s)
    }
}

/// Read a `b` (length-prefixed bytes).
unsafe fn read_bytes(ptr: *const u8, off: &mut usize, end: usize) -> Result<Vec<u8>, Error> {
    unsafe {
        let n = read_u32(ptr, off, end)? as usize;
        if *off + n > end {
            return Err(Error::Truncated);
        }
        let v = core::slice::from_raw_parts(ptr.add(*off), n).to_vec();
        *off += n;
        Ok(v)
    }
}

pub unsafe fn parse(blob: *mut c_void, len: usize) -> Result<Args, Error> {
    unsafe {
        let ptr = blob as *const u8;
        let mut off = 0usize;
        let app_domain = read_str(ptr, &mut off, len)?;
        let amsi = read_u32(ptr, &mut off, len)? != 0;
        let etw = read_u32(ptr, &mut off, len)? != 0;
        let mailslot = read_u32(ptr, &mut off, len)? != 0;
        let entry_point = read_u32(ptr, &mut off, len)?;
        let slot_name = read_str(ptr, &mut off, len)?;
        let pipe_name = read_str(ptr, &mut off, len)?;
        let asm_args = read_str(ptr, &mut off, len)?;
        let mode = read_u32(ptr, &mut off, len)?;
        let main_name = read_str(ptr, &mut off, len)?;
        let asm_bytes = read_bytes(ptr, &mut off, len)?;
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
