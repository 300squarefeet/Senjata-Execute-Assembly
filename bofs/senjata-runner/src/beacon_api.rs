//! Cobalt Strike UDPK BeaconAPI function table. CS passes a pointer to a
//! struct of `PVOID` fields as the first part of the postex args blob.
//! See Arsenal Kit `async-execute` for reference; layout has been stable
//! across CS 4.10–4.12 (only growing at the tail).

use core::ffi::c_void;

/// First arg to BeaconPrintf — CS callback ID.
pub const CALLBACK_OUTPUT: i32 = 0x00;
pub const CALLBACK_ERROR: i32 = 0x0d;

type BeaconPrintfFn = unsafe extern "C" fn(ty: i32, fmt: *const u8, ...);
type BeaconOutputFn = unsafe extern "C" fn(ty: i32, data: *const u8, len: i32);

/// Live BeaconAPI handle. Construct via `parse()` at postex_main entry.
pub struct Api {
    pub beacon_printf: Option<BeaconPrintfFn>,
    pub beacon_output: Option<BeaconOutputFn>,
}

impl Api {
    /// Wrap a raw `printf("%s\0")` so callers don't need varargs syntax.
    #[allow(dead_code)]
    pub unsafe fn printf(&self, ty: i32, cstr: *const u8) {
        unsafe {
            if let Some(f) = self.beacon_printf {
                f(ty, b"%s\0".as_ptr(), cstr);
            }
        }
    }

    /// Emit a raw byte slice as Beacon output.
    pub unsafe fn output(&self, ty: i32, data: &[u8]) {
        unsafe {
            if let Some(f) = self.beacon_output {
                f(ty, data.as_ptr(), data.len() as i32);
            }
        }
    }
}

/// Parse the BeaconAPI table from the head of the postex args blob.
/// Returns the Api struct and the remaining bytes (the orchestrator args).
///
/// Layout: 22 × `*const c_void` = 176 bytes on x64. Subsequent bytes are
/// the packed orchestrator args.
pub unsafe fn parse(data: *mut u8, len: usize) -> Api {
    unsafe {
        const N_FN: usize = 22;
        const TBL_BYTES: usize = N_FN * core::mem::size_of::<*const c_void>();
        if len < TBL_BYTES {
            return Api {
                beacon_printf: None,
                beacon_output: None,
            };
        }
        let tbl = data as *const *const c_void;
        // Indices match the BeaconAPI struct documented above.
        let printf_ptr = *tbl.add(13);
        let output_ptr = *tbl.add(12);
        Api {
            beacon_printf: if printf_ptr.is_null() {
                None
            } else {
                Some(core::mem::transmute::<*const c_void, BeaconPrintfFn>(
                    printf_ptr,
                ))
            },
            beacon_output: if output_ptr.is_null() {
                None
            } else {
                Some(core::mem::transmute::<*const c_void, BeaconOutputFn>(
                    output_ptr,
                ))
            },
        }
    }
}

/// Slice the orchestrator args out of the blob (after the BeaconAPI table).
#[allow(dead_code)]
pub unsafe fn args_blob(data: *mut u8, len: usize) -> (*mut u8, usize) {
    const TBL_BYTES: usize = 22 * core::mem::size_of::<*const c_void>();
    if len <= TBL_BYTES {
        return (core::ptr::null_mut(), 0);
    }
    unsafe { (data.add(TBL_BYTES), len - TBL_BYTES) }
}
