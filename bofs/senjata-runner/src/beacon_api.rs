//! Cobalt Strike BeaconAPI for the postex DLL.
//!
//! BeaconAPI splits into two groups by mechanism:
//!
//! 1. **Smartinject-resolved imports** (declared `extern "C"` from
//!    `beacon.dll`): functions that need cross-process state — output
//!    delivery, token impersonation, admin check, pipe-side input.
//!    CS's reflective loader rewrites the IAT entries to point at
//!    in-process proxies that forward via `gPipeHandle`.
//!
//! 2. **Locally-implemented helpers** (plain Rust functions): pure
//!    data-manipulation primitives that Arsenal Kit's `beacon.cpp`
//!    statically links into every postex DLL — `BeaconDataParse`,
//!    `BeaconDataInt`, `BeaconDataExtract`, `BeaconDataLength`. These
//!    do NOT cross the process boundary; they walk the user-args
//!    buffer in-place.
//!
//! Our v0.3.5 build mistakenly put group 2 into the import table.
//! Smartinject doesn't resolve those names, so the IAT entries stayed
//! unresolved and first call faulted the sacrificial. This version
//! ports the C++ reference inline (see
//! `arsenal-kit/kits/postex/base/beacon.cpp` lines 233-297).

use core::ffi::c_void;

/// Callback type for standard postex output. Beacon prints the bytes as-is.
pub const CALLBACK_OUTPUT: i32 = 0x00;
/// Callback type for error postex output. Beacon prints in red on the
/// client side.
pub const CALLBACK_ERROR: i32 = 0x0d;

/// `ExitFunc` value in POSTEX_ARGUMENTS for ExitProcess (default fork/run).
#[allow(dead_code)]
pub const EXITFUNC_PROCESS: u32 = 0x56A2B5F0;
/// `ExitFunc` value in POSTEX_ARGUMENTS for ExitThread.
pub const EXITFUNC_THREAD: u32 = 0x0A2A1DE0;

/// Beacon's data-parser state. Layout matches Arsenal Kit's
/// `kits/postex/base/beacon.h::datap`.
#[repr(C)]
pub struct Datap {
    pub original: *mut i8,
    pub buffer: *mut i8,
    pub length: i32,
    pub size: i32,
}

unsafe extern "C" {
    /// Send a length-counted byte buffer to Beacon for display.
    /// Smartinject-resolved.
    pub fn BeaconOutput(ty: i32, data: *const u8, len: i32);

    /// printf-style output. Smartinject-resolved.
    pub fn BeaconPrintf(ty: i32, fmt: *const u8, ...);
}

/// Wrapper for `BeaconOutput` that accepts a Rust byte slice.
///
/// # Safety
/// Callers must be on the postex thread (i.e. inside DllEntryPoint(
/// DLL_POSTEX_ATTACH)). Calling before smartinject has rewritten the
/// IAT will jump to the unresolved import stub.
#[inline]
pub unsafe fn output(ty: i32, data: &[u8]) {
    unsafe { BeaconOutput(ty, data.as_ptr(), data.len() as i32) };
}

#[used]
static _BEACON_PRINTF_KEEPALIVE: unsafe extern "C" fn(i32, *const u8, ...) = BeaconPrintf;

// ---------------------------------------------------------------------------
// Local data-parser implementations (group 2). Ported from
// `arsenal-kit/kits/postex/base/beacon.cpp` lines 233-297.
//
// IMPORTANT: bof_pack on the Sleep side stores integers in BIG-ENDIAN
// (Java's network byte order). BeaconDataInt swaps to native LE.
// ---------------------------------------------------------------------------

/// Initialise the parser against `buffer`. The buffer is the
/// user-args blob CS placed in `lpReserved`; `size` is from
/// `gPostexArgumentsBuffer.UserArgumentBufferSize`.
#[inline]
pub unsafe fn beacon_data_parse(parser: &mut Datap, buffer: *const u8, size: i32) {
    parser.original = buffer as *mut i8;
    parser.buffer = buffer as *mut i8;
    parser.size = size;
    parser.length = size;
}

/// Pop a 4-byte big-endian integer (Sleep's `i` field).
#[inline]
pub unsafe fn beacon_data_int(parser: &mut Datap) -> i32 {
    unsafe {
        let raw = (parser.buffer as *const i32).read_unaligned();
        parser.buffer = parser.buffer.add(4);
        parser.length -= 4;
        raw.swap_bytes()
    }
}

/// Pop a length-prefixed buffer (Sleep's `z` and `b` fields). Returns
/// a pointer into the buffer and writes the size out (if `out_size`
/// non-null). For `z` fields the bytes include the trailing NUL.
#[inline]
pub unsafe fn beacon_data_extract(parser: &mut Datap, out_size: *mut i32) -> *const u8 {
    unsafe {
        let size = beacon_data_int(parser);
        let p = parser.buffer as *const u8;
        parser.buffer = parser.buffer.add(size as usize);
        // beacon.cpp doesn't decrement length here — match its behaviour
        // so BeaconDataLength reports remaining minus header counts only.
        if !out_size.is_null() {
            *out_size = size;
        }
        p
    }
}

/// Remaining bytes in the parser.
#[inline]
#[allow(dead_code)]
pub fn beacon_data_length(parser: &Datap) -> i32 {
    parser.length
}

#[allow(non_camel_case_types)]
#[allow(dead_code)]
pub type c_void_t = c_void;
