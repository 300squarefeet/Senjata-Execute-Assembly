//! Cobalt Strike BeaconAPI imports for the postex DLL.
//!
//! Unlike the old function-pointer-table approach (which guessed CS's
//! internal BeaconAPI struct layout), this matches the Arsenal Kit
//! `kits/postex/base` reference exactly: BeaconAPI functions are
//! linked as ordinary DLL imports against `beacon.dll`. CS's reflective
//! loader (smartinject) walks the IAT after image-load and rewrites any
//! `beacon.dll` import to point at an in-process proxy that forwards the
//! call to Beacon via the named pipe whose handle lives in
//! `crate::pipes::G_PIPE_HANDLE`.
//!
//! Only the functions we actually call are declared here. Adding more is
//! free — just add the symbol to `beacon.def` and the `extern "C"` block.

/// Callback type for standard postex output. Beacon prints the bytes as-is.
pub const CALLBACK_OUTPUT: i32 = 0x00;
/// Callback type for error postex output. Beacon prints in red on the
/// client side.
pub const CALLBACK_ERROR: i32 = 0x0d;

/// `ExitFunc` value in POSTEX_ARGUMENTS that asks PostexExit to call
/// `ExitProcess(0)` (default for fork-and-run sacrificials). Currently
/// only `EXITFUNC_THREAD` is matched explicitly; anything else, including
/// `EXITFUNC_PROCESS`, falls into the default ExitProcess path.
#[allow(dead_code)]
pub const EXITFUNC_PROCESS: u32 = 0x56A2B5F0;
/// `ExitFunc` value in POSTEX_ARGUMENTS that asks PostexExit to call
/// `ExitThread(0)` (set by CS when the postex job is injected into an
/// existing remote process and the operator picked "thread" exit semantics).
pub const EXITFUNC_THREAD: u32 = 0x0A2A1DE0;

/// Beacon's datap parser state — must match the layout in
/// `arsenal-kit/kits/postex/base/beacon.h` exactly. Beacon implements
/// `BeaconDataParse/Int/Extract` on the other side of the smartinject
/// proxy; they walk this struct in-place.
#[repr(C)]
pub struct Datap {
    pub original: *mut i8,
    pub buffer: *mut i8,
    pub length: i32,
    pub size: i32,
}

unsafe extern "C" {
    /// Send a length-counted byte buffer to Beacon for display.
    /// `ty` is one of the `CALLBACK_*` constants.
    pub fn BeaconOutput(ty: i32, data: *const u8, len: i32);

    /// printf-style output. We use it for short status lines.
    pub fn BeaconPrintf(ty: i32, fmt: *const u8, ...);

    /// Initialise `parser` against the user-args buffer. CS's bof_pack
    /// emits a 4-byte total-size header before the packed fields;
    /// BeaconDataParse consumes it so subsequent BeaconDataInt /
    /// BeaconDataExtract calls see the field stream directly.
    pub fn BeaconDataParse(parser: *mut Datap, buffer: *const u8, size: i32);

    /// Pop the next `i` field.
    pub fn BeaconDataInt(parser: *mut Datap) -> i32;

    /// Pop the next `b` (or `z`) field and return its size via `*size`.
    /// For `z` fields the returned bytes include the trailing NUL.
    pub fn BeaconDataExtract(parser: *mut Datap, size: *mut i32) -> *mut u8;

    /// Bytes remaining in the parser.
    pub fn BeaconDataLength(parser: *mut Datap) -> i32;
}

/// Wrapper for `BeaconOutput` that accepts a Rust byte slice.
///
/// # Safety
/// Callers must hold the CS UDPK execution context — i.e. be called from
/// the thread that received `DllEntryPoint(DLL_POSTEX_ATTACH)`. Calling
/// before smartinject has rewritten the IAT (e.g. from `DLL_PROCESS_ATTACH`)
/// will jump to the unresolved import stub and crash the sacrificial.
#[inline]
pub unsafe fn output(ty: i32, data: &[u8]) {
    unsafe { BeaconOutput(ty, data.as_ptr(), data.len() as i32) };
}

/// Force the linker to keep the `BeaconPrintf` IAT entry alive even though
/// no Rust call site references it. Operators occasionally hot-load
/// extensions to the runner that DO call it; if it isn't in the IAT,
/// smartinject has nothing to rewrite and the call jumps into the
/// fixed-up stub from libgcc. Costs 1 IAT slot (~24 bytes).
#[used]
static _BEACON_PRINTF_KEEPALIVE: unsafe extern "C" fn(i32, *const u8, ...) = BeaconPrintf;
