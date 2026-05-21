//! Cobalt Strike BeaconAPI — fully local implementations.
//!
//! Discovery from v0.3.11 test #11: BeaconOutput / BeaconPrintf are NOT
//! smartinject-resolved imports either. Like BeaconData*, they are
//! statically linked in Arsenal Kit's `kits/postex/base/beacon.cpp` and
//! write chunk-encoded frames directly to `gPipeHandle` via WriteFile.
//! Our v0.3.10 declared them as extern "C" imports against beacon.dll;
//! smartinject didn't resolve them, the IAT entries jumped to NULL, and
//! the sacrificial crashed on first BeaconOutput call.
//!
//! This file ports the entire BeaconAPI surface needed by our orchestrator
//! locally. No more extern declarations against beacon.dll.

use alloc::boxed::Box;
use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};

use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Storage::FileSystem::WriteFile;

use crate::pipes::gPipeHandle;
use crate::postex::gPostexArgumentsBuffer;

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

// ---------------------------------------------------------------------------
// BeaconOutput / BeaconPrintf — local implementations (group 1).
// Port of arsenal-kit/kits/postex/base/beacon.cpp lines 18-123.
//
// Wire format (per-chunk, big-endian header):
//   [DWORD: total chunk length = sizeof(DWORD) + payload]
//   [DWORD: flags = chunk_id (low 16 bits) | T-bit (bit 16: 1=final, 0=partial)]
//   [DWORD: callback type]
//   [payload bytes]
// ---------------------------------------------------------------------------

/// Mutex sequencing all BeaconOutput writes to gPipeHandle. The C++
/// reference doesn't lock — but their model is "single postex thread".
/// Our orchestrator runs a background streamer thread plus the main
/// postex thread, both calling BeaconOutput concurrently. Cheapest
/// serializer: spin lock using an atomic exchange.
static OUTPUT_LOCK: AtomicUsize = AtomicUsize::new(0);

fn output_lock_acquire() {
    // Best-effort spin. Worst case both threads write small frames; the
    // spin window is microseconds.
    while OUTPUT_LOCK
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

fn output_lock_release() {
    OUTPUT_LOCK.store(0, Ordering::Release);
}

/// Read the operator-configured `MaxPacketSize` from gPostexArgumentsBuffer.
/// Default to 524288 if zero / invalid.
unsafe fn max_packet_size() -> usize {
    unsafe {
        let pa: *const crate::postex::PostexArguments =
            core::ptr::addr_of!(gPostexArgumentsBuffer) as *const _;
        let v = (*pa).max_packet_size;
        if v <= 0 {
            524288
        } else {
            v as usize
        }
    }
}

/// `BeaconOutput` — write `data[..len]` to operator with callback type `ty`.
/// Chunks the payload if it exceeds the negotiated MaxPacketSize.
///
/// # Safety
/// Must be called after `start_named_pipe_server` populated `gPipeHandle`.
/// `data` must point at `len` valid bytes.
#[inline]
pub unsafe fn beacon_output(ty: i32, data: *const u8, len: i32) {
    unsafe {
        if len <= 0 {
            return;
        }
        let pipe = gPipeHandle;
        if pipe == INVALID_HANDLE_VALUE || pipe.is_null() {
            return;
        }

        const HEADER_SIZE: usize = 3 * core::mem::size_of::<u32>();
        let chunk_size = max_packet_size();
        let max_payload = chunk_size.saturating_sub(HEADER_SIZE);
        if max_payload == 0 {
            return;
        }

        output_lock_acquire();

        let total_len = len as usize;
        let mut written: usize = 0;
        let mut chunk_id: u16 = 0;
        while written < total_len {
            let remaining = total_len - written;
            let payload_len = if remaining < max_payload { remaining } else { max_payload };
            let is_final = (remaining == payload_len) as u32;
            let flags: u32 = (chunk_id as u32) | (is_final << 16);

            // Stack buffer for small chunks; heap fallback if max_payload
            // larger than 65536 (rare; we only need to send small bursts).
            // Pre-allocate 65536 + HEADER_SIZE on stack — safe for postex DLL
            // since we control stack usage (~4 MiB default in dllhost).
            let mut stack_buf = [0u8; 65536 + HEADER_SIZE];
            let buf: &mut [u8] = if HEADER_SIZE + payload_len <= stack_buf.len() {
                &mut stack_buf[..HEADER_SIZE + payload_len]
            } else {
                // Fallback: alloc via global allocator. Safe — BeaconAlloc
                // uses HeapAlloc.
                let v = alloc::vec![0u8; HEADER_SIZE + payload_len];
                // Leak it to keep lifetime simple inside the loop iteration;
                // we'll just rely on Box::leak-style by using Vec::leak.
                Box::leak(v.into_boxed_slice())
            };

            // Header (big-endian).
            let hdr_len = (core::mem::size_of::<u32>() as u32) + (payload_len as u32);
            buf[0..4].copy_from_slice(&hdr_len.to_be_bytes());
            buf[4..8].copy_from_slice(&flags.to_be_bytes());
            buf[8..12].copy_from_slice(&(ty as u32).to_be_bytes());

            // Payload.
            core::ptr::copy_nonoverlapping(
                data.add(written),
                buf[HEADER_SIZE..].as_mut_ptr(),
                payload_len,
            );

            // Write.
            let mut nw: u32 = 0;
            let ok = WriteFile(
                pipe,
                buf.as_ptr(),
                (HEADER_SIZE + payload_len) as u32,
                &mut nw,
                core::ptr::null_mut(),
            );
            if ok == 0 {
                break;
            }

            written += payload_len;
            chunk_id = chunk_id.wrapping_add(1);
        }

        output_lock_release();
    }
}

/// printf-style helper. We only need this for stub keepalive (the
/// orchestrator no longer references it directly); kept tiny.
#[allow(dead_code)]
pub unsafe fn beacon_printf(ty: i32, msg: &[u8]) {
    unsafe {
        beacon_output(ty, msg.as_ptr(), msg.len() as i32);
    }
}

/// Public wrapper used by the orchestrator + lib.rs.
#[inline]
pub unsafe fn output(ty: i32, data: &[u8]) {
    unsafe { beacon_output(ty, data.as_ptr(), data.len() as i32) }
}

// ---------------------------------------------------------------------------
// Local data-parser implementations (group 2). Ported from
// `arsenal-kit/kits/postex/base/beacon.cpp` lines 233-297.
//
// IMPORTANT: bof_pack on the Sleep side stores integers in BIG-ENDIAN
// (Java's network byte order). BeaconDataInt swaps to native LE.
// ---------------------------------------------------------------------------

#[inline]
pub unsafe fn beacon_data_parse(parser: &mut Datap, buffer: *const u8, size: i32) {
    parser.original = buffer as *mut i8;
    parser.buffer = buffer as *mut i8;
    parser.size = size;
    parser.length = size;
}

#[inline]
pub unsafe fn beacon_data_int(parser: &mut Datap) -> i32 {
    unsafe {
        let raw = (parser.buffer as *const i32).read_unaligned();
        parser.buffer = parser.buffer.add(4);
        parser.length -= 4;
        raw.swap_bytes()
    }
}

#[inline]
pub unsafe fn beacon_data_extract(parser: &mut Datap, out_size: *mut i32) -> *const u8 {
    unsafe {
        let size = beacon_data_int(parser);
        let p = parser.buffer as *const u8;
        parser.buffer = parser.buffer.add(size as usize);
        if !out_size.is_null() {
            *out_size = size;
        }
        p
    }
}

#[inline]
#[allow(dead_code)]
pub fn beacon_data_length(parser: &Datap) -> i32 {
    parser.length
}

#[allow(non_camel_case_types)]
#[allow(dead_code)]
pub type c_void_t = c_void;
