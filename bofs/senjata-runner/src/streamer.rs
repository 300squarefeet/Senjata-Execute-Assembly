//! Background reader thread: pull bytes from the orchestrator's pipe and
//! forward them to operator via BeaconAPI BeaconOutput. Runs in parallel
//! with the assembly invoke so output arrives live (delay = Beacon sleep
//! cycle).

use core::ffi::c_void;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::System::Threading::{CreateThread, INFINITE, WaitForSingleObject};

use crate::beacon_api::{Api, CALLBACK_OUTPUT};

/// Boxed context shared between the thread and its parent.
pub struct StreamerCtx {
    pub pipe_read: HANDLE,
    pub api_output: Option<unsafe extern "C" fn(i32, *const u8, i32)>,
}

/// Thread proc: read pipe → BeaconOutput in a loop until ERROR_BROKEN_PIPE.
unsafe extern "system" fn thread_proc(arg: *mut c_void) -> u32 {
    unsafe {
        // Reclaim the box so it's freed on thread exit.
        let ctx: alloc::boxed::Box<StreamerCtx> =
            alloc::boxed::Box::from_raw(arg as *mut StreamerCtx);
        let mut buf = [0u8; 8192];
        loop {
            let mut n: u32 = 0;
            let ok = ReadFile(
                ctx.pipe_read,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut n,
                core::ptr::null_mut(),
            );
            if ok == 0 || n == 0 {
                break; // EOF or error — write end closed.
            }
            if let Some(out) = ctx.api_output {
                out(CALLBACK_OUTPUT, buf.as_ptr(), n as i32);
            }
        }
        drop(ctx);
        0
    }
}

/// Spawn the reader. Returns the thread handle (caller waits on it before
/// `postex_main` exits) and leaks the ctx box (thread reclaims it).
pub unsafe fn spawn(pipe_read: HANDLE, api: &Api) -> HANDLE {
    unsafe {
        let ctx = alloc::boxed::Box::new(StreamerCtx {
            pipe_read,
            api_output: api.beacon_output,
        });
        let ctx_ptr = alloc::boxed::Box::into_raw(ctx) as *mut c_void;
        CreateThread(
            core::ptr::null(),
            0,
            Some(thread_proc),
            ctx_ptr,
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
