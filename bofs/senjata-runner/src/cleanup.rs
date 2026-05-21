//! Terminate the sacrificial process cleanly when postex_main returns.
//! Plain `return` may leave managed threads alive; explicit termination
//! guarantees the process exits.

use opsec_peb::{resolve_export, resolve_module};
use opsec_strcrypt::hash;

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
