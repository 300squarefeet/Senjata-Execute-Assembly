//! senjata-runner — UDPK postex DLL. Reflectively loaded by Cobalt Strike
//! into a sacrificial process via `beacon_execute_postex_job`. Receives
//! the BeaconAPI function table and the orchestrator's input args, then
//! invokes `clr_orchestrator::orchestrate()`.
//!
//! Built as `cdylib` → produces a Windows DLL with a single named export
//! (`postex_main`) that CS calls.
#![no_std]
#![no_main]
#![cfg(target_os = "windows")]

extern crate alloc;

use core::panic::PanicInfo;

#[global_allocator]
static __ALLOC: rustbof::allocator::BeaconAlloc = rustbof::allocator::BeaconAlloc;

mod args;
mod beacon_api;
mod cleanup;
mod streamer;

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}

/// CS UDPK entrypoint. The postex shellcode calls this after reflective DLL
/// load completes. `data` points at a CS-allocated blob whose layout is:
///   [BeaconAPI function pointer table][packed orchestrator args]
///
/// We're given the length; we split the blob and dispatch.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn postex_main(data: *mut u8, len: i32) {
    unsafe {
        // Phase 3: scaffold only — resolve BeaconAPI, print hello, return.
        let api = beacon_api::parse(data, len as usize);
        api.printf(
            beacon_api::CALLBACK_OUTPUT,
            b"[runner] hello from senjata-runner\0".as_ptr(),
        );
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(
    _module: *mut core::ffi::c_void,
    _reason: u32,
    _reserved: *mut core::ffi::c_void,
) -> i32 {
    1
}
