//! Dispatch on Runtime.
//!
//! NetFx4 → clr_netfx (existing ICLRMetaHost path + c6 fix)
//! CoreClr → clr_core (new CoreCLR hosting via opsec_coreclr)

use crate::error::BofError;
use crate::pe_parser::{AsmInfo, Runtime};

/// Top-level entry: orchestrate end-to-end runtime selection + invoke.
///
/// # Safety
/// `asm_bytes` must point to a valid managed PE.
pub unsafe fn dispatch(
    info: &AsmInfo,
    asm_bytes: &[u8],
    app_domain: &str,
    asm_args: &str,
    entry_point_flag: u32,
) -> Result<(), BofError> {
    unsafe {
        match info.runtime {
            Runtime::NetFx4 => crate::clr_netfx::run(
                info, asm_bytes, app_domain, asm_args, entry_point_flag,
            ),
            Runtime::CoreClr => crate::clr_core::run(
                asm_bytes, asm_args, entry_point_flag,
            ),
        }
    }
}
