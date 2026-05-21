//! Dispatch on Runtime + mode.
//!
//! NetFx4 + mode 0: clr_netfx::run (single-file byte[] load)
//! NetFx4 + mode 1: clr_netfx::run_multi (multi-file pre-load deps + main)
//! CoreClr: clr_core::run (.NET 6+ via opsec_coreclr)

use crate::error::BofError;
use crate::pe_parser::{AsmInfo, Runtime};

/// Top-level entry: orchestrate end-to-end runtime selection + invoke.
///
/// # Safety
/// `asm_bytes` must point to a valid managed PE in single-file mode, or to a
/// valid multi-file blob (see clr_netfx::parse_multi_blob) in multi-file mode.
#[allow(clippy::too_many_arguments)]
pub unsafe fn dispatch(
    info: &AsmInfo,
    asm_bytes: &[u8],
    app_domain: &str,
    asm_args: &str,
    entry_point_flag: u32,
    mode: u32,
    main_name: &str,
    pipe_handle: usize,
) -> Result<(), BofError> {
    unsafe {
        match info.runtime {
            Runtime::NetFx4 => {
                if mode == 1 {
                    let files = crate::clr_netfx::parse_multi_blob(asm_bytes)?;
                    crate::clr_netfx::run_multi(
                        info, &files, main_name, app_domain, asm_args, entry_point_flag,
                        pipe_handle,
                    )
                } else {
                    crate::clr_netfx::run(
                        info, asm_bytes, app_domain, asm_args, entry_point_flag,
                        pipe_handle,
                    )
                }
            }
            Runtime::CoreClr => crate::clr_core::run(
                asm_bytes, asm_args, entry_point_flag,
            ),
        }
    }
}
