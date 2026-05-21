//! Dispatch on Runtime + mode.
//!
//! NetFx4 + mode 0: netfx::run (single-file byte[] load)
//! NetFx4 + mode 1: netfx::run_multi (multi-file pre-load deps + main)
//! CoreClr: core::run (.NET 6+ via opsec_coreclr)

use crate::error::OrchestratorError as BofError;
use crate::pe_parser::{AsmInfo, Runtime};

/// Print drained assembly output to Beacon's error stream. Lives here
/// rather than in `lib.rs` because the parent module has a `pub mod core`
/// submodule that shadows the stdlib `core` crate inside macro expansions
/// (edition-2024 hygiene), preventing `rustbof::eprintln!` from resolving
/// `core::fmt::Write`. dispatch.rs has no such shadowing.
pub fn print_output(output: &str) {
    rustbof::eprintln!("\n{}", output);
}

/// Top-level entry: orchestrate end-to-end runtime selection + invoke.
///
/// # Safety
/// `asm_bytes` must point to a valid managed PE in single-file mode, or to a
/// valid multi-file blob (see netfx::parse_multi_blob) in multi-file mode.
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
                    let files = crate::netfx::parse_multi_blob(asm_bytes)?;
                    crate::netfx::run_multi(
                        info, &files, main_name, app_domain, asm_args, entry_point_flag,
                        pipe_handle,
                    )
                } else {
                    crate::netfx::run(
                        info, asm_bytes, app_domain, asm_args, entry_point_flag,
                        pipe_handle,
                    )
                }
            }
            Runtime::CoreClr => crate::core::run(
                asm_bytes, asm_args, entry_point_flag,
            ),
        }
    }
}
