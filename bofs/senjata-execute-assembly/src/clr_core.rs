//! CoreCLR path — delegates to opsec_coreclr crate.

use crate::error::BofError;

/// Wraps opsec_coreclr::run with BofError mapping.
///
/// # Safety
/// `asm_bytes` must be a valid managed PE.
pub unsafe fn run(
    asm_bytes: &[u8],
    asm_args: &str,
    entry_point_flag: u32,
) -> Result<(), BofError> {
    unsafe {
        opsec_coreclr::run(asm_bytes, asm_args, entry_point_flag)
            .map_err(map_err)
    }
}

fn map_err(e: opsec_coreclr::Error) -> BofError {
    use opsec_coreclr::CoreExport as CE;
    use opsec_coreclr::Error as E;
    match e {
        E::DotnetRootNotFound => BofError::Clr { hr: -1, op: "core1" },
        E::RuntimeNotFound => BofError::Clr { hr: -1, op: "core2" },
        E::CoreClrLoadFailed => BofError::Clr { hr: -1, op: "core3" },
        E::ExportNotFound(CE::CoreClrInitialize) => BofError::Clr { hr: -1, op: "core4" },
        E::ExportNotFound(CE::CoreClrCreateDelegate) => BofError::Clr { hr: -1, op: "core5a" },
        E::ExportNotFound(_) => BofError::Clr { hr: -1, op: "core5" },
        E::StubDropFailed => BofError::Clr { hr: -1, op: "core6" },
        E::InitFailed(hr) => BofError::Clr { hr, op: "core7" },
        E::CreateDelegateFailed(hr) => BofError::Clr { hr, op: "core8" },
        E::StubReturned(rc) => BofError::Clr { hr: rc, op: "core9" },
    }
}
