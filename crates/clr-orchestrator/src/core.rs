//! CoreCLR path — delegates to opsec_coreclr crate.

// TEMP: wired in Task 1.10
type BofError = ();

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
        E::DotnetRootNotFound => (),
        E::RuntimeNotFound => (),
        E::CoreClrLoadFailed => (),
        E::ExportNotFound(CE::CoreClrInitialize) => (),
        E::ExportNotFound(CE::CoreClrCreateDelegate) => (),
        E::ExportNotFound(_) => (),
        E::StubDropFailed => (),
        E::InitFailed(_hr) => (),
        E::CreateDelegateFailed(_hr) => (),
        E::StubReturned(_rc) => (),
    }
}
