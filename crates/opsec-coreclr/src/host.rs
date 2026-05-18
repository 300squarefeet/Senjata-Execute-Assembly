//! Host orchestrator — full impl in Phase 6.
#![allow(dead_code)]

#[derive(Debug)]
pub enum Error {
    DotnetRootNotFound,
    RuntimeNotFound,
    CoreClrLoadFailed,
    ExportNotFound(&'static str),
    StubDropFailed,
    InitFailed(i32),
    CreateDelegateFailed(i32),
    StubReturned(i32),
}

#[allow(clippy::missing_safety_doc)]
pub unsafe fn run(
    _asm_bytes: &[u8],
    _asm_args: &str,
    _entry_point_flag: u32,
) -> Result<(), Error> {
    // Phase 6 will fill this in.
    Err(Error::DotnetRootNotFound)
}
