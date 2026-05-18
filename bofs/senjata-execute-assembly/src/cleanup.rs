use core::arch::asm;

/// Captures a resume point for the ExitProcess HWBP trap. The returned RIP
/// addresses the `lea` instruction inside this function; when the trap
/// rewrites the context, execution re-enters here and unwinds back to the
/// orchestrator's frame via the normal function epilogue.
///
/// # Safety
/// Windows x64 only. Caller must ensure no live references exist at any
/// stack address above the saved RSP, since the trap may rewind the stack.
#[inline(never)]
pub unsafe fn save_cleanup_point() -> (usize, usize) {
    let rip: usize;
    let rsp: usize;
    unsafe {
        asm!(
            "lea {rip}, [rip + 0]",
            "mov {rsp}, rsp",
            rip = out(reg) rip,
            rsp = out(reg) rsp,
            options(nostack, preserves_flags),
        );
    }
    (rip, rsp)
}
