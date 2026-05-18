use core::arch::naked_asm;

/// Extract SSN from clean NT stub: `4C 8B D1  B8 ?? ?? ?? ??  ...`
/// Returns Some(ssn) if unhooked, None if the prologue looks patched.
pub unsafe fn extract_ssn(stub: *const u8) -> Option<u32> {
    unsafe {
        if *stub == 0x4c && *stub.add(1) == 0x8b && *stub.add(2) == 0xd1
            && *stub.add(3) == 0xb8
        {
            let ssn = core::ptr::read_unaligned(stub.add(4) as *const u32);
            Some(ssn)
        } else {
            None
        }
    }
}

/// Indirect syscall via a `syscall; ret` gadget inside ntdll (never from our .text).
/// 4 args in rcx/rdx/r8/r9; SSN in eax; gadget address in r11.
///
/// # Safety
/// `gadget` must point to valid `syscall; ret` inside ntdll; ssn must be correct.
#[naked]
pub unsafe extern "system" fn indirect_syscall4(
    _arg1: usize, _arg2: usize, _arg3: usize, _arg4: usize,
    _ssn: u32, _gadget: usize,
) -> i32 {
    unsafe {
        naked_asm!(
            "mov r10, rcx",
            "mov eax, [rsp + 0x28]",
            "mov r11, [rsp + 0x30]",
            "jmp r11",
        );
    }
}
