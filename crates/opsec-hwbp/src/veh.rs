use crate::descriptor::{CallbackKind, DescriptorTable};

const RESUME_FLAG: u32 = 1 << 16;
const STATUS_SINGLE_STEP: u32 = 0x80000004;

static TABLE: DescriptorTable = DescriptorTable::new();

pub fn table() -> &'static DescriptorTable {
    &TABLE
}

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT, EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
    EXCEPTION_RECORD,
};

#[cfg(target_os = "windows")]
pub unsafe extern "system" fn dispatch(info: *mut EXCEPTION_POINTERS) -> i32 {
    unsafe {
        let rec: &EXCEPTION_RECORD = &*(*info).ExceptionRecord;
        if rec.ExceptionCode as u32 != STATUS_SINGLE_STEP {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        let ctx: &mut CONTEXT = &mut *(*info).ContextRecord;
        let rip = ctx.Rip as usize;
        let tid = current_thread_id();

        let Some(d) = TABLE.find(rip, tid) else {
            return EXCEPTION_CONTINUE_SEARCH;
        };

        match d.callback {
            CallbackKind::RipRet => {
                if let Some(r) = find_ret_gadget(rip, 500) {
                    ctx.Rax = 0x80070057; // E_INVALIDARG
                    ctx.Rip = r as u64;
                    ctx.EFlags |= RESUME_FLAG;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
                EXCEPTION_CONTINUE_SEARCH
            }
            CallbackKind::ExitTrap { resume_rip, resume_rsp } => {
                // One-shot: remove the descriptor so subsequent calls to
                // RtlExitUserProcess (e.g. from postex_exit → ExitProcess)
                // don't re-fire and corrupt the stack.
                TABLE.remove(d.address, d.thread_id);
                // Clear DR for this slot in the current thread's CONTEXT so
                // the HW breakpoint stops firing immediately on this thread.
                match d.slot {
                    0 => { ctx.Dr0 = 0; ctx.Dr7 &= !1u64; }
                    1 => { ctx.Dr1 = 0; ctx.Dr7 &= !(1u64 << 2); }
                    2 => { ctx.Dr2 = 0; ctx.Dr7 &= !(1u64 << 4); }
                    3 => { ctx.Dr3 = 0; ctx.Dr7 &= !(1u64 << 6); }
                    _ => {}
                }
                // Signal orchestrate_internal that we took the exit-trap path
                // so it skips re-dispatching the assembly.
                crate::engine::EXIT_TRAP_FIRED.store(1, core::sync::atomic::Ordering::Relaxed);
                ctx.Rip = resume_rip as u64;
                ctx.Rsp = resume_rsp as u64;
                ctx.EFlags |= RESUME_FLAG;
                EXCEPTION_CONTINUE_EXECUTION
            }
        }
    }
}

unsafe fn find_ret_gadget(start: usize, dist: usize) -> Option<usize> {
    unsafe {
        for i in 0..dist {
            let b = *((start + i) as *const u8);
            if b == 0xC3 {
                return Some(start + i);
            }
        }
        None
    }
}

#[cfg(target_os = "windows")]
unsafe fn current_thread_id() -> u32 {
    unsafe {
        let tid: u32;
        core::arch::asm!(
            "mov {0:e}, gs:[0x48]",
            out(reg) tid,
            options(nostack, preserves_flags, readonly),
        );
        tid
    }
}
