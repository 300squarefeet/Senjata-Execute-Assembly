use core::arch::naked_asm;
use opsec_peb::{ModuleHandle, resolve_module, resolve_export};
use opsec_strcrypt::hash;

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

/// 6-argument variant: rcx, rdx, r8, r9 + 2 stack slots.
/// SSN at [rsp+0x38], gadget at [rsp+0x40].
///
/// # Safety
/// Same as `indirect_syscall4`.
#[naked]
pub unsafe extern "system" fn indirect_syscall6(
    _a1: usize, _a2: usize, _a3: usize, _a4: usize,
    _a5: usize, _a6: usize,
    _ssn: u32, _gadget: usize,
) -> i32 {
    unsafe {
        naked_asm!(
            "mov r10, rcx",
            "mov eax, [rsp + 0x38]",
            "mov r11, [rsp + 0x40]",
            "jmp r11",
        );
    }
}

/// 11-argument variant for NtCreateFile (rcx, rdx, r8, r9 + 7 stack slots).
/// SSN at [rsp+0x60], gadget at [rsp+0x68].
///
/// # Safety
/// `gadget` must be a valid `syscall; ret` in ntdll; ssn must match the
/// canonical export for the OS build.
#[naked]
pub unsafe extern "system" fn indirect_syscall11(
    _a1: usize, _a2: usize, _a3: usize, _a4: usize,
    _a5: usize, _a6: usize, _a7: usize, _a8: usize,
    _a9: usize, _a10: usize, _a11: usize,
    _ssn: u32, _gadget: usize,
) -> i32 {
    unsafe {
        naked_asm!(
            "mov r10, rcx",
            "mov eax, [rsp + 0x60]",
            "mov r11, [rsp + 0x68]",
            "jmp r11",
        );
    }
}

/// Discriminant for `Error::StubNotFound` — avoids plaintext NT API names
/// in `.rdata` of the linked BOF. `Debug` is implemented manually to suppress
/// variant-name string literals that the derive macro would otherwise embed.
pub enum BootstrapExport {
    NtGetContextThread,
    NtSetContextThread,
    NtCreateFile,
    NtWriteFile,
    NtClose,
    NtQueryDirectoryFile,
    NtOpenKey,
    NtQueryValueKey,
    NtProtectVirtualMemory,
}

impl core::fmt::Debug for BootstrapExport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Intentionally opaque — variant names must not appear in .rdata.
        f.write_str("export")
    }
}

#[derive(Debug)]
pub enum Error {
    NtdllNotFound,
    StubNotFound(BootstrapExport),
    GadgetNotFound,
}

pub struct Bootstrap {
    pub ntdll: ModuleHandle,
    pub gadget: usize,
    pub get_ctx: *const u8,
    pub get_ctx_ssn: u32,
    pub set_ctx: *const u8,
    pub set_ctx_ssn: u32,
    pub create_file: *const u8,
    pub create_file_ssn: u32,
    pub write_file: *const u8,
    pub write_file_ssn: u32,
    pub close: *const u8,
    pub close_ssn: u32,
    pub query_dir_file: *const u8,
    pub query_dir_file_ssn: u32,
    pub open_key: *const u8,
    pub open_key_ssn: u32,
    pub query_value_key: *const u8,
    pub query_value_key_ssn: u32,
    pub protect_vm: *const u8,
    pub protect_vm_ssn: u32,
}

impl Bootstrap {
    pub unsafe fn init() -> Result<Self, Error> {
        let ntdll = unsafe {
            resolve_module(hash!("ntdll.dll")).ok_or(Error::NtdllNotFound)?
        };

        let get_ctx = unsafe {
            resolve_export(ntdll, hash!("NtGetContextThread"))
                .ok_or(Error::StubNotFound(BootstrapExport::NtGetContextThread))? as *const u8
        };

        let set_ctx = unsafe {
            resolve_export(ntdll, hash!("NtSetContextThread"))
                .ok_or(Error::StubNotFound(BootstrapExport::NtSetContextThread))? as *const u8
        };

        let get_ctx_ssn = unsafe { extract_ssn(get_ctx).unwrap_or(0) };
        let set_ctx_ssn = unsafe { extract_ssn(set_ctx).unwrap_or(0) };

        let size = unsafe { pe_size_of_image(ntdll) };
        let gadget = unsafe {
            crate::gadget::find_syscall_ret(ntdll.as_usize(), size)
                .ok_or(Error::GadgetNotFound)?
        };

        let create_file = unsafe {
            resolve_export(ntdll, hash!("NtCreateFile"))
                .ok_or(Error::StubNotFound(BootstrapExport::NtCreateFile))? as *const u8
        };
        let write_file = unsafe {
            resolve_export(ntdll, hash!("NtWriteFile"))
                .ok_or(Error::StubNotFound(BootstrapExport::NtWriteFile))? as *const u8
        };
        let close = unsafe {
            resolve_export(ntdll, hash!("NtClose"))
                .ok_or(Error::StubNotFound(BootstrapExport::NtClose))? as *const u8
        };
        let query_dir_file = unsafe {
            resolve_export(ntdll, hash!("NtQueryDirectoryFile"))
                .ok_or(Error::StubNotFound(BootstrapExport::NtQueryDirectoryFile))? as *const u8
        };
        let open_key = unsafe {
            resolve_export(ntdll, hash!("NtOpenKey"))
                .ok_or(Error::StubNotFound(BootstrapExport::NtOpenKey))? as *const u8
        };
        let query_value_key = unsafe {
            resolve_export(ntdll, hash!("NtQueryValueKey"))
                .ok_or(Error::StubNotFound(BootstrapExport::NtQueryValueKey))? as *const u8
        };
        let protect_vm = unsafe {
            resolve_export(ntdll, hash!("NtProtectVirtualMemory"))
                .ok_or(Error::StubNotFound(BootstrapExport::NtProtectVirtualMemory))? as *const u8
        };
        let create_file_ssn      = unsafe { extract_ssn(create_file).unwrap_or(0) };
        let write_file_ssn       = unsafe { extract_ssn(write_file).unwrap_or(0) };
        let close_ssn            = unsafe { extract_ssn(close).unwrap_or(0) };
        let query_dir_file_ssn   = unsafe { extract_ssn(query_dir_file).unwrap_or(0) };
        let open_key_ssn         = unsafe { extract_ssn(open_key).unwrap_or(0) };
        let query_value_key_ssn  = unsafe { extract_ssn(query_value_key).unwrap_or(0) };
        let protect_vm_ssn       = unsafe { extract_ssn(protect_vm).unwrap_or(0) };

        Ok(Bootstrap {
            ntdll, gadget,
            get_ctx, get_ctx_ssn,
            set_ctx, set_ctx_ssn,
            create_file, create_file_ssn,
            write_file, write_file_ssn,
            close, close_ssn,
            query_dir_file, query_dir_file_ssn,
            open_key, open_key_ssn,
            query_value_key, query_value_key_ssn,
            protect_vm, protect_vm_ssn,
        })
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

    /// Direct + indirect dispatch for NtCreateFile (11 args).
    ///
    /// # Safety
    /// All pointer args must satisfy NtCreateFile's ABI contract.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn nt_create_file(
        &self,
        file_handle: *mut *mut core::ffi::c_void,
        desired_access: u32,
        object_attrs: *mut core::ffi::c_void,
        io_status: *mut core::ffi::c_void,
        alloc_size: *mut i64,
        file_attrs: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *mut core::ffi::c_void,
        ea_length: u32,
    ) -> i32 {
        unsafe {
            if extract_ssn(self.create_file).is_some() {
                type Fn = unsafe extern "system" fn(
                    *mut *mut core::ffi::c_void, u32,
                    *mut core::ffi::c_void, *mut core::ffi::c_void,
                    *mut i64, u32, u32, u32, u32,
                    *mut core::ffi::c_void, u32,
                ) -> i32;
                let f: Fn = core::mem::transmute(self.create_file);
                f(file_handle, desired_access, object_attrs, io_status,
                  alloc_size, file_attrs, share_access, create_disposition,
                  create_options, ea_buffer, ea_length)
            } else {
                indirect_syscall11(
                    file_handle as usize, desired_access as usize,
                    object_attrs as usize, io_status as usize,
                    alloc_size as usize, file_attrs as usize,
                    share_access as usize, create_disposition as usize,
                    create_options as usize, ea_buffer as usize,
                    ea_length as usize,
                    self.create_file_ssn, self.gadget,
                )
            }
        }
    }

    /// NtWriteFile (9 args). Last 2 stack slots zeroed in the 11-arg trampoline path.
    ///
    /// # Safety
    /// All pointer args must satisfy NtWriteFile's ABI.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn nt_write_file(
        &self,
        file: *mut core::ffi::c_void,
        event: *mut core::ffi::c_void,
        apc: *mut core::ffi::c_void,
        apc_ctx: *mut core::ffi::c_void,
        io_status: *mut core::ffi::c_void,
        buffer: *const core::ffi::c_void,
        length: u32,
        byte_offset: *const i64,
        key: *const u32,
    ) -> i32 {
        unsafe {
            if extract_ssn(self.write_file).is_some() {
                type Fn = unsafe extern "system" fn(
                    *mut core::ffi::c_void, *mut core::ffi::c_void,
                    *mut core::ffi::c_void, *mut core::ffi::c_void,
                    *mut core::ffi::c_void, *const core::ffi::c_void,
                    u32, *const i64, *const u32,
                ) -> i32;
                let f: Fn = core::mem::transmute(self.write_file);
                f(file, event, apc, apc_ctx, io_status, buffer,
                  length, byte_offset, key)
            } else {
                indirect_syscall11(
                    file as usize, event as usize,
                    apc as usize, apc_ctx as usize,
                    io_status as usize, buffer as usize,
                    length as usize, byte_offset as usize,
                    key as usize, 0, 0,
                    self.write_file_ssn, self.gadget,
                )
            }
        }
    }

    /// NtClose — single arg.
    ///
    /// # Safety
    /// `handle` must be a valid open handle.
    pub unsafe fn nt_close(&self, handle: *mut core::ffi::c_void) -> i32 {
        unsafe {
            if extract_ssn(self.close).is_some() {
                type Fn = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;
                let f: Fn = core::mem::transmute(self.close);
                f(handle)
            } else {
                indirect_syscall4(
                    handle as usize, 0, 0, 0,
                    self.close_ssn, self.gadget,
                )
            }
        }
    }

    /// NtQueryDirectoryFile — 11 args.
    ///
    /// # Safety
    /// All pointer args must satisfy NtQueryDirectoryFile's ABI.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn nt_query_directory_file(
        &self,
        file: *mut core::ffi::c_void,
        event: *mut core::ffi::c_void,
        apc: *mut core::ffi::c_void,
        apc_ctx: *mut core::ffi::c_void,
        io_status: *mut core::ffi::c_void,
        buffer: *mut core::ffi::c_void,
        length: u32,
        info_class: u32,
        return_single: u32,
        file_name: *mut core::ffi::c_void,
        restart_scan: u32,
    ) -> i32 {
        unsafe {
            if extract_ssn(self.query_dir_file).is_some() {
                type Fn = unsafe extern "system" fn(
                    *mut core::ffi::c_void, *mut core::ffi::c_void,
                    *mut core::ffi::c_void, *mut core::ffi::c_void,
                    *mut core::ffi::c_void, *mut core::ffi::c_void,
                    u32, u32, u32,
                    *mut core::ffi::c_void, u32,
                ) -> i32;
                let f: Fn = core::mem::transmute(self.query_dir_file);
                f(file, event, apc, apc_ctx, io_status, buffer, length,
                  info_class, return_single, file_name, restart_scan)
            } else {
                indirect_syscall11(
                    file as usize, event as usize,
                    apc as usize, apc_ctx as usize,
                    io_status as usize, buffer as usize,
                    length as usize, info_class as usize,
                    return_single as usize, file_name as usize,
                    restart_scan as usize,
                    self.query_dir_file_ssn, self.gadget,
                )
            }
        }
    }

    /// NtOpenKey — 3 args.
    ///
    /// # Safety
    /// `attrs` must satisfy OBJECT_ATTRIBUTES contract.
    pub unsafe fn nt_open_key(
        &self,
        key_handle: *mut *mut core::ffi::c_void,
        desired_access: u32,
        attrs: *mut core::ffi::c_void,
    ) -> i32 {
        unsafe {
            if extract_ssn(self.open_key).is_some() {
                type Fn = unsafe extern "system" fn(
                    *mut *mut core::ffi::c_void, u32,
                    *mut core::ffi::c_void,
                ) -> i32;
                let f: Fn = core::mem::transmute(self.open_key);
                f(key_handle, desired_access, attrs)
            } else {
                indirect_syscall4(
                    key_handle as usize, desired_access as usize,
                    attrs as usize, 0,
                    self.open_key_ssn, self.gadget,
                )
            }
        }
    }

    /// NtQueryValueKey — 6 args.
    ///
    /// # Safety
    /// Pointer args must satisfy NtQueryValueKey's ABI.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn nt_query_value_key(
        &self,
        key: *mut core::ffi::c_void,
        value_name: *mut core::ffi::c_void,
        info_class: u32,
        info: *mut core::ffi::c_void,
        info_length: u32,
        result_length: *mut u32,
    ) -> i32 {
        unsafe {
            if extract_ssn(self.query_value_key).is_some() {
                type Fn = unsafe extern "system" fn(
                    *mut core::ffi::c_void, *mut core::ffi::c_void,
                    u32, *mut core::ffi::c_void, u32, *mut u32,
                ) -> i32;
                let f: Fn = core::mem::transmute(self.query_value_key);
                f(key, value_name, info_class, info, info_length, result_length)
            } else {
                indirect_syscall6(
                    key as usize, value_name as usize,
                    info_class as usize, info as usize,
                    info_length as usize, result_length as usize,
                    self.query_value_key_ssn, self.gadget,
                )
            }
        }
    }

    /// NtProtectVirtualMemory — 5 args. Reuses `indirect_syscall6` with the
    /// 6th arg zeroed (NtProtectVirtualMemory's stub does not read it).
    ///
    /// # Safety
    /// All pointer args must satisfy NtProtectVirtualMemory's ABI.
    pub unsafe fn nt_protect_virtual_memory(
        &self,
        process: *mut core::ffi::c_void,
        base_address: *mut *mut core::ffi::c_void,
        region_size: *mut usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> i32 {
        unsafe {
            if extract_ssn(self.protect_vm).is_some() {
                type Fn = unsafe extern "system" fn(
                    *mut core::ffi::c_void,
                    *mut *mut core::ffi::c_void,
                    *mut usize,
                    u32,
                    *mut u32,
                ) -> i32;
                let f: Fn = core::mem::transmute(self.protect_vm);
                f(process, base_address, region_size, new_protect, old_protect)
            } else {
                indirect_syscall6(
                    process as usize,
                    base_address as usize,
                    region_size as usize,
                    new_protect as usize,
                    old_protect as usize,
                    0,
                    self.protect_vm_ssn,
                    self.gadget,
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
