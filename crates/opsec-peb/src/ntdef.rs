//! Minimal NT undocumented structures for PEB walking.
//! x64 layouts only.

use core::ffi::c_void;

#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *const u16,
}

#[repr(C)]
pub struct ListEntry {
    pub flink: *mut ListEntry,
    pub blink: *mut ListEntry,
}

/// LDR_DATA_TABLE_ENTRY (partial — only fields we need).
/// Offsets are stable across Windows 10/11.
#[repr(C)]
pub struct LdrDataTableEntry {
    pub in_load_order_links: ListEntry,
    pub in_memory_order_links: ListEntry,
    pub in_initialization_order_links: ListEntry,
    pub dll_base: *mut c_void,
    pub entry_point: *mut c_void,
    pub size_of_image: u32,
    _padding: u32,
    pub full_dll_name: UnicodeString,
    pub base_dll_name: UnicodeString,
}

#[repr(C)]
pub struct PebLdrData {
    pub length: u32,
    pub initialized: u8,
    _pad1: [u8; 3],
    pub ss_handle: *mut c_void,
    pub in_load_order_module_list: ListEntry,
    pub in_memory_order_module_list: ListEntry,
    pub in_initialization_order_module_list: ListEntry,
}

#[repr(C)]
pub struct Peb {
    pub inherited_address_space: u8,
    pub read_image_file_exec_options: u8,
    pub being_debugged: u8,
    pub bit_field: u8,
    _padding: [u8; 4],
    pub mutant: *mut c_void,
    pub image_base_address: *mut c_void,
    pub ldr: *mut PebLdrData,
}

#[repr(C)]
pub struct Teb {
    _reserved1: [*mut c_void; 12],
    pub peb: *mut Peb,
}

/// Read TEB via GS segment register on x64.
///
/// # Safety
/// Must be called from a Windows x64 thread.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn current_teb() -> *mut Teb {
    let teb: *mut Teb;
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[0x30]",
            out(reg) teb,
            options(nostack, preserves_flags, readonly),
        );
    }
    teb
}
