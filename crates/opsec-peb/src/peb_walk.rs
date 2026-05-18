use core::ffi::c_void;

#[cfg(target_arch = "x86_64")]
use crate::hash::djb2;
#[cfg(target_arch = "x86_64")]
use crate::ntdef::{current_teb, LdrDataTableEntry, ListEntry};

#[derive(Clone, Copy)]
pub struct ModuleHandle(pub *mut c_void);

impl ModuleHandle {
    pub fn as_usize(self) -> usize {
        self.0 as usize
    }
}

/// Walk PEB->Ldr->InMemoryOrderModuleList, find module by DJB2 hash of base name
/// (case-insensitive: ASCII lowercased before hashing).
///
/// # Safety
/// Must be called from a Windows x64 thread with a valid TEB.
#[cfg(target_arch = "x86_64")]
pub unsafe fn resolve_module(name_hash: u32) -> Option<ModuleHandle> {
    unsafe {
        let teb = current_teb();
        let peb = (*teb).peb;
        if peb.is_null() {
            return None;
        }
        let ldr = (*peb).ldr;
        if ldr.is_null() {
            return None;
        }

        let head = &(*ldr).in_memory_order_module_list as *const ListEntry as *mut ListEntry;
        let mut cur = (*head).flink;

        while cur != head {
            // in_memory_order_links is the 2nd field of LdrDataTableEntry
            // Each ListEntry is 16 bytes on x64, so subtract 16 to get entry base
            let entry = (cur as usize - 16) as *const LdrDataTableEntry;
            let name = &(*entry).base_dll_name;
            if !name.buffer.is_null() && name.length > 0 {
                let mut buf = [0u8; 256];
                let len = (name.length / 2) as usize;
                if len < buf.len() {
                    for i in 0..len {
                        let wch = *name.buffer.add(i);
                        let b = if (b'A' as u16..=b'Z' as u16).contains(&wch) {
                            (wch + 32) as u8
                        } else {
                            wch as u8
                        };
                        buf[i] = b;
                    }
                    if djb2(&buf[..len]) == name_hash {
                        return Some(ModuleHandle((*entry).dll_base));
                    }
                }
            }
            cur = (*cur).flink;
        }
        None
    }
}

/// Resolve a module and then resolve an export within it.
pub unsafe fn resolve_export(module: ModuleHandle, name_hash: u32) -> Option<*const ()> {
    unsafe {
        let rva = crate::pe::resolve_export_in_image(module.as_usize(), name_hash)?;
        Some((module.as_usize() + rva as usize) as *const ())
    }
}
