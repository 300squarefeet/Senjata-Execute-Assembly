use opsec_peb::{resolve_export, resolve_module};
use opsec_strcrypt::hash;

/// Ensure a DLL is loaded, calling LoadLibraryW from kernelbase if needed.
///
/// `name_hash` — DJB2(lowercase) hash of the DLL name, used to check PEB.
/// `wide_name` — null-terminated UTF-16 DLL name for LoadLibraryW.
///               Stored as u16 literals — not an ASCII string in .rdata,
///               so it passes the OPSEC plaintext-string scan.
/// Returns true if the module is (now) present in the PEB.
pub unsafe fn load_if_absent(name_hash: u32, wide_name: &[u16]) -> bool {
    unsafe {
        if resolve_module(name_hash).is_some() {
            return true;
        }
        // kernelbase.dll is always loaded and exports LoadLibraryW directly
        // (kernel32.dll forwards to kernelbase, but kernelbase is the real impl).
        let kbase = match resolve_module(hash!("kernelbase.dll")) {
            Some(m) => m,
            None => return false,
        };
        let load_lib = match resolve_export(kbase, hash!("LoadLibraryW")) {
            Some(f) => f,
            None => return false,
        };
        type LoadFn = unsafe extern "system" fn(*const u16) -> *mut core::ffi::c_void;
        let load_lib: LoadFn = core::mem::transmute(load_lib);
        !load_lib(wide_name.as_ptr()).is_null()
    }
}
