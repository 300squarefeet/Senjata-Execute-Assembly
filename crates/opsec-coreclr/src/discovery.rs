//! Three-tier discovery of the .NET install root:
//!   1. env  $DOTNET_ROOT
//!   2. registry HKLM\SOFTWARE\dotnet\Setup\InstalledVersions\x64 :: InstallLocation
//!   3. well-known C:\Program Files\dotnet
//!
//! Then enumerate `shared\Microsoft.NETCore.App\X.Y.Z\` and pick the
//! highest semver.

use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;
use opsec_bootstrap::Bootstrap;
use opsec_peb::{resolve_export, resolve_module};
use opsec_strcrypt::{hash, obf, obfw};

use crate::fs::{
    IoStatusBlock, ObjectAttributes, OBJ_CASE_INSENSITIVE,
    FILE_DIRECTORY_FILE, FILE_SHARE_READ,
    make_unicode_string,
};
pub use crate::semver::semver_cmp;

const FILE_LIST_DIRECTORY: u32 = 0x0001;
const SYNCHRONIZE: u32 = 0x00100000;
const FILE_SYNCHRONOUS_IO_NONALERT_LOCAL: u32 = 0x20;
const FILE_OPEN: u32 = 0x01;
const FILE_INFORMATION_CLASS_FULL_DIR: u32 = 2;  // FileFullDirectoryInformation

/// Read env var via `kernelbase!GetEnvironmentVariableW` resolved through PEB walk.
unsafe fn read_env(name_w: &[u16]) -> Option<String> {
    unsafe {
        let kbase = resolve_module(hash!("kernelbase.dll"))?;
        let getenv = resolve_export(kbase, hash!("GetEnvironmentVariableW"))?;
        type Fn = unsafe extern "system" fn(*const u16, *mut u16, u32) -> u32;
        let f: Fn = core::mem::transmute(getenv);
        let mut buf = [0u16; 1024];
        let n = f(name_w.as_ptr(), buf.as_mut_ptr(), buf.len() as u32);
        if n == 0 || (n as usize) >= buf.len() {
            return None;
        }
        let slice = &buf[..n as usize];
        String::from_utf16(slice).ok().filter(|s| !s.is_empty())
    }
}

/// Find the .NET install root. Returns DOS-style path (e.g. "C:\Program Files\dotnet").
///
/// # Safety
/// Calls into kernelbase + ntdll via PEB-walked exports.
pub unsafe fn find_dotnet_root(bs: &Bootstrap) -> Option<String> {
    unsafe {
        // Tier 1: env DOTNET_ROOT
        let dr_name = obfw!("DOTNET_ROOT");
        let mut env_name: Vec<u16> = dr_name.as_wide().to_vec();
        env_name.push(0);
        if let Some(s) = read_env(&env_name) {
            return Some(s);
        }

        // Tier 2: registry HKLM\SOFTWARE\dotnet\Setup\InstalledVersions\x64
        let subkey_obf = obfw!("\\Registry\\Machine\\SOFTWARE\\dotnet\\Setup\\InstalledVersions\\x64");
        let mut subkey: Vec<u16> = subkey_obf.as_wide().to_vec();
        subkey.push(0);
        let value_obf = obfw!("InstallLocation");
        let mut value: Vec<u16> = value_obf.as_wide().to_vec();
        value.push(0);
        if let Some(s) = crate::registry::read_reg_sz_machine(bs, &mut subkey, &mut value) {
            return Some(s);
        }

        // Tier 3: well-known
        let well_known = obf!("C:\\Program Files\\dotnet");
        let well_known_str = core::str::from_utf8(well_known.as_bytes())
            .unwrap_or("C:\\Program Files\\dotnet");
        Some(String::from(well_known_str))
    }
}

/// Find the highest-semver subdir under `<root>\shared\Microsoft.NETCore.App\`.
///
/// # Safety
/// Calls into ntdll via Bootstrap.
pub unsafe fn find_highest_runtime(bs: &Bootstrap, dotnet_root: &str) -> Option<String> {
    unsafe {
        let nca_dir = obf!("\\shared\\Microsoft.NETCore.App");
        let dir = alloc::format!(
            "{}{}",
            dotnet_root,
            core::str::from_utf8(nca_dir.as_bytes()).unwrap_or(""),
        );
        let entries = enumerate_dir(bs, &dir)?;
        let best = entries.iter()
            .filter(|name| name.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false))
            .filter(|name| !name.contains('-'))  // skip preview/-rc.X
            .map(|s| s.as_str())
            .max_by(|a, b| semver_cmp(a, b))?;
        Some(String::from(best))
    }
}

/// Enumerate names in a directory via NtCreateFile (FILE_OPEN + FILE_DIRECTORY_FILE)
/// + NtQueryDirectoryFile.
///
/// # Safety
/// Calls into ntdll via Bootstrap.
pub unsafe fn enumerate_dir(bs: &Bootstrap, dir_dos: &str) -> Option<Vec<String>> {
    unsafe {
        let mut nt_path: Vec<u16> = alloc::format!("\\??\\{}", dir_dos).encode_utf16().collect();
        nt_path.push(0);
        let mut uname = make_unicode_string(&mut nt_path);
        let mut attrs = ObjectAttributes {
            length: core::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: core::ptr::null_mut(),
            object_name: &mut uname,
            attributes: OBJ_CASE_INSENSITIVE,
            security_descriptor: core::ptr::null_mut(),
            security_qos: core::ptr::null_mut(),
        };
        let mut iosb = IoStatusBlock { union_status: 0, information: 0 };
        let mut handle: *mut c_void = core::ptr::null_mut();
        let status = bs.nt_create_file(
            &mut handle,
            FILE_LIST_DIRECTORY | SYNCHRONIZE,
            &mut attrs as *mut _ as *mut c_void,
            &mut iosb as *mut _ as *mut c_void,
            core::ptr::null_mut(),
            0,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT_LOCAL,
            core::ptr::null_mut(),
            0);
        if status < 0 || handle.is_null() {
            return None;
        }

        let mut buf = [0u8; 4096];
        let mut out = Vec::new();
        let mut restart: u32 = 1;
        loop {
            let mut iosb2 = IoStatusBlock { union_status: 0, information: 0 };
            let status = bs.nt_query_directory_file(
                handle,
                core::ptr::null_mut(), core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut iosb2 as *mut _ as *mut c_void,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                FILE_INFORMATION_CLASS_FULL_DIR,
                0,
                core::ptr::null_mut(),
                restart);
            restart = 0;
            if status < 0 { break; }
            if iosb2.information == 0 { break; }

            let mut off = 0usize;
            loop {
                if off + 68 >= buf.len() { break; }
                let info = &buf[off..];
                let next_off = u32::from_le_bytes([info[0], info[1], info[2], info[3]]) as usize;
                let name_len = u32::from_le_bytes([info[60], info[61], info[62], info[63]]) as usize;
                let name_start = 68usize;
                let name_end = name_start + name_len;
                if name_end > info.len() { break; }
                let u16s: Vec<u16> = info[name_start..name_end]
                    .chunks_exact(2)
                    .map(|p| u16::from_le_bytes([p[0], p[1]]))
                    .collect();
                let name = String::from_utf16(&u16s).ok();
                if let Some(n) = name {
                    if n != "." && n != ".." {
                        out.push(n);
                    }
                }
                if next_off == 0 { break; }
                off += next_off;
            }
        }
        bs.nt_close(handle);
        if out.is_empty() { None } else { Some(out) }
    }
}

/// Enumerate all `.dll` files in a directory and return as a `;`-separated string of full paths.
///
/// # Safety
/// Calls into ntdll via Bootstrap.
pub unsafe fn build_tpa_list(bs: &Bootstrap, runtime_dir: &str) -> Option<String> {
    unsafe {
        let entries = enumerate_dir(bs, runtime_dir)?;
        let mut out = String::new();
        for name in entries.iter() {
            if !name.to_ascii_lowercase().ends_with(".dll") { continue; }
            if !out.is_empty() { out.push(';'); }
            out.push_str(runtime_dir);
            out.push('\\');
            out.push_str(name);
        }
        if out.is_empty() { None } else { Some(out) }
    }
}
