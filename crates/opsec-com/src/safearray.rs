#![allow(non_snake_case)]

use core::ffi::c_void;
use opsec_peb::{resolve_export, resolve_module};
use opsec_strcrypt::hash;

#[repr(C)]
pub struct SafeArrayBound {
    pub cElements: u32,
    pub lLbound: i32,
}

#[repr(C)]
pub struct SafeArray {
    pub cDims: u16,
    pub fFeatures: u16,
    pub cbElements: u32,
    pub cLocks: u32,
    pub pvData: *mut c_void,
    pub rgsabound: [SafeArrayBound; 1],
}

pub const VT_UI1: u16 = 0x0011;
pub const VT_BSTR: u16 = 0x0008;
pub const VT_VARIANT: u16 = 0x000C;

pub struct OwnedSafeArray {
    pub ptr: *mut SafeArray,
}

impl OwnedSafeArray {
    pub unsafe fn create(vt: u16, n_elements: u32) -> Option<Self> {
        unsafe {
            // Wide "oleaut32.dll\0" — UTF-16 literals, not plaintext ASCII.
            const OLEAUT_W: &[u16] = &[
                0x6F,0x6C,0x65,0x61,0x75,0x74,0x33,0x32,0x2E,0x64,0x6C,0x6C,0,
            ];
            if !crate::loader::load_if_absent(hash!("oleaut32.dll"), OLEAUT_W) {
                return None;
            }
            let oleaut32 = resolve_module(hash!("oleaut32.dll"))?;
            let create = resolve_export(oleaut32, hash!("SafeArrayCreate"))?;
            type Fn = unsafe extern "system" fn(u16, u32, *const SafeArrayBound) -> *mut SafeArray;
            let f: Fn = core::mem::transmute(create);
            let bound = SafeArrayBound { cElements: n_elements, lLbound: 0 };
            let p = f(vt, 1, &bound);
            if p.is_null() { None } else { Some(OwnedSafeArray { ptr: p }) }
        }
    }

    /// Copy raw bytes into a `VT_UI1` array using `SafeArrayAccessData` /
    /// `SafeArrayUnaccessData` (the documented API). Replaces direct
    /// `(*ptr).pvData` reads which can fail `AppDomain.Load_3` with
    /// `ERROR_BAD_FORMAT` on certain Windows builds.
    pub unsafe fn copy_from(&self, src: &[u8]) -> bool {
        unsafe {
            let oleaut = match resolve_module(hash!("oleaut32.dll")) {
                Some(m) => m,
                None => return false,
            };
            let access = match resolve_export(oleaut, hash!("SafeArrayAccessData")) {
                Some(f) => f,
                None => return false,
            };
            let unaccess = match resolve_export(oleaut, hash!("SafeArrayUnaccessData")) {
                Some(f) => f,
                None => return false,
            };
            type AccessFn =
                unsafe extern "system" fn(*mut SafeArray, *mut *mut c_void) -> i32;
            type UnaccessFn = unsafe extern "system" fn(*mut SafeArray) -> i32;
            let access_f: AccessFn = core::mem::transmute(access);
            let unaccess_f: UnaccessFn = core::mem::transmute(unaccess);

            let mut pv: *mut c_void = core::ptr::null_mut();
            let hr = access_f(self.ptr, &mut pv);
            if hr < 0 || pv.is_null() {
                return false;
            }
            core::ptr::copy_nonoverlapping(src.as_ptr(), pv as *mut u8, src.len());
            let _ = unaccess_f(self.ptr);
            true
        }
    }
}

impl Drop for OwnedSafeArray {
    fn drop(&mut self) {
        unsafe {
            if let Some(m) = resolve_module(hash!("oleaut32.dll")) {
                if let Some(d) = resolve_export(m, hash!("SafeArrayDestroy")) {
                    type Fn = unsafe extern "system" fn(*mut SafeArray) -> i32;
                    let f: Fn = core::mem::transmute(d);
                    f(self.ptr);
                }
            }
        }
    }
}
