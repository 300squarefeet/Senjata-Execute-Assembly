use crate::comptr::IUnknownVtbl;
use crate::safearray::SafeArray;
use crate::variant::Variant;
use core::ffi::c_void;

#[repr(C)]
pub struct AppDomainVtbl {
    pub base: IUnknownVtbl,
    pub _pad1: [usize; 13],
    pub load_3: unsafe extern "system" fn(*mut c_void, *mut SafeArray, *mut *mut c_void) -> i32,
}

#[repr(C)]
pub struct AppDomain {
    pub vtbl: *const AppDomainVtbl,
}

#[repr(C)]
pub struct AssemblyVtbl {
    pub base: IUnknownVtbl,
    pub _pad: [usize; 27],
    pub entry_point: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32,
}

#[repr(C)]
pub struct Assembly {
    pub vtbl: *const AssemblyVtbl,
}

#[repr(C)]
pub struct MethodInfoVtbl {
    pub base: IUnknownVtbl,
    pub _pad: [usize; 35],
    pub invoke_3: unsafe extern "system" fn(*mut c_void, Variant, *mut SafeArray, *mut Variant) -> i32,
}

#[repr(C)]
pub struct MethodInfo {
    pub vtbl: *const MethodInfoVtbl,
}
