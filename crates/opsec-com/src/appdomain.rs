use crate::comptr::IUnknownVtbl;
use crate::safearray::SafeArray;
use crate::variant::Variant;
use core::ffi::c_void;

#[repr(C)]
pub struct AppDomainVtbl {
    pub base: IUnknownVtbl,
    // IDispatch (4) + ToString..Load_2 (38) = 42 slots before Load_3 (index 45)
    pub _pad1: [usize; 42],
    pub load_3: unsafe extern "system" fn(*mut c_void, *mut SafeArray, *mut *mut c_void) -> i32, // index 45
}

#[repr(C)]
pub struct AppDomain {
    pub vtbl: *const AppDomainVtbl,
}

#[repr(C)]
pub struct AssemblyVtbl {
    pub base: IUnknownVtbl,
    // IDispatch (4) + ToString..FullName (9) = 13 slots before EntryPoint (index 16)
    pub _pad: [usize; 13],
    pub entry_point: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32, // index 16
}

#[repr(C)]
pub struct Assembly {
    pub vtbl: *const AssemblyVtbl,
}

#[repr(C)]
pub struct MethodInfoVtbl {
    pub base: IUnknownVtbl,
    // IDispatch (4) + ToString..IsConstructor (30) = 34 slots before Invoke_3 (index 37)
    pub _pad: [usize; 34],
    pub invoke_3: unsafe extern "system" fn(*mut c_void, Variant, *mut SafeArray, *mut Variant) -> i32, // index 37
}

#[repr(C)]
pub struct MethodInfo {
    pub vtbl: *const MethodInfoVtbl,
}
