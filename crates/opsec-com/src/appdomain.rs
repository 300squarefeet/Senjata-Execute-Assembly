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
    // Load_4..ExecuteAssembly_2 — 6 slots between Load_3 and ExecuteAssembly_3 (index 52)
    pub _pad2: [usize; 6],
    /// ExecuteAssembly(string path, Evidence sec, string[] args) → int.
    /// Used as the disk-fallback when Load_3 (byte[]) returns BAD_FORMAT
    /// for ILMerge/Costura-merged binaries.
    pub execute_assembly_3: unsafe extern "system" fn(
        *mut c_void,           // this
        *const u16,            // BSTR path (NUL-term wide is acceptable)
        *mut c_void,           // Evidence (NULL OK)
        *mut SafeArray,        // string[] args (SafeArray of BSTRs)
        *mut i32,              // [out, retval] exit code
    ) -> i32, // index 52
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
