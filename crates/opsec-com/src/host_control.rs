use crate::comptr::{Guid, IUnknownVtbl};
use core::ffi::c_void;

/// IHostControl vtable layout (5 methods: IUnknown + GetHostManager + SetAppDomainManager).
#[repr(C)]
pub struct IHostControlVtbl {
    pub base: IUnknownVtbl,
    /// GetHostManager(riid: *const Guid, ppObject: *mut *mut c_void) -> HRESULT — index 3
    pub get_host_manager: unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> i32,
    /// SetAppDomainManager(dwAppDomainID: u32, pUnkAppDomainManager: *mut c_void) -> HRESULT — index 4
    pub set_app_domain_manager: unsafe extern "system" fn(*mut c_void, u32, *mut c_void) -> i32,
}

/// In-memory layout of a HostControl COM instance. Allocated via GlobalAlloc; lives
/// for the lifetime of the Beacon process after first BOF invocation.
#[repr(C)]
pub struct HostControlObject {
    pub vtbl: *const IHostControlVtbl,
    pub ref_count: i32,
    /// Pointer to the MemoryManagerObject registered with this control.
    pub memory_manager: *mut super::host_memory_manager::MemoryManagerObject,
}

/// IHostMalloc vtable (6 methods: IUnknown + Alloc + DebugAlloc + Free).
#[repr(C)]
pub struct IHostMallocVtbl {
    pub base: IUnknownVtbl,
    /// Alloc(cbSize, eCriticalLevel, ppMem) -> HRESULT — index 3
    pub alloc: unsafe extern "system" fn(*mut c_void, usize, u32, *mut *mut c_void) -> i32,
    /// DebugAlloc(cbSize, eCriticalLevel, pszFileName, iLineNo, ppMem) -> HRESULT — index 4
    pub debug_alloc: unsafe extern "system" fn(*mut c_void, usize, u32, *const u8, i32, *mut *mut c_void) -> i32,
    /// Free(pMem) -> HRESULT — index 5
    pub free: unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32,
}

/// In-memory layout of a HostMalloc COM instance. Allocated via GlobalAlloc per CLR
/// memory manager; one per CreateMalloc call from the CLR.
#[repr(C)]
pub struct HostMallocObject {
    pub vtbl: *const IHostMallocVtbl,
    pub ref_count: i32,
    pub heap_handle: *mut c_void,
}
