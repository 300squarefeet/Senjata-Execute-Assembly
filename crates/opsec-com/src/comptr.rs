use core::marker::PhantomData;
use core::ptr::NonNull;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

#[repr(C)]
pub struct IUnknownVtbl {
    pub query_interface: unsafe extern "system" fn(*mut core::ffi::c_void, *const Guid, *mut *mut core::ffi::c_void) -> i32,
    pub add_ref: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32,
    pub release: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32,
}

#[repr(C)]
pub struct IUnknown {
    pub vtbl: *const IUnknownVtbl,
}

pub struct ComPtr<T> {
    ptr: NonNull<T>,
    _phantom: PhantomData<T>,
}

impl<T> ComPtr<T> {
    pub unsafe fn from_raw(p: *mut T) -> Option<Self> {
        NonNull::new(p).map(|ptr| ComPtr { ptr, _phantom: PhantomData })
    }
    pub fn as_raw(&self) -> *mut T { self.ptr.as_ptr() }
}

impl<T> Drop for ComPtr<T> {
    fn drop(&mut self) {
        unsafe {
            let unk = self.ptr.as_ptr() as *mut IUnknown;
            ((*(*unk).vtbl).release)(unk as *mut core::ffi::c_void);
        }
    }
}
