//! Custom memory allocator using the Windows process heap.

use core::alloc::{GlobalAlloc, Layout};
use windows_sys::Win32::System::Memory::{GetProcessHeap, HeapAlloc, HeapFree};

/// Global allocator that uses the Windows process heap.
pub struct BeaconAlloc;

unsafe impl GlobalAlloc for BeaconAlloc {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let heap = unsafe { GetProcessHeap() };
        unsafe { HeapAlloc(heap, 0, layout.size()) as *mut u8 }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let heap = unsafe { GetProcessHeap() };
        if !ptr.is_null() && layout.size() > 0 {
            unsafe { HeapFree(heap, 0, ptr as *const _) };
        }
    }
}
