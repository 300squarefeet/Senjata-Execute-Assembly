use opsec_com::comptr::{ComPtr, Guid, IUnknown, IUnknownVtbl};
use std::sync::atomic::{AtomicU32, Ordering};

static RELEASE_COUNT: AtomicU32 = AtomicU32::new(0);

unsafe extern "system" fn mock_qi(_: *mut core::ffi::c_void, _: *const Guid, _: *mut *mut core::ffi::c_void) -> i32 { 0 }
unsafe extern "system" fn mock_addref(_: *mut core::ffi::c_void) -> u32 { 1 }
unsafe extern "system" fn mock_release(_: *mut core::ffi::c_void) -> u32 {
    RELEASE_COUNT.fetch_add(1, Ordering::SeqCst);
    0
}

const VTBL: IUnknownVtbl = IUnknownVtbl {
    query_interface: mock_qi,
    add_ref: mock_addref,
    release: mock_release,
};

#[test]
fn comptr_release_on_drop() {
    let mut obj = IUnknown { vtbl: &VTBL };
    RELEASE_COUNT.store(0, Ordering::SeqCst);
    {
        let _p = unsafe { ComPtr::<IUnknown>::from_raw(&mut obj as *mut _) }.unwrap();
    }
    assert_eq!(RELEASE_COUNT.load(Ordering::SeqCst), 1);
}
