//! Persistent storage across BOF executions.

use core::ffi::c_void;
use crate::beacon_api;
use crate::str::to_cstr;

/// Empty data store slot.
pub const DATA_STORE_TYPE_EMPTY: i32 = 0;
/// General file data store entry.
pub const DATA_STORE_TYPE_GENERAL_FILE: i32 = 1;

/// Adds a key/value pair to the persistent store.
#[inline]
pub fn add(key: &str, ptr: *mut c_void) -> bool {
    let key = to_cstr(key);
    (unsafe { BeaconAddValue(key.as_ptr().cast(), ptr) }) != 0
}

/// Retrieves a value from the persistent store.
#[inline]
pub fn get(key: &str) -> *mut c_void {
    let key = to_cstr(key);
    unsafe { BeaconGetValue(key.as_ptr().cast()) }
}

/// Removes a key/value pair from the persistent store.
#[inline]
pub fn remove(key: &str) -> bool {
    let key = to_cstr(key);
    (unsafe { BeaconRemoveValue(key.as_ptr().cast()) }) != 0
}

/// Data store object entry.
#[repr(C)]
pub struct DataStoreObject {
    /// Entry type (empty or general file).
    pub entry_type: i32,
    /// Hash of the stored data.
    pub hash: u64,
    /// Whether the data is currently masked.
    pub masked: i32,
    /// Pointer to the data buffer.
    pub buffer: *mut u8,
    /// Length of the data in bytes.
    pub length: usize,
}

impl DataStoreObject {
    /// Returns the data as a byte slice.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.buffer, self.length) }
    }

    /// Returns `true` if the entry is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entry_type == DATA_STORE_TYPE_EMPTY
    }

    /// Returns `true` if the data is currently masked.
    #[inline]
    pub fn is_masked(&self) -> bool {
        self.masked != 0
    }
}

/// Retrieves a data store item by index.
#[inline]
pub fn data_store_get(index: usize) -> Option<&'static DataStoreObject> {
    let ptr = unsafe { BeaconDataStoreGetItem(index) };
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &*ptr })
    }
}

/// Masks a data store item for protection.
#[inline]
pub fn data_store_protect(index: usize) {
    unsafe { BeaconDataStoreProtectItem(index) };
}

/// Unmasks a data store item for access.
#[inline]
pub fn data_store_unprotect(index: usize) {
    unsafe { BeaconDataStoreUnprotectItem(index) };
}

/// Returns the maximum number of data store entries.
#[inline]
pub fn data_store_max_entries() -> usize {
    unsafe { BeaconDataStoreMaxEntries() }
}

beacon_api!(BeaconDataStoreGetItem: extern "C" fn(index: usize) -> *mut DataStoreObject);
beacon_api!(BeaconDataStoreProtectItem: extern "C" fn(index: usize));
beacon_api!(BeaconDataStoreUnprotectItem: extern "C" fn(index: usize));
beacon_api!(BeaconDataStoreMaxEntries: extern "C" fn() -> usize);
beacon_api!(BeaconAddValue: extern "C" fn(key: *const i8, ptr: *mut c_void) -> i32);
beacon_api!(BeaconGetValue: extern "C" fn(key: *const i8) -> *mut c_void);
beacon_api!(BeaconRemoveValue: extern "C" fn(key: *const i8) -> i32);
