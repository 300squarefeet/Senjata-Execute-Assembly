//! Token management for impersonation and privilege checks.

use crate::beacon_api;

/// Applies a security token to the current thread.
#[inline]
pub fn use_token(token: *mut core::ffi::c_void) -> bool {
    (unsafe { BeaconUseToken(token) }) != 0
}

/// Reverts to the original security token.
#[inline]
pub fn revert_token() {
    unsafe { BeaconRevertToken() };
}

/// Returns `true` if the current session has administrator privileges.
#[inline]
pub fn is_admin() -> bool {
    (unsafe { BeaconIsAdmin() }) != 0
}

beacon_api!(BeaconUseToken: extern "C" fn(token: *mut core::ffi::c_void) -> i32);
beacon_api!(BeaconRevertToken: extern "C" fn());
beacon_api!(BeaconIsAdmin: extern "C" fn() -> i32);
