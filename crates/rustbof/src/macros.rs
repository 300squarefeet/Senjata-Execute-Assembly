//! Macros for output and Beacon API imports.

/// Prints formatted text to the Beacon output buffer.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = write!($crate::output::BeaconWriter, $($arg)*);
    }};
}

/// Prints formatted text with a newline to the Beacon output buffer.
#[macro_export]
macro_rules! println {
    () => {{ $crate::print!("\n"); }};
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = write!($crate::output::BeaconWriter, $($arg)*);
        let _ = write!($crate::output::BeaconWriter, "\n");
    }};
}

/// Prints formatted error text and flushes immediately.
#[macro_export]
macro_rules! eprint {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = write!($crate::output::BeaconWriter, $($arg)*);
        $crate::output::flush($crate::output::CALLBACK_ERROR);
    }};
}

/// Prints formatted error text with a newline and flushes immediately.
#[macro_export]
macro_rules! eprintln {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = write!($crate::output::BeaconWriter, $($arg)*);
        let _ = write!($crate::output::BeaconWriter, "\n");
        $crate::output::flush($crate::output::CALLBACK_ERROR);
    }};
}

/// Declares an external Beacon API function.
///
/// # Examples
///
/// ```ignore
/// beacon_api!(BeaconOutput: extern "C" fn(ty: i32, data: *const u8, len: i32));
/// ```
#[macro_export]
macro_rules! beacon_api {
    ($sym:ident : extern $abi:literal fn ( $($an:ident : $aty:ty),* $(,)? ) $(-> $ret:ty)? ) => {
        unsafe extern $abi {
            fn $sym( $($an : $aty),* ) $(-> $ret)?;
        }
    };
}
