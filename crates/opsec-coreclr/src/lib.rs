//! CoreCLR (.NET 6+) hosting via direct coreclr.dll API.
//!
//! Sibling to `opsec-com` (.NET Framework path). Loaded only when the PE
//! parser detects a `.NETCoreApp,Version=` TargetFrameworkAttribute marker.
#![no_std]
extern crate alloc;

pub mod semver;
#[cfg(target_arch = "x86_64")]
pub mod fs;
#[cfg(target_arch = "x86_64")]
pub mod registry;
#[cfg(target_arch = "x86_64")]
pub mod discovery;
pub mod host;
pub mod stub_artifact;

pub use host::Error;
pub use host::run;
