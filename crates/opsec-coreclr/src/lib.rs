//! CoreCLR (.NET 6+) hosting via direct coreclr.dll API.
//!
//! Sibling to `opsec-com` (.NET Framework path). Loaded only when the PE
//! parser detects a `.NETCoreApp,Version=` TargetFrameworkAttribute marker.
#![no_std]
extern crate alloc;

pub mod discovery;
pub mod fs;
pub mod host;
pub mod registry;
pub mod stub_artifact;

pub use host::Error;
pub use host::run;
