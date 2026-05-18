//! Typed COM FFI for CLR hosting interfaces.
#![no_std]
extern crate alloc;

pub mod comptr;
pub mod guids;
#[cfg(target_os = "windows")]
pub mod bstr;
#[cfg(target_os = "windows")]
pub mod safearray;
#[cfg(target_os = "windows")]
pub mod variant;
#[cfg(target_os = "windows")]
pub mod appdomain;
#[cfg(target_os = "windows")]
pub mod clr;
