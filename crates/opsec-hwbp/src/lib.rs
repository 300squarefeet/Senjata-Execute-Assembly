//! Hardware breakpoint engine + VEH dispatch.
#![no_std]
extern crate alloc;

pub mod descriptor;
pub mod spin;
#[cfg(target_os = "windows")]
pub mod engine;
#[cfg(target_os = "windows")]
pub mod veh;

#[cfg(target_os = "windows")]
pub use engine::{Error, HwbpEngine, HwbpGuard};
