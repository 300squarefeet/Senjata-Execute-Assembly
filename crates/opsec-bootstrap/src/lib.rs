//! Indirect-syscall fallback for NtGetContextThread/NtSetContextThread.
#![no_std]
#![feature(naked_functions)]

pub mod gadget;

#[cfg(target_arch = "x86_64")]
pub mod syscall;

#[cfg(target_arch = "x86_64")]
pub use syscall::{Bootstrap, Error};
