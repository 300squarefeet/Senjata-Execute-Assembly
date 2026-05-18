//! PEB walker + DJB2 export resolver.

#![no_std]

mod hash;
pub mod ntdef;
pub mod pe;
pub mod peb_walk;

pub use hash::djb2;
pub use peb_walk::{resolve_export, resolve_module, ModuleHandle};
