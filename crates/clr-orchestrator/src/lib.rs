//! Shared CLR-hosting orchestrator used by both `senjata-execute-assembly`
//! (BOF, inline mode) and `senjata-runner` (postex DLL, sacrificial mode).
//!
//! All CLR lifecycle logic, PE parsing, named-pipe I/O, HWBP bypass
//! installation, and managed-helper invocation lives here. Both artefacts
//! call `orchestrate()` and differ only in how they receive args and
//! deliver output.
#![no_std]
#![cfg_attr(not(test), no_main)]

extern crate alloc;

// Module wiring populated by subsequent tasks.
#[cfg(target_os = "windows")]
pub mod error;
#[cfg(target_os = "windows")]
pub use error::OrchestratorError;

pub mod pe_parser;

#[cfg(target_os = "windows")]
pub mod io;
#[cfg(target_os = "windows")]
pub mod cleanup;
#[cfg(target_os = "windows")]
pub mod core;
#[cfg(target_os = "windows")]
pub mod netfx;
#[cfg(target_os = "windows")]
pub mod dispatch;
