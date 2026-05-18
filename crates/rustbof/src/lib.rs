//! Beacon Object File (BOF) runtime support library.
//!
//! # Examples
//!
//! Basic BOF:
//!
//! ```ignore
//! #![no_std]
//!
//! use rustbof::println;
//!
//! #[rustbof::main]
//! fn main() {
//!     println!("Hello from Rust BOF!");
//! }
//! ```
//!
//! BOF with argument parsing:
//!
//! ```ignore
//! #![no_std]
//!
//! use rustbof::{println, data::DataParser};
//!
//! #[rustbof::main]
//! fn main(args: *mut u8, args_len: usize) {
//!     let mut parser = DataParser::new(args, args_len);
//!     let name = parser.get_str();
//!     println!("Hello, {name}!");
//! }
//! ```

#![no_std]

extern crate alloc;

pub mod allocator;
pub mod data;
pub mod download;
pub mod output;
pub mod store;
pub mod token;
pub mod str;

mod macros;

pub use rustbof_derive::main;

//////////////////////////////////////////////////////////////////
/// Required by `compiler_builtins` for floating-point operations.
//////////////////////////////////////////////////////////////////

#[unsafe(no_mangle)]
extern "C" fn fmaf(a: f32, b: f32, c: f32) -> f32 {
    a * b + c
}

#[unsafe(no_mangle)]
extern "C" fn fma(a: f64, b: f64, c: f64) -> f64 {
    a * b + c
}
