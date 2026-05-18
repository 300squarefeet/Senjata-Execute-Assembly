//! Senjata-Execute-Assembly BOF — entry point.
#![no_std]

pub mod args;
pub mod pe_parser;

#[rustbof::main]
fn main(_args: *mut u8, _len: usize) {
    rustbof::println!("[+] senjata-execute-assembly skeleton OK");
}
