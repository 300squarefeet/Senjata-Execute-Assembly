//! Procedural macros for the Beacon BOF runtime.

use proc_macro::TokenStream;
use quote::quote;
use syn::{ItemFn, parse_macro_input};

/// Marks a function as the BOF entry point.
///
/// # Examples
///
/// Basic BOF without arguments:
///
/// ```ignore
/// #![no_std]
///
/// use rustbof::println;
///
/// #[rustbof::main]
/// fn main() {
///     println!("Hello from BOF!");
/// }
/// ```
///
/// BOF with argument parsing:
///
/// ```ignore
/// #![no_std]
///
/// use rustbof::{println, data::DataParser};
///
/// #[rustbof::main]
/// fn main(args: *mut u8, len: usize) {
///     let mut parser = DataParser::new(args, len);
///     let name = parser.get_str();
///     println!("Hello, {name}!");
/// }
/// ```
#[proc_macro_attribute]
pub fn main(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);
    let fn_name = &input.sig.ident;
    let fn_block = &input.block;
    let has_args = !input.sig.inputs.is_empty();

    let expanded = if has_args {
        quote! {
            extern crate alloc;

            #[global_allocator]
            static __ALLOC: rustbof::allocator::BeaconAlloc = rustbof::allocator::BeaconAlloc;

            #[cfg(not(test))]
            #[panic_handler]
            fn __panic(_: &core::panic::PanicInfo) -> ! {
                loop {}
            }

            #[unsafe(export_name = "go")]
            extern "C" fn #fn_name(args: *mut u8, len: usize) {
                #fn_block
                rustbof::output::flush(rustbof::output::CALLBACK_OUTPUT_UTF8);
            }
        }
    } else {
        quote! {
            extern crate alloc;

            #[global_allocator]
            static __ALLOC: rustbof::allocator::BeaconAlloc = rustbof::allocator::BeaconAlloc;

            #[cfg(not(test))]
            #[panic_handler]
            fn __panic(_: &core::panic::PanicInfo) -> ! {
                loop {}
            }

            #[unsafe(export_name = "go")]
            extern "C" fn #fn_name() {
                #fn_block
                rustbof::output::flush(rustbof::output::CALLBACK_OUTPUT_UTF8);
            }
        }
    };

    TokenStream::from(expanded)
}
