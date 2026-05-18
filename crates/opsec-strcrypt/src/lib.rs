//! Compile-time XOR string encryption proc-macros.

use proc_macro::TokenStream;
use proc_macro2::Literal;
use quote::quote;
use syn::{LitStr, parse_macro_input};

/// Compute a DJB2 hash of a string literal at compile time.
///
/// # Example
/// ```ignore
/// const H: u32 = hash!("ntdll.dll");
/// ```
#[proc_macro]
pub fn hash(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr);
    let s = lit.value();
    let h = djb2_compile(s.as_bytes());
    let h_lit = Literal::u32_suffixed(h);
    quote! { #h_lit }.into()
}

/// XOR-encrypt a byte string literal at compile time. Returns a `SecureStr`
/// that decrypts on first use and wipes on drop.
///
/// # Example
/// ```ignore
/// let s = obf!("AmsiScanBuffer");
/// do_something(s.as_bytes());
/// // memory is zeroed when `s` is dropped
/// ```
#[proc_macro]
pub fn obf(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr);
    let s = lit.value();
    let bytes = s.as_bytes().to_vec();
    let key: u8 = derive_key(&lit, &bytes);
    let encrypted: Vec<u8> = bytes.iter().map(|b| b ^ key).collect();
    let len = encrypted.len();

    quote! {
        {
            const ENC: [u8; #len] = [ #(#encrypted),* ];
            const KEY: u8 = #key;
            ::opsec_strcrypt_rt::SecureStr::<#len>::new(ENC, KEY)
        }
    }
    .into()
}

/// XOR-encrypt a UTF-16 wide string literal at compile time. Returns a
/// `SecureWideStr` that decrypts on first use and wipes on drop.
///
/// # Example
/// ```ignore
/// let s = obfw!("kernel32.dll");
/// some_wide_api(s.as_wide());
/// ```
#[proc_macro]
pub fn obfw(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr);
    let s = lit.value();
    let units: Vec<u16> = s.encode_utf16().collect();
    let key_byte: u8 = derive_key(&lit, s.as_bytes());
    let key: u16 = (key_byte as u16) | 0xAA00;
    let encrypted: Vec<u16> = units.iter().map(|u| u ^ key).collect();
    let len = encrypted.len();

    quote! {
        {
            const ENC: [u16; #len] = [ #(#encrypted),* ];
            const KEY: u16 = #key;
            ::opsec_strcrypt_rt::SecureWideStr::<#len>::new(ENC, KEY)
        }
    }
    .into()
}

/// DJB2 hash computed at proc-macro (host) compile time, matching the
/// `opsec_peb::djb2` const fn exactly.
const fn djb2_compile(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < bytes.len() {
        hash = hash.wrapping_mul(33).wrapping_add(bytes[i] as u32);
        i += 1;
    }
    hash
}

/// Derive a non-zero XOR key from the literal's span debug string mixed with
/// the raw content bytes, so each call site gets a distinct key.
fn derive_key(lit: &LitStr, content: &[u8]) -> u8 {
    let span_str = format!("{:?}", lit.span());
    let mut h: u32 = 5381;
    for b in span_str.bytes().chain(content.iter().copied()) {
        h = h.wrapping_mul(33).wrapping_add(b as u32);
    }
    let k = (h & 0xFF) as u8;
    if k == 0 { 0xA5 } else { k }
}
