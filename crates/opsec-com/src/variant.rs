use opsec_peb::{resolve_export, resolve_module};
use opsec_strcrypt::hash;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Variant {
    pub vt: u16,
    pub _r1: u16,
    pub _r2: u16,
    pub _r3: u16,
    pub payload: [u64; 2],
}

pub struct OwnedVariant {
    pub v: Variant,
}

impl Drop for OwnedVariant {
    fn drop(&mut self) {
        unsafe {
            if let Some(m) = resolve_module(hash!("oleaut32.dll")) {
                if let Some(c) = resolve_export(m, hash!("VariantClear")) {
                    type Fn = unsafe extern "system" fn(*mut Variant) -> i32;
                    let f: Fn = core::mem::transmute(c);
                    f(&mut self.v);
                }
            }
        }
    }
}
