use opsec_peb::{resolve_export, resolve_module};
use opsec_strcrypt::hash;

pub type Bstr = *mut u16;

pub struct OwnedBstr {
    pub s: Bstr,
}

impl OwnedBstr {
    pub unsafe fn from_utf16(wide: &[u16]) -> Option<Self> {
        unsafe {
            let oleaut = resolve_module(hash!("oleaut32.dll"))?;
            let alloc_fn = resolve_export(oleaut, hash!("SysAllocStringLen"))?;
            type Fn = unsafe extern "system" fn(*const u16, u32) -> Bstr;
            let f: Fn = core::mem::transmute(alloc_fn);
            let b = f(wide.as_ptr(), wide.len() as u32);
            if b.is_null() { None } else { Some(OwnedBstr { s: b }) }
        }
    }
}

impl Drop for OwnedBstr {
    fn drop(&mut self) {
        unsafe {
            if let Some(m) = resolve_module(hash!("oleaut32.dll")) {
                if let Some(free_fn) = resolve_export(m, hash!("SysFreeString")) {
                    type Fn = unsafe extern "system" fn(Bstr);
                    let f: Fn = core::mem::transmute(free_fn);
                    f(self.s);
                }
            }
        }
    }
}
