//! Implemented in Task 3.3.
pub const CALLBACK_OUTPUT: i32 = 0;

#[allow(dead_code)]
pub struct Api;

#[allow(dead_code)]
impl Api {
    pub unsafe fn printf(&self, _ty: i32, _msg: *const u8) {}
}

pub unsafe fn parse(_data: *mut u8, _len: usize) -> Api {
    Api
}
