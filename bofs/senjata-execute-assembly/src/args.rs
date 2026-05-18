use alloc::string::String;
use alloc::vec::Vec;
use rustbof::data::DataParser;

#[derive(Debug)]
pub struct Args {
    pub app_domain: String,
    pub amsi: bool,
    pub etw: bool,
    pub mailslot: bool,
    pub entry_point: u32,
    pub slot_name: String,
    pub pipe_name: String,
    pub asm_args: String,
    pub asm_bytes: Vec<u8>,
}

#[derive(Debug)]
pub enum Error {
    Truncated,
}

pub fn parse(raw: *mut u8, len: usize) -> Result<Args, Error> {
    let mut p = DataParser::new(raw, len);
    let app_domain = p.get_str().into();
    let amsi = p.get_int() != 0;
    let etw = p.get_int() != 0;
    let mailslot = p.get_int() != 0;
    let entry_point = p.get_int() as u32;
    let slot_name = p.get_str().into();
    let pipe_name = p.get_str().into();
    let asm_args = p.get_str().into();
    let asm_bytes = p.get_bytes().to_vec();
    Ok(Args {
        app_domain,
        amsi,
        etw,
        mailslot,
        entry_point,
        slot_name,
        pipe_name,
        asm_args,
        asm_bytes,
    })
}
