use opsec_peb::{djb2, pe};

const FIXTURE: &[u8] = include_bytes!("fixtures/mini-pe.bin");

#[test]
fn resolves_foo() {
    let base = FIXTURE.as_ptr() as usize;
    let rva = unsafe { pe::resolve_export_in_image(base, djb2(b"foo")) };
    assert_eq!(rva, Some(0x2000));
}

#[test]
fn resolves_bar() {
    let base = FIXTURE.as_ptr() as usize;
    let rva = unsafe { pe::resolve_export_in_image(base, djb2(b"bar")) };
    assert_eq!(rva, Some(0x2010));
}

#[test]
fn missing_export_returns_none() {
    let base = FIXTURE.as_ptr() as usize;
    let rva = unsafe { pe::resolve_export_in_image(base, djb2(b"nonexistent")) };
    assert_eq!(rva, None);
}
