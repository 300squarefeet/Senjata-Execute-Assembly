use opsec_strcrypt::{hash, obf, obfw};

#[test]
fn hash_is_const_djb2() {
    const H: u32 = hash!("ntdll.dll");
    assert_eq!(H, opsec_peb::djb2(b"ntdll.dll"));
}

#[test]
fn obf_roundtrip() {
    let s = obf!("AmsiScanBuffer");
    assert_eq!(s.as_bytes(), b"AmsiScanBuffer");
}

#[test]
fn obf_does_not_contain_plaintext_in_macro_output() {
    let s = obf!("kernel32.dll");
    assert_eq!(s.as_bytes(), b"kernel32.dll");
}

#[test]
fn obfw_roundtrip() {
    let s = obfw!("ntdll.dll");
    let expected: Vec<u16> = "ntdll.dll".encode_utf16().collect();
    assert_eq!(s.as_wide(), expected.as_slice());
}
