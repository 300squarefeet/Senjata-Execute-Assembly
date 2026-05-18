use opsec_peb::djb2;

#[test]
fn djb2_known_values() {
    assert_eq!(djb2(b""), 5381);
    assert_eq!(djb2(b"a"), 177670);
    assert_eq!(djb2(b"hello"), 261238937);  // u32 wrapping
}

#[test]
fn djb2_module_names() {
    let h = djb2(b"ntdll.dll");
    assert_ne!(h, 0);
    let h2 = djb2(b"ntdll.dll");
    assert_eq!(h, h2);
}

#[test]
fn djb2_case_sensitive() {
    assert_ne!(djb2(b"ntdll.dll"), djb2(b"NTDLL.DLL"));
}
