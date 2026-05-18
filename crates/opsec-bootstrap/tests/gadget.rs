use opsec_bootstrap::gadget::find_syscall_ret;

#[test]
fn finds_gadget_in_buffer() {
    let mut buf = vec![0u8; 4096];
    buf[2000] = 0x0F;
    buf[2001] = 0x05;
    buf[2002] = 0xC3;
    let base = buf.as_ptr() as usize;
    let res = unsafe { find_syscall_ret(base, buf.len()) };
    assert_eq!(res, Some(base + 2000));
}

#[test]
fn returns_none_when_absent() {
    let buf = vec![0u8; 4096];
    let base = buf.as_ptr() as usize;
    assert_eq!(unsafe { find_syscall_ret(base, buf.len()) }, None);
}
