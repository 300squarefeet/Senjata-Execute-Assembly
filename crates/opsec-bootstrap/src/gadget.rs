/// Scan `len` bytes starting at `base`, return address of first `syscall; ret` (0F 05 C3).
///
/// # Safety
/// `base..base+len` must be a readable region.
pub unsafe fn find_syscall_ret(base: usize, len: usize) -> Option<usize> {
    let mut i = 0usize;
    while i + 3 <= len {
        let p = (base + i) as *const u8;
        unsafe {
            if *p == 0x0F && *p.add(1) == 0x05 && *p.add(2) == 0xC3 {
                return Some(base + i);
            }
        }
        i += 1;
    }
    None
}
