/// DJB2 hash (Daniel J. Bernstein, times-33 + c, seed 5381).
/// Case-sensitive — callers must normalize if they want case-insensitive lookups.
pub const fn djb2(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < bytes.len() {
        hash = hash.wrapping_mul(33).wrapping_add(bytes[i] as u32);
        i += 1;
    }
    hash
}
