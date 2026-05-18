//! Runtime support for opsec-strcrypt proc-macros.
#![no_std]

/// Stack-resident XOR-decrypted byte string. Wipes itself on drop.
pub struct SecureStr<const N: usize> {
    decrypted: [u8; N],
}

impl<const N: usize> SecureStr<N> {
    pub const fn new(enc: [u8; N], key: u8) -> Self {
        let mut decrypted = [0u8; N];
        let mut i = 0;
        while i < N {
            decrypted[i] = enc[i] ^ key;
            i += 1;
        }
        Self { decrypted }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.decrypted
    }
}

impl<const N: usize> Drop for SecureStr<N> {
    fn drop(&mut self) {
        for i in 0..N {
            unsafe { core::ptr::write_volatile(&mut self.decrypted[i], 0) };
        }
    }
}

/// Stack-resident XOR-decrypted UTF-16 wide string. Wipes itself on drop.
pub struct SecureWideStr<const N: usize> {
    decrypted: [u16; N],
}

impl<const N: usize> SecureWideStr<N> {
    pub const fn new(enc: [u16; N], key: u16) -> Self {
        let mut decrypted = [0u16; N];
        let mut i = 0;
        while i < N {
            decrypted[i] = enc[i] ^ key;
            i += 1;
        }
        Self { decrypted }
    }
    pub fn as_wide(&self) -> &[u16] {
        &self.decrypted
    }
}

impl<const N: usize> Drop for SecureWideStr<N> {
    fn drop(&mut self) {
        for i in 0..N {
            unsafe { core::ptr::write_volatile(&mut self.decrypted[i], 0) };
        }
    }
}
