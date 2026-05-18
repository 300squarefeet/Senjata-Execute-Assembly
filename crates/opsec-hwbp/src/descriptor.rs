use crate::spin::SpinLock;
use alloc::vec::Vec;

#[derive(Clone, Copy)]
pub enum CallbackKind {
    /// Skip the patched function: find a `ret` (0xC3) within ±500 bytes of RIP.
    RipRet,
    /// Abandon the calling stack; jump to (resume_rip, resume_rsp).
    ExitTrap { resume_rip: usize, resume_rsp: usize },
}

#[derive(Clone, Copy)]
pub struct Descriptor {
    pub address: usize,
    pub slot: u8,
    pub thread_id: u32,   // 0 = all threads
    pub callback: CallbackKind,
}

pub struct DescriptorTable {
    inner: SpinLock<Vec<Descriptor>>,
}

impl DescriptorTable {
    #[allow(clippy::new_without_default)] // const fn; Default::default cannot be const
    pub const fn new() -> Self {
        Self { inner: SpinLock::new(Vec::new()) }
    }
    pub fn insert(&self, d: Descriptor) {
        self.inner.lock().push(d);
    }
    pub fn remove(&self, address: usize, thread_id: u32) {
        self.inner.lock().retain(|d| !(d.address == address && d.thread_id == thread_id));
    }
    pub fn find(&self, address: usize, thread_id: u32) -> Option<Descriptor> {
        self.inner.lock().iter()
            .find(|d| d.address == address && (d.thread_id == 0 || d.thread_id == thread_id))
            .copied()
    }
    pub fn snapshot(&self) -> Vec<Descriptor> {
        self.inner.lock().clone()
    }
    pub fn clear(&self) {
        self.inner.lock().clear();
    }
}
