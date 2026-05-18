use opsec_hwbp::descriptor::{CallbackKind, Descriptor, DescriptorTable};

#[test]
fn insert_remove_lookup() {
    let table = DescriptorTable::new();
    let d = Descriptor {
        address: 0x1000,
        slot: 0,
        thread_id: 0,
        callback: CallbackKind::RipRet,
    };
    table.insert(d);
    assert!(table.find(0x1000, 0).is_some());
    table.remove(0x1000, 0);
    assert!(table.find(0x1000, 0).is_none());
}

#[test]
fn multiple_descriptors() {
    let table = DescriptorTable::new();
    for i in 0..4u64 {
        table.insert(Descriptor {
            address: 0x1000 + (i * 0x100) as usize,
            slot: (i % 4) as u8,
            thread_id: 0,
            callback: CallbackKind::RipRet,
        });
    }
    assert_eq!(table.snapshot().len(), 4);
}
