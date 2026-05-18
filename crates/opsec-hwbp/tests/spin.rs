use opsec_hwbp::spin::SpinLock;
use std::sync::Arc;
use std::thread;

#[test]
fn single_threaded_lock_unlock() {
    let lock = SpinLock::new(42u32);
    {
        let mut g = lock.lock();
        *g = 100;
    }
    assert_eq!(*lock.lock(), 100);
}

#[test]
fn multithreaded_mutex_correctness() {
    let lock = Arc::new(SpinLock::new(0u32));
    let mut handles = vec![];
    for _ in 0..10 {
        let l = lock.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..1000 {
                let mut g = l.lock();
                *g += 1;
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
    assert_eq!(*lock.lock(), 10_000);
}
