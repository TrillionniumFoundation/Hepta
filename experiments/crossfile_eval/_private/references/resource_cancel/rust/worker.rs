use std::sync::atomic::{AtomicBool, Ordering};
pub fn execute(data: Vec<u8>, flag: &AtomicBool) -> u64 {
    let cancel = data[0] != 0;
    if cancel { while !flag.load(Ordering::Acquire) { std::hint::spin_loop(); } }
    let value: u64 = data[1..].iter().map(|v| *v as u64).sum();
    drop(data);
    value + if cancel { 1000000 } else { 0 }
}
