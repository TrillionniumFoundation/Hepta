use std::sync::atomic::{AtomicBool, Ordering};
pub fn execute(data: Vec<u8>, flag: &AtomicBool) -> u64 {
    if data[0] != 0 { while !flag.load(Ordering::Acquire) { std::hint::spin_loop(); } }
    let value = data.len() as u64;
    drop(data);
    value
}
