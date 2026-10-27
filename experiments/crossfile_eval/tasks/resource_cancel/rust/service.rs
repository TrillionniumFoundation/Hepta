use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::candidate::worker;
pub fn run(n: usize, cancel: bool) -> i64 {
    if n < 2 { return -1; }
    let mut data = vec![0u8; n];
    data[0] = u8::from(cancel);
    let flag = Arc::new(AtomicBool::new(false));
    let token = Arc::clone(&flag);
    let handle = std::thread::spawn(move || worker::execute(data, &token));
    handle.join().unwrap() as i64
}
