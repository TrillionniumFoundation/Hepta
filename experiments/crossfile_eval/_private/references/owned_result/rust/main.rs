pub mod storage;
pub mod service;
pub fn task(a: i64, b: i64) -> i64 { service::process(a as usize, b != 0) }
