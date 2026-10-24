pub mod worker;
pub mod service;
pub fn task(a: i64, b: i64) -> i64 { service::run(a as usize, b != 0) }
