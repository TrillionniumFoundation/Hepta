pub mod foreign;
pub mod adapter;
pub fn task(a: i64, b: i64) -> i64 { adapter::run(a, b) }
