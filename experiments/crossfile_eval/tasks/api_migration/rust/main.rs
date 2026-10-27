pub mod pricing;
pub mod receipt;
pub fn task(a: i64, b: i64) -> i64 { receipt::total(a, b) }
