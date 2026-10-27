use crate::candidate::pricing;
pub fn total(qty: i64, unit: i64) -> i64 { pricing::subtotal(qty, unit) }
