use crate::candidate::pricing;
pub fn total(qty: i64, unit: i64) -> i64 {
    let discount = if qty >= 10 { 1250 } else { 250 };
    match pricing::quote(qty, pricing::Price { unit_cents: unit, discount_bps: discount }) {
        Ok(value) => value, Err(_) => -1,
    }
}
