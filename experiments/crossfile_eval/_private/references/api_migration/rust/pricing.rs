pub struct Price { pub unit_cents: i64, pub discount_bps: i64 }
pub fn quote(qty: i64, price: Price) -> Result<i64, i32> {
    if qty < 0 || price.unit_cents < 0 || price.discount_bps < 0 || price.discount_bps > 10000 { return Err(1); }
    Ok(qty * price.unit_cents * (10000 - price.discount_bps) / 10000)
}
