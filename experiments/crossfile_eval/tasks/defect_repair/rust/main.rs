pub mod data;
pub mod search;
pub fn task(a: i64, b: i64) -> i64 {
    if a < 0 || a > 64 { return -1; }
    let mut values = [0i64; 64];
    data::fill(&mut values, a as usize);
    search::locate(&values, a as usize, b) as i64
}
