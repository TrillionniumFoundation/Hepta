pub fn locate(values: &[i64], count: usize, key: i64) -> usize {
    if count == 0 { return 0; }
    let mut lo = 0;
    let mut hi = count - 1;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if values[mid] <= key { lo = mid + 1; } else { hi = mid; }
    }
    lo
}
