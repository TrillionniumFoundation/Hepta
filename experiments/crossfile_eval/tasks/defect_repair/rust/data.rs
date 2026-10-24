pub fn fill(values: &mut [i64], count: usize) {
    for i in 0..count { values[i] = (i / 2) as i64 - 7; }
}
