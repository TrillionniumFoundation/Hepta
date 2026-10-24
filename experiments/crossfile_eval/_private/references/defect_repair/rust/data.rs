pub fn fill(values: &mut [i64], count: usize) {
    for i in 0..count { values[i] = (i / 3) as i64 - 7; }
}
