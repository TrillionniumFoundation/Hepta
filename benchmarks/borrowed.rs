//! Handwritten safe-slice reference for borrowed.hepta's correctness test.
fn safe_sum(data: &[u64]) -> u64 {
    let mut total = 0u64;
    let mut index = 0usize;
    while index < data.len() {
        total = total.wrapping_add(data[index]);
        index = index.wrapping_add(1);
    }
    total
}

fn safe_copy(destination: &mut [u64], source: &[u64]) {
    assert!(destination.len() == source.len());
    let mut index = 0usize;
    while index < source.len() {
        destination[index] = source[index];
        index = index.wrapping_add(1);
    }
}

fn main() {
    let source = [0u64, 1, 2, 3, u64::MAX];
    let mut destination = [0u64; 5];
    safe_copy(&mut destination, &source);
    assert!(safe_sum(&source) == 5);
    assert!(safe_sum(&destination) == 5);
    assert!(destination[4] == source[4]);
}
