//! Independent handwritten Rust baseline with the same raw-pointer contracts.
//! The optimizer, target CPU, overflow checks, and link settings are matched.
#![no_std]

#[unsafe(no_mangle)]
pub unsafe extern "C" fn hepta_sum(data: *const u64, count: usize) -> u64 {
    let mut sum: u64 = 0;
    let mut index: usize = 0;
    while index < count {
        sum = sum.wrapping_add(unsafe { data.add(index).read() });
        index = index.wrapping_add(1);
    }
    sum
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn hepta_copy(destination: *mut u64, source: *const u64, count: usize) {
    let mut index: usize = 0;
    while index < count {
        unsafe { destination.add(index).write(source.add(index).read()) };
        index = index.wrapping_add(1);
    }
}
