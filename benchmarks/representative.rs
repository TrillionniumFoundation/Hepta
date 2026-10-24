//! Independent handwritten reference, matching the raw pointer, overflow,
//! allocation and native ABI contracts of representative.hepta.
#![no_std]

#[unsafe(no_mangle)]
pub unsafe extern "C" fn hepta_fnv1a(data: *const u8, count: usize) -> u64 {
    let mut hash = 14695981039346656037u64;
    let mut i = 0usize;
    while i < count {
        hash = (hash ^ unsafe { data.add(i).read() } as u64).wrapping_mul(1099511628211);
        i = i.wrapping_add(1);
    }
    hash
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn hepta_histogram(data: *const u8, count: usize, bins: *mut u64) -> u64 {
    let mut i = 0usize;
    while i < 256 {
        unsafe { bins.add(i).write(0) };
        i = i.wrapping_add(1);
    }
    i = 0;
    while i < count {
        let bin = unsafe { data.add(i).read() } as usize;
        unsafe { bins.add(bin).write(bins.add(bin).read().wrapping_add(1)) };
        i = i.wrapping_add(1);
    }
    i = 0;
    let mut checksum = 0u64;
    while i < 256 {
        checksum = checksum.wrapping_add(unsafe { bins.add(i).read() }.wrapping_mul(i as u64));
        i = i.wrapping_add(1);
    }
    checksum
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn hepta_dot(left: *const u64, right: *const u64, count: usize) -> u64 {
    let mut total = 0u64;
    let mut i = 0usize;
    while i < count {
        total = total.wrapping_add(unsafe { left.add(i).read().wrapping_mul(right.add(i).read()) });
        i = i.wrapping_add(1);
    }
    total
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn hepta_binary_search(data: *const u64, count: usize, queries: *const u64, query_count: usize) -> u64 {
    let mut checksum = 0u64;
    let mut query = 0usize;
    while query < query_count {
        let key = unsafe { queries.add(query).read() };
        let mut low = 0usize;
        let mut high = count;
        while low < high {
            let mid = low.wrapping_add(high.wrapping_sub(low) >> 1);
            if unsafe { data.add(mid).read() } < key {
                low = mid.wrapping_add(1);
            } else {
                high = mid;
            }
        }
        checksum = checksum.wrapping_add(low as u64);
        query = query.wrapping_add(1);
    }
    checksum
}
