fn bytes(size: usize) -> Result<Vec<u8>, ()> {
    let mut value = Vec::new();
    value.try_reserve_exact(size).map_err(|_| ())?;
    value.resize(size, 0);
    Ok(value)
}

#[no_mangle]
pub extern "C" fn full_lifecycle(size: usize, seed: u32) -> u64 {
    let mut value = match bytes(size) { Ok(v) => v, Err(()) => return 1001 };
    for (i, byte) in value.iter_mut().enumerate() { *byte = (i as u32).wrapping_add(seed) as u8; }
    value.iter().map(|&byte| u64::from(byte)).sum()
}

#[no_mangle]
pub extern "C" fn packet_xor(size: usize, seed: u32) -> u64 {
    let mut first = match bytes(size) { Ok(v) => v, Err(()) => return 1001 };
    for (i, byte) in first.iter_mut().enumerate() { *byte = (i as u32).wrapping_mul(13).wrapping_add(seed) as u8; }
    let mut second = match bytes(size) { Ok(v) => v, Err(()) => return 1001 };
    for (i, (target, &source)) in second.iter_mut().zip(first.iter()).enumerate() {
        *target = source ^ (i as u32).wrapping_add(seed ^ 90) as u8;
    }
    second.iter().map(|&byte| u64::from(byte)).sum()
}
