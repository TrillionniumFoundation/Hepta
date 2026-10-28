// Independent safe Vec/slice baseline. Only the required exported ABI attribute
// is allowed under the unsafe-code lint; the function body contains no unsafe.
#![deny(unsafe_code)]

fn checksum_byte(state: u32, byte: u8, polynomial: u32) -> u32 {
    let mut value = state ^ u32::from(byte);
    for _ in 0..8 {
        value = if value & 1 != 0 { (value >> 1) ^ polynomial } else { value >> 1 };
    }
    value
}

#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn checksum_chunk(count: usize, packed: u64, state: u32,
                                 polynomial: u32) -> u64 {
    if count == 0 { return u64::from(state); }
    if count > 8 { return 1_u64 << 32; }
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(count).is_err() { return 2_u64 << 32; }
    bytes.resize(count, 0_u8);
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (packed >> (index * 8)) as u8;
    }
    let mut value = state;
    for &byte in &bytes { value = checksum_byte(value, byte, polynomial); }
    u64::from(value)
}
