// Safe Vec/slice kernel; only the C measurement ABI wrappers below are unsafe.
#[no_mangle]
pub extern "C" fn calculate(n: usize, seed: u32) -> u64 {
    let mut bytes = Vec::<u8>::new();
    if bytes.try_reserve_exact(n).is_err() { return 1001; }
    bytes.resize(n, 0);
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = (i as u32).wrapping_add(seed) as u8;
    }
    let result = bytes.iter().map(|&byte| u64::from(byte)).sum();
    drop(bytes);
    result
}

#[repr(C)]
pub struct Metrics { fields: [u64; 14] }
extern "C" {
    fn metrics_begin(fail: u64);
    fn metrics_end(out: *mut Metrics);
}
#[no_mangle]
pub extern "C" fn probe_begin(fail: u64) { unsafe { metrics_begin(fail); } }
#[no_mangle]
pub unsafe extern "C" fn probe_end(out: *mut Metrics) { metrics_end(out); }
