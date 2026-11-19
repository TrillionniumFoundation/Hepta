// Rust release baselines with the same C ABI and valid-input benchmark work.
// The FFI slices require caller liveness; this file is not an all-Safe-Rust API.
#[no_mangle]
#[inline(never)]
pub extern "C" fn reference_madd(a:u64,b:u64,c:u64)->u64 { a.wrapping_mul(b).wrapping_add(c) }
fn range(p:usize,extent:u64,n:u64) {
    if n>extent || (n!=0 && (p==0 || p.checked_add(n as usize).is_none())) { std::process::abort(); }
}
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn reference_sum(p:*const u8,extent:u64,n:u64)->u64 {
    range(p as usize,extent,n);
    if n==0 { return 0; }
    std::slice::from_raw_parts(p,n as usize).iter().fold(0u64,|a,&b|a.wrapping_add(b as u64))
}
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn reference_zero(p:*const u8,extent:u64,n:u64)->u64 {
    range(p as usize,extent,n);
    if n==0 { return 1; }
    (std::slice::from_raw_parts(p,n as usize).iter().fold(0u8,|a,&b|a|b)==0) as u64
}
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn reference_copy(d:*mut u8,de:u64,s:*const u8,se:u64,n:u64)->u64 {
    range(d as usize,de,n); range(s as usize,se,n);
    if n==0 { return 0; }
    if (d as usize)<(s as usize)+n as usize && (s as usize)<(d as usize)+n as usize { std::process::abort(); }
    std::ptr::copy_nonoverlapping(s,d,n as usize);
    n
}
