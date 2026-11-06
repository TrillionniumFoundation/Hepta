//! Independently authored strong Rust comparator for the complete six-function
//! stb_divide 0.94 truncating configuration. No imported C/HIA implementation.
#![no_std]

// The profiler runtime registers an exit hook when PGO is enabled. Link libc
// explicitly for the same no_std baseline in every build configuration.
#[link(name = "c")]
unsafe extern "C" { fn abort() -> !; }
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! { unsafe { abort() } }

const ZERO_DIVISOR: i64 = 2_147_483_648;
const SIGNED_OVERFLOW: i64 = 2_147_483_649;

#[inline(always)]
fn invalid(a: i32, b: i32) -> Option<i64> {
    if b == 0 { Some(ZERO_DIVISOR) }
    else if a == i32::MIN && b == -1 { Some(SIGNED_OVERFLOW) }
    else { None }
}

#[unsafe(no_mangle)]
pub extern "C" fn service_stb_div_trunc(a: i32, b: i32) -> i64 {
    if let Some(error) = invalid(a, b) { return error; }
    (a / b) as i64
}
#[unsafe(no_mangle)]
pub extern "C" fn service_stb_div_floor(a: i32, b: i32) -> i64 {
    if let Some(error) = invalid(a, b) { return error; }
    let q = a / b;
    let r = a % b;
    (q - i32::from(r != 0 && (r < 0) != (b < 0))) as i64
}
#[unsafe(no_mangle)]
pub extern "C" fn service_stb_div_eucl(a: i32, b: i32) -> i64 {
    if let Some(error) = invalid(a, b) { return error; }
    a.div_euclid(b) as i64
}
#[unsafe(no_mangle)]
pub extern "C" fn service_stb_mod_trunc(a: i32, b: i32) -> i64 {
    if let Some(error) = invalid(a, b) { return error; }
    (a % b) as i64
}
#[unsafe(no_mangle)]
pub extern "C" fn service_stb_mod_floor(a: i32, b: i32) -> i64 {
    if let Some(error) = invalid(a, b) { return error; }
    let r = a % b;
    (if r != 0 && (r < 0) != (b < 0) { r + b } else { r }) as i64
}
#[unsafe(no_mangle)]
pub extern "C" fn service_stb_mod_eucl(a: i32, b: i32) -> i64 {
    if let Some(error) = invalid(a, b) { return error; }
    a.rem_euclid(b) as i64
}
