//! Independent Rust baselines for the fixed signed-scalar protocol.
//!
//! Every exported entry has the same raw-word SysV transport as the HIA
//! verified scalar loader. Signed and narrow values are interpreted explicitly
//! from their low bits; a signed result is sign-extended to the returned word.
//! Checked failures abort rather than unwinding across the foreign interface.

#[inline(always)]
fn required<T>(value: Option<T>) -> T {
    match value {
        Some(value) => value,
        None => std::process::abort(),
    }
}

macro_rules! binary {
    ($name:ident, $ty:ty, $method:ident) => {
        #[no_mangle]
        #[inline(never)]
        pub extern "C" fn $name(a: u64, b: u64) -> u64 {
            (a as $ty).$method(b as $ty) as u64
        }
    };
}

macro_rules! checked_binary {
    ($name:ident, $ty:ty, $method:ident) => {
        #[no_mangle]
        #[inline(never)]
        pub extern "C" fn $name(a: u64, b: u64) -> u64 {
            required((a as $ty).$method(b as $ty)) as u64
        }
    };
}

macro_rules! checked_shift {
    ($name:ident, $ty:ty, $bits:expr, $method:ident) => {
        #[no_mangle]
        #[inline(never)]
        pub extern "C" fn $name(a: u64, b: u64) -> u64 {
            let count = b as $ty;
            // Test the complete normalized signed count before narrowing it
            // to u32; Rust's checked_shl alone would otherwise lose high bits.
            if count < 0 || count >= $bits {
                std::process::abort();
            }
            required((a as $ty).$method(count as u32)) as u64
        }
    };
}

macro_rules! identity {
    ($name:ident, $ty:ty) => {
        #[no_mangle]
        #[inline(never)]
        pub extern "C" fn $name(a: u64, _b: u64) -> u64 {
            (a as $ty) as u64
        }
    };
}

macro_rules! cast_wrap {
    ($name:ident, $from:ty, $to:ty) => {
        #[no_mangle]
        #[inline(never)]
        pub extern "C" fn $name(a: u64, _b: u64) -> u64 {
            ((a as $from) as $to) as u64
        }
    };
}

macro_rules! cast_checked {
    ($name:ident, $from:ty, $to:ty) => {
        #[no_mangle]
        #[inline(never)]
        pub extern "C" fn $name(a: u64, _b: u64) -> u64 {
            match <$to>::try_from(a as $from) {
                Ok(value) => value as u64,
                Err(_) => std::process::abort(),
            }
        }
    };
}

binary!(signed_i64_add_wrap, i64, wrapping_add);
binary!(signed_i64_sub_wrap, i64, wrapping_sub);
binary!(signed_i64_mul_wrap, i64, wrapping_mul);
checked_binary!(signed_i64_add_checked, i64, checked_add);
checked_binary!(signed_i64_sub_checked, i64, checked_sub);
checked_binary!(signed_i64_mul_checked, i64, checked_mul);
checked_binary!(signed_i64_div_checked, i64, checked_div);
checked_binary!(signed_i64_rem_checked, i64, checked_rem);

#[no_mangle]
#[inline(never)]
pub extern "C" fn signed_i64_neg_checked(a: u64, _b: u64) -> u64 {
    required((a as i64).checked_neg()) as u64
}

checked_shift!(signed_i64_shl_checked, i64, 64, checked_shl);
checked_shift!(signed_i64_shr_checked, i64, 64, checked_shr);

identity!(signed_i8_identity, i8);
binary!(signed_i8_add_wrap, i8, wrapping_add);
checked_binary!(signed_i8_add_checked, i8, checked_add);
checked_shift!(signed_i8_shr_checked, i8, 8, checked_shr);

identity!(signed_i16_identity, i16);
binary!(signed_i16_add_wrap, i16, wrapping_add);
checked_binary!(signed_i16_add_checked, i16, checked_add);
checked_shift!(signed_i16_shr_checked, i16, 16, checked_shr);

identity!(signed_i32_identity, i32);
binary!(signed_i32_add_wrap, i32, wrapping_add);
checked_binary!(signed_i32_add_checked, i32, checked_add);
checked_shift!(signed_i32_shr_checked, i32, 32, checked_shr);

cast_wrap!(signed_i64_to_u64_wrap, i64, u64);
cast_checked!(signed_i64_to_u64_checked, i64, u64);
cast_wrap!(signed_u64_to_i64_wrap, u64, i64);
cast_checked!(signed_u64_to_i64_checked, u64, i64);
cast_wrap!(signed_i64_to_i8_wrap, i64, i8);
cast_checked!(signed_i64_to_i8_checked, i64, i8);
cast_wrap!(signed_i64_to_u8_wrap, i64, u8);
cast_checked!(signed_i64_to_u8_checked, i64, u8);
cast_wrap!(signed_u64_to_i32_wrap, u64, i32);
cast_checked!(signed_u64_to_i32_checked, u64, i32);
