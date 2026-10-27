// Generated caller-unsafe C ABI bridge. NOT a proof of foreign pointer validity.

// SAFETY: nonempty buffers must be initialized, aligned, live within one allocation,

// stable throughout the call; a mutable slice additionally requires exclusive access.

// These are caller-supplied contracts and may narrow the original C input domain.

#[export_name = "int_compare"]
pub unsafe extern "C" fn __hepta_c_export_0(b_vlocation1: *mut core::ffi::c_void, b_vlocation2: *mut core::ffi::c_void) -> i32 {
    let n_b_vlocation1 = 1 as usize;
    if n_b_vlocation1 > (isize::MAX as usize) / core::mem::size_of::<i32>() { std::process::abort(); }
    if n_b_vlocation1 != 0 && (b_vlocation1.is_null() || (b_vlocation1 as usize) % core::mem::align_of::<i32>() != 0) { std::process::abort(); }
    let s_b_vlocation1 = if n_b_vlocation1 == 0 { &[] } else { unsafe { core::slice::from_raw_parts(b_vlocation1.cast::<i32>(), n_b_vlocation1) } };
    let n_b_vlocation2 = 1 as usize;
    if n_b_vlocation2 > (isize::MAX as usize) / core::mem::size_of::<i32>() { std::process::abort(); }
    if n_b_vlocation2 != 0 && (b_vlocation2.is_null() || (b_vlocation2 as usize) % core::mem::align_of::<i32>() != 0) { std::process::abort(); }
    let s_b_vlocation2 = if n_b_vlocation2 == 0 { &[] } else { unsafe { core::slice::from_raw_parts(b_vlocation2.cast::<i32>(), n_b_vlocation2) } };
    h_c_int_compare(s_b_vlocation1, s_b_vlocation2)
}

#[export_name = "int_equal"]
pub unsafe extern "C" fn __hepta_c_export_1(b_vlocation1: *mut core::ffi::c_void, b_vlocation2: *mut core::ffi::c_void) -> i32 {
    let n_b_vlocation1 = 1 as usize;
    if n_b_vlocation1 > (isize::MAX as usize) / core::mem::size_of::<i32>() { std::process::abort(); }
    if n_b_vlocation1 != 0 && (b_vlocation1.is_null() || (b_vlocation1 as usize) % core::mem::align_of::<i32>() != 0) { std::process::abort(); }
    let s_b_vlocation1 = if n_b_vlocation1 == 0 { &[] } else { unsafe { core::slice::from_raw_parts(b_vlocation1.cast::<i32>(), n_b_vlocation1) } };
    let n_b_vlocation2 = 1 as usize;
    if n_b_vlocation2 > (isize::MAX as usize) / core::mem::size_of::<i32>() { std::process::abort(); }
    if n_b_vlocation2 != 0 && (b_vlocation2.is_null() || (b_vlocation2 as usize) % core::mem::align_of::<i32>() != 0) { std::process::abort(); }
    let s_b_vlocation2 = if n_b_vlocation2 == 0 { &[] } else { unsafe { core::slice::from_raw_parts(b_vlocation2.cast::<i32>(), n_b_vlocation2) } };
    h_c_int_equal(s_b_vlocation1, s_b_vlocation2)
}

#[export_name = "int_hash"]
pub unsafe extern "C" fn __hepta_c_export_2(b_vlocation: *mut core::ffi::c_void) -> u32 {
    let n_b_vlocation = 1 as usize;
    if n_b_vlocation > (isize::MAX as usize) / core::mem::size_of::<i32>() { std::process::abort(); }
    if n_b_vlocation != 0 && (b_vlocation.is_null() || (b_vlocation as usize) % core::mem::align_of::<i32>() != 0) { std::process::abort(); }
    let s_b_vlocation = if n_b_vlocation == 0 { &[] } else { unsafe { core::slice::from_raw_parts(b_vlocation.cast::<i32>(), n_b_vlocation) } };
    h_c_int_hash(s_b_vlocation)
}
