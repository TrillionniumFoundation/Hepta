// Generated caller-unsafe C ABI bridge. NOT a proof of foreign pointer validity.

// SAFETY: nonempty buffers must be initialized, aligned, live within one allocation,

// stable throughout the call; a mutable slice additionally requires exclusive access.

// These are caller-supplied contracts and may narrow the original C input domain.

#[export_name = "mutate_bytes"]
pub unsafe extern "C" fn __hepta_c_export_1(b_data: *mut u8, b_count: usize, b_seed: u8) -> u32 {
    let n_b_data = b_count as usize;
    if n_b_data > (isize::MAX as usize) / core::mem::size_of::<u8>() { std::process::abort(); }
    if n_b_data != 0 && (b_data.is_null() || (b_data as usize) % core::mem::align_of::<u8>() != 0) { std::process::abort(); }
    let s_b_data = if n_b_data == 0 { &mut [] } else { unsafe { core::slice::from_raw_parts_mut(b_data, n_b_data) } };
    h_c_mutate_bytes(s_b_data, b_count, b_seed)
}

#[export_name = "native_add"]
pub unsafe extern "C" fn __hepta_c_export_2(b_a: i32, b_b: i32) -> i32 {
    h_c_native_add(b_a, b_b)
}

#[export_name = "native_transform"]
pub unsafe extern "C" fn __hepta_c_export_3(b_value: H_C_NativePoint, b_data: *const u8, b_count: usize) -> H_C_NativePoint {
    let n_b_data = b_count as usize;
    if n_b_data > (isize::MAX as usize) / core::mem::size_of::<u8>() { std::process::abort(); }
    if n_b_data != 0 && (b_data.is_null() || (b_data as usize) % core::mem::align_of::<u8>() != 0) { std::process::abort(); }
    let s_b_data = if n_b_data == 0 { &[] } else { unsafe { core::slice::from_raw_parts(b_data, n_b_data) } };
    h_c_native_transform(b_value, s_b_data, b_count)
}

#[export_name = "owned_calloc_sum"]
pub unsafe extern "C" fn __hepta_c_export_4(b_count: usize) -> i64 {
    h_c_owned_calloc_sum(b_count)
}

#[export_name = "owned_malloc_sum"]
pub unsafe extern "C" fn __hepta_c_export_5(b_count: usize) -> i64 {
    h_c_owned_malloc_sum(b_count)
}

#[export_name = "sum_bytes"]
pub unsafe extern "C" fn __hepta_c_export_6(b_data: *const u8, b_count: usize) -> u32 {
    let n_b_data = b_count as usize;
    if n_b_data > (isize::MAX as usize) / core::mem::size_of::<u8>() { std::process::abort(); }
    if n_b_data != 0 && (b_data.is_null() || (b_data as usize) % core::mem::align_of::<u8>() != 0) { std::process::abort(); }
    let s_b_data = if n_b_data == 0 { &[] } else { unsafe { core::slice::from_raw_parts(b_data, n_b_data) } };
    h_c_sum_bytes(s_b_data, b_count)
}
