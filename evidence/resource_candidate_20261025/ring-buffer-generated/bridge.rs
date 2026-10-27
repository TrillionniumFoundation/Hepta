// Caller-unsafe original C ABI. Initialized live disjoint storage is an external obligation.

// Numeric interval checks reject overlap; they do not prove provenance or allocation extent.

fn __hepta_view_range(address: usize, count: usize, size: usize, align: usize) -> (usize, usize) {
    if count > (isize::MAX as usize) / size || count != 0 && (address == 0 || address % align != 0) { std::process::abort(); }
    let bytes = count.checked_mul(size).unwrap_or_else(|| std::process::abort());
    (address, address.checked_add(bytes).unwrap_or_else(|| std::process::abort()))
}

fn __hepta_view_disjoint(a: (usize, usize), b: (usize, usize)) {
    if a.0 < a.1 && b.0 < b.1 && a.0 < b.1 && b.0 < a.1 { std::process::abort(); }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct __HeptaAbi_C_ring_buffer_t {
    f_buffer: *mut u8,
    f_buffer_mask: usize,
    f_tail_index: usize,
    f_head_index: usize,
}

#[export_name = "ring_buffer_dequeue"]
pub unsafe extern "C" fn __hepta_c_view_export_0(b_buffer: *mut __HeptaAbi_C_ring_buffer_t, b_data: *mut u8) -> u8 {
    let r_b_buffer = __hepta_view_range(b_buffer as usize, 1, core::mem::size_of::<__HeptaAbi_C_ring_buffer_t>(), core::mem::align_of::<__HeptaAbi_C_ring_buffer_t>());
    let a_b_buffer = unsafe { b_buffer.read() };
    let mut s_b_buffer = H_C_ring_buffer_t { h_f_buffer_mask: a_b_buffer.f_buffer_mask, h_f_tail_index: a_b_buffer.f_tail_index, h_f_head_index: a_b_buffer.f_head_index };
    let n_b_buffer_f_buffer = (a_b_buffer.f_buffer_mask as usize).checked_add(1).unwrap_or_else(|| std::process::abort());
    let p_b_buffer_f_buffer = a_b_buffer.f_buffer;
    let r_b_buffer_f_buffer = __hepta_view_range(p_b_buffer_f_buffer as usize, n_b_buffer_f_buffer, core::mem::size_of::<u8>(), core::mem::align_of::<u8>());
    let n_b_data = 1;
    let r_b_data = __hepta_view_range(b_data as usize, n_b_data, core::mem::size_of::<u8>(), core::mem::align_of::<u8>());
    __hepta_view_disjoint(r_b_buffer, r_b_buffer_f_buffer);
    __hepta_view_disjoint(r_b_buffer, r_b_data);
    __hepta_view_disjoint(r_b_buffer_f_buffer, r_b_data);
    let s_b_buffer_f_buffer = if n_b_buffer_f_buffer == 0 { &mut [] } else { unsafe { core::slice::from_raw_parts_mut(p_b_buffer_f_buffer, n_b_buffer_f_buffer) } };
    let s_b_data = if n_b_data == 0 { &mut [] } else { unsafe { core::slice::from_raw_parts_mut(b_data, n_b_data) } };
    let result = h_c_ring_buffer_dequeue(&mut s_b_buffer, s_b_buffer_f_buffer, s_b_data, 0);
    unsafe { b_buffer.write(__HeptaAbi_C_ring_buffer_t { f_buffer: a_b_buffer.f_buffer, f_buffer_mask: s_b_buffer.h_f_buffer_mask, f_tail_index: s_b_buffer.h_f_tail_index, f_head_index: s_b_buffer.h_f_head_index }); }
    result
}

#[export_name = "ring_buffer_dequeue_arr"]
pub unsafe extern "C" fn __hepta_c_view_export_1(b_buffer: *mut __HeptaAbi_C_ring_buffer_t, b_data: *mut u8, b_len: usize) -> usize {
    let r_b_buffer = __hepta_view_range(b_buffer as usize, 1, core::mem::size_of::<__HeptaAbi_C_ring_buffer_t>(), core::mem::align_of::<__HeptaAbi_C_ring_buffer_t>());
    let a_b_buffer = unsafe { b_buffer.read() };
    let mut s_b_buffer = H_C_ring_buffer_t { h_f_buffer_mask: a_b_buffer.f_buffer_mask, h_f_tail_index: a_b_buffer.f_tail_index, h_f_head_index: a_b_buffer.f_head_index };
    let n_b_buffer_f_buffer = (a_b_buffer.f_buffer_mask as usize).checked_add(1).unwrap_or_else(|| std::process::abort());
    let p_b_buffer_f_buffer = a_b_buffer.f_buffer;
    let r_b_buffer_f_buffer = __hepta_view_range(p_b_buffer_f_buffer as usize, n_b_buffer_f_buffer, core::mem::size_of::<u8>(), core::mem::align_of::<u8>());
    let n_b_data = b_len as usize;
    let r_b_data = __hepta_view_range(b_data as usize, n_b_data, core::mem::size_of::<u8>(), core::mem::align_of::<u8>());
    __hepta_view_disjoint(r_b_buffer, r_b_buffer_f_buffer);
    __hepta_view_disjoint(r_b_buffer, r_b_data);
    __hepta_view_disjoint(r_b_buffer_f_buffer, r_b_data);
    let s_b_buffer_f_buffer = if n_b_buffer_f_buffer == 0 { &mut [] } else { unsafe { core::slice::from_raw_parts_mut(p_b_buffer_f_buffer, n_b_buffer_f_buffer) } };
    let s_b_data = if n_b_data == 0 { &mut [] } else { unsafe { core::slice::from_raw_parts_mut(b_data, n_b_data) } };
    let result = h_c_ring_buffer_dequeue_arr(&mut s_b_buffer, s_b_buffer_f_buffer, s_b_data, 0, b_len);
    unsafe { b_buffer.write(__HeptaAbi_C_ring_buffer_t { f_buffer: a_b_buffer.f_buffer, f_buffer_mask: s_b_buffer.h_f_buffer_mask, f_tail_index: s_b_buffer.h_f_tail_index, f_head_index: s_b_buffer.h_f_head_index }); }
    result
}

#[export_name = "ring_buffer_init"]
pub unsafe extern "C" fn __hepta_c_view_export_2(b_buffer: *mut __HeptaAbi_C_ring_buffer_t, b_buf: *mut u8, b_buf_size: usize) -> () {
    let r_b_buffer = __hepta_view_range(b_buffer as usize, 1, core::mem::size_of::<__HeptaAbi_C_ring_buffer_t>(), core::mem::align_of::<__HeptaAbi_C_ring_buffer_t>());
    let mut s_b_buffer = H_C_ring_buffer_t { h_f_buffer_mask: 0, h_f_tail_index: 0, h_f_head_index: 0 };
    let n_b_buf = b_buf_size as usize;
    let r_b_buf = __hepta_view_range(b_buf as usize, n_b_buf, core::mem::size_of::<u8>(), core::mem::align_of::<u8>());
    __hepta_view_disjoint(r_b_buffer, r_b_buf);
    let s_b_buf = if n_b_buf == 0 { &mut [] } else { unsafe { core::slice::from_raw_parts_mut(b_buf, n_b_buf) } };
    let result = h_c_ring_buffer_init(&mut s_b_buffer, s_b_buf, 0, b_buf_size);
    unsafe { b_buffer.write(__HeptaAbi_C_ring_buffer_t { f_buffer: b_buf, f_buffer_mask: s_b_buffer.h_f_buffer_mask, f_tail_index: s_b_buffer.h_f_tail_index, f_head_index: s_b_buffer.h_f_head_index }); }
    result
}

#[export_name = "ring_buffer_is_empty"]
pub unsafe extern "C" fn __hepta_c_view_export_3(b_buffer: *mut __HeptaAbi_C_ring_buffer_t) -> u8 {
    let r_b_buffer = __hepta_view_range(b_buffer as usize, 1, core::mem::size_of::<__HeptaAbi_C_ring_buffer_t>(), core::mem::align_of::<__HeptaAbi_C_ring_buffer_t>());
    let a_b_buffer = unsafe { b_buffer.read() };
    let mut s_b_buffer = H_C_ring_buffer_t { h_f_buffer_mask: a_b_buffer.f_buffer_mask, h_f_tail_index: a_b_buffer.f_tail_index, h_f_head_index: a_b_buffer.f_head_index };
    let n_b_buffer_f_buffer = (a_b_buffer.f_buffer_mask as usize).checked_add(1).unwrap_or_else(|| std::process::abort());
    let p_b_buffer_f_buffer = a_b_buffer.f_buffer;
    let r_b_buffer_f_buffer = __hepta_view_range(p_b_buffer_f_buffer as usize, n_b_buffer_f_buffer, core::mem::size_of::<u8>(), core::mem::align_of::<u8>());
    let s_b_buffer_f_buffer = if n_b_buffer_f_buffer == 0 { &[] } else { unsafe { core::slice::from_raw_parts(p_b_buffer_f_buffer, n_b_buffer_f_buffer) } };
    let result = h_c_ring_buffer_is_empty(&s_b_buffer, s_b_buffer_f_buffer);
    result
}

#[export_name = "ring_buffer_is_full"]
pub unsafe extern "C" fn __hepta_c_view_export_4(b_buffer: *mut __HeptaAbi_C_ring_buffer_t) -> u8 {
    let r_b_buffer = __hepta_view_range(b_buffer as usize, 1, core::mem::size_of::<__HeptaAbi_C_ring_buffer_t>(), core::mem::align_of::<__HeptaAbi_C_ring_buffer_t>());
    let a_b_buffer = unsafe { b_buffer.read() };
    let mut s_b_buffer = H_C_ring_buffer_t { h_f_buffer_mask: a_b_buffer.f_buffer_mask, h_f_tail_index: a_b_buffer.f_tail_index, h_f_head_index: a_b_buffer.f_head_index };
    let n_b_buffer_f_buffer = (a_b_buffer.f_buffer_mask as usize).checked_add(1).unwrap_or_else(|| std::process::abort());
    let p_b_buffer_f_buffer = a_b_buffer.f_buffer;
    let r_b_buffer_f_buffer = __hepta_view_range(p_b_buffer_f_buffer as usize, n_b_buffer_f_buffer, core::mem::size_of::<u8>(), core::mem::align_of::<u8>());
    let s_b_buffer_f_buffer = if n_b_buffer_f_buffer == 0 { &[] } else { unsafe { core::slice::from_raw_parts(p_b_buffer_f_buffer, n_b_buffer_f_buffer) } };
    let result = h_c_ring_buffer_is_full(&s_b_buffer, s_b_buffer_f_buffer);
    result
}

#[export_name = "ring_buffer_num_items"]
pub unsafe extern "C" fn __hepta_c_view_export_5(b_buffer: *mut __HeptaAbi_C_ring_buffer_t) -> usize {
    let r_b_buffer = __hepta_view_range(b_buffer as usize, 1, core::mem::size_of::<__HeptaAbi_C_ring_buffer_t>(), core::mem::align_of::<__HeptaAbi_C_ring_buffer_t>());
    let a_b_buffer = unsafe { b_buffer.read() };
    let mut s_b_buffer = H_C_ring_buffer_t { h_f_buffer_mask: a_b_buffer.f_buffer_mask, h_f_tail_index: a_b_buffer.f_tail_index, h_f_head_index: a_b_buffer.f_head_index };
    let n_b_buffer_f_buffer = (a_b_buffer.f_buffer_mask as usize).checked_add(1).unwrap_or_else(|| std::process::abort());
    let p_b_buffer_f_buffer = a_b_buffer.f_buffer;
    let r_b_buffer_f_buffer = __hepta_view_range(p_b_buffer_f_buffer as usize, n_b_buffer_f_buffer, core::mem::size_of::<u8>(), core::mem::align_of::<u8>());
    let s_b_buffer_f_buffer = if n_b_buffer_f_buffer == 0 { &[] } else { unsafe { core::slice::from_raw_parts(p_b_buffer_f_buffer, n_b_buffer_f_buffer) } };
    let result = h_c_ring_buffer_num_items(&s_b_buffer, s_b_buffer_f_buffer);
    result
}

#[export_name = "ring_buffer_peek"]
pub unsafe extern "C" fn __hepta_c_view_export_6(b_buffer: *mut __HeptaAbi_C_ring_buffer_t, b_data: *mut u8, b_index: usize) -> u8 {
    let r_b_buffer = __hepta_view_range(b_buffer as usize, 1, core::mem::size_of::<__HeptaAbi_C_ring_buffer_t>(), core::mem::align_of::<__HeptaAbi_C_ring_buffer_t>());
    let a_b_buffer = unsafe { b_buffer.read() };
    let mut s_b_buffer = H_C_ring_buffer_t { h_f_buffer_mask: a_b_buffer.f_buffer_mask, h_f_tail_index: a_b_buffer.f_tail_index, h_f_head_index: a_b_buffer.f_head_index };
    let n_b_buffer_f_buffer = (a_b_buffer.f_buffer_mask as usize).checked_add(1).unwrap_or_else(|| std::process::abort());
    let p_b_buffer_f_buffer = a_b_buffer.f_buffer;
    let r_b_buffer_f_buffer = __hepta_view_range(p_b_buffer_f_buffer as usize, n_b_buffer_f_buffer, core::mem::size_of::<u8>(), core::mem::align_of::<u8>());
    let n_b_data = 1;
    let r_b_data = __hepta_view_range(b_data as usize, n_b_data, core::mem::size_of::<u8>(), core::mem::align_of::<u8>());
    __hepta_view_disjoint(r_b_buffer, r_b_buffer_f_buffer);
    __hepta_view_disjoint(r_b_buffer, r_b_data);
    __hepta_view_disjoint(r_b_buffer_f_buffer, r_b_data);
    let s_b_buffer_f_buffer = if n_b_buffer_f_buffer == 0 { &mut [] } else { unsafe { core::slice::from_raw_parts_mut(p_b_buffer_f_buffer, n_b_buffer_f_buffer) } };
    let s_b_data = if n_b_data == 0 { &mut [] } else { unsafe { core::slice::from_raw_parts_mut(b_data, n_b_data) } };
    let result = h_c_ring_buffer_peek(&mut s_b_buffer, s_b_buffer_f_buffer, s_b_data, 0, b_index);
    unsafe { b_buffer.write(__HeptaAbi_C_ring_buffer_t { f_buffer: a_b_buffer.f_buffer, f_buffer_mask: s_b_buffer.h_f_buffer_mask, f_tail_index: s_b_buffer.h_f_tail_index, f_head_index: s_b_buffer.h_f_head_index }); }
    result
}

#[export_name = "ring_buffer_queue"]
pub unsafe extern "C" fn __hepta_c_view_export_7(b_buffer: *mut __HeptaAbi_C_ring_buffer_t, b_data: u8) -> () {
    let r_b_buffer = __hepta_view_range(b_buffer as usize, 1, core::mem::size_of::<__HeptaAbi_C_ring_buffer_t>(), core::mem::align_of::<__HeptaAbi_C_ring_buffer_t>());
    let a_b_buffer = unsafe { b_buffer.read() };
    let mut s_b_buffer = H_C_ring_buffer_t { h_f_buffer_mask: a_b_buffer.f_buffer_mask, h_f_tail_index: a_b_buffer.f_tail_index, h_f_head_index: a_b_buffer.f_head_index };
    let n_b_buffer_f_buffer = (a_b_buffer.f_buffer_mask as usize).checked_add(1).unwrap_or_else(|| std::process::abort());
    let p_b_buffer_f_buffer = a_b_buffer.f_buffer;
    let r_b_buffer_f_buffer = __hepta_view_range(p_b_buffer_f_buffer as usize, n_b_buffer_f_buffer, core::mem::size_of::<u8>(), core::mem::align_of::<u8>());
    __hepta_view_disjoint(r_b_buffer, r_b_buffer_f_buffer);
    let s_b_buffer_f_buffer = if n_b_buffer_f_buffer == 0 { &mut [] } else { unsafe { core::slice::from_raw_parts_mut(p_b_buffer_f_buffer, n_b_buffer_f_buffer) } };
    let result = h_c_ring_buffer_queue(&mut s_b_buffer, s_b_buffer_f_buffer, b_data);
    unsafe { b_buffer.write(__HeptaAbi_C_ring_buffer_t { f_buffer: a_b_buffer.f_buffer, f_buffer_mask: s_b_buffer.h_f_buffer_mask, f_tail_index: s_b_buffer.h_f_tail_index, f_head_index: s_b_buffer.h_f_head_index }); }
    result
}

#[export_name = "ring_buffer_queue_arr"]
pub unsafe extern "C" fn __hepta_c_view_export_8(b_buffer: *mut __HeptaAbi_C_ring_buffer_t, b_data: *const u8, b_size: usize) -> () {
    let r_b_buffer = __hepta_view_range(b_buffer as usize, 1, core::mem::size_of::<__HeptaAbi_C_ring_buffer_t>(), core::mem::align_of::<__HeptaAbi_C_ring_buffer_t>());
    let a_b_buffer = unsafe { b_buffer.read() };
    let mut s_b_buffer = H_C_ring_buffer_t { h_f_buffer_mask: a_b_buffer.f_buffer_mask, h_f_tail_index: a_b_buffer.f_tail_index, h_f_head_index: a_b_buffer.f_head_index };
    let n_b_buffer_f_buffer = (a_b_buffer.f_buffer_mask as usize).checked_add(1).unwrap_or_else(|| std::process::abort());
    let p_b_buffer_f_buffer = a_b_buffer.f_buffer;
    let r_b_buffer_f_buffer = __hepta_view_range(p_b_buffer_f_buffer as usize, n_b_buffer_f_buffer, core::mem::size_of::<u8>(), core::mem::align_of::<u8>());
    let n_b_data = b_size as usize;
    let r_b_data = __hepta_view_range(b_data as usize, n_b_data, core::mem::size_of::<u8>(), core::mem::align_of::<u8>());
    __hepta_view_disjoint(r_b_buffer, r_b_buffer_f_buffer);
    __hepta_view_disjoint(r_b_buffer, r_b_data);
    __hepta_view_disjoint(r_b_buffer_f_buffer, r_b_data);
    let s_b_buffer_f_buffer = if n_b_buffer_f_buffer == 0 { &mut [] } else { unsafe { core::slice::from_raw_parts_mut(p_b_buffer_f_buffer, n_b_buffer_f_buffer) } };
    let s_b_data = if n_b_data == 0 { &[] } else { unsafe { core::slice::from_raw_parts(b_data, n_b_data) } };
    let result = h_c_ring_buffer_queue_arr(&mut s_b_buffer, s_b_buffer_f_buffer, s_b_data, 0, b_size);
    unsafe { b_buffer.write(__HeptaAbi_C_ring_buffer_t { f_buffer: a_b_buffer.f_buffer, f_buffer_mask: s_b_buffer.h_f_buffer_mask, f_tail_index: s_b_buffer.h_f_tail_index, f_head_index: s_b_buffer.h_f_head_index }); }
    result
}
