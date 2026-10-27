/* Hepta independent C11/GCC backend. No Rust compiler involved. */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
_Static_assert(CHAR_BIT == 8 && sizeof(size_t) == 8 && sizeof(intptr_t) == 8, "C backend requires the qualified 64-bit data model");
typedef struct { uint8_t *data; size_t len; } __hepta_cb_buffer;
typedef struct { uint32_t tag; union { struct { __hepta_cb_buffer f_0; } v_Ok; struct { uint8_t f_0; } v_Err; } payload; } __hepta_cb_aggregate_0;
typedef struct { __hepta_cb_buffer h_data; uint64_t h_tag; } __hepta_cb_aggregate_2;
typedef struct { uint32_t tag; union { struct { __hepta_cb_aggregate_2 f_0; } v_Ok; struct { uint8_t f_0; } v_Err; } payload; } __hepta_cb_aggregate_3;
static inline int64_t __hepta_cb_i64_bits(uint64_t x) { uint64_t bits = (uint64_t)x; int64_t out; memcpy(&out, &bits, sizeof out); return out; }
static inline int64_t __hepta_cb_i64_add(int64_t a, int64_t b) { int64_t r; if (__builtin_add_overflow(a,b,&r)) abort(); return r; }
static inline int64_t __hepta_cb_i64_sub(int64_t a, int64_t b) { int64_t r; if (__builtin_sub_overflow(a,b,&r)) abort(); return r; }
static inline int64_t __hepta_cb_i64_mul(int64_t a, int64_t b) { int64_t r; if (__builtin_mul_overflow(a,b,&r)) abort(); return r; }
static inline int64_t __hepta_cb_i64_div(int64_t a, int64_t b) { if (b == 0 || (a == INT64_MIN && b == -1)) abort(); return a / b; }
static inline int64_t __hepta_cb_i64_rem(int64_t a, int64_t b) { if (b == 0 || (a == INT64_MIN && b == -1)) abort(); return a % b; }
static inline int64_t __hepta_cb_i64_wrapping_add(int64_t a, int64_t b) { return __hepta_cb_i64_bits((uint64_t)a + (uint64_t)b); }
static inline int64_t __hepta_cb_i64_wrapping_sub(int64_t a, int64_t b) { return __hepta_cb_i64_bits((uint64_t)a - (uint64_t)b); }
static inline int64_t __hepta_cb_i64_wrapping_mul(int64_t a, int64_t b) { return __hepta_cb_i64_bits((uint64_t)a * (uint64_t)b); }
static inline int64_t __hepta_cb_i64_and(int64_t a, int64_t b) { return __hepta_cb_i64_bits((uint64_t)a & (uint64_t)b); }
static inline int64_t __hepta_cb_i64_or(int64_t a, int64_t b) { return __hepta_cb_i64_bits((uint64_t)a | (uint64_t)b); }
static inline int64_t __hepta_cb_i64_xor(int64_t a, int64_t b) { return __hepta_cb_i64_bits((uint64_t)a ^ (uint64_t)b); }
static inline int64_t __hepta_cb_i64_min(int64_t a, int64_t b) { return a < b ? a : b; }
static inline int64_t __hepta_cb_i64_max(int64_t a, int64_t b) { return a > b ? a : b; }
static inline int64_t __hepta_cb_i64_shl(int64_t a, int64_t b) { if ((uint64_t)b >= sizeof(a)*CHAR_BIT) abort(); return __hepta_cb_i64_bits((uint64_t)a << b); }
static inline int64_t __hepta_cb_i64_shr(int64_t a, int64_t b) { if ((uint64_t)b >= sizeof(a)*CHAR_BIT) abort(); uint64_t x = (uint64_t)(uint64_t)a >> b; if (a < 0 && b) x |= UINT64_MAX << (sizeof(a)*CHAR_BIT - b); return __hepta_cb_i64_bits(x); }
static inline uint64_t __hepta_cb_u64_bits(uint64_t x) { uint64_t bits = (uint64_t)x; uint64_t out; memcpy(&out, &bits, sizeof out); return out; }
static inline uint64_t __hepta_cb_u64_add(uint64_t a, uint64_t b) { uint64_t r; if (__builtin_add_overflow(a,b,&r)) abort(); return r; }
static inline uint64_t __hepta_cb_u64_sub(uint64_t a, uint64_t b) { uint64_t r; if (__builtin_sub_overflow(a,b,&r)) abort(); return r; }
static inline uint64_t __hepta_cb_u64_mul(uint64_t a, uint64_t b) { uint64_t r; if (__builtin_mul_overflow(a,b,&r)) abort(); return r; }
static inline uint64_t __hepta_cb_u64_div(uint64_t a, uint64_t b) { if (b == 0) abort(); return a / b; }
static inline uint64_t __hepta_cb_u64_rem(uint64_t a, uint64_t b) { if (b == 0) abort(); return a % b; }
static inline uint64_t __hepta_cb_u64_wrapping_add(uint64_t a, uint64_t b) { return __hepta_cb_u64_bits((uint64_t)a + (uint64_t)b); }
static inline uint64_t __hepta_cb_u64_wrapping_sub(uint64_t a, uint64_t b) { return __hepta_cb_u64_bits((uint64_t)a - (uint64_t)b); }
static inline uint64_t __hepta_cb_u64_wrapping_mul(uint64_t a, uint64_t b) { return __hepta_cb_u64_bits((uint64_t)a * (uint64_t)b); }
static inline uint64_t __hepta_cb_u64_and(uint64_t a, uint64_t b) { return __hepta_cb_u64_bits((uint64_t)a & (uint64_t)b); }
static inline uint64_t __hepta_cb_u64_or(uint64_t a, uint64_t b) { return __hepta_cb_u64_bits((uint64_t)a | (uint64_t)b); }
static inline uint64_t __hepta_cb_u64_xor(uint64_t a, uint64_t b) { return __hepta_cb_u64_bits((uint64_t)a ^ (uint64_t)b); }
static inline uint64_t __hepta_cb_u64_min(uint64_t a, uint64_t b) { return a < b ? a : b; }
static inline uint64_t __hepta_cb_u64_max(uint64_t a, uint64_t b) { return a > b ? a : b; }
static inline uint64_t __hepta_cb_u64_shl(uint64_t a, uint64_t b) { if ((uint64_t)b >= sizeof(a)*CHAR_BIT) abort(); return __hepta_cb_u64_bits((uint64_t)a << b); }
static inline uint64_t __hepta_cb_u64_shr(uint64_t a, uint64_t b) { if ((uint64_t)b >= sizeof(a)*CHAR_BIT) abort(); uint64_t x = (uint64_t)(uint64_t)a >> b; return __hepta_cb_u64_bits(x); }
static inline size_t __hepta_cb_usize_bits(uint64_t x) { size_t bits = (size_t)x; size_t out; memcpy(&out, &bits, sizeof out); return out; }
static inline size_t __hepta_cb_usize_add(size_t a, size_t b) { size_t r; if (__builtin_add_overflow(a,b,&r)) abort(); return r; }
static inline size_t __hepta_cb_usize_sub(size_t a, size_t b) { size_t r; if (__builtin_sub_overflow(a,b,&r)) abort(); return r; }
static inline size_t __hepta_cb_usize_mul(size_t a, size_t b) { size_t r; if (__builtin_mul_overflow(a,b,&r)) abort(); return r; }
static inline size_t __hepta_cb_usize_div(size_t a, size_t b) { if (b == 0) abort(); return a / b; }
static inline size_t __hepta_cb_usize_rem(size_t a, size_t b) { if (b == 0) abort(); return a % b; }
static inline size_t __hepta_cb_usize_wrapping_add(size_t a, size_t b) { return __hepta_cb_usize_bits((uint64_t)a + (uint64_t)b); }
static inline size_t __hepta_cb_usize_wrapping_sub(size_t a, size_t b) { return __hepta_cb_usize_bits((uint64_t)a - (uint64_t)b); }
static inline size_t __hepta_cb_usize_wrapping_mul(size_t a, size_t b) { return __hepta_cb_usize_bits((uint64_t)a * (uint64_t)b); }
static inline size_t __hepta_cb_usize_and(size_t a, size_t b) { return __hepta_cb_usize_bits((uint64_t)a & (uint64_t)b); }
static inline size_t __hepta_cb_usize_or(size_t a, size_t b) { return __hepta_cb_usize_bits((uint64_t)a | (uint64_t)b); }
static inline size_t __hepta_cb_usize_xor(size_t a, size_t b) { return __hepta_cb_usize_bits((uint64_t)a ^ (uint64_t)b); }
static inline size_t __hepta_cb_usize_min(size_t a, size_t b) { return a < b ? a : b; }
static inline size_t __hepta_cb_usize_max(size_t a, size_t b) { return a > b ? a : b; }
static inline size_t __hepta_cb_usize_shl(size_t a, size_t b) { if ((uint64_t)b >= sizeof(a)*CHAR_BIT) abort(); return __hepta_cb_usize_bits((uint64_t)a << b); }
static inline size_t __hepta_cb_usize_shr(size_t a, size_t b) { if ((uint64_t)b >= sizeof(a)*CHAR_BIT) abort(); uint64_t x = (uint64_t)(size_t)a >> b; return __hepta_cb_usize_bits(x); }

static bool __hepta_cb_allocate(size_t size, __hepta_cb_buffer *out) {
    if (size > PTRDIFF_MAX) return false;
    uint8_t *data = size ? calloc(size, sizeof(uint8_t)) : NULL;
    if (size && !data) return false;
    *out = (__hepta_cb_buffer){data, size};
    return true;
}
static __hepta_cb_buffer __hepta_cb_buffer_new(size_t size) {
    __hepta_cb_buffer out;
    if (!__hepta_cb_allocate(size, &out)) abort();
    return out;
}

static __hepta_cb_aggregate_0 __hepta_cb_try_buffer(size_t size) {
    __hepta_cb_buffer out;
    if (!__hepta_cb_allocate(size, &out))
        return (__hepta_cb_aggregate_0){.tag=1, .payload.v_Err={.f_0=1}};
    return (__hepta_cb_aggregate_0){.tag=0, .payload.v_Ok={.f_0=out}};
}

static void __hepta_cb_drop_0(__hepta_cb_aggregate_2 value);
static void __hepta_cb_drop_1(__hepta_cb_buffer value);
static void __hepta_cb_drop_0(__hepta_cb_aggregate_2 value) { __hepta_cb_drop_1(value.h_data); }
static void __hepta_cb_drop_1(__hepta_cb_buffer value) { free(value.data); }
uint64_t __hepta_cb_fn_M2812056b16998cdf_probe(size_t h_size, bool h_ok);
void __hepta_cb_fn_main(void);
__hepta_cb_aggregate_3 __hepta_cb_generic_2_M2812056b16998cdf_finish(__hepta_cb_aggregate_2 h_value, bool h_ok, uint8_t h_error);
const __hepta_cb_buffer * __hepta_cb_generic_3_M2812056b16998cdf_view(const __hepta_cb_buffer *h_value);
const __hepta_cb_aggregate_2 * __hepta_cb_generic_4_M2812056b16998cdf_view(const __hepta_cb_aggregate_2 *h_value);
void __hepta_cb_generic_5_M2812056b16998cdf_dispose(__hepta_cb_aggregate_2 h_value);
__hepta_cb_aggregate_2 __hepta_cb_generic_6_M2812056b16998cdf_forward(__hepta_cb_aggregate_2 h_value);
#line 11 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
uint64_t __hepta_cb_fn_M2812056b16998cdf_probe(size_t h_size, bool h_ok) {
#line 12 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
size_t __hepta_cb_v1 = h_size;
#line 12 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v2 = __hepta_cb_try_buffer(__hepta_cb_v1);
#line 12 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_0 h_allocated = __hepta_cb_v2;
#line 13 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v3 = h_allocated;
#line 13 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v4 = __hepta_cb_v3;
#line 13 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
switch (__hepta_cb_v4.tag) {
#line 13 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
case 1: {
#line 13 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
uint8_t h_allocation_error = __hepta_cb_v4.payload.v_Err.f_0;
#line 14 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
uint64_t __hepta_cb_v5 = (uint64_t)UINT64_C(1000);
#line 14 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
uint8_t __hepta_cb_v6 = h_allocation_error;
#line 14 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
uint64_t __hepta_cb_v7 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v6);
#line 14 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
uint64_t __hepta_cb_v8 = __hepta_cb_u64_add(__hepta_cb_v5, __hepta_cb_v7);
#line 14 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
return __hepta_cb_v8;
#line 14 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
break; }
#line 14 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
case 0: {
#line 14 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_buffer h_bytes = __hepta_cb_v4.payload.v_Ok.f_0;
#line 16 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_buffer __hepta_cb_v9 = h_bytes;
#line 16 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_buffer __hepta_cb_v10 = __hepta_cb_v9;
#line 16 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
uint64_t __hepta_cb_v11 = (uint64_t)UINT64_C(23);
#line 16 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v12 = (__hepta_cb_aggregate_2){ .h_data = __hepta_cb_v10, .h_tag = __hepta_cb_v11 };
#line 16 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v13 = __hepta_cb_v12;
#line 16 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
bool __hepta_cb_v14 = h_ok;
#line 16 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
uint8_t __hepta_cb_v15 = (uint8_t)UINT64_C(19);
#line 16 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_3 __hepta_cb_v16 = __hepta_cb_generic_2_M2812056b16998cdf_finish(__hepta_cb_v13, __hepta_cb_v14, __hepta_cb_v15);
#line 16 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_3 h_result = __hepta_cb_v16;
#line 17 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_3 __hepta_cb_v17 = h_result;
#line 17 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_3 __hepta_cb_v18 = __hepta_cb_v17;
#line 17 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
switch (__hepta_cb_v18.tag) {
#line 17 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
case 0: {
#line 17 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 h_packet = __hepta_cb_v18.payload.v_Ok.f_0;
#line 19 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
const __hepta_cb_buffer * __hepta_cb_arg19 = &((h_packet).h_data);
#line 19 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
const __hepta_cb_buffer * __hepta_cb_view20 = __hepta_cb_generic_3_M2812056b16998cdf_view(__hepta_cb_arg19);
#line 19 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
size_t __hepta_cb_v21 = ((*__hepta_cb_view20)).len;
#line 19 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
size_t h_observed_size = __hepta_cb_v21;
#line 20 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
size_t __hepta_cb_v22 = h_observed_size;
#line 20 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
uint64_t __hepta_cb_v23 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v22);
#line 20 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
const __hepta_cb_aggregate_2 * __hepta_cb_arg24 = &(h_packet);
#line 20 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
const __hepta_cb_aggregate_2 * __hepta_cb_view25 = __hepta_cb_generic_4_M2812056b16998cdf_view(__hepta_cb_arg24);
#line 20 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
uint64_t __hepta_cb_v26 = ((*__hepta_cb_view25)).h_tag;
#line 20 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
uint64_t __hepta_cb_v27 = __hepta_cb_u64_add(__hepta_cb_v23, __hepta_cb_v26);
#line 20 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
uint64_t h_answer = __hepta_cb_v27;
#line 21 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v28 = h_packet;
#line 21 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v29 = __hepta_cb_v28;
#line 21 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_generic_5_M2812056b16998cdf_dispose(__hepta_cb_v29);
#line 21 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
uint64_t __hepta_cb_v30 = h_answer;
#line 21 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
return __hepta_cb_v30;
#line 21 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
break; }
#line 21 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
case 1: {
#line 21 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
uint8_t h_problem = __hepta_cb_v18.payload.v_Err.f_0;
#line 23 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
uint8_t __hepta_cb_v31 = h_problem;
#line 23 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
uint64_t __hepta_cb_v32 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v31);
#line 23 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
return __hepta_cb_v32;
#line 23 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
break; }
#line 23 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
default: abort(); }
#line 23 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
break; }
#line 23 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
default: abort(); }
#line 23 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
}
#line 4 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
void __hepta_cb_fn_main(void) {
#line 5 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
uint64_t __hepta_cb_v33 = (uint64_t)UINT64_C(0);
#line 5 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
uint64_t h_checksum = __hepta_cb_v33;
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
int64_t __hepta_cb_v34 = (int64_t)INT64_C(0);
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
int64_t __hepta_cb_v35 = (int64_t)INT64_C(128);
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
for (int64_t h_index = __hepta_cb_v34; h_index < __hepta_cb_v35; ++h_index) { 
#line 7 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
int64_t __hepta_cb_v36 = h_index;
#line 7 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
size_t __hepta_cb_v37 = __hepta_cb_usize_bits((uint64_t)__hepta_cb_v36);
#line 7 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
size_t h_size = __hepta_cb_v37;
#line 8 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
size_t __hepta_cb_v38 = h_size;
#line 8 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
bool __hepta_cb_v39 = true;
#line 8 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
uint64_t __hepta_cb_v40 = __hepta_cb_fn_M2812056b16998cdf_probe(__hepta_cb_v38, __hepta_cb_v39);
#line 8 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
uint64_t h_accepted = __hepta_cb_v40;
#line 9 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
size_t __hepta_cb_v41 = h_size;
#line 9 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
bool __hepta_cb_v42 = false;
#line 9 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
uint64_t __hepta_cb_v43 = __hepta_cb_fn_M2812056b16998cdf_probe(__hepta_cb_v41, __hepta_cb_v42);
#line 9 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
uint64_t h_refused = __hepta_cb_v43;
#line 10 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
uint64_t __hepta_cb_v44 = h_accepted;
#line 10 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
int64_t __hepta_cb_v45 = h_index;
#line 10 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
uint64_t __hepta_cb_v46 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v45);
#line 10 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
uint64_t __hepta_cb_v47 = (uint64_t)UINT64_C(23);
#line 10 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
uint64_t __hepta_cb_v48 = __hepta_cb_u64_add(__hepta_cb_v46, __hepta_cb_v47);
#line 10 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
bool __hepta_cb_v49 = (__hepta_cb_v44 == __hepta_cb_v48);
#line 10 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
if (!__hepta_cb_v49) abort();
#line 11 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
uint64_t __hepta_cb_v50 = h_refused;
#line 11 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
uint64_t __hepta_cb_v51 = (uint64_t)UINT64_C(19);
#line 11 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
bool __hepta_cb_v52 = (__hepta_cb_v50 == __hepta_cb_v51);
#line 11 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
if (!__hepta_cb_v52) abort();
#line 12 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
uint64_t __hepta_cb_v53 = h_checksum;
#line 12 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
uint64_t __hepta_cb_v54 = h_accepted;
#line 12 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
uint64_t __hepta_cb_v55 = __hepta_cb_u64_add(__hepta_cb_v53, __hepta_cb_v54);
#line 12 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
uint64_t __hepta_cb_v56 = h_refused;
#line 12 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
uint64_t __hepta_cb_v57 = __hepta_cb_u64_add(__hepta_cb_v55, __hepta_cb_v56);
#line 12 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
h_checksum = __hepta_cb_v57; }
#line 14 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
uint64_t __hepta_cb_v58 = h_checksum;
#line 14 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
uint64_t __hepta_cb_v59 = (uint64_t)UINT64_C(13504);
#line 14 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
bool __hepta_cb_v60 = (__hepta_cb_v58 == __hepta_cb_v59);
#line 14 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
if (!__hepta_cb_v60) abort();
#line 15 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
uint64_t __hepta_cb_v61 = h_checksum;
#line 15 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
int64_t __hepta_cb_v62 = __hepta_cb_i64_bits((uint64_t)__hepta_cb_v61);
#line 15 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
((void)printf("%" PRId64 "\n", __hepta_cb_v62));
#line 15 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/main.hepta"
}
#line 7 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_3 __hepta_cb_generic_2_M2812056b16998cdf_finish(__hepta_cb_aggregate_2 h_value, bool h_ok, uint8_t h_error) {
#line 8 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
bool __hepta_cb_v63 = h_ok;
#line 8 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
bool __hepta_cb_v64 = (!__hepta_cb_v63);
#line 8 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
if (__hepta_cb_v64) { 
#line 8 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v65 = h_value;
#line 8 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v66 = __hepta_cb_v65;
#line 8 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_generic_5_M2812056b16998cdf_dispose(__hepta_cb_v66);
#line 8 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
uint8_t __hepta_cb_v67 = h_error;
#line 8 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_3 __hepta_cb_v68 = (__hepta_cb_aggregate_3){ .tag = 1, .payload.v_Err = { .f_0 = __hepta_cb_v67 } };
#line 8 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
return __hepta_cb_v68; } else {  }
#line 9 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v69 = h_value;
#line 9 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v70 = __hepta_cb_v69;
#line 9 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v71 = __hepta_cb_generic_6_M2812056b16998cdf_forward(__hepta_cb_v70);
#line 9 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v72 = __hepta_cb_v71;
#line 9 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_3 __hepta_cb_v73 = (__hepta_cb_aggregate_3){ .tag = 0, .payload.v_Ok = { .f_0 = __hepta_cb_v72 } };
#line 9 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
return __hepta_cb_v73;
#line 9 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
}
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
const __hepta_cb_buffer * __hepta_cb_generic_3_M2812056b16998cdf_view(const __hepta_cb_buffer *h_value) {
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
return &((*h_value));
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
}
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
const __hepta_cb_aggregate_2 * __hepta_cb_generic_4_M2812056b16998cdf_view(const __hepta_cb_aggregate_2 *h_value) {
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
return &((*h_value));
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
}
#line 5 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
void __hepta_cb_generic_5_M2812056b16998cdf_dispose(__hepta_cb_aggregate_2 h_value) {
#line 5 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v74 = h_value;
#line 5 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v75 = __hepta_cb_v74;
#line 5 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_drop_0(__hepta_cb_v75);
#line 5 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
}
#line 4 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_generic_6_M2812056b16998cdf_forward(__hepta_cb_aggregate_2 h_value) {
#line 4 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v76 = h_value;
#line 4 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v77 = __hepta_cb_v76;
#line 4 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
return __hepta_cb_v77;
#line 4 "/workspace/scratch/c7c6ee414a6c/hepta-research/examples/c_owned_backend/owned.hepta"
}
int main(void) { __hepta_cb_fn_main(); return 0; }
