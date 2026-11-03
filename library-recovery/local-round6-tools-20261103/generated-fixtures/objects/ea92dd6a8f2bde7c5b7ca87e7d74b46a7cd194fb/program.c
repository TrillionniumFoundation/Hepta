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
typedef struct { __hepta_cb_buffer h_data; } __hepta_cb_aggregate_0;
typedef struct { __hepta_cb_aggregate_0 h_resource0; __hepta_cb_aggregate_0 h_resource1; } __hepta_cb_aggregate_2;
typedef struct { uint32_t tag; union { struct { __hepta_cb_aggregate_0 f_0; } v_Ok; struct { uint8_t f_0; } v_Err; } payload; } __hepta_cb_aggregate_3;
typedef struct { uint32_t tag; union { struct { __hepta_cb_buffer f_0; } v_Ok; struct { uint8_t f_0; } v_Err; } payload; } __hepta_cb_aggregate_4;
typedef struct { const uint8_t *data; size_t len; } __hepta_cb_slice_5;
typedef struct { uint32_t tag; union { struct { __hepta_cb_aggregate_2 f_0; } v_Ok; struct { uint8_t f_0; } v_Err; } payload; } __hepta_cb_aggregate_6;
static inline int32_t __hepta_cb_i32_bits(uint64_t x) { uint32_t bits = (uint32_t)x; int32_t out; memcpy(&out, &bits, sizeof out); return out; }
static inline int32_t __hepta_cb_i32_add(int32_t a, int32_t b) { int32_t r; if (__builtin_add_overflow(a,b,&r)) abort(); return r; }
static inline int32_t __hepta_cb_i32_sub(int32_t a, int32_t b) { int32_t r; if (__builtin_sub_overflow(a,b,&r)) abort(); return r; }
static inline int32_t __hepta_cb_i32_mul(int32_t a, int32_t b) { int32_t r; if (__builtin_mul_overflow(a,b,&r)) abort(); return r; }
static inline int32_t __hepta_cb_i32_div(int32_t a, int32_t b) { if (b == 0 || (a == INT32_MIN && b == -1)) abort(); return a / b; }
static inline int32_t __hepta_cb_i32_rem(int32_t a, int32_t b) { if (b == 0 || (a == INT32_MIN && b == -1)) abort(); return a % b; }
static inline int32_t __hepta_cb_i32_wrapping_add(int32_t a, int32_t b) { return __hepta_cb_i32_bits((uint64_t)a + (uint64_t)b); }
static inline int32_t __hepta_cb_i32_wrapping_sub(int32_t a, int32_t b) { return __hepta_cb_i32_bits((uint64_t)a - (uint64_t)b); }
static inline int32_t __hepta_cb_i32_wrapping_mul(int32_t a, int32_t b) { return __hepta_cb_i32_bits((uint64_t)a * (uint64_t)b); }
static inline int32_t __hepta_cb_i32_and(int32_t a, int32_t b) { return __hepta_cb_i32_bits((uint64_t)a & (uint64_t)b); }
static inline int32_t __hepta_cb_i32_or(int32_t a, int32_t b) { return __hepta_cb_i32_bits((uint64_t)a | (uint64_t)b); }
static inline int32_t __hepta_cb_i32_xor(int32_t a, int32_t b) { return __hepta_cb_i32_bits((uint64_t)a ^ (uint64_t)b); }
static inline int32_t __hepta_cb_i32_min(int32_t a, int32_t b) { return a < b ? a : b; }
static inline int32_t __hepta_cb_i32_max(int32_t a, int32_t b) { return a > b ? a : b; }
static inline int32_t __hepta_cb_i32_shl(int32_t a, int32_t b) { if ((uint64_t)b >= sizeof(a)*CHAR_BIT) abort(); return __hepta_cb_i32_bits((uint64_t)a << b); }
static inline int32_t __hepta_cb_i32_shr(int32_t a, int32_t b) { if ((uint64_t)b >= sizeof(a)*CHAR_BIT) abort(); uint64_t x = (uint64_t)(uint32_t)a >> b; if (a < 0 && b) x |= UINT64_MAX << (sizeof(a)*CHAR_BIT - b); return __hepta_cb_i32_bits(x); }
static inline uint32_t __hepta_cb_u32_bits(uint64_t x) { uint32_t bits = (uint32_t)x; uint32_t out; memcpy(&out, &bits, sizeof out); return out; }
static inline uint32_t __hepta_cb_u32_add(uint32_t a, uint32_t b) { uint32_t r; if (__builtin_add_overflow(a,b,&r)) abort(); return r; }
static inline uint32_t __hepta_cb_u32_sub(uint32_t a, uint32_t b) { uint32_t r; if (__builtin_sub_overflow(a,b,&r)) abort(); return r; }
static inline uint32_t __hepta_cb_u32_mul(uint32_t a, uint32_t b) { uint32_t r; if (__builtin_mul_overflow(a,b,&r)) abort(); return r; }
static inline uint32_t __hepta_cb_u32_div(uint32_t a, uint32_t b) { if (b == 0) abort(); return a / b; }
static inline uint32_t __hepta_cb_u32_rem(uint32_t a, uint32_t b) { if (b == 0) abort(); return a % b; }
static inline uint32_t __hepta_cb_u32_wrapping_add(uint32_t a, uint32_t b) { return __hepta_cb_u32_bits((uint64_t)a + (uint64_t)b); }
static inline uint32_t __hepta_cb_u32_wrapping_sub(uint32_t a, uint32_t b) { return __hepta_cb_u32_bits((uint64_t)a - (uint64_t)b); }
static inline uint32_t __hepta_cb_u32_wrapping_mul(uint32_t a, uint32_t b) { return __hepta_cb_u32_bits((uint64_t)a * (uint64_t)b); }
static inline uint32_t __hepta_cb_u32_and(uint32_t a, uint32_t b) { return __hepta_cb_u32_bits((uint64_t)a & (uint64_t)b); }
static inline uint32_t __hepta_cb_u32_or(uint32_t a, uint32_t b) { return __hepta_cb_u32_bits((uint64_t)a | (uint64_t)b); }
static inline uint32_t __hepta_cb_u32_xor(uint32_t a, uint32_t b) { return __hepta_cb_u32_bits((uint64_t)a ^ (uint64_t)b); }
static inline uint32_t __hepta_cb_u32_min(uint32_t a, uint32_t b) { return a < b ? a : b; }
static inline uint32_t __hepta_cb_u32_max(uint32_t a, uint32_t b) { return a > b ? a : b; }
static inline uint32_t __hepta_cb_u32_shl(uint32_t a, uint32_t b) { if ((uint64_t)b >= sizeof(a)*CHAR_BIT) abort(); return __hepta_cb_u32_bits((uint64_t)a << b); }
static inline uint32_t __hepta_cb_u32_shr(uint32_t a, uint32_t b) { if ((uint64_t)b >= sizeof(a)*CHAR_BIT) abort(); uint64_t x = (uint64_t)(uint32_t)a >> b; return __hepta_cb_u32_bits(x); }
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
static inline uint8_t __hepta_cb_u8_bits(uint64_t x) { uint8_t bits = (uint8_t)x; uint8_t out; memcpy(&out, &bits, sizeof out); return out; }
static inline uint8_t __hepta_cb_u8_add(uint8_t a, uint8_t b) { uint8_t r; if (__builtin_add_overflow(a,b,&r)) abort(); return r; }
static inline uint8_t __hepta_cb_u8_sub(uint8_t a, uint8_t b) { uint8_t r; if (__builtin_sub_overflow(a,b,&r)) abort(); return r; }
static inline uint8_t __hepta_cb_u8_mul(uint8_t a, uint8_t b) { uint8_t r; if (__builtin_mul_overflow(a,b,&r)) abort(); return r; }
static inline uint8_t __hepta_cb_u8_div(uint8_t a, uint8_t b) { if (b == 0) abort(); return a / b; }
static inline uint8_t __hepta_cb_u8_rem(uint8_t a, uint8_t b) { if (b == 0) abort(); return a % b; }
static inline uint8_t __hepta_cb_u8_wrapping_add(uint8_t a, uint8_t b) { return __hepta_cb_u8_bits((uint64_t)a + (uint64_t)b); }
static inline uint8_t __hepta_cb_u8_wrapping_sub(uint8_t a, uint8_t b) { return __hepta_cb_u8_bits((uint64_t)a - (uint64_t)b); }
static inline uint8_t __hepta_cb_u8_wrapping_mul(uint8_t a, uint8_t b) { return __hepta_cb_u8_bits((uint64_t)a * (uint64_t)b); }
static inline uint8_t __hepta_cb_u8_and(uint8_t a, uint8_t b) { return __hepta_cb_u8_bits((uint64_t)a & (uint64_t)b); }
static inline uint8_t __hepta_cb_u8_or(uint8_t a, uint8_t b) { return __hepta_cb_u8_bits((uint64_t)a | (uint64_t)b); }
static inline uint8_t __hepta_cb_u8_xor(uint8_t a, uint8_t b) { return __hepta_cb_u8_bits((uint64_t)a ^ (uint64_t)b); }
static inline uint8_t __hepta_cb_u8_min(uint8_t a, uint8_t b) { return a < b ? a : b; }
static inline uint8_t __hepta_cb_u8_max(uint8_t a, uint8_t b) { return a > b ? a : b; }
static inline uint8_t __hepta_cb_u8_shl(uint8_t a, uint8_t b) { if ((uint64_t)b >= sizeof(a)*CHAR_BIT) abort(); return __hepta_cb_u8_bits((uint64_t)a << b); }
static inline uint8_t __hepta_cb_u8_shr(uint8_t a, uint8_t b) { if ((uint64_t)b >= sizeof(a)*CHAR_BIT) abort(); uint64_t x = (uint64_t)(uint8_t)a >> b; return __hepta_cb_u8_bits(x); }
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

static __hepta_cb_aggregate_4 __hepta_cb_try_buffer(size_t size) {
    __hepta_cb_buffer out;
    if (!__hepta_cb_allocate(size, &out))
        return (__hepta_cb_aggregate_4){.tag=1, .payload.v_Err={.f_0=1}};
    return (__hepta_cb_aggregate_4){.tag=0, .payload.v_Ok={.f_0=out}};
}

static void __hepta_cb_drop_0(__hepta_cb_buffer value);
static void __hepta_cb_drop_1(__hepta_cb_aggregate_0 value);
static void __hepta_cb_drop_0(__hepta_cb_buffer value) { free(value.data); }
static void __hepta_cb_drop_1(__hepta_cb_aggregate_0 value) { __hepta_cb_drop_0(value.h_data); }
__hepta_cb_aggregate_3 __hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_new(size_t h_size, bool h_reject);
__hepta_cb_aggregate_0 __hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_move(__hepta_cb_aggregate_0 h_owner);
void __hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_drop(__hepta_cb_aggregate_0 h_owner);
size_t __hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_size(const __hepta_cb_aggregate_0 *h_owner);
__hepta_cb_slice_5 __hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_data(const __hepta_cb_aggregate_0 *h_owner);
void __hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_fill(__hepta_cb_aggregate_0 *h_owner, uint8_t h_value);
uint8_t __hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_get(const __hepta_cb_aggregate_0 *h_owner, size_t h_index);
void __hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_set(__hepta_cb_aggregate_0 *h_owner, size_t h_index, uint8_t h_value);
__hepta_cb_aggregate_2 __hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_move(__hepta_cb_aggregate_2 h_owner);
void __hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_drop(__hepta_cb_aggregate_2 h_owner);
__hepta_cb_aggregate_6 __hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_new(size_t h_arg0, size_t h_arg1, uint32_t h_arg2);
void __hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_method0(__hepta_cb_aggregate_2 *h_receiver, uint8_t h_arg0);
size_t __hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_method1(const __hepta_cb_aggregate_2 *h_receiver);
uint64_t __hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_method2(const __hepta_cb_aggregate_2 *h_receiver, size_t h_arg0);
uint64_t __hepta_cb_fn_Mcf03d00758734ee2_translated_run(size_t h_arg0, size_t h_arg1, uint8_t h_arg2, size_t h_arg3, uint32_t h_arg4, uint32_t h_arg5);
uint64_t composed_case(size_t h_left, size_t h_right, uint8_t h_value, size_t h_index, uint32_t h_reject, uint32_t h_early);
#line 5 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_3 __hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_new(size_t h_size, bool h_reject) {
#line 6 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v1 = h_size;
#line 6 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_4 __hepta_cb_v2 = __hepta_cb_try_buffer(__hepta_cb_v1);
#line 6 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
switch (__hepta_cb_v2.tag) {
#line 6 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
case 1: {
#line 6 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t h_code = __hepta_cb_v2.payload.v_Err.f_0;
#line 7 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v3 = h_code;
#line 7 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_3 __hepta_cb_v4 = (__hepta_cb_aggregate_3){ .tag = 1, .payload.v_Err = { .f_0 = __hepta_cb_v3 } };
#line 7 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v4;
#line 7 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
break; }
#line 7 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
case 0: {
#line 7 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_buffer h_bytes = __hepta_cb_v2.payload.v_Ok.f_0;
#line 9 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
bool __hepta_cb_v5 = h_reject;
#line 9 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
if (__hepta_cb_v5) { 
#line 10 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_buffer __hepta_cb_v6 = h_bytes;
#line 10 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_buffer __hepta_cb_v7 = __hepta_cb_v6;
#line 10 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_drop_0(__hepta_cb_v7);
#line 11 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v8 = (uint8_t)UINT64_C(2);
#line 11 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_3 __hepta_cb_v9 = (__hepta_cb_aggregate_3){ .tag = 1, .payload.v_Err = { .f_0 = __hepta_cb_v8 } };
#line 11 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v9; } else {  }
#line 13 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_buffer __hepta_cb_v10 = h_bytes;
#line 13 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_buffer __hepta_cb_v11 = __hepta_cb_v10;
#line 13 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v12 = (__hepta_cb_aggregate_0){ .h_data = __hepta_cb_v11 };
#line 13 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_3 __hepta_cb_v13 = (__hepta_cb_aggregate_3){ .tag = 0, .payload.v_Ok = { .f_0 = __hepta_cb_v12 } };
#line 13 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v13;
#line 13 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
break; }
#line 13 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
default: abort(); }
#line 13 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
}
#line 18 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_move(__hepta_cb_aggregate_0 h_owner) {
#line 19 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v14 = h_owner;
#line 19 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v15 = __hepta_cb_v14;
#line 19 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v15;
#line 19 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
}
#line 22 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
void __hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_drop(__hepta_cb_aggregate_0 h_owner) {
#line 23 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v16 = h_owner;
#line 23 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v17 = __hepta_cb_v16;
#line 23 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_drop_1(__hepta_cb_v17);
#line 23 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
}
#line 26 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_size(const __hepta_cb_aggregate_0 *h_owner) {
#line 27 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v18 = (((*h_owner)).h_data).len;
#line 27 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v18;
#line 27 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
}
#line 30 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_slice_5 __hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_data(const __hepta_cb_aggregate_0 *h_owner) {
#line 31 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return (__hepta_cb_slice_5){(((*h_owner)).h_data).data, (((*h_owner)).h_data).len};
#line 31 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
}
#line 34 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
void __hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_fill(__hepta_cb_aggregate_0 *h_owner, uint8_t h_value) {
#line 35 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v19 = (size_t)UINT64_C(0);
#line 35 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v20 = (((*h_owner)).h_data).len;
#line 35 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
for (size_t h_index = __hepta_cb_v19; h_index < __hepta_cb_v20; ++h_index) { 
#line 35 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v21 = h_value;
#line 35 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v22 = h_index;
#line 35 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
if (__hepta_cb_v22 >= (((*h_owner)).h_data).len) abort();
#line 35 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
((((*h_owner)).h_data).data)[__hepta_cb_v22] = __hepta_cb_v21; }
#line 35 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
}
#line 38 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_get(const __hepta_cb_aggregate_0 *h_owner, size_t h_index) {
#line 39 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v23 = h_index;
#line 39 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
if (__hepta_cb_v23 >= (((*h_owner)).h_data).len) abort();
#line 39 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v24 = ((((*h_owner)).h_data).data)[__hepta_cb_v23];
#line 39 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v24;
#line 39 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
}
#line 42 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
void __hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_set(__hepta_cb_aggregate_0 *h_owner, size_t h_index, uint8_t h_value) {
#line 43 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v25 = h_value;
#line 43 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v26 = h_index;
#line 43 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
if (__hepta_cb_v26 >= (((*h_owner)).h_data).len) abort();
#line 43 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
((((*h_owner)).h_data).data)[__hepta_cb_v26] = __hepta_cb_v25;
#line 43 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
}
#line 48 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_move(__hepta_cb_aggregate_2 h_owner) {
#line 48 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v27 = h_owner;
#line 48 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v28 = __hepta_cb_v27;
#line 48 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v28;
#line 48 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
}
#line 50 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
void __hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_drop(__hepta_cb_aggregate_2 h_owner) {
#line 51 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v29 = (h_owner).h_resource0;
#line 51 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v30 = __hepta_cb_v29;
#line 51 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_drop(__hepta_cb_v30);
#line 52 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v31 = (h_owner).h_resource1;
#line 52 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v32 = __hepta_cb_v31;
#line 52 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_drop(__hepta_cb_v32);
#line 52 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
}
#line 55 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_6 __hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_new(size_t h_arg0, size_t h_arg1, uint32_t h_arg2) {
#line 56 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v33 = h_arg0;
#line 56 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v34 = h_arg2;
#line 56 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v35 = (int64_t)INT64_C(1);
#line 56 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v36 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v35);
#line 56 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v37 = __hepta_cb_u32_bits((uint64_t)__hepta_cb_v36);
#line 56 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
bool __hepta_cb_v38 = (__hepta_cb_v34 == __hepta_cb_v37);
#line 56 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_3 __hepta_cb_v39 = __hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_new(__hepta_cb_v33, __hepta_cb_v38);
#line 56 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
switch (__hepta_cb_v39.tag) {
#line 56 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
case 1: {
#line 56 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t h_code = __hepta_cb_v39.payload.v_Err.f_0;
#line 58 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v40 = h_code;
#line 58 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_6 __hepta_cb_v41 = (__hepta_cb_aggregate_6){ .tag = 1, .payload.v_Err = { .f_0 = __hepta_cb_v40 } };
#line 58 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v41;
#line 58 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
break; }
#line 58 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
case 0: {
#line 58 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_0 h_created0 = __hepta_cb_v39.payload.v_Ok.f_0;
#line 61 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v42 = h_arg1;
#line 61 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v43 = h_arg2;
#line 61 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v44 = (int64_t)INT64_C(2);
#line 61 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v45 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v44);
#line 61 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v46 = __hepta_cb_u32_bits((uint64_t)__hepta_cb_v45);
#line 61 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
bool __hepta_cb_v47 = (__hepta_cb_v43 == __hepta_cb_v46);
#line 61 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_3 __hepta_cb_v48 = __hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_new(__hepta_cb_v42, __hepta_cb_v47);
#line 61 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
switch (__hepta_cb_v48.tag) {
#line 61 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
case 1: {
#line 61 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t h_code = __hepta_cb_v48.payload.v_Err.f_0;
#line 63 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v49 = h_created0;
#line 63 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v50 = __hepta_cb_v49;
#line 63 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_drop(__hepta_cb_v50);
#line 64 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v51 = h_code;
#line 64 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_6 __hepta_cb_v52 = (__hepta_cb_aggregate_6){ .tag = 1, .payload.v_Err = { .f_0 = __hepta_cb_v51 } };
#line 64 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v52;
#line 64 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
break; }
#line 64 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
case 0: {
#line 64 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_0 h_created1 = __hepta_cb_v48.payload.v_Ok.f_0;
#line 67 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v53 = h_arg2;
#line 67 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v54 = (int64_t)INT64_C(3);
#line 67 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v55 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v54);
#line 67 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v56 = __hepta_cb_u32_bits((uint64_t)__hepta_cb_v55);
#line 67 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
bool __hepta_cb_v57 = (__hepta_cb_v53 == __hepta_cb_v56);
#line 67 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
if (__hepta_cb_v57) { 
#line 68 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v58 = h_created1;
#line 68 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v59 = __hepta_cb_v58;
#line 68 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_drop(__hepta_cb_v59);
#line 69 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v60 = h_created0;
#line 69 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v61 = __hepta_cb_v60;
#line 69 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_drop(__hepta_cb_v61);
#line 70 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v62 = (uint8_t)UINT64_C(3);
#line 70 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_6 __hepta_cb_v63 = (__hepta_cb_aggregate_6){ .tag = 1, .payload.v_Err = { .f_0 = __hepta_cb_v62 } };
#line 70 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v63; } else {  }
#line 72 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v64 = h_created0;
#line 72 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v65 = __hepta_cb_v64;
#line 72 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v66 = h_created1;
#line 72 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v67 = __hepta_cb_v66;
#line 72 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v68 = (__hepta_cb_aggregate_2){ .h_resource0 = __hepta_cb_v65, .h_resource1 = __hepta_cb_v67 };
#line 72 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_6 __hepta_cb_v69 = (__hepta_cb_aggregate_6){ .tag = 0, .payload.v_Ok = { .f_0 = __hepta_cb_v68 } };
#line 72 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v69;
#line 72 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
break; }
#line 72 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
default: abort(); }
#line 72 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
break; }
#line 72 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
default: abort(); }
#line 72 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
}
#line 79 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
void __hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_method0(__hepta_cb_aggregate_2 *h_receiver, uint8_t h_arg0) {
#line 80 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg70 = &(((*h_receiver)).h_resource0);
#line 80 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v71 = h_arg0;
#line 80 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_fill(__hepta_cb_arg70, __hepta_cb_v71);
#line 81 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg72 = &(((*h_receiver)).h_resource1);
#line 81 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v73 = h_arg0;
#line 81 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v74 = __hepta_cb_u32_bits((uint64_t)__hepta_cb_v73);
#line 81 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v75 = (int64_t)INT64_C(37);
#line 81 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v76 = __hepta_cb_u32_bits((uint64_t)__hepta_cb_v75);
#line 81 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v77 = __hepta_cb_u32_xor(__hepta_cb_v74, __hepta_cb_v76);
#line 81 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v78 = __hepta_cb_u8_bits((uint64_t)__hepta_cb_v77);
#line 81 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_fill(__hepta_cb_arg72, __hepta_cb_v78);
#line 82 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg79 = &(((*h_receiver)).h_resource0);
#line 82 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v80 = __hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_size(__hepta_cb_arg79);
#line 82 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v81 = (int64_t)INT64_C(0);
#line 82 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v82 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v81);
#line 82 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v83 = __hepta_cb_usize_bits((uint64_t)__hepta_cb_v82);
#line 82 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
bool __hepta_cb_v84 = (__hepta_cb_v80 != __hepta_cb_v83);
#line 82 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
if (__hepta_cb_v84) { 
#line 83 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg85 = &(((*h_receiver)).h_resource0);
#line 83 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v86 = (int64_t)INT64_C(0);
#line 83 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v87 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v86);
#line 83 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v88 = __hepta_cb_usize_bits((uint64_t)__hepta_cb_v87);
#line 83 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v89 = h_arg0;
#line 83 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v90 = __hepta_cb_u32_bits((uint64_t)__hepta_cb_v89);
#line 83 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v91 = (int64_t)INT64_C(91);
#line 83 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v92 = __hepta_cb_u32_bits((uint64_t)__hepta_cb_v91);
#line 83 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v93 = __hepta_cb_u32_xor(__hepta_cb_v90, __hepta_cb_v92);
#line 83 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v94 = __hepta_cb_u8_bits((uint64_t)__hepta_cb_v93);
#line 83 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_set(__hepta_cb_arg85, __hepta_cb_v88, __hepta_cb_v94); } else {  }
#line 83 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
}
#line 87 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_method1(const __hepta_cb_aggregate_2 *h_receiver) {
#line 88 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg95 = &(((*h_receiver)).h_resource0);
#line 88 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v96 = __hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_size(__hepta_cb_arg95);
#line 88 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg97 = &(((*h_receiver)).h_resource1);
#line 88 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v98 = __hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_size(__hepta_cb_arg97);
#line 88 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
bool __hepta_cb_v99 = (__hepta_cb_v96 < __hepta_cb_v98);
#line 88 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
if (__hepta_cb_v99) { 
#line 89 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg100 = &(((*h_receiver)).h_resource0);
#line 89 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v101 = __hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_size(__hepta_cb_arg100);
#line 89 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t h_result1 = __hepta_cb_v101;
#line 90 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v102 = h_result1;
#line 90 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v102; } else {  }
#line 92 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg103 = &(((*h_receiver)).h_resource1);
#line 92 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v104 = __hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_size(__hepta_cb_arg103);
#line 92 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t h_result2 = __hepta_cb_v104;
#line 93 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v105 = h_result2;
#line 93 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v105;
#line 93 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
}
#line 96 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_method2(const __hepta_cb_aggregate_2 *h_receiver, size_t h_arg0) {
#line 97 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg106 = &(((*h_receiver)).h_resource0);
#line 97 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_slice_5 __hepta_cb_view107 = __hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_data(__hepta_cb_arg106);
#line 97 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v108 = h_arg0;
#line 97 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
if (__hepta_cb_v108 >= (__hepta_cb_view107).len) abort();
#line 97 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v109 = ((__hepta_cb_view107).data)[__hepta_cb_v108];
#line 97 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v110 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v109);
#line 97 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v111 = (int64_t)INT64_C(3);
#line 97 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v112 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v111);
#line 97 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v113 = __hepta_cb_u64_wrapping_mul(__hepta_cb_v110, __hepta_cb_v112);
#line 97 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t h_local3 = __hepta_cb_v113;
#line 98 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v114 = h_local3;
#line 98 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg115 = &(((*h_receiver)).h_resource1);
#line 98 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v116 = h_arg0;
#line 98 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v117 = __hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_get(__hepta_cb_arg115, __hepta_cb_v116);
#line 98 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v118 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v117);
#line 98 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v119 = __hepta_cb_u64_wrapping_add(__hepta_cb_v114, __hepta_cb_v118);
#line 98 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg120 = &(((*h_receiver)).h_resource0);
#line 98 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v121 = __hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_size(__hepta_cb_arg120);
#line 98 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v122 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v121);
#line 98 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v123 = __hepta_cb_u64_wrapping_add(__hepta_cb_v119, __hepta_cb_v122);
#line 98 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg124 = &(((*h_receiver)).h_resource1);
#line 98 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v125 = __hepta_cb_fn_Mcf03d00758734ee2_HeptaLeaf_size(__hepta_cb_arg124);
#line 98 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v126 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v125);
#line 98 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v127 = __hepta_cb_u64_wrapping_add(__hepta_cb_v123, __hepta_cb_v126);
#line 98 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t h_result4 = __hepta_cb_v127;
#line 99 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v128 = h_result4;
#line 99 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v128;
#line 99 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
}
#line 102 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_fn_Mcf03d00758734ee2_translated_run(size_t h_arg0, size_t h_arg1, uint8_t h_arg2, size_t h_arg3, uint32_t h_arg4, uint32_t h_arg5) {
#line 103 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v129 = h_arg0;
#line 103 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v130 = h_arg1;
#line 103 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v131 = (int64_t)INT64_C(0);
#line 103 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v132 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v131);
#line 103 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v133 = __hepta_cb_u32_bits((uint64_t)__hepta_cb_v132);
#line 103 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_6 __hepta_cb_v134 = __hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_new(__hepta_cb_v129, __hepta_cb_v130, __hepta_cb_v133);
#line 103 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
switch (__hepta_cb_v134.tag) {
#line 103 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
case 1: {
#line 103 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t h_error6 = __hepta_cb_v134.payload.v_Err.f_0;
#line 105 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v135 = h_error6;
#line 105 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v136 = (uint8_t)UINT64_C(1);
#line 105 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
bool __hepta_cb_v137 = (__hepta_cb_v135 == __hepta_cb_v136);
#line 105 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
if (__hepta_cb_v137) { 
#line 105 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v138 = (int64_t)INT64_C(1001);
#line 105 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v139 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v138);
#line 105 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v140 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v139);
#line 105 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v140; } else {  }
#line 106 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v141 = h_error6;
#line 106 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v142 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v141);
#line 106 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t h_caughtcode = __hepta_cb_v142;
#line 107 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v143 = (int64_t)INT64_C(1000);
#line 107 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v144 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v143);
#line 107 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v145 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v144);
#line 107 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v146 = h_caughtcode;
#line 107 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v147 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v146);
#line 107 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v148 = __hepta_cb_u64_wrapping_add(__hepta_cb_v145, __hepta_cb_v147);
#line 107 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v148;
#line 107 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
break; }
#line 107 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
case 0: {
#line 107 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 h_local5value = __hepta_cb_v134.payload.v_Ok.f_0;
#line 110 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v149 = h_local5value;
#line 110 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v150 = __hepta_cb_v149;
#line 110 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 h_local5 = __hepta_cb_v150;
#line 111 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 * __hepta_cb_arg151 = &(h_local5);
#line 111 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v152 = h_arg2;
#line 111 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_method0(__hepta_cb_arg151, __hepta_cb_v152);
#line 112 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v153 = h_arg5;
#line 112 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v154 = (int64_t)INT64_C(1);
#line 112 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v155 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v154);
#line 112 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v156 = __hepta_cb_u32_bits((uint64_t)__hepta_cb_v155);
#line 112 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
bool __hepta_cb_v157 = (__hepta_cb_v153 == __hepta_cb_v156);
#line 112 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
if (__hepta_cb_v157) { 
#line 113 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v158 = h_arg1;
#line 113 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v159 = h_arg0;
#line 113 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v160 = h_arg4;
#line 113 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_6 __hepta_cb_v161 = __hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_new(__hepta_cb_v158, __hepta_cb_v159, __hepta_cb_v160);
#line 113 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
switch (__hepta_cb_v161.tag) {
#line 113 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
case 1: {
#line 113 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t h_error8 = __hepta_cb_v161.payload.v_Err.f_0;
#line 115 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v162 = h_local5;
#line 115 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v163 = __hepta_cb_v162;
#line 115 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_drop(__hepta_cb_v163);
#line 116 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v164 = h_error8;
#line 116 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v165 = (uint8_t)UINT64_C(1);
#line 116 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
bool __hepta_cb_v166 = (__hepta_cb_v164 == __hepta_cb_v165);
#line 116 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
if (__hepta_cb_v166) { 
#line 116 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v167 = (int64_t)INT64_C(1001);
#line 116 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v168 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v167);
#line 116 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v169 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v168);
#line 116 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v169; } else {  }
#line 117 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v170 = h_error8;
#line 117 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v171 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v170);
#line 117 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t h_caughtcode = __hepta_cb_v171;
#line 118 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v172 = (int64_t)INT64_C(1000);
#line 118 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v173 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v172);
#line 118 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v174 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v173);
#line 118 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v175 = h_caughtcode;
#line 118 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v176 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v175);
#line 118 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v177 = __hepta_cb_u64_wrapping_add(__hepta_cb_v174, __hepta_cb_v176);
#line 118 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v177;
#line 118 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
break; }
#line 118 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
case 0: {
#line 118 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 h_local7value = __hepta_cb_v161.payload.v_Ok.f_0;
#line 121 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v178 = h_local7value;
#line 121 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v179 = __hepta_cb_v178;
#line 121 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 h_local7 = __hepta_cb_v179;
#line 122 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 * __hepta_cb_arg180 = &(h_local7);
#line 122 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v181 = h_arg2;
#line 122 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v182 = __hepta_cb_u32_bits((uint64_t)__hepta_cb_v181);
#line 122 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v183 = (int64_t)INT64_C(19);
#line 122 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v184 = __hepta_cb_u32_bits((uint64_t)__hepta_cb_v183);
#line 122 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v185 = __hepta_cb_u32_xor(__hepta_cb_v182, __hepta_cb_v184);
#line 122 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v186 = __hepta_cb_u8_bits((uint64_t)__hepta_cb_v185);
#line 122 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_method0(__hepta_cb_arg180, __hepta_cb_v186);
#line 123 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v187 = h_arg3;
#line 123 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
const __hepta_cb_aggregate_2 * __hepta_cb_arg188 = &(h_local7);
#line 123 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v189 = __hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_method1(__hepta_cb_arg188);
#line 123 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
bool __hepta_cb_v190 = (__hepta_cb_v187 >= __hepta_cb_v189);
#line 123 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
if (__hepta_cb_v190) { 
#line 124 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v191 = (int64_t)INT64_C(3003);
#line 124 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v192 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v191);
#line 124 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v193 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v192);
#line 124 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t h_result9 = __hepta_cb_v193;
#line 125 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v194 = h_local7;
#line 125 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v195 = __hepta_cb_v194;
#line 125 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_drop(__hepta_cb_v195);
#line 126 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v196 = h_local5;
#line 126 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v197 = __hepta_cb_v196;
#line 126 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_drop(__hepta_cb_v197);
#line 127 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v198 = h_result9;
#line 127 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v198; } else {  }
#line 129 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v199 = h_arg2;
#line 129 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v200 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v199);
#line 129 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v201 = (int64_t)INT64_C(255);
#line 129 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v202 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v201);
#line 129 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
bool __hepta_cb_v203 = (__hepta_cb_v200 == __hepta_cb_v202);
#line 129 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
if (__hepta_cb_v203) { 
#line 130 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
const __hepta_cb_aggregate_2 * __hepta_cb_arg204 = &(h_local7);
#line 130 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v205 = h_arg3;
#line 130 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v206 = __hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_method2(__hepta_cb_arg204, __hepta_cb_v205);
#line 130 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t h_result10 = __hepta_cb_v206;
#line 131 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v207 = h_local7;
#line 131 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v208 = __hepta_cb_v207;
#line 131 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_drop(__hepta_cb_v208);
#line 132 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v209 = h_local5;
#line 132 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v210 = __hepta_cb_v209;
#line 132 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_drop(__hepta_cb_v210);
#line 133 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v211 = h_result10;
#line 133 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v211; } else {  }
#line 135 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v212 = h_local7;
#line 135 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v213 = __hepta_cb_v212;
#line 135 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_drop(__hepta_cb_v213);
#line 135 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
break; }
#line 135 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
default: abort(); } } else {  }
#line 139 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v214 = h_arg0;
#line 139 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v215 = (int64_t)INT64_C(1);
#line 139 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v216 = __hepta_cb_usize_bits((uint64_t)__hepta_cb_v215);
#line 139 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v217 = __hepta_cb_usize_wrapping_add(__hepta_cb_v214, __hepta_cb_v216);
#line 139 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v218 = h_arg1;
#line 139 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v219 = (int64_t)INT64_C(2);
#line 139 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v220 = __hepta_cb_usize_bits((uint64_t)__hepta_cb_v219);
#line 139 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v221 = __hepta_cb_usize_wrapping_add(__hepta_cb_v218, __hepta_cb_v220);
#line 139 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v222 = h_arg4;
#line 139 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_6 __hepta_cb_v223 = __hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_new(__hepta_cb_v217, __hepta_cb_v221, __hepta_cb_v222);
#line 139 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
switch (__hepta_cb_v223.tag) {
#line 139 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
case 1: {
#line 139 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t h_error12 = __hepta_cb_v223.payload.v_Err.f_0;
#line 141 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v224 = h_local5;
#line 141 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v225 = __hepta_cb_v224;
#line 141 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_drop(__hepta_cb_v225);
#line 142 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v226 = h_error12;
#line 142 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v227 = (uint8_t)UINT64_C(1);
#line 142 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
bool __hepta_cb_v228 = (__hepta_cb_v226 == __hepta_cb_v227);
#line 142 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
if (__hepta_cb_v228) { 
#line 142 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v229 = (int64_t)INT64_C(1001);
#line 142 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v230 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v229);
#line 142 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v231 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v230);
#line 142 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v231; } else {  }
#line 143 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v232 = h_error12;
#line 143 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v233 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v232);
#line 143 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t h_caughtcode = __hepta_cb_v233;
#line 144 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v234 = (int64_t)INT64_C(1000);
#line 144 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v235 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v234);
#line 144 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v236 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v235);
#line 144 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v237 = h_caughtcode;
#line 144 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v238 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v237);
#line 144 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v239 = __hepta_cb_u64_wrapping_add(__hepta_cb_v236, __hepta_cb_v238);
#line 144 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v239;
#line 144 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
break; }
#line 144 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
case 0: {
#line 144 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 h_local11value = __hepta_cb_v223.payload.v_Ok.f_0;
#line 147 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v240 = h_local11value;
#line 147 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v241 = __hepta_cb_v240;
#line 147 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 h_local11 = __hepta_cb_v241;
#line 148 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 * __hepta_cb_arg242 = &(h_local11);
#line 148 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v243 = h_arg2;
#line 148 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v244 = __hepta_cb_u32_bits((uint64_t)__hepta_cb_v243);
#line 148 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v245 = (int64_t)INT64_C(17);
#line 148 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v246 = __hepta_cb_u32_bits((uint64_t)__hepta_cb_v245);
#line 148 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v247 = __hepta_cb_u32_xor(__hepta_cb_v244, __hepta_cb_v246);
#line 148 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v248 = __hepta_cb_u8_bits((uint64_t)__hepta_cb_v247);
#line 148 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_method0(__hepta_cb_arg242, __hepta_cb_v248);
#line 149 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v249 = h_local11;
#line 149 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v250 = __hepta_cb_v249;
#line 149 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v251 = __hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_move(__hepta_cb_v250);
#line 149 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 h_local13 = __hepta_cb_v251;
#line 150 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v252 = h_arg5;
#line 150 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v253 = (int64_t)INT64_C(2);
#line 150 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v254 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v253);
#line 150 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v255 = __hepta_cb_u32_bits((uint64_t)__hepta_cb_v254);
#line 150 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
bool __hepta_cb_v256 = (__hepta_cb_v252 == __hepta_cb_v255);
#line 150 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
if (__hepta_cb_v256) { 
#line 151 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v257 = h_arg3;
#line 151 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
const __hepta_cb_aggregate_2 * __hepta_cb_arg258 = &(h_local13);
#line 151 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v259 = __hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_method1(__hepta_cb_arg258);
#line 151 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
bool __hepta_cb_v260 = (__hepta_cb_v257 >= __hepta_cb_v259);
#line 151 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
if (__hepta_cb_v260) { 
#line 152 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v261 = (int64_t)INT64_C(4003);
#line 152 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v262 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v261);
#line 152 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v263 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v262);
#line 152 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t h_result14 = __hepta_cb_v263;
#line 153 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v264 = h_local13;
#line 153 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v265 = __hepta_cb_v264;
#line 153 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_drop(__hepta_cb_v265);
#line 154 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v266 = h_local5;
#line 154 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v267 = __hepta_cb_v266;
#line 154 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_drop(__hepta_cb_v267);
#line 155 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v268 = h_result14;
#line 155 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v268; } else {  }
#line 157 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
const __hepta_cb_aggregate_2 * __hepta_cb_arg269 = &(h_local13);
#line 157 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v270 = h_arg3;
#line 157 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v271 = __hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_method2(__hepta_cb_arg269, __hepta_cb_v270);
#line 157 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t h_result15 = __hepta_cb_v271;
#line 158 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v272 = h_local13;
#line 158 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v273 = __hepta_cb_v272;
#line 158 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_drop(__hepta_cb_v273);
#line 159 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v274 = h_local5;
#line 159 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v275 = __hepta_cb_v274;
#line 159 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_drop(__hepta_cb_v275);
#line 160 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v276 = h_result15;
#line 160 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v276; } else {  }
#line 162 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v277 = (int64_t)INT64_C(1);
#line 162 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v278 = __hepta_cb_usize_bits((uint64_t)__hepta_cb_v277);
#line 162 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v279 = (int64_t)INT64_C(2);
#line 162 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v280 = __hepta_cb_usize_bits((uint64_t)__hepta_cb_v279);
#line 162 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v281 = (int64_t)INT64_C(0);
#line 162 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v282 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v281);
#line 162 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v283 = __hepta_cb_u32_bits((uint64_t)__hepta_cb_v282);
#line 162 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_6 __hepta_cb_v284 = __hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_new(__hepta_cb_v278, __hepta_cb_v280, __hepta_cb_v283);
#line 162 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
switch (__hepta_cb_v284.tag) {
#line 162 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
case 1: {
#line 162 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t h_error17 = __hepta_cb_v284.payload.v_Err.f_0;
#line 164 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v285 = h_local13;
#line 164 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v286 = __hepta_cb_v285;
#line 164 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_drop(__hepta_cb_v286);
#line 165 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v287 = h_local5;
#line 165 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v288 = __hepta_cb_v287;
#line 165 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_drop(__hepta_cb_v288);
#line 166 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v289 = h_error17;
#line 166 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v290 = (uint8_t)UINT64_C(1);
#line 166 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
bool __hepta_cb_v291 = (__hepta_cb_v289 == __hepta_cb_v290);
#line 166 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
if (__hepta_cb_v291) { 
#line 166 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v292 = (int64_t)INT64_C(1001);
#line 166 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v293 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v292);
#line 166 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v294 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v293);
#line 166 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v294; } else {  }
#line 167 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v295 = h_error17;
#line 167 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v296 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v295);
#line 167 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t h_caughtcode = __hepta_cb_v296;
#line 168 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v297 = (int64_t)INT64_C(1000);
#line 168 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v298 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v297);
#line 168 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v299 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v298);
#line 168 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v300 = h_caughtcode;
#line 168 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v301 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v300);
#line 168 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v302 = __hepta_cb_u64_wrapping_add(__hepta_cb_v299, __hepta_cb_v301);
#line 168 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v302;
#line 168 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
break; }
#line 168 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
case 0: {
#line 168 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 h_local16value = __hepta_cb_v284.payload.v_Ok.f_0;
#line 171 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v303 = h_local16value;
#line 171 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v304 = __hepta_cb_v303;
#line 171 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 h_local16 = __hepta_cb_v304;
#line 172 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 * __hepta_cb_arg305 = &(h_local16);
#line 172 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v306 = (int64_t)INT64_C(7);
#line 172 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v307 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v306);
#line 172 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint8_t __hepta_cb_v308 = __hepta_cb_u8_bits((uint64_t)__hepta_cb_v307);
#line 172 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_method0(__hepta_cb_arg305, __hepta_cb_v308);
#line 173 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v309 = h_arg5;
#line 173 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v310 = (int64_t)INT64_C(3);
#line 173 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v311 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v310);
#line 173 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint32_t __hepta_cb_v312 = __hepta_cb_u32_bits((uint64_t)__hepta_cb_v311);
#line 173 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
bool __hepta_cb_v313 = (__hepta_cb_v309 == __hepta_cb_v312);
#line 173 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
if (__hepta_cb_v313) { 
#line 174 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
const __hepta_cb_aggregate_2 * __hepta_cb_arg314 = &(h_local16);
#line 174 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v315 = (int64_t)INT64_C(0);
#line 174 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v316 = __hepta_cb_usize_bits((uint64_t)__hepta_cb_v315);
#line 174 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v317 = __hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_method2(__hepta_cb_arg314, __hepta_cb_v316);
#line 174 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t h_result18 = __hepta_cb_v317;
#line 175 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v318 = h_local16;
#line 175 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v319 = __hepta_cb_v318;
#line 175 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_drop(__hepta_cb_v319);
#line 176 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v320 = h_local13;
#line 176 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v321 = __hepta_cb_v320;
#line 176 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_drop(__hepta_cb_v321);
#line 177 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v322 = h_local5;
#line 177 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v323 = __hepta_cb_v322;
#line 177 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_drop(__hepta_cb_v323);
#line 178 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v324 = h_result18;
#line 178 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v324; } else {  }
#line 180 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v325 = h_local16;
#line 180 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v326 = __hepta_cb_v325;
#line 180 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_drop(__hepta_cb_v326);
#line 180 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
break; }
#line 180 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
default: abort(); }
#line 183 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v327 = h_local13;
#line 183 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v328 = __hepta_cb_v327;
#line 183 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_drop(__hepta_cb_v328);
#line 183 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
break; }
#line 183 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
default: abort(); }
#line 186 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v329 = h_arg3;
#line 186 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
const __hepta_cb_aggregate_2 * __hepta_cb_arg330 = &(h_local5);
#line 186 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v331 = __hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_method1(__hepta_cb_arg330);
#line 186 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
bool __hepta_cb_v332 = (__hepta_cb_v329 >= __hepta_cb_v331);
#line 186 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
if (__hepta_cb_v332) { 
#line 187 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int64_t __hepta_cb_v333 = (int64_t)INT64_C(2003);
#line 187 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
int32_t __hepta_cb_v334 = __hepta_cb_i32_bits((uint64_t)__hepta_cb_v333);
#line 187 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v335 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v334);
#line 187 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t h_result19 = __hepta_cb_v335;
#line 188 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v336 = h_local5;
#line 188 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v337 = __hepta_cb_v336;
#line 188 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_drop(__hepta_cb_v337);
#line 189 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v338 = h_result19;
#line 189 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v338; } else {  }
#line 191 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
const __hepta_cb_aggregate_2 * __hepta_cb_arg339 = &(h_local5);
#line 191 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
size_t __hepta_cb_v340 = h_arg3;
#line 191 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v341 = __hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_method2(__hepta_cb_arg339, __hepta_cb_v340);
#line 191 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t h_result20 = __hepta_cb_v341;
#line 192 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v342 = h_local5;
#line 192 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v343 = __hepta_cb_v342;
#line 192 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_HeptaComposite_drop(__hepta_cb_v343);
#line 193 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
uint64_t __hepta_cb_v344 = h_result20;
#line 193 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
return __hepta_cb_v344;
#line 193 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
break; }
#line 193 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
default: abort(); }
#line 193 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/migrated.hepta"
}
#line 4 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/consumer.hepta"
uint64_t composed_case(size_t h_left, size_t h_right, uint8_t h_value, size_t h_index, uint32_t h_reject, uint32_t h_early) {
#line 6 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/consumer.hepta"
size_t __hepta_cb_v345 = h_left;
#line 6 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/consumer.hepta"
size_t __hepta_cb_v346 = h_right;
#line 6 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/consumer.hepta"
uint8_t __hepta_cb_v347 = h_value;
#line 6 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/consumer.hepta"
size_t __hepta_cb_v348 = h_index;
#line 6 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/consumer.hepta"
uint32_t __hepta_cb_v349 = h_reject;
#line 6 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/consumer.hepta"
uint32_t __hepta_cb_v350 = h_early;
#line 6 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/consumer.hepta"
uint64_t __hepta_cb_v351 = __hepta_cb_fn_Mcf03d00758734ee2_translated_run(__hepta_cb_v345, __hepta_cb_v346, __hepta_cb_v347, __hepta_cb_v348, __hepta_cb_v349, __hepta_cb_v350);
#line 6 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/consumer.hepta"
return __hepta_cb_v351;
#line 6 "/home/runner/work/Hepta/Hepta/artifacts/verified-optimization/cpp-scoped/consumer.hepta"
}

/* Compiled as C++ for the original, and C for translated implementations. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include "cases.h"

static volatile bool observed_tracking;
static volatile size_t observed_refuse_at, observed_allocated, observed_freed, observed_refusals, observed_attempts;
static volatile intptr_t observed_live;
static volatile uint64_t observed_trace;
static void* volatile observed_pointers[8];
static volatile size_t observed_sizes[8];

static uint64_t observe_word(uint64_t state, uint64_t word) {
    for (unsigned i = 0; i < 8; ++i) { state ^= (word >> (i * 8)) & 255; state *= UINT64_C(1099511628211); }
    return state;
}
static void observe_event(uint64_t kind, size_t identity, size_t size) {
    observed_trace = observe_word(observe_word(observe_word(observed_trace, kind), identity), size);
}
static bool refuse_allocation(size_t size) {
    if (!observed_tracking) return false;
    observed_attempts = observed_attempts + 1;
    if (observed_attempts != observed_refuse_at) return false;
    observed_refusals = observed_refusals + 1;
    observe_event(3, observed_attempts, size);
    return true;
}
static void record_allocation(void* pointer, size_t size) {
    if (!observed_tracking || !pointer) return;
    if (observed_allocated >= 8) abort();
    observed_pointers[observed_allocated] = pointer;
    observed_sizes[observed_allocated] = size;
    observed_allocated = observed_allocated + 1;
    observed_live = observed_live + 1;
    observe_event(1, observed_allocated, size);
}
static void record_release(void* pointer) {
    if (!observed_tracking || !pointer) return;
    for (size_t i = 0; i < observed_allocated; ++i) {
        if (observed_pointers[i] == pointer) {
            observed_pointers[i] = NULL;
            observed_freed = observed_freed + 1;
            observed_live = observed_live - 1;
            observe_event(2, i + 1, observed_sizes[i]);
            return;
        }
    }
    abort(); /* Unknown or double release is a native observation failure. */
}
#ifdef __cplusplus
#include <new>
extern "C" uint64_t composed_case(size_t, size_t, uint8_t, size_t, uint32_t, uint32_t) noexcept;
void* operator new[](std::size_t size) {
    if (refuse_allocation(size)) throw std::bad_alloc();
    void* pointer = std::malloc(size);
    if (!pointer) throw std::bad_alloc();
    record_allocation(pointer, size);
    return pointer;
}
void operator delete[](void* pointer) noexcept { record_release(pointer); std::free(pointer); }
void operator delete[](void* pointer, std::size_t) noexcept { ::operator delete[](pointer); }
#else
extern uint64_t composed_case(size_t, size_t, uint8_t, size_t, uint32_t, uint32_t);
void* __real_calloc(size_t, size_t);
void* __real_malloc(size_t);
void __real_free(void*);
void* __wrap_calloc(size_t count, size_t size) {
    if (refuse_allocation(count * size)) return NULL;
    void* pointer = __real_calloc(count, size);
    record_allocation(pointer, count * size);
    return pointer;
}
void* __wrap_malloc(size_t size) {
    if (refuse_allocation(size)) return NULL;
    void* pointer = __real_malloc(size);
    record_allocation(pointer, size);
    return pointer;
}
void __wrap_free(void* pointer) { record_release(pointer); __real_free(pointer); }
#endif

int main(void) {
    uint64_t digest = UINT64_C(14695981039346656037);
    size_t total_allocations = 0, total_frees = 0, total_refusals = 0;
    for (size_t i = 0; i < COMPOSED_CASE_COUNT; ++i) {
        const struct ComposedCase* current = &composed_cases[i];
        observed_allocated = 0; observed_freed = 0; observed_refusals = 0; observed_attempts = 0;
        observed_live = 0; observed_trace = UINT64_C(14695981039346656037);
        for (size_t j = 0; j < 8; ++j) { observed_pointers[j] = NULL; observed_sizes[j] = 0; }
        observed_refuse_at = current->refuse_at; observed_tracking = true;
        uint64_t actual = composed_case(current->left, current->right, current->value, current->index, current->reject, current->early);
        observed_tracking = false;
        if (actual != current->expected) {
            printf("{\"ok\":false,\"failure\":\"value\",\"case\":%zu,\"expected\":%" PRIu64 ",\"actual\":%" PRIu64 "}\n", i, current->expected, actual);
            return 2;
        }
        if (observed_allocated != current->allocated || observed_freed != current->allocated || observed_live != 0 ||
            observed_refusals != current->refusals || observed_attempts != current->allocated + current->refusals || observed_trace != current->trace) {
            printf("{\"ok\":false,\"failure\":\"lifecycle\",\"case\":%zu,\"allocated\":%zu,\"freed\":%zu,\"live\":%" PRIdPTR ",\"refusals\":%zu,\"trace\":\"%016" PRIx64 "\",\"expected_trace\":\"%016" PRIx64 "\"}\n",
                   i, observed_allocated, observed_freed, observed_live, observed_refusals, observed_trace, current->trace);
            return 3;
        }
        total_allocations += observed_allocated; total_frees += observed_freed; total_refusals += observed_refusals;
        digest = observe_word(digest, i); digest = observe_word(digest, actual); digest = observe_word(digest, observed_trace);
        digest = observe_word(digest, observed_allocated); digest = observe_word(digest, observed_freed); digest = observe_word(digest, observed_refusals);
    }
    printf("{\"ok\":true,\"cases\":%zu,\"observations_fnv64\":\"%016" PRIx64 "\",\"allocations\":%zu,\"frees\":%zu,\"refusals\":%zu,\"live\":0}\n",
           (size_t)COMPOSED_CASE_COUNT, digest, total_allocations, total_frees, total_refusals);
    return 0;
}
